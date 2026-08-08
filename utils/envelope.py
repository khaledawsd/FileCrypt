"""Passphrase mode: one self-contained encrypted file, no key file.

The default flow hands back two files, and the key file is a single point of
failure -- lose it and the data is gone. Passphrase mode removes that failure
case by deriving the key from something the user remembers instead of from
``os.urandom``.

That only helps if there is genuinely nothing left to keep, which means the
encrypted file has to describe itself::

    b"FCP1" | header length (4 bytes, big endian) | header JSON | ciphertext | MAC

The header names the algorithm, the original filename and the KDF parameters --
everything except the secret. The 32-byte trailing MAC covers every preceding
byte under a key derived independently of the cipher key, which buys three
things: a wrong passphrase is rejected before any decryption is attempted, the
header cannot be edited in transit, and every algorithm gets tamper detection,
including the educational ones that have none of their own.

Note what is deliberately *absent*: the ``plaintext_sha256`` that
:mod:`utils.keyfile` records. In a key file that checksum is harmless, because
whoever holds the key file already holds the key. Writing it next to the
ciphertext instead would hand anyone with the file an oracle for confirming
guesses about its contents. The MAC serves the same purpose and leaks nothing.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
from datetime import UTC, datetime
from hashlib import sha256

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .encryption_utils import ALGORITHMS, KEY_BYTES, DecryptionError

MAGIC = b"FCP1"
FORMAT = "filecrypt-envelope"
VERSION = 1
EXTENSION = ".fcx"

#: Shortest passphrase the app will accept. Everything here rests on the
#: passphrase, so a two-character one would make the scrypt cost pointless.
MIN_PASSPHRASE = 8

_LENGTH_BYTES = 4
_MAC_BYTES = 32
_SALT_BYTES = 16
_MAX_HEADER = 64 * 1024

# scrypt at its "interactive" setting: roughly 32 MB and a tenth of a second per
# attempt. The cost is the point -- it is what makes guessing expensive.
_N, _R, _P = 2 ** 15, 8, 1

# These parameters arrive inside an attacker-supplied file and are read *before*
# the MAC can be checked, because deriving the MAC key is what they are for.
# scrypt allocates 128*N*r bytes, so an unbounded N is a memory bomb.
_N_RANGE = (2 ** 14, 2 ** 17)
_R_RANGE = (1, 16)
_P_RANGE = (1, 4)


def _fail(message: str) -> None:
    raise DecryptionError(message)


def check_passphrase(passphrase: str) -> str:
    """Validate a passphrase at the point a user supplies one."""
    passphrase = (passphrase or "").strip()
    if len(passphrase) < MIN_PASSPHRASE:
        _fail(f"Use a passphrase of at least {MIN_PASSPHRASE} characters.")
    return passphrase


# --------------------------------------------------------------------------
# Key derivation
# --------------------------------------------------------------------------

def _validate(params: dict) -> tuple[bytes, int, int, int]:
    if not isinstance(params, dict) or params.get("name") != "scrypt":
        _fail("This file uses a key derivation method this build does not know.")
    try:
        salt = base64.b64decode(params.get("salt", ""), validate=True)
        n, r, p = int(params["n"]), int(params["r"]), int(params["p"])
    except (binascii.Error, KeyError, TypeError, ValueError) as exc:
        raise DecryptionError("The header's KDF parameters are malformed.") from exc

    in_range = (
        _N_RANGE[0] <= n <= _N_RANGE[1]
        and _R_RANGE[0] <= r <= _R_RANGE[1]
        and _P_RANGE[0] <= p <= _P_RANGE[1]
        and n & (n - 1) == 0          # scrypt requires a power of two
        and 8 <= len(salt) <= 64
    )
    if not in_range:
        _fail("The header's KDF parameters are outside the supported range.")
    return salt, n, r, p


def derive(passphrase: str, params: dict | None = None) -> tuple[bytes, bytes, dict]:
    """Turn a passphrase into a cipher key, a MAC key, and the params used.

    Two independent keys come out of one scrypt call rather than two, because
    scrypt is deliberately slow and one pass is all the entropy needs.
    """
    if params is None:
        salt, n, r, p = os.urandom(_SALT_BYTES), _N, _R, _P
        params = {
            "name": "scrypt",
            "salt": base64.b64encode(salt).decode(),
            "n": n, "r": r, "p": p,
        }
    else:
        salt, n, r, p = _validate(params)

    material = Scrypt(salt=salt, length=KEY_BYTES * 2, n=n, r=r, p=p).derive(
        passphrase.encode("utf-8")
    )
    return material[:KEY_BYTES], material[KEY_BYTES:], params


# --------------------------------------------------------------------------
# Reading and writing the container
# --------------------------------------------------------------------------

def is_envelope(raw: bytes) -> bool:
    """Cheap check for whether a file carries its own header."""
    return raw[:len(MAGIC)] == MAGIC


def wrap(
    algorithm: str,
    original_filename: str,
    material: dict,
    ciphertext: bytes,
    params: dict,
    mac_key: bytes,
) -> bytes:
    """Assemble the finished self-contained file."""
    header = json.dumps(
        {
            "format": FORMAT,
            "version": VERSION,
            "algorithm": algorithm,
            "original_filename": original_filename,
            "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "kdf": params,
            "material": material,
        },
        indent=2,
    ).encode("utf-8")

    body = MAGIC + len(header).to_bytes(_LENGTH_BYTES, "big") + header + ciphertext
    return body + hmac.new(mac_key, body, sha256).digest()


def unwrap(raw: bytes, passphrase: str) -> tuple[dict, bytes, bytes]:
    """Verify and open an envelope, returning (header, ciphertext, cipher_key)."""
    prefix = len(MAGIC) + _LENGTH_BYTES
    if not is_envelope(raw) or len(raw) < prefix + _MAC_BYTES:
        _fail("That file is not a passphrase-encrypted FileCrypt file.")

    header_len = int.from_bytes(raw[len(MAGIC):prefix], "big")
    if not 0 < header_len <= _MAX_HEADER or len(raw) < prefix + header_len + _MAC_BYTES:
        _fail("This file's header is damaged.")

    try:
        doc = json.loads(raw[prefix:prefix + header_len].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecryptionError("This file's header is damaged.") from exc

    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        _fail("That file is not a passphrase-encrypted FileCrypt file.")
    if doc.get("version") != VERSION:
        _fail(f"Envelope version {doc.get('version')!r} is not supported by this build.")
    if doc.get("algorithm") not in ALGORITHMS:
        _fail(f"The header names an unknown algorithm: {doc.get('algorithm')!r}")
    if not isinstance(doc.get("material"), dict):
        _fail("This file's header is damaged.")

    # The KDF parameters are used before the MAC is checked -- deriving the MAC
    # key is precisely what they are for -- so _validate has to be strict. Once
    # the MAC passes, the header as a whole is known to be untampered.
    cipher_key, mac_key, _ = derive(passphrase, doc["kdf"])

    body, mac = raw[:-_MAC_BYTES], raw[-_MAC_BYTES:]
    if not hmac.compare_digest(hmac.new(mac_key, body, sha256).digest(), mac):
        _fail("Wrong passphrase, or the file has been modified.")

    return doc, body[prefix + header_len:], cipher_key
