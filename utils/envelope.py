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
from typing import NoReturn

from argon2.low_level import Type as _Argon2Type
from argon2.low_level import hash_secret_raw as _argon2_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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


def _fail(message: str) -> NoReturn:
    """Always raises. Annotated NoReturn so a check that calls it narrows types
    afterwards the same way a bare `raise` would."""
    raise DecryptionError(message)


# --------------------------------------------------------------------------
# Key derivation functions
# --------------------------------------------------------------------------
# Three, for three different reasons:
#
#   scrypt    -- the default. Memory-hard, no extra dependency, and what every
#                file written before the others existed uses.
#   argon2id  -- the current best-practice answer. Opt-in, because making it the
#                default would produce files older builds cannot read.
#   pbkdf2    -- the weakest of the three, and present because WebCrypto offers
#                no other password KDF. Without it the browser could not write a
#                file this server can read, which is the whole point of doing
#                the encryption client-side.
#
# Every parameter below arrives inside an attacker-supplied file and is used
# *before* the MAC can be checked -- deriving the MAC key is what they are for.
# Each KDF therefore declares hard bounds. Unbounded, scrypt's N or Argon2's
# memory_cost is a straightforward way to make the process allocate gigabytes.

DEFAULT_KDF = "scrypt"

_SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
_ARGON2 = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
_PBKDF2 = {"iterations": 600_000}

_SALT_RANGE = (8, 64)


def _int(params: dict, key: str, low: int, high: int) -> int:
    try:
        value = int(params[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise DecryptionError(f"The header's {key} parameter is malformed.") from exc
    if not low <= value <= high:
        _fail(f"The header's {key} parameter is outside the supported range.")
    return value


def _scrypt_derive(passphrase: bytes, salt: bytes, params: dict, length: int) -> bytes:
    n = _int(params, "n", 2 ** 14, 2 ** 17)
    if n & (n - 1):
        _fail("scrypt's n parameter must be a power of two.")
    r = _int(params, "r", 1, 16)
    p = _int(params, "p", 1, 4)
    return Scrypt(salt=salt, length=length, n=n, r=r, p=p).derive(passphrase)


def _argon2_derive(passphrase: bytes, salt: bytes, params: dict, length: int) -> bytes:
    return _argon2_raw(
        secret=passphrase,
        salt=salt,
        time_cost=_int(params, "time_cost", 1, 10),
        memory_cost=_int(params, "memory_cost", 8 * 1024, 512 * 1024),  # KiB
        parallelism=_int(params, "parallelism", 1, 8),
        hash_len=length,
        type=_Argon2Type.ID,
    )


def _pbkdf2_derive(passphrase: bytes, salt: bytes, params: dict, length: int) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        # The floor is the security-relevant bound here; the ceiling only stops
        # a crafted file from pinning a CPU.
        iterations=_int(params, "iterations", 100_000, 5_000_000),
    ).derive(passphrase)


_KDFS = {
    "scrypt": (_scrypt_derive, _SCRYPT),
    "argon2id": (_argon2_derive, _ARGON2),
    "pbkdf2": (_pbkdf2_derive, _PBKDF2),
}

#: Selectable names, in the order they should be offered.
KDF_NAMES = tuple(_KDFS)

KDF_LABELS = {
    "scrypt": "scrypt: memory-hard, the default",
    "argon2id": "Argon2id: current best practice",
    "pbkdf2": "PBKDF2: weakest of the three; what the browser can do natively",
}


def check_passphrase(passphrase: str) -> str:
    """Validate a passphrase at the point a user supplies one."""
    passphrase = (passphrase or "").strip()
    if len(passphrase) < MIN_PASSPHRASE:
        _fail(f"Use a passphrase of at least {MIN_PASSPHRASE} characters.")
    return passphrase


# --------------------------------------------------------------------------
# Key derivation
# --------------------------------------------------------------------------

def new_params(name: str = DEFAULT_KDF) -> dict:
    """Fresh KDF parameters, with a random salt, for a new file."""
    if name not in _KDFS:
        raise ValueError(f"unknown kdf: {name!r}")
    return {
        "name": name,
        "salt": base64.b64encode(os.urandom(_SALT_BYTES)).decode(),
        **_KDFS[name][1],
    }


def derive(
    passphrase: str,
    params: dict | None = None,
    *,
    name: str = DEFAULT_KDF,
) -> tuple[bytes, bytes, dict]:
    """Turn a passphrase into a cipher key, a MAC key, and the params used.

    Both keys come out of one KDF call rather than two. These functions are
    deliberately slow, and one pass yields far more entropy than two 32-byte
    keys need; running it twice would double the cost for nothing.
    """
    if params is None:
        params = new_params(name)

    kdf_name = params.get("name") if isinstance(params, dict) else None
    entry = _KDFS.get(kdf_name) if isinstance(kdf_name, str) else None
    if entry is None:
        _fail(f"This file uses a key derivation method this build does not know: {kdf_name!r}")

    try:
        salt = base64.b64decode(params.get("salt", ""), validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise DecryptionError("The header's salt is malformed.") from exc
    if not _SALT_RANGE[0] <= len(salt) <= _SALT_RANGE[1]:
        _fail("The header's salt is not a usable length.")

    material = entry[0](passphrase.encode("utf-8"), salt, params, KEY_BYTES * 2)
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
