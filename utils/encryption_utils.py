"""Reversible file encryption algorithms.

Every algorithm exposes the same pair of functions::

    encrypt(data: bytes, *, key: bytes | None = None) -> (ciphertext, material)
    decrypt(ciphertext: bytes, material: dict, *, key: bytes | None = None) -> bytes

``material`` holds everything needed to reverse the operation. It is written
verbatim into the key file the user downloads, which is the only place key
material exists once a request finishes -- the server keeps nothing.

``key`` is how passphrase mode plugs in. Left as ``None`` -- the default, and
what the key-file flow does -- each algorithm invents its own random secret and
reports it in ``material``. Passed a 32-byte secret, the algorithm uses that
instead and returns ``material`` *without* the key in it, because in passphrase
mode the secret is reconstructed from what the user remembers rather than
stored. See ``utils.envelope`` for where those bytes come from.

Algorithms fall into two groups:

* Standard      -- fernet, aes, rsa, blowfish. Vetted constructions.
* Educational   -- chaos, dna, quantum. Reversible and key-driven, but they are
                   demonstrations of a concept, not reviewed cryptography.
                   ALGORITHMS[name].educational marks them.

visual_crypto is a special case: it splits an *image* into two shares and
stacking them back reveals a black-and-white approximation. It is lossy by
construction and only accepts images. See ``VisualCrypto``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import os
import zipfile
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np
from Crypto.Cipher import Blowfish
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(Exception):
    """Raised when ciphertext cannot be recovered with the supplied key."""


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def _keystream(key: bytes, nbytes: int, label: bytes) -> np.ndarray:
    """Deterministic pseudo-random bytes derived from ``key`` and ``label``.

    AES-256 in counter mode is used purely as a fast, reproducible generator so
    the educational algorithms below get a full-length keystream instead of the
    32-bit seed a PRNG like ``np.random.seed`` would limit them to.
    """
    if nbytes <= 0:
        return np.empty(0, dtype=np.uint8)
    derived = hashlib.sha256(key + b"|" + label).digest()
    cipher = Cipher(algorithms.AES(derived), modes.CTR(b"\x00" * 16))
    stream = cipher.encryptor().update(b"\x00" * nbytes)
    return np.frombuffer(stream, dtype=np.uint8)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DecryptionError(message)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _unb64(value, field_name: str) -> bytes:
    _require(isinstance(value, str) and value != "", f"Key file has no {field_name} entry.")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecryptionError(f"The {field_name} entry in the key file is malformed.") from exc


KEY_BYTES = 32


def _pick_key(key: bytes | None) -> tuple[bytes, dict]:
    """Settle on the secret for one encryption, and what must be recorded.

    A caller-supplied key was derived from a passphrase: reproducible, so the
    key file records nothing. A generated one exists only inside this call, so
    it has to be written down or the file is unrecoverable.
    """
    if key is not None:
        _require(len(key) == KEY_BYTES, "Derived key is the wrong size.")
        return key, {}
    generated = os.urandom(KEY_BYTES)
    return generated, {"key": _b64(generated)}


def _load_key(material: dict, key: bytes | None) -> bytes:
    """The decryption-time counterpart of :func:`_pick_key`."""
    return key if key is not None else _unb64(material.get("key"), "key")


# --------------------------------------------------------------------------
# 1. Fernet -- AES-128-CBC + HMAC-SHA256, from the cryptography library
# --------------------------------------------------------------------------

def fernet_encrypt(data: bytes, *, key: bytes | None = None) -> tuple[bytes, dict]:
    # Fernet wants its key as url-safe base64 rather than raw bytes, so this one
    # cannot use _pick_key: the generated form is kept in its historical string
    # shape so key files written by older builds still load.
    if key is None:
        token_key = Fernet.generate_key()
        return Fernet(token_key).encrypt(data), {"key": token_key.decode()}
    return Fernet(base64.urlsafe_b64encode(key)).encrypt(data), {}


def fernet_decrypt(data: bytes, material: dict, *, key: bytes | None = None) -> bytes:
    token_key = (
        base64.urlsafe_b64encode(key) if key is not None
        else material.get("key", "").encode()
    )
    try:
        return Fernet(token_key).decrypt(data)
    except Exception as exc:  # InvalidToken and malformed keys alike
        raise DecryptionError("Wrong key, or the file has been modified.") from exc


# --------------------------------------------------------------------------
# 2. AES-256-GCM
# --------------------------------------------------------------------------
# The original code used CBC, which cannot tell a wrong key from a corrupt file
# and happily emits garbage. GCM authenticates, so both cases fail loudly.

def aes_encrypt(data: bytes, *, key: bytes | None = None) -> tuple[bytes, dict]:
    key, material = _pick_key(key)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce + ciphertext, material


def aes_decrypt(data: bytes, material: dict, *, key: bytes | None = None) -> bytes:
    _require(len(data) > 12, "File is too short to be valid AES output.")
    key = _load_key(material, key)
    try:
        return AESGCM(key).decrypt(data[:12], data[12:], None)
    except Exception as exc:
        raise DecryptionError("Wrong key, or the file has been modified.") from exc


# --------------------------------------------------------------------------
# 3. RSA -- hybrid RSA-2048-OAEP wrapping an AES-256-GCM data key
# --------------------------------------------------------------------------
# RSA cannot encrypt bulk data. The previous implementation split the file into
# 190-byte chunks (roughly 88,000 modular exponentiations for a 16 MB upload)
# and, worse, saved the *public* key, leaving nothing able to decrypt. The
# standard fix is hybrid encryption: RSA protects a random AES key, AES
# protects the file, and the key file carries the private half.

_RSA_WRAPPED_LEN = 256  # 2048-bit modulus


def rsa_encrypt(data: bytes, *, key: bytes | None = None) -> tuple[bytes, dict]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    data_key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, data, None)

    wrapped = private_key.public_key().encrypt(
        data_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    # In passphrase mode the private key travels inside the encrypted file
    # rather than in a separate key file, so it has to be encrypted too --
    # otherwise the key that opens the ciphertext would sit in the clear right
    # next to it. PKCS#8 already has a standard way to do that.
    protection = (
        serialization.BestAvailableEncryption(key) if key is not None
        else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=protection,
    ).decode()
    return wrapped + nonce + ciphertext, {"private_key": pem}


def rsa_decrypt(data: bytes, material: dict, *, key: bytes | None = None) -> bytes:
    _require(
        len(data) > _RSA_WRAPPED_LEN + 12,
        "File is too short to be valid RSA output.",
    )
    pem = material.get("private_key")
    if not isinstance(pem, str) or not pem:
        raise DecryptionError("Key file has no private_key entry.")

    try:
        private_key = serialization.load_pem_private_key(pem.encode(), password=key)
    except (TypeError, ValueError) as exc:
        # Also where a passphrase-encrypted PEM opened without the passphrase
        # lands, which is the common case rather than the exotic one.
        raise DecryptionError("Wrong key, or the file has been modified.") from exc

    # The PEM decides what comes back, and the PEM came from the key file. Only
    # RSA keys have decrypt(); an Ed25519 one would raise AttributeError into
    # the catch-all below and be reported as a wrong key, which it is not.
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise DecryptionError("That key file holds a private key that is not RSA.")

    try:
        data_key = private_key.decrypt(
            data[:_RSA_WRAPPED_LEN],
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return AESGCM(data_key).decrypt(
            data[_RSA_WRAPPED_LEN:_RSA_WRAPPED_LEN + 12],
            data[_RSA_WRAPPED_LEN + 12:],
            None,
        )
    except Exception as exc:
        raise DecryptionError("Wrong key, or the file has been modified.") from exc


# --------------------------------------------------------------------------
# 4. Blowfish-CBC
# --------------------------------------------------------------------------
# Kept because it was on the menu, switched from ECB to CBC with a random IV.
# ECB leaks structure: identical plaintext blocks produce identical ciphertext,
# which on an image leaves the outline plainly visible.

_BF_BLOCK = Blowfish.block_size  # 8 bytes


def blowfish_encrypt(data: bytes, *, key: bytes | None = None) -> tuple[bytes, dict]:
    key, material = _pick_key(key)  # Blowfish accepts 4..56 bytes
    iv = os.urandom(_BF_BLOCK)
    pad_len = _BF_BLOCK - (len(data) % _BF_BLOCK)
    padded = data + bytes([pad_len] * pad_len)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return iv + cipher.encrypt(padded), material


def blowfish_decrypt(data: bytes, material: dict, *, key: bytes | None = None) -> bytes:
    key = _load_key(material, key)
    _require(
        len(data) > _BF_BLOCK and len(data) % _BF_BLOCK == 0,
        "File is not a whole number of Blowfish blocks.",
    )
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, data[:_BF_BLOCK])
    plain = cipher.decrypt(data[_BF_BLOCK:])
    pad_len = plain[-1] if plain else 0
    _require(
        1 <= pad_len <= _BF_BLOCK and plain[-pad_len:] == bytes([pad_len]) * pad_len,
        "Wrong key, or the file has been modified.",
    )
    return plain[:-pad_len]


# --------------------------------------------------------------------------
# 5. Chaos -- logistic map keystream
# --------------------------------------------------------------------------
# The original seeded numpy's Mersenne Twister with four key bytes, capping the
# keyspace at 2**32 regardless of key length. This runs an actual logistic map,
# x -> r*x*(1-x), which is what "chaos-based encryption" refers to.
#
# A single orbit would mean one Python-level iteration per byte. Instead LANES
# independent orbits advance together as one numpy operation, so a megabyte
# costs a few hundred vector steps. Each orbit gets its own x0 and r from the
# key, so the full 256-bit key drives the keystream.

_CHAOS_LANES = 4096
_CHAOS_WARMUP = 64
_EPS = 1e-12


def _chaos_keystream(key: bytes, nbytes: int) -> np.ndarray:
    seed = _keystream(key, _CHAOS_LANES * 16, b"chaos-seed")
    halves = seed.reshape(_CHAOS_LANES, 2, 8)

    # Map 64 random bits into (0,1) and r into [3.9, 4.0), the chaotic regime.
    raw_x = halves[:, 0, :].copy().view(np.uint64).ravel()
    raw_r = halves[:, 1, :].copy().view(np.uint64).ravel()
    scale = float(1 << 53)
    x = ((raw_x >> np.uint64(11)).astype(np.float64) + 0.5) / scale
    r = 3.9 + ((raw_r >> np.uint64(11)).astype(np.float64) / scale) * 0.0999

    for _ in range(_CHAOS_WARMUP):
        x = r * x * (1.0 - x)

    steps = -(-nbytes // _CHAOS_LANES)  # ceil
    out = np.empty((steps, _CHAOS_LANES), dtype=np.uint8)
    for i in range(steps):
        x = r * x * (1.0 - x)
        # Guard against the measure-zero orbits that collapse onto a fixed
        # point and would emit a constant keystream from then on.
        collapsed = (x < _EPS) | (x > 1.0 - _EPS)
        if collapsed.any():
            x = np.where(collapsed, 0.5 - _EPS, x)
        # Low mantissa bits of a chaotic orbit; exact integer extraction, so
        # this stays reproducible across platforms.
        out[i] = x.view(np.uint64).astype(np.uint8)
    return out.ravel()[:nbytes]


def chaos_encrypt(data: bytes, *, key: bytes | None = None) -> tuple[bytes, dict]:
    key, material = _pick_key(key)
    stream = _chaos_keystream(key, len(data))
    cipher = np.frombuffer(data, dtype=np.uint8) ^ stream
    return cipher.tobytes(), material


def chaos_decrypt(data: bytes, material: dict, *, key: bytes | None = None) -> bytes:
    key = _load_key(material, key)
    stream = _chaos_keystream(key, len(data))
    return (np.frombuffer(data, dtype=np.uint8) ^ stream).tobytes()


# --------------------------------------------------------------------------
# 6. DNA -- key-driven base substitution
# --------------------------------------------------------------------------
# Previously the key was unused: the transform was one of three fixed
# operations, and which one had been applied was written into the key file in
# plain text. Anyone holding the ciphertext could undo it.
#
# Here each byte becomes four DNA bases (2 bits each). The keystream picks one
# of the eight standard DNA coding rules per byte, then adds a keystream base
# modulo 4 -- the "DNA addition" operation. Both steps are key-dependent and
# both invert cleanly.

# The eight classic coding rules, as permutations of {A=0, C=1, G=2, T=3}.
_DNA_RULES = np.array(
    [
        [0, 1, 2, 3], [0, 2, 1, 3], [1, 0, 3, 2], [1, 3, 0, 2],
        [2, 0, 3, 1], [2, 3, 0, 1], [3, 1, 2, 0], [3, 2, 1, 0],
    ],
    dtype=np.uint8,
)
_DNA_RULES_INV = np.argsort(_DNA_RULES, axis=1).astype(np.uint8)


def _dna_parts(key: bytes, n: int) -> tuple[np.ndarray, np.ndarray]:
    rules = _keystream(key, n, b"dna-rule") % 8
    bases = (_keystream(key, n * 4, b"dna-base") % 4).reshape(n, 4)
    return rules, bases


def _unpack_bases(arr: np.ndarray) -> np.ndarray:
    return np.stack([(arr >> shift) & 3 for shift in (0, 2, 4, 6)], axis=1)


def _pack_bases(bases: np.ndarray) -> np.ndarray:
    out = np.zeros(bases.shape[0], dtype=np.uint8)
    for i, shift in enumerate((0, 2, 4, 6)):
        out |= bases[:, i] << shift
    return out


def dna_encrypt(data: bytes, *, key: bytes | None = None) -> tuple[bytes, dict]:
    key, material = _pick_key(key)
    arr = np.frombuffer(data, dtype=np.uint8)
    if arr.size == 0:
        return b"", material
    rules, ks_bases = _dna_parts(key, arr.size)
    bases = _unpack_bases(arr)
    bases = _DNA_RULES[rules[:, None], bases]        # apply coding rule
    bases = (bases + ks_bases) % 4                    # DNA addition
    return _pack_bases(bases).tobytes(), material


def dna_decrypt(data: bytes, material: dict, *, key: bytes | None = None) -> bytes:
    key = _load_key(material, key)
    arr = np.frombuffer(data, dtype=np.uint8)
    if arr.size == 0:
        return b""
    rules, ks_bases = _dna_parts(key, arr.size)
    bases = _unpack_bases(arr)
    bases = (bases - ks_bases) % 4
    bases = _DNA_RULES_INV[rules[:, None], bases]
    return _pack_bases(bases).tobytes()


# --------------------------------------------------------------------------
# 7. Quantum-inspired -- reversible gate circuit
# --------------------------------------------------------------------------
# The original mapped each byte to cos^2(pixel*pi/255) and rounded to an
# integer. Cosine is not injective over 0..255 and the rounding discards more,
# so the transform destroyed the file: nothing could recover it, and no decrypt
# function existed.
#
# Real quantum circuits are unitary, hence reversible, and that is the property
# worth borrowing. Each byte is treated as eight qubits and three rounds of
# reversible gates are applied:
#
#   X gate    -- flip qubits against a keystream byte
#   qubit map -- permute the eight bit positions (key-selected)
#   CNOT      -- entangle each byte with its predecessor via cumulative XOR
#
# Every gate is its own kind of invertible, so decryption runs the circuit
# backwards.

_Q_ROUNDS = 3


def _bit_perm_tables(key: bytes) -> tuple[np.ndarray, np.ndarray]:
    """Build byte lookup tables for a key-selected permutation of bit positions."""
    forward = np.empty((_Q_ROUNDS, 256), dtype=np.uint8)
    inverse = np.empty((_Q_ROUNDS, 256), dtype=np.uint8)
    selector = _keystream(key, _Q_ROUNDS * 8, b"quantum-perm")
    for rnd in range(_Q_ROUNDS):
        # Fisher-Yates over the eight bit positions, driven by the keystream.
        perm = list(range(8))
        chunk = selector[rnd * 8:(rnd + 1) * 8]
        for i in range(7, 0, -1):
            j = int(chunk[i]) % (i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        for value in range(256):
            moved = 0
            for bit in range(8):
                if (value >> bit) & 1:
                    moved |= 1 << perm[bit]
            forward[rnd, value] = moved
            inverse[rnd, moved] = value
    return forward, inverse


def quantum_encrypt(data: bytes, *, key: bytes | None = None) -> tuple[bytes, dict]:
    key, material = _pick_key(key)
    arr = np.frombuffer(data, dtype=np.uint8).copy()
    if arr.size == 0:
        return b"", material
    forward, _ = _bit_perm_tables(key)
    for rnd in range(_Q_ROUNDS):
        arr ^= _keystream(key, arr.size, b"quantum-x-%d" % rnd)   # Pauli-X
        arr = forward[rnd][arr]                                    # qubit remap
        arr = np.bitwise_xor.accumulate(arr)                       # CNOT chain
    return arr.tobytes(), material


def quantum_decrypt(data: bytes, material: dict, *, key: bytes | None = None) -> bytes:
    key = _load_key(material, key)
    arr = np.frombuffer(data, dtype=np.uint8).copy()
    if arr.size == 0:
        return b""
    _, inverse = _bit_perm_tables(key)
    for rnd in reversed(range(_Q_ROUNDS)):
        # Undo the cumulative XOR: x[i] = y[i] ^ y[i-1].
        arr[1:] ^= arr[:-1].copy()
        arr = inverse[rnd][arr]
        arr ^= _keystream(key, arr.size, b"quantum-x-%d" % rnd)
    return arr.tobytes()


# --------------------------------------------------------------------------
# 8. Visual cryptography -- Naor-Shamir (2,2) scheme
# --------------------------------------------------------------------------
# Images only, and lossy by design. Each pixel becomes a 2x2 block of
# subpixels. For a white pixel both shares get the same random block; for a
# black pixel they get complementary blocks. Stacking the shares (a pixelwise
# AND) leaves black pixels fully black and white pixels half black -- readable
# as grey. Neither share alone reveals anything.
#
# The old implementation set share2 = NOT share1 for every pixel, so stacking
# always produced solid black and no image ever came back.


class VisualCryptoError(Exception):
    """Raised when visual cryptography is given something it cannot handle."""


_VC_LAYOUT = np.array([[[1, 0], [0, 1]], [[0, 1], [1, 0]]], dtype=np.uint8)

# A share archive is the one input whose decompressed size is not bounded by the
# upload limit: deflate happily turns 32 MB of zeros into gigabytes. Two shares
# of a sane image stay well under this.
_VC_MAX_SHARE_BYTES = 256 * 1024 * 1024


def _tile(blocks: np.ndarray) -> np.ndarray:
    """(h, w, 2, 2) blocks -> (2h, 2w) image."""
    h, w = blocks.shape[:2]
    return blocks.transpose(0, 2, 1, 3).reshape(h * 2, w * 2)


def looks_like_shares(data: bytes) -> bool:
    """True for the archive ``visual_encrypt`` produces.

    Visual cryptography is the one algorithm whose key file holds no key -- the
    shares themselves are the secret. Recognising its output by shape lets the
    decrypt path stop demanding a key file that would contain nothing.
    """
    if data[:2] != b"PK":
        return False
    try:
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    return sum(name.lower().endswith(".png") for name in names) >= 2


def visual_encrypt(data: bytes, *, key: bytes | None = None) -> tuple[bytes, dict]:
    from PIL import Image, UnidentifiedImageError

    try:
        image = Image.open(io.BytesIO(data))
        image.load()
    except (UnidentifiedImageError, OSError) as exc:
        raise VisualCryptoError(
            "Visual cryptography works on images only. Pick another algorithm "
            "for this file."
        ) from exc

    # 1 = white, 0 = black after the dither-free threshold conversion.
    mono = image.convert("L").point(lambda v: 255 if v > 127 else 0).convert("1")
    pixels = np.array(mono, dtype=np.uint8)
    height, width = pixels.shape

    rng = np.random.default_rng(list(os.urandom(32)))
    choice = rng.integers(0, 2, size=(height, width))

    share1_blocks = _VC_LAYOUT[choice]                     # (h, w, 2, 2)
    # White pixel: shares match. Black pixel: shares are complements.
    share2_blocks = np.where(
        pixels[:, :, None, None] == 1, share1_blocks, 1 - share1_blocks
    ).astype(np.uint8)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, blocks in (("share1.png", share1_blocks), ("share2.png", share2_blocks)):
            png = io.BytesIO()
            Image.fromarray(_tile(blocks) * 255, mode="L").convert("1").save(png, format="PNG")
            archive.writestr(name, png.getvalue())
        archive.writestr(
            "README.txt",
            "Naor-Shamir (2,2) visual cryptography shares.\n\n"
            "Either share on its own reveals nothing. Print both on transparent\n"
            "film and lay one over the other to read the image, or upload this\n"
            "zip to the Decrypt panel to stack them digitally.\n\n"
            "Stacking returns a black-and-white approximation at twice the\n"
            "original width and height. It does not return the original file.\n",
        )
    return buffer.getvalue(), {"width": width, "height": height}


def visual_decrypt(data: bytes, material: dict, *, key: bytes | None = None) -> bytes:
    from PIL import Image, UnidentifiedImageError

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        names = archive.namelist()
    except (zipfile.BadZipFile, OSError) as exc:
        raise DecryptionError(
            "Expected the share archive produced by visual cryptography."
        ) from exc

    wanted = [n for n in names if n.lower().endswith(".png")]
    _require(len(wanted) >= 2, "The archive needs both share images.")

    shares = []
    for name in sorted(wanted)[:2]:
        # Trust the declared size only as a reason to refuse early; the read
        # below is still capped, because the header is attacker-controlled and
        # may understate what the member actually expands to.
        _require(
            archive.getinfo(name).file_size <= _VC_MAX_SHARE_BYTES,
            "That share image is implausibly large.",
        )
        try:
            with archive.open(name) as handle:
                raw = handle.read(_VC_MAX_SHARE_BYTES + 1)
        except (zipfile.BadZipFile, OSError) as exc:
            raise DecryptionError("That share image could not be read.") from exc
        _require(len(raw) <= _VC_MAX_SHARE_BYTES, "That share image is implausibly large.")

        # A .png name proves nothing about the contents. Since any zip holding
        # two of them is now routed here without a key file, an ordinary archive
        # dropped in by mistake reaches this line -- and must get a sentence
        # rather than a stack trace.
        try:
            image = Image.open(io.BytesIO(raw))
            image.load()
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            raise DecryptionError(
                "That archive does not hold a pair of share images."
            ) from exc
        shares.append(np.array(image.convert("1"), dtype=np.uint8))

    _require(shares[0].shape == shares[1].shape, "The two shares are different sizes.")

    stacked = shares[0] & shares[1]  # physical overlay: black wins
    out = io.BytesIO()
    Image.fromarray(stacked * 255, mode="L").convert("1").save(out, format="PNG")
    return out.getvalue()


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Algorithm:
    name: str
    label: str
    summary: str
    # Both take a keyword-only `key`, which Callable cannot spell out.
    encrypt: Callable[..., tuple[bytes, dict]]
    decrypt: Callable[..., bytes]
    educational: bool = False
    images_only: bool = False
    lossy: bool = False
    extension: str = ".enc"
    notes: str = ""
    # Visual cryptography is the exception: its secret is the pair of shares
    # themselves, so there is no key for a passphrase to stand in for.
    supports_passphrase: bool = True


ALGORITHMS: dict[str, Algorithm] = {
    a.name: a
    for a in [
        Algorithm(
            "fernet", "Fernet",
            "AES-128-CBC with an HMAC signature. Safe default.",
            fernet_encrypt, fernet_decrypt,
        ),
        Algorithm(
            "aes", "AES-256-GCM",
            "Authenticated encryption. Detects tampering and wrong keys.",
            aes_encrypt, aes_decrypt,
        ),
        Algorithm(
            "rsa", "RSA-2048 (hybrid)",
            "RSA wraps a random AES-256-GCM key. Key file holds the private key.",
            rsa_encrypt, rsa_decrypt,
        ),
        Algorithm(
            "blowfish", "Blowfish-CBC",
            "Legacy 64-bit block cipher. Kept for compatibility.",
            blowfish_encrypt, blowfish_decrypt,
            notes="Blowfish's small block size makes it unsuitable for files "
                  "over a few hundred megabytes. Prefer AES-256-GCM.",
        ),
        Algorithm(
            "chaos", "Chaos (logistic map)",
            "XOR against a keystream from a chaotic map.",
            chaos_encrypt, chaos_decrypt, educational=True,
        ),
        Algorithm(
            "dna", "DNA coding",
            "Bytes become DNA bases, then key-driven rule substitution.",
            dna_encrypt, dna_decrypt, educational=True,
        ),
        Algorithm(
            "quantum", "Quantum-inspired",
            "Reversible gate circuit over the bits of each byte.",
            quantum_encrypt, quantum_decrypt, educational=True,
        ),
        Algorithm(
            "visual_crypto", "Visual cryptography",
            "Splits an image into two shares that reveal it when stacked.",
            visual_encrypt, visual_decrypt,
            images_only=True, lossy=True, extension=".shares.zip",
            supports_passphrase=False,
            notes="Images only. Stacking returns a black-and-white "
                  "approximation at double size, not the original file.",
        ),
    ]
}

DEFAULT_ALGORITHM = "aes"
