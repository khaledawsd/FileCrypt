"""Golden vectors: files encrypted by an older build must still open.

Every other test in this suite encrypts and decrypts with the same code in the
same process, which proves the pair is self-consistent and nothing more. A
refactor that changed both halves identically would sail through all of them
while quietly making every file anyone had already encrypted unreadable.

These read frozen bytes off disk instead. They are the only tests here that can
fail in a way that means "you just broke somebody's data".

When one fails, the fix is almost never to regenerate the vector. See
`tests/vectors/generate.py`.
"""

import hashlib
import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils import envelope, keyfile
from utils.encryption_utils import ALGORITHMS, DecryptionError

VECTORS = Path(__file__).resolve().parent / "vectors"

# Must match generate.py. Restating it rather than importing is the point: if
# someone edits the generator's plaintext, these tests fail loudly instead of
# silently following along.
PLAINTEXT = "FileCrypt golden vector\n\x00ÿ binary ✓ unicode\n".encode() * 8
PASSPHRASE = "correct horse battery staple"

LOSSLESS = sorted(name for name, a in ALGORITHMS.items() if not a.lossy)
SEALABLE = sorted(name for name, a in ALGORITHMS.items() if a.supports_passphrase)


def read(name: str) -> bytes:
    path = VECTORS / name
    if not path.is_file():
        pytest.fail(f"missing vector {name}; run tests/vectors/generate.py to add it")
    return path.read_bytes()


# ------------------------------------------------------------- key file mode

@pytest.mark.parametrize("name", LOSSLESS)
def test_stored_key_file_still_opens_stored_ciphertext(name):
    doc = keyfile.parse(read(f"{name}.key.json"))
    assert doc["algorithm"] == name
    recovered = ALGORITHMS[name].decrypt(read(f"{name}.bin"), doc["material"])
    assert recovered == PLAINTEXT
    keyfile.verify(doc, recovered)  # the stored checksum must still match


def test_legacy_format_name_is_still_accepted():
    """Key files predating the rename say `cryptoimage-key`."""
    doc = keyfile.parse(read("legacy.key.json"))
    assert doc["format"] == "cryptoimage-key"
    assert ALGORITHMS["aes"].decrypt(read("aes.bin"), doc["material"]) == PLAINTEXT


def test_stored_fernet_key_keeps_its_historical_string_shape():
    """Fernet stores a url-safe base64 *string*, not the base64 bytes the other
    algorithms use. The passphrase work could easily have normalised that."""
    doc = keyfile.parse(read("fernet.key.json"))
    key = doc["material"]["key"]
    assert isinstance(key, str)
    assert len(key) == 44 and key.endswith("=")


def test_stored_shares_still_stack():
    stacked = ALGORITHMS["visual_crypto"].decrypt(read("visual_crypto.bin"), {})
    assert stacked[:8] == b"\x89PNG\r\n\x1a\n"


# ------------------------------------------------------------ passphrase mode

def envelope_name(algorithm: str, kdf: str) -> str:
    """scrypt vectors predate the others and keep their unsuffixed names."""
    suffix = "" if kdf == envelope.DEFAULT_KDF else f".{kdf}"
    return f"{algorithm}{suffix}.fcx"


@pytest.mark.parametrize("name", SEALABLE)
@pytest.mark.parametrize("kdf", list(envelope.KDF_NAMES))
def test_stored_envelope_still_opens_with_its_passphrase(name, kdf):
    doc, ciphertext, cipher_key = envelope.unwrap(
        read(envelope_name(name, kdf)), PASSPHRASE
    )
    assert doc["algorithm"] == name
    assert doc["kdf"]["name"] == kdf
    assert doc["original_filename"] == "vector.txt"
    recovered = ALGORITHMS[name].decrypt(ciphertext, doc["material"], key=cipher_key)
    assert recovered == PLAINTEXT


@pytest.mark.parametrize("name", SEALABLE)
def test_stored_envelope_rejects_the_wrong_passphrase(name):
    with pytest.raises(DecryptionError):
        envelope.unwrap(read(f"{name}.fcx"), "not the right passphrase")


def test_stored_envelope_header_is_still_shaped_as_documented():
    """FORMAT.md promises this layout; a reader in another language depends on it."""
    raw = read("aes.fcx")
    assert raw[:4] == b"FCP1"
    header_len = int.from_bytes(raw[4:8], "big")
    header = raw[8:8 + header_len]
    assert header.startswith(b"{") and header.rstrip().endswith(b"}")

    import json
    doc = json.loads(header)
    assert doc["format"] == "filecrypt-envelope"
    assert doc["version"] == 1
    assert doc["kdf"]["name"] == "scrypt"
    assert set(doc["kdf"]) == {"name", "salt", "n", "r", "p"}


def test_no_stored_envelope_leaks_its_plaintext_hash():
    """The property that makes the envelope safe to hand to anyone."""
    digest = hashlib.sha256(PLAINTEXT)
    for name in SEALABLE:
        for kdf in envelope.KDF_NAMES:
            raw = read(envelope_name(name, kdf))
            assert digest.hexdigest().encode() not in raw
            assert digest.digest() not in raw


# ------------------------------------------------------------------ HTTP path

def test_a_stored_file_decrypts_through_the_running_app():
    """End to end, because the route layer can break compatibility too."""
    from app import create_app

    client = create_app().test_client()
    response = client.post(
        "/decrypt",
        data={
            "file": (io.BytesIO(read("aes.bin")), "aes.bin"),
            "key_file": (io.BytesIO(read("aes.key.json")), "aes.key.json"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert response.data == PLAINTEXT
