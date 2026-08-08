"""Cross-implementation vectors: files written by the browser, read by Python.

There are two independent implementations of the same two formats now --
`utils/` in Python and `static/js/crypto.js` in the browser -- and the failure
mode that matters is not either one crashing. It is the two of them drifting
apart so that a file encrypted in the browser cannot be decrypted by the server,
or worse, decrypts to something subtly different.

Nothing in `test_vectors.py` catches that: those vectors were written by the
Python code that reads them back. The files here were produced by
`static/js/crypto.js` running in a real browser, captured, and committed. They
are the only evidence in the suite that the two implementations agree.

To regenerate after an intentional format change, see the recipe at the bottom
of this file -- and expect to update FORMAT.md at the same time.
"""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils import envelope, keyfile
from utils.encryption_utils import ALGORITHMS

VECTORS = Path(__file__).resolve().parent / "vectors" / "webcrypto"
PASSPHRASE = "correct horse battery staple"


def read(name: str) -> bytes:
    path = VECTORS / name
    if not path.is_file():
        pytest.fail(f"missing browser vector {name}")
    return path.read_bytes()


@pytest.fixture(scope="module")
def expected() -> bytes:
    return read("plaintext.bin")


# ------------------------------------------------------------- key file mode

def test_python_decrypts_a_browser_key_file(expected):
    doc = keyfile.parse(read("aes.key.json"))
    plaintext = ALGORITHMS["aes"].decrypt(read("aes.bin"), doc["material"])
    assert plaintext == expected


def test_the_browser_computed_the_same_checksum_python_would(expected):
    """The strongest single signal that the two agree.

    The browser hashed its plaintext with WebCrypto and wrote the result into
    the key file. If Python's hash of what it decrypted matches, then both the
    AES layer and the SHA-256 layer produced identical bytes on both sides.
    """
    doc = keyfile.parse(read("aes.key.json"))
    assert doc["plaintext_sha256"] == hashlib.sha256(expected).hexdigest()
    keyfile.verify(doc, expected)  # the check the app itself performs


def test_browser_key_file_has_the_documented_shape():
    doc = json.loads(read("aes.key.json"))
    assert doc["format"] == "filecrypt-key"
    assert doc["version"] == 1
    assert doc["algorithm"] == "aes"
    # Standard base64 of 32 raw bytes, as the other algorithms use -- not the
    # url-safe string shape Fernet needs.
    assert len(keyfile.parse(read("aes.key.json"))["material"]["key"]) == 44


# ----------------------------------------------------------- passphrase mode

def test_python_opens_a_browser_envelope(expected):
    doc, ciphertext, cipher_key = envelope.unwrap(read("aes.pbkdf2.fcx"), PASSPHRASE)
    assert doc["algorithm"] == "aes"
    assert doc["kdf"]["name"] == "pbkdf2"
    plaintext = ALGORITHMS["aes"].decrypt(ciphertext, doc["material"], key=cipher_key)
    assert plaintext == expected


def test_the_browsers_mac_verifies_under_pythons_hmac():
    """unwrap() checks the MAC before returning, so reaching this line at all
    means the browser's HMAC-SHA256 and Python's agreed on every byte."""
    doc, _, _ = envelope.unwrap(read("aes.pbkdf2.fcx"), PASSPHRASE)
    assert doc["format"] == "filecrypt-envelope"


def test_a_browser_envelope_rejects_the_wrong_passphrase():
    from utils.encryption_utils import DecryptionError

    with pytest.raises(DecryptionError):
        envelope.unwrap(read("aes.pbkdf2.fcx"), "not the right passphrase")


def test_browser_envelope_uses_parameters_python_accepts():
    """PBKDF2 is the only password KDF WebCrypto has, so the browser must pick
    settings inside the bounds the server enforces or its files are unreadable."""
    raw = read("aes.pbkdf2.fcx")
    header_len = int.from_bytes(raw[4:8], "big")
    kdf = json.loads(raw[8:8 + header_len])["kdf"]

    assert kdf["name"] == "pbkdf2"
    assert kdf["iterations"] >= 100_000        # the floor utils/envelope enforces
    assert 8 <= len(kdf["salt"]) * 3 // 4 <= 64


def test_browser_envelope_leaks_no_plaintext_hash(expected):
    """The browser must honour this too, not just the Python side."""
    raw = read("aes.pbkdf2.fcx")
    digest = hashlib.sha256(expected)
    assert digest.hexdigest().encode() not in raw
    assert digest.digest() not in raw


# ---------------------------------------------------------------------------
# Regenerating these
# ---------------------------------------------------------------------------
# There is no script, because generating them requires a browser. Serve the app,
# open it, and run this in the devtools console:
#
#     const enc = new TextEncoder();
#     const plain = enc.encode("whatever you like");
#     const kf = await FileCryptWeb.encryptWithKeyFile(plain, "vector.txt");
#     const sealed = await FileCryptWeb.encryptWithPassphrase(
#         plain, "vector.txt", "correct horse battery staple");
#
# Save kf.payload as aes.bin, kf.keyJson as aes.key.json, sealed as
# aes.pbkdf2.fcx, and the plaintext as plaintext.bin.
