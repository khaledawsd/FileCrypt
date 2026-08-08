"""Passphrase mode: the envelope format and the route that produces it.

The properties worth pinning down here are the ones that make passphrase mode
worth having at all -- that a file needs nothing but the passphrase, that a
wrong one is refused rather than acted on, and that the file leaks nothing
about its contents to whoever is holding it.
"""

import base64
import hashlib
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from utils import envelope
from utils.encryption_utils import ALGORITHMS, DecryptionError

PASSPHRASE = "correct horse battery staple"

SEALABLE = [name for name, a in ALGORITHMS.items() if a.supports_passphrase]

PAYLOADS = [
    pytest.param(b"", id="empty"),
    pytest.param(b"\x00", id="one-byte"),
    pytest.param("unicode ✓ and newlines\n\n".encode(), id="text"),
    pytest.param(bytes(range(256)) * 200, id="binary-51k"),
]


@pytest.fixture
def client():
    return create_app().test_client()


def seal(payload: bytes, name: str, passphrase: str = PASSPHRASE) -> bytes:
    cipher_key, mac_key, params = envelope.derive(passphrase)
    ciphertext, material = ALGORITHMS[name].encrypt(payload, key=cipher_key)
    return envelope.wrap(name, "report.pdf", material, ciphertext, params, mac_key)


def open_sealed(blob: bytes, passphrase: str = PASSPHRASE) -> bytes:
    doc, ciphertext, cipher_key = envelope.unwrap(blob, passphrase)
    return ALGORITHMS[doc["algorithm"]].decrypt(
        ciphertext, doc["material"], key=cipher_key
    )


# ----------------------------------------------------------------- envelope

@pytest.mark.parametrize("name", SEALABLE)
@pytest.mark.parametrize("payload", PAYLOADS)
def test_round_trip_needs_only_the_passphrase(name, payload):
    assert open_sealed(seal(payload, name), PASSPHRASE) == payload


@pytest.mark.parametrize("name", SEALABLE)
def test_wrong_passphrase_is_refused(name):
    blob = seal(b"the real message" * 32, name)
    with pytest.raises(DecryptionError):
        open_sealed(blob, "a completely different passphrase")


@pytest.mark.parametrize("name", SEALABLE)
def test_two_runs_of_one_passphrase_differ(name):
    """A fresh salt per file, so the same passphrase never repeats a key."""
    payload = b"repeatable input"
    assert seal(payload, name) != seal(payload, name)


@pytest.mark.parametrize("offset", [-1, -40, 200])
def test_tampering_is_caught_even_for_unauthenticated_algorithms(offset):
    """chaos is a bare XOR keystream with no integrity of its own.

    Inside an envelope it inherits the MAC, so a flipped bit is reported
    instead of quietly producing a wrong file.
    """
    blob = bytearray(seal(b"A" * 4096, "chaos"))
    blob[offset] ^= 0x01
    with pytest.raises(DecryptionError):
        open_sealed(bytes(blob))


def test_envelope_says_nothing_about_the_plaintext():
    """A key file may record a plaintext checksum; the file itself must not.

    Anyone holding the file would otherwise have an oracle for confirming
    guesses about what is inside it.
    """
    payload = b"guessable contents"
    blob = seal(payload, "aes")
    assert hashlib.sha256(payload).hexdigest().encode() not in blob
    assert hashlib.sha256(payload).digest() not in blob


def test_envelope_header_carries_no_key():
    doc, _, _ = envelope.unwrap(seal(b"data" * 100, "aes"), PASSPHRASE)
    assert doc["material"] == {}
    assert "key" not in json.dumps(doc["kdf"])


def test_rsa_private_key_inside_an_envelope_is_encrypted():
    """RSA keeps its PEM in the header, so the PEM itself must be protected."""
    doc, _, _ = envelope.unwrap(seal(b"data" * 100, "rsa"), PASSPHRASE)
    pem = doc["material"]["private_key"]
    assert "ENCRYPTED PRIVATE KEY" in pem
    assert "BEGIN PRIVATE KEY" not in pem


# ------------------------------------------------------- untrusted header

@pytest.mark.parametrize("params,reason", [
    ({"name": "scrypt", "n": 2 ** 30, "r": 8, "p": 1}, "memory bomb"),
    ({"name": "scrypt", "n": 2 ** 15 + 1, "r": 8, "p": 1}, "not a power of two"),
    ({"name": "scrypt", "n": 2 ** 15, "r": 999, "p": 1}, "r out of range"),
    ({"name": "scrypt", "n": 2 ** 15, "r": 8, "p": 999}, "p out of range"),
    ({"name": "pbkdf2", "n": 2 ** 15, "r": 8, "p": 1}, "unknown kdf"),
])
def test_kdf_parameters_from_the_file_are_clamped(params, reason):
    """These are read before the MAC can be checked, so they must be bounded.

    scrypt allocates 128*N*r bytes; an unchecked N in a crafted header would be
    a straightforward way to exhaust memory.
    """
    cipher_key, mac_key, good = envelope.derive(PASSPHRASE)
    ciphertext, material = ALGORITHMS["aes"].encrypt(b"data" * 100, key=cipher_key)
    params = {"salt": good["salt"], **params}
    blob = envelope.wrap("aes", "x.bin", material, ciphertext, params, mac_key)

    with pytest.raises(DecryptionError):
        envelope.unwrap(blob, PASSPHRASE)


@pytest.mark.parametrize("raw", [
    b"",
    b"FCP1",
    b"not an envelope at all",
    b"FCP1" + (0).to_bytes(4, "big") + b"\x00" * 32,
    b"FCP1" + (10 ** 6).to_bytes(4, "big") + b"\x00" * 32,
    b"FCP1" + (4).to_bytes(4, "big") + b"{{{{" + b"\x00" * 32,
])
def test_damaged_envelopes_are_rejected(raw):
    with pytest.raises(DecryptionError):
        envelope.unwrap(raw, PASSPHRASE)


def test_truncated_envelope_is_rejected():
    blob = seal(b"data" * 500, "aes")
    with pytest.raises(DecryptionError):
        envelope.unwrap(blob[:-8], PASSPHRASE)


@pytest.mark.parametrize("bad", ["", "   ", "short", "1234567"])
def test_short_passphrases_are_refused(bad):
    with pytest.raises(DecryptionError):
        envelope.check_passphrase(bad)


def test_minimum_length_passphrase_is_accepted():
    assert envelope.check_passphrase("a" * envelope.MIN_PASSPHRASE)


# --------------------------------------------------------------------- HTTP

def post_encrypt(client, payload, name, passphrase=PASSPHRASE, filename="report.pdf"):
    data = {"file": (io.BytesIO(payload), filename), "algorithm": name}
    if passphrase is not None:
        data["passphrase"] = passphrase
    return client.post("/encrypt", data=data, content_type="multipart/form-data")


@pytest.mark.parametrize("name", SEALABLE)
def test_http_round_trip(client, name):
    payload = bytes(range(256)) * 100
    body = post_encrypt(client, payload, name).get_json()

    assert body["passphrase_mode"] is True
    assert body["key"] is None
    assert body["encrypted"]["filename"] == "report.pdf.fcx"

    recovered = client.post(
        "/decrypt",
        data={
            "file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.fcx"),
            "passphrase": PASSPHRASE,
        },
        content_type="multipart/form-data",
    )
    assert recovered.status_code == 200
    assert recovered.data == payload
    assert recovered.headers["X-Verified"] == "mac"


def test_decrypting_an_envelope_without_a_passphrase_is_refused(client):
    body = post_encrypt(client, b"data" * 100, "aes").get_json()
    response = client.post(
        "/decrypt",
        data={"file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.fcx")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "passphrase" in response.get_json()["error"].lower()


def test_decrypting_with_the_wrong_passphrase_is_refused(client):
    body = post_encrypt(client, b"data" * 100, "aes").get_json()
    response = client.post(
        "/decrypt",
        data={
            "file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.fcx"),
            "passphrase": "some other passphrase",
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400


def test_short_passphrase_is_refused_by_the_route(client):
    response = post_encrypt(client, b"data" * 100, "aes", passphrase="abc")
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_visual_crypto_rejects_a_passphrase(client):
    """It has no key, so there is nothing for a passphrase to stand in for."""
    response = post_encrypt(client, b"data" * 100, "visual_crypto")
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_key_file_mode_is_untouched_by_all_this(client):
    """No passphrase field means the original two-file flow, unchanged."""
    body = post_encrypt(client, b"data" * 100, "aes", passphrase=None).get_json()
    assert body["passphrase_mode"] is False
    assert body["key"]["filename"] == "report.pdf.key.json"
    assert body["encrypted"]["filename"] == "report.pdf.enc"
