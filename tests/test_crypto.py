"""Round-trip and error-path tests.

Run with:  venv\\Scripts\\python.exe -m pytest tests -q

The point of these is narrow but important: every algorithm on the menu must
return exactly what went in, and a wrong key must be reported rather than
silently producing garbage.
"""

import base64
import io
import sys
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from utils import keyfile
from utils.encryption_utils import ALGORITHMS, DecryptionError

BYTE_LIKE = [
    pytest.param(b"", id="empty"),
    pytest.param(b"\x00", id="one-byte"),
    pytest.param("unicode ✓ and newlines\n\n".encode("utf-8"), id="text"),
    pytest.param(bytes(range(256)) * 500, id="binary-128k"),
]

LOSSLESS = [name for name, a in ALGORITHMS.items() if not a.lossy]


def sample_png() -> bytes:
    arr = np.zeros((48, 64), dtype=np.uint8)
    arr[10:38, 10:54] = 255
    buf = io.BytesIO()
    Image.fromarray(arr, mode="L").save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def client():
    return create_app().test_client()


# ---------------------------------------------------------------- algorithms

@pytest.mark.parametrize("name", LOSSLESS)
@pytest.mark.parametrize("payload", BYTE_LIKE)
def test_round_trip_is_exact(name, payload):
    alg = ALGORITHMS[name]
    ciphertext, material = alg.encrypt(payload)
    assert alg.decrypt(ciphertext, material) == payload


@pytest.mark.parametrize("name", LOSSLESS)
def test_ciphertext_differs_from_plaintext(name):
    payload = b"A" * 4096
    ciphertext, _ = ALGORITHMS[name].encrypt(payload)
    assert payload not in ciphertext


@pytest.mark.parametrize("name", LOSSLESS)
def test_same_input_encrypts_differently_each_time(name):
    """Fresh key material per call, so two runs must not collide."""
    payload = b"repeatable input"
    first, _ = ALGORITHMS[name].encrypt(payload)
    second, _ = ALGORITHMS[name].encrypt(payload)
    assert first != second


def test_visual_crypto_stacking_reveals_the_shape():
    alg = ALGORITHMS["visual_crypto"]
    shares, material = alg.encrypt(sample_png())
    stacked = np.array(
        Image.open(io.BytesIO(alg.decrypt(shares, material))).convert("1"),
        dtype=np.uint8,
    )
    assert stacked.shape == (96, 128)  # doubled in both directions
    assert 0.35 < stacked[20:76, 20:108].mean() < 0.65  # light region -> ~50%
    assert stacked[0:16, 0:16].mean() < 0.01            # dark region -> solid


def test_visual_crypto_rejects_non_images():
    from utils.encryption_utils import VisualCryptoError

    with pytest.raises(VisualCryptoError):
        ALGORITHMS["visual_crypto"].encrypt(b"not an image")


# ------------------------------------------------------------------ keyfile

@pytest.mark.parametrize("name", LOSSLESS)
def test_wrong_key_is_always_detected(name):
    """The authenticated ciphers catch this themselves; the demo algorithms
    rely on the checksum in the key file. Both paths must refuse."""
    alg = ALGORITHMS[name]
    payload = b"the real message" * 64
    ciphertext, _ = alg.encrypt(payload)
    _, wrong_material = alg.encrypt(b"decoy")
    doc = keyfile.build(name, "x.bin", wrong_material, payload)

    with pytest.raises(DecryptionError):
        recovered = alg.decrypt(ciphertext, wrong_material)
        keyfile.verify(doc, recovered)


@pytest.mark.parametrize("raw", [
    b"not json at all",
    b"{}",
    b'{"format": "something-else"}',
    b'{"format": "filecrypt-key", "version": 99}',
    b'{"format": "filecrypt-key", "version": 1, "algorithm": "made-up"}',
    b'{"format": "filecrypt-key", "version": 1, "algorithm": "aes"}',
])
def test_malformed_key_files_are_rejected(raw):
    with pytest.raises(DecryptionError):
        keyfile.parse(raw)


# --------------------------------------------------------------------- HTTP

def post_encrypt(client, payload, name, filename="report.pdf"):
    return client.post(
        "/encrypt",
        data={"file": (io.BytesIO(payload), filename), "algorithm": name},
        content_type="multipart/form-data",
    )


@pytest.mark.parametrize("name", list(ALGORITHMS))
def test_http_cycle(client, name):
    alg = ALGORITHMS[name]
    payload = sample_png() if alg.images_only else bytes(range(256)) * 200
    filename = "photo.png" if alg.images_only else "report.pdf"

    response = post_encrypt(client, payload, name, filename)
    assert response.status_code == 200
    body = response.get_json()

    recovered = client.post(
        "/decrypt",
        data={
            "file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.enc"),
            "key_file": (io.BytesIO(base64.b64decode(body["key"]["data"])), "x.key.json"),
        },
        content_type="multipart/form-data",
    )
    assert recovered.status_code == 200
    if not alg.lossy:
        assert recovered.data == payload


def test_key_can_be_pasted_instead_of_uploaded(client):
    """The decrypt panel accepts the key JSON as text as well as a file."""
    payload = b"pasted-key path" * 100
    body = post_encrypt(client, payload, "aes").get_json()
    key_json = base64.b64decode(body["key"]["data"]).decode("utf-8")

    response = client.post(
        "/decrypt",
        data={
            "file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.enc"),
            "key_text": key_json,
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert response.data == payload


def test_decrypt_without_any_key_is_rejected(client):
    body = post_encrypt(client, b"data", "aes").get_json()
    response = client.post(
        "/decrypt",
        data={"file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.enc")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "error" in response.get_json()


@pytest.mark.parametrize("supplied", [
    "../../../../etc/passwd",
    "..\\..\\windows\\system32\\config.sys",
    "plain.txt",
])
def test_uploaded_filenames_cannot_escape_or_inject(client, supplied):
    body = post_encrypt(client, b"data", "aes", supplied).get_json()
    for field in (body["encrypted"]["filename"], body["key"]["filename"]):
        assert not any(ch in field for ch in "/\\\r\n\"")


def test_index_lists_every_algorithm(client):
    page = client.get("/").data
    for name in ALGORITHMS:
        assert f'value="{name}"'.encode() in page


@pytest.mark.parametrize("data,expected", [
    ({"algorithm": "aes"}, 400),
    ({"file": (io.BytesIO(b""), "e.txt"), "algorithm": "aes"}, 400),
    ({"file": (io.BytesIO(b"x"), "a.txt"), "algorithm": "nope"}, 400),
])
def test_encrypt_rejects_bad_requests(client, data, expected):
    response = client.post("/encrypt", data=data, content_type="multipart/form-data")
    assert response.status_code == expected
    assert "error" in response.get_json()


def test_upload_over_the_limit_returns_413(client):
    app = create_app()
    oversize = b"\x00" * (app.config["MAX_CONTENT_LENGTH"] + 1024)
    response = post_encrypt(client, oversize, "aes", "big.bin")
    assert response.status_code == 413
    assert "error" in response.get_json()
