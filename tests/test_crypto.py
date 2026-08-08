"""Round-trip and error-path tests.

Run with:  venv\\Scripts\\python.exe -m pytest tests -q

The point of these is narrow but important: every algorithm on the menu must
return exactly what went in, and a wrong key must be reported rather than
silently producing garbage.
"""

import base64
import io
import json
import re
import sys
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from routes.crypto import safe_name
from utils import encryption_utils, keyfile
from utils.encryption_utils import ALGORITHMS, DecryptionError

BYTE_LIKE = [
    pytest.param(b"", id="empty"),
    pytest.param(b"\x00", id="one-byte"),
    pytest.param("unicode ✓ and newlines\n\n".encode(), id="text"),
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


# ---------------------------------------------------------------- safe_name

@pytest.mark.parametrize("supplied,expected", [
    ("../../../../etc/passwd", "passwd"),
    ("..\\..\\windows\\system32\\config.sys", "config.sys"),
    ("plain.txt", "plain.txt"),
    ("with:colon*star?.txt", "withcolonstar.txt"),
    ("head\r\ninjection.txt", "headinjection.txt"),
    ("  spaced.txt  ", "spaced.txt"),
    ("", "file"),
    ("...", "file"),
    ("/", "file"),
    ("x" * 300, "x" * 120),
])
def test_safe_name_strips_everything_dangerous(supplied, expected):
    assert safe_name(supplied) == expected


# ------------------------------------------------------- verification paths

def test_key_file_naming_the_wrong_algorithm_is_refused(client):
    """The algorithm comes from the key file, so it is user-controlled.

    Point an AES key file at `chaos` and the material still parses -- it is a
    32-byte key either way -- so the transform runs and emits garbage. Only the
    checksum stands between that and a silently corrupt download.
    """
    body = post_encrypt(client, b"payload" * 100, "aes").get_json()
    doc = json.loads(base64.b64decode(body["key"]["data"]))
    doc["algorithm"] = "chaos"

    response = client.post(
        "/decrypt",
        data={
            "file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.enc"),
            "key_text": json.dumps(doc),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_lossy_algorithms_record_no_checksum():
    """verify() has to be a no-op for them: there is no original to match."""
    doc = keyfile.build("visual_crypto", "photo.png", {"width": 4, "height": 4}, b"ignored")
    assert "plaintext_sha256" not in doc
    keyfile.verify(doc, b"anything at all")  # must not raise


@pytest.mark.parametrize("name,expected", [
    ("aes", "checksum"),
    ("chaos", "checksum"),
    ("visual_crypto", "none"),
])
def test_decrypt_reports_which_check_ran(client, name, expected):
    """The page used to claim a checksum matched no matter what happened."""
    alg = ALGORITHMS[name]
    payload = sample_png() if alg.images_only else b"contents" * 50
    body = post_encrypt(client, payload, name, "photo.png").get_json()

    response = client.post(
        "/decrypt",
        data={
            "file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.enc"),
            "key_file": (io.BytesIO(base64.b64decode(body["key"]["data"])), "x.key.json"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert response.headers["X-Verified"] == expected
    assert response.headers["X-Lossy"] == ("1" if alg.lossy else "0")


def test_unicode_filenames_survive_the_round_trip(client):
    """Header values are latin-1 on the wire, so the name travels percent-encoded."""
    body = post_encrypt(client, b"data" * 20, "aes", "文档 résumé.pdf").get_json()
    response = client.post(
        "/decrypt",
        data={
            "file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.enc"),
            "key_file": (io.BytesIO(base64.b64decode(body["key"]["data"])), "x.key.json"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    from urllib.parse import unquote
    assert unquote(response.headers["X-Original-Filename"]) == "文档 résumé.pdf"


# ------------------------------------------------------------ visual crypto

def test_shares_decrypt_without_any_key_file(client):
    """Its key file holds no key, so the decrypt panel should not demand one."""
    body = post_encrypt(client, sample_png(), "visual_crypto", "photo.png").get_json()
    response = client.post(
        "/decrypt",
        data={"file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])),
                       "photo.png.shares.zip")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert response.headers["X-Lossy"] == "1"


def test_a_non_share_file_without_a_key_is_still_refused(client):
    body = post_encrypt(client, b"data" * 20, "aes").get_json()
    response = client.post(
        "/decrypt",
        data={"file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.enc")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400


def test_oversized_share_is_refused(monkeypatch):
    """The cap is what stops a deflate bomb expanding past the upload limit.

    Shrinking it rather than building a real bomb keeps the test fast; the
    branch under test is the same one either way.
    """
    shares, material = ALGORITHMS["visual_crypto"].encrypt(sample_png())
    monkeypatch.setattr(encryption_utils, "_VC_MAX_SHARE_BYTES", 64)
    with pytest.raises(DecryptionError):
        ALGORITHMS["visual_crypto"].decrypt(shares, material)


# -------------------------------------------------------- response hardening

def test_security_headers_are_set(client):
    response = client.get("/")
    csp = response.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_the_inline_theme_script_carries_the_policy_nonce(client):
    """CSP is only worth anything if the one inline script actually matches it."""
    response = client.get("/")
    nonce = re.search(r"'nonce-([^']+)'", response.headers["Content-Security-Policy"])
    assert nonce, "no nonce in the policy"
    assert f'nonce="{nonce.group(1)}"'.encode() in response.data


def test_each_request_gets_a_fresh_nonce(client):
    first = client.get("/").headers["Content-Security-Policy"]
    second = client.get("/").headers["Content-Security-Policy"]
    assert first != second


def test_decrypted_files_are_not_cached(client):
    body = post_encrypt(client, b"sensitive" * 20, "aes").get_json()
    response = client.post(
        "/decrypt",
        data={
            "file": (io.BytesIO(base64.b64decode(body["encrypted"]["data"])), "x.enc"),
            "key_file": (io.BytesIO(base64.b64decode(body["key"]["data"])), "x.key.json"),
        },
        content_type="multipart/form-data",
    )
    assert response.headers["Cache-Control"] == "no-store"
