"""Shared fixtures and the /encrypt response parser.

/encrypt returns a framed binary body rather than JSON -- see
``routes.crypto._encrypted_response`` for why -- so every test that encrypts
over HTTP needs the same few lines to take it apart. They live here once.
"""

import io
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

import numpy as np
import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app


@pytest.fixture
def client():
    return create_app().test_client()


def sample_png() -> bytes:
    arr = np.zeros((48, 64), dtype=np.uint8)
    arr[10:38, 10:54] = 255
    buf = io.BytesIO()
    Image.fromarray(arr, mode="L").save(buf, format="PNG")
    return buf.getvalue()


@dataclass(frozen=True)
class Encrypted:
    """What /encrypt returned, unpacked."""

    payload: bytes
    key_bytes: bytes | None
    filename: str
    key_filename: str | None
    algorithm: str
    algorithm_label: str
    lossy: bool
    passphrase_mode: bool

    @property
    def as_upload(self) -> tuple[io.BytesIO, str]:
        return io.BytesIO(self.payload), self.filename

    @property
    def key_as_upload(self) -> tuple[io.BytesIO, str]:
        return io.BytesIO(self.key_bytes), self.key_filename


def parse_encrypted(response) -> Encrypted:
    """Unpack `uint32 key length | key JSON | ciphertext` plus its headers."""
    body = response.data
    assert len(body) >= 4, "response is too short to carry a length prefix"
    key_length = int.from_bytes(body[:4], "big")
    assert 4 + key_length <= len(body), "declared key length runs past the body"

    header = response.headers.get
    return Encrypted(
        payload=body[4 + key_length:],
        key_bytes=body[4:4 + key_length] if key_length else None,
        filename=unquote(header("X-Filename", "")),
        key_filename=unquote(header("X-Key-Filename")) if key_length else None,
        algorithm=header("X-Algorithm", ""),
        algorithm_label=unquote(header("X-Algorithm-Label", "")),
        lossy=header("X-Lossy") == "1",
        passphrase_mode=header("X-Passphrase-Mode") == "1",
    )


def encrypt_via_http(
    client,
    payload: bytes,
    algorithm: str = "aes",
    filename: str = "report.pdf",
    passphrase: str | None = None,
    kdf: str | None = None,
):
    """POST to /encrypt. Returns the raw response so error cases stay testable."""
    data = {"file": (io.BytesIO(payload), filename), "algorithm": algorithm}
    if passphrase is not None:
        data["passphrase"] = passphrase
    if kdf is not None:
        data["kdf"] = kdf
    return client.post("/encrypt", data=data, content_type="multipart/form-data")


def encrypt_ok(client, payload: bytes, algorithm: str = "aes", **kwargs) -> Encrypted:
    """As above, but asserts success and hands back the unpacked result."""
    response = encrypt_via_http(client, payload, algorithm, **kwargs)
    assert response.status_code == 200, response.get_data(as_text=True)[:200]
    return parse_encrypted(response)
