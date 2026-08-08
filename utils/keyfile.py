"""The key file: a self-describing JSON container.

Nothing is stored server-side, so the key file has to carry everything needed
to reverse an encryption: which algorithm ran, the key material it produced,
the original filename, and a checksum of the plaintext.

The checksum is what lets every algorithm report a wrong key. AES, Fernet and
RSA authenticate internally and would catch it anyway; the educational
algorithms are raw transforms that would otherwise hand back plausible-looking
garbage without complaint.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from .encryption_utils import ALGORITHMS, DecryptionError

FORMAT = "filecrypt-key"
SUPPORTED_FORMATS = {FORMAT, "cryptoimage-key"}
VERSION = 1


def build(algorithm: str, original_filename: str, material: dict, plaintext: bytes) -> dict:
    """Assemble the key document for a finished encryption."""
    spec = ALGORITHMS[algorithm]
    doc = {
        "format": FORMAT,
        "version": VERSION,
        "algorithm": algorithm,
        "original_filename": original_filename,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "material": material,
    }
    if not spec.lossy:
        doc["plaintext_sha256"] = hashlib.sha256(plaintext).hexdigest()
    if spec.educational:
        doc["warning"] = (
            "This algorithm is a demonstration, not reviewed cryptography. "
            "Do not rely on it to protect anything that matters."
        )
    return doc


def dumps(doc: dict) -> bytes:
    return json.dumps(doc, indent=2).encode("utf-8")


def parse(raw: bytes) -> dict:
    """Read and validate an uploaded key file."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecryptionError(
            "That does not look like a key file. Upload the .key.json file "
            "you downloaded alongside the encrypted file."
        ) from exc

    if not isinstance(doc, dict) or doc.get("format") not in SUPPORTED_FORMATS:
        raise DecryptionError("That JSON file is not a FileCrypt key file.")

    if doc.get("version") != VERSION:
        raise DecryptionError(
            f"Key file version {doc.get('version')!r} is not supported by this build."
        )

    algorithm = doc.get("algorithm")
    if algorithm not in ALGORITHMS:
        raise DecryptionError(f"Key file names an unknown algorithm: {algorithm!r}")

    if not isinstance(doc.get("material"), dict):
        raise DecryptionError("Key file is missing its material section.")

    return doc


def verify(doc: dict, plaintext: bytes) -> None:
    """Confirm recovered bytes match the checksum recorded at encryption time."""
    expected = doc.get("plaintext_sha256")
    if not expected:
        return  # lossy algorithm, or a key file written without one
    if hashlib.sha256(plaintext).hexdigest() != expected:
        raise DecryptionError(
            "Wrong key: the recovered data does not match the checksum in the "
            "key file."
        )
