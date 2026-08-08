"""The whole application: one page, two operations, no stored state.

/encrypt takes a file and returns it encrypted. In the default flow that means
two downloads -- the ciphertext and a key file holding random key material. Give
it a passphrase instead and it returns one self-contained file with the key
derived rather than stored; see :mod:`utils.envelope`.

/decrypt takes back whatever /encrypt produced and streams the original file. It
works out which of the three shapes it was handed rather than asking:

* a self-contained envelope    -> needs the passphrase, nothing else
* a visual-crypto share archive -> needs nothing; the shares are the secret
* anything else                 -> needs the key file

Nothing touches the disk or a database in between. Once a response is sent the
server has no copy of the file, the key, or the passphrase.
"""

from __future__ import annotations

import base64
import posixpath
from datetime import datetime
from urllib.parse import quote

from flask import Blueprint, current_app, jsonify, render_template, request

from utils import envelope, keyfile
from utils.encryption_utils import (
    ALGORITHMS,
    DEFAULT_ALGORITHM,
    DecryptionError,
    VisualCryptoError,
    looks_like_shares,
)

bp = Blueprint("crypto", __name__)

# Filenames arrive from the client and are echoed back into download names.
# Strip every directory component and control character so nothing can escape
# the intended name or inject a response header.
_UNSAFE = set('<>:"/\\|?*') | {chr(c) for c in range(32)}


def safe_name(name: str, fallback: str = "file") -> str:
    name = posixpath.basename((name or "").replace("\\", "/")).strip()
    name = "".join(ch for ch in name if ch not in _UNSAFE)
    name = name.strip(". ")
    return name[:120] or fallback


@bp.route("/")
def index():
    algorithms = [
        {
            "name": a.name,
            "label": a.label,
            "summary": a.summary,
            "educational": a.educational,
            "images_only": a.images_only,
            "lossy": a.lossy,
            "supports_passphrase": a.supports_passphrase,
            "notes": a.notes,
        }
        for a in ALGORITHMS.values()
    ]
    return render_template(
        "index.html",
        algorithms=algorithms,
        default_algorithm=DEFAULT_ALGORITHM,
        default_algorithm_label=ALGORITHMS[DEFAULT_ALGORITHM].label,
        max_mb=current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024),
        min_passphrase=envelope.MIN_PASSPHRASE,
        year=datetime.now().year,
    )


@bp.route("/encrypt", methods=["POST"])
def encrypt():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"error": "Choose a file to encrypt."}), 400

    algorithm = request.form.get("algorithm", DEFAULT_ALGORITHM)
    spec = ALGORITHMS.get(algorithm)
    if spec is None:
        return jsonify({"error": f"Unknown algorithm: {algorithm}"}), 400

    passphrase = (request.form.get("passphrase") or "").strip()
    if passphrase and not spec.supports_passphrase:
        return jsonify(
            {"error": f"{spec.label} has no key for a passphrase to replace."}
        ), 400

    data = upload.read()
    if not data:
        return jsonify({"error": "That file is empty."}), 400

    original = safe_name(upload.filename)

    try:
        if passphrase:
            passphrase = envelope.check_passphrase(passphrase)
            cipher_key, mac_key, params = envelope.derive(passphrase)
            ciphertext, material = spec.encrypt(data, key=cipher_key)
            blob = envelope.wrap(
                algorithm, original, material, ciphertext, params, mac_key
            )
            return jsonify(
                {
                    "ok": True,
                    "algorithm": algorithm,
                    "algorithm_label": spec.label,
                    "lossy": spec.lossy,
                    "passphrase_mode": True,
                    "encrypted": {
                        "filename": original + envelope.EXTENSION,
                        "size": len(blob),
                        "data": base64.b64encode(blob).decode(),
                    },
                    "key": None,
                }
            )

        ciphertext, material = spec.encrypt(data)
    except DecryptionError as exc:  # passphrase rejected before any work
        return jsonify({"error": str(exc)}), 400
    except VisualCryptoError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        current_app.logger.exception("Encryption failed (%s)", algorithm)
        return jsonify({"error": "Encryption failed. See the server log."}), 500

    key_bytes = keyfile.dumps(keyfile.build(algorithm, original, material, data))

    return jsonify(
        {
            "ok": True,
            "algorithm": algorithm,
            "algorithm_label": spec.label,
            "lossy": spec.lossy,
            "passphrase_mode": False,
            "encrypted": {
                "filename": original + spec.extension,
                "size": len(ciphertext),
                "data": base64.b64encode(ciphertext).decode(),
            },
            "key": {
                "filename": original + ".key.json",
                "size": len(key_bytes),
                "data": base64.b64encode(key_bytes).decode(),
            },
        }
    )


def _read_key_document(payload: bytes) -> dict:
    """Work out how to open ``payload`` from whatever the form supplied.

    Returns the key document. Raises DecryptionError with a message aimed at
    the user when the request does not carry enough to proceed.
    """
    key_upload = request.files.get("key_file")
    key_text = (request.form.get("key_text") or "").strip()

    # An uploaded key file wins if somehow both are present.
    if key_upload is not None and key_upload.filename:
        return keyfile.parse(key_upload.read())
    if key_text:
        return keyfile.parse(key_text.encode("utf-8"))

    # No key supplied. Visual cryptography genuinely does not need one -- the
    # shares are the secret -- so recognise its archive rather than demanding a
    # key file that would hold nothing but an image size.
    if looks_like_shares(payload):
        return {"algorithm": "visual_crypto", "material": {}}

    raise DecryptionError("Paste your key, or upload the .key.json file.")


@bp.route("/decrypt", methods=["POST"])
def decrypt():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"error": "Choose the encrypted file."}), 400

    payload = upload.read()
    if not payload:
        return jsonify({"error": "The encrypted file is empty."}), 400

    passphrase = (request.form.get("passphrase") or "").strip()
    sealed = envelope.is_envelope(payload)

    if sealed and not passphrase:
        return jsonify({"error": "This file needs the passphrase it was encrypted with."}), 400

    try:
        if sealed:
            doc, ciphertext, cipher_key = envelope.unwrap(payload, passphrase)
            verified = "mac"
        else:
            doc, ciphertext, cipher_key = _read_key_document(payload), payload, None
            verified = "checksum" if doc.get("plaintext_sha256") else "none"
    except DecryptionError as exc:
        return jsonify({"error": str(exc)}), 400

    spec = ALGORITHMS[doc["algorithm"]]

    try:
        plaintext = spec.decrypt(ciphertext, doc["material"], key=cipher_key)
        keyfile.verify(doc, plaintext)
    except DecryptionError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        current_app.logger.exception("Decryption failed (%s)", doc["algorithm"])
        return jsonify({"error": "Decryption failed. See the server log."}), 500

    name = safe_name(doc.get("original_filename", ""), fallback="recovered")
    if spec.lossy:
        name = posixpath.splitext(name)[0] + "_stacked.png"

    response = current_app.response_class(plaintext, mimetype="application/octet-stream")
    response.headers.set("Content-Disposition", "attachment", filename=name)
    # Header values are latin-1 on the wire, so a name like "文档.pdf" cannot go
    # in raw. The page decodes this with decodeURIComponent.
    response.headers["X-Original-Filename"] = quote(name, safe="")
    # How the result was checked, so the page can say something true about it
    # rather than always claiming a checksum matched.
    response.headers["X-Verified"] = verified
    response.headers["X-Lossy"] = "1" if spec.lossy else "0"
    return response


@bp.app_errorhandler(413)
def too_large(_error):
    limit = current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    return jsonify({"error": f"File is larger than the {limit} MB limit."}), 413
