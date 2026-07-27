"""The whole application: one page, two operations, no stored state.

/encrypt takes a file, returns the ciphertext and key file as base64 in JSON so
the browser can offer them as two separate downloads. /decrypt takes both back
and streams the original file. Nothing touches the disk or a database in
between -- once a response is sent the server has no copy of the file and no
copy of the key.
"""

from __future__ import annotations

import base64
import posixpath
from datetime import datetime

from flask import Blueprint, current_app, jsonify, render_template, request

from utils import keyfile
from utils.encryption_utils import (
    ALGORITHMS,
    DEFAULT_ALGORITHM,
    DecryptionError,
    VisualCryptoError,
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

    data = upload.read()
    if not data:
        return jsonify({"error": "That file is empty."}), 400

    original = safe_name(upload.filename)

    try:
        ciphertext, material = spec.encrypt(data)
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


@bp.route("/decrypt", methods=["POST"])
def decrypt():
    payload = request.files.get("file")
    key_upload = request.files.get("key_file")
    key_text = (request.form.get("key_text") or "").strip()

    if payload is None or not payload.filename:
        return jsonify({"error": "Choose the encrypted file."}), 400

    # The key can arrive either as the downloaded .key.json or pasted into the
    # textarea. An uploaded file wins if somehow both are present.
    if key_upload is not None and key_upload.filename:
        raw_key = key_upload.read()
    elif key_text:
        raw_key = key_text.encode("utf-8")
    else:
        return jsonify({"error": "Paste your key, or upload the .key.json file."}), 400

    try:
        doc = keyfile.parse(raw_key)
    except DecryptionError as exc:
        return jsonify({"error": str(exc)}), 400

    spec = ALGORITHMS[doc["algorithm"]]
    ciphertext = payload.read()
    if not ciphertext:
        return jsonify({"error": "The encrypted file is empty."}), 400

    try:
        plaintext = spec.decrypt(ciphertext, doc["material"])
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
    response.headers["X-Original-Filename"] = name
    response.headers["Access-Control-Expose-Headers"] = "X-Original-Filename"
    return response


@bp.app_errorhandler(413)
def too_large(_error):
    limit = current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    return jsonify({"error": f"File is larger than the {limit} MB limit."}), 413
