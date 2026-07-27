"""FileCrypt - stateless file encryption.

Upload a file, pick an algorithm, get back the encrypted file and its key.
Nothing is written to disk and nothing is remembered: no database, no accounts,
no upload folder. Lose the key file and the data is gone.
"""

import os

from flask import Flask

from routes.crypto import bp as crypto_bp

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "32"))


def create_app() -> Flask:
    app = Flask(__name__)

    # Requests are handled entirely in memory, so the ceiling is really about
    # how much RAM one upload may consume: the file, its ciphertext, and the
    # base64 of that ciphertext all coexist briefly.
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

    # No sessions, no cookies, no flash messages -- hence no secret key. If you
    # add anything session-backed later, read it from the environment rather
    # than hardcoding it.
    app.register_blueprint(crypto_bp)
    return app


app = create_app()

if __name__ == "__main__":
    # Running this file directly is the dev entrypoint, so pick up template
    # edits without a restart. Flask only does this automatically in debug
    # mode, which otherwise leaves you staring at a cached page. A production
    # WSGI server imports `app` above and keeps the default caching.
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
