"""FileCrypt - stateless file encryption.

Upload a file, pick an algorithm, get back the encrypted file and its key --
or give it a passphrase and get back one self-contained file with nothing to
keep alongside it. Nothing is written to disk and nothing is remembered: no
database, no accounts, no upload folder.
"""

import os
import secrets

from flask import Flask, g, request

from routes.crypto import bp as crypto_bp

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "32"))

# Everything this page needs comes from this origin: no CDN, no fonts, no
# analytics, no outbound requests of any kind. Stating that explicitly means a
# successful HTML injection still has nowhere to send a file or a passphrase.
# The one inline script -- the pre-paint theme switch in base.html, which has to
# be inline or the page flashes -- is allowed by per-response nonce rather than
# by opening the policy up with 'unsafe-inline'.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-{nonce}'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)

_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",  # for browsers predating frame-ancestors
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), usb=()",
}


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

    @app.before_request
    def _make_nonce() -> None:
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def _expose_nonce() -> dict:
        return {"csp_nonce": g.get("csp_nonce", "")}

    @app.after_request
    def _harden(response):
        response.headers.setdefault(
            "Content-Security-Policy", _CSP.format(nonce=g.get("csp_nonce", ""))
        )
        for header, value in _HEADERS.items():
            response.headers.setdefault(header, value)
        # Decrypted files come back through here. Letting a browser or proxy
        # cache one would put on disk exactly what this app promises not to.
        if request.endpoint != "static":
            response.headers.setdefault("Cache-Control", "no-store")
        return response

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
