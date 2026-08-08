"""Command-line front end for the same engine the web app uses.

``utils`` never imported Flask, so this is a thin shell over it rather than a
reimplementation -- which matters, because two code paths that encrypt slightly
differently is exactly how a file becomes unrecoverable.

    python cli.py algorithms
    python cli.py encrypt report.pdf --algorithm aes
    python cli.py encrypt report.pdf --passphrase
    python cli.py decrypt report.pdf.enc --key report.pdf.key.json
    python cli.py decrypt report.pdf.fcx --passphrase

Passphrases are read from a terminal prompt, never from an argument, so they do
not end up in shell history or in another user's ``ps`` output. For unattended
runs set FILECRYPT_PASSPHRASE instead, with the usual caveats about secrets in
environment variables.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from utils import envelope, keyfile
from utils.encryption_utils import (
    ALGORITHMS,
    DEFAULT_ALGORITHM,
    DecryptionError,
    VisualCryptoError,
    looks_like_shares,
)

PASSPHRASE_ENV = "FILECRYPT_PASSPHRASE"


class Failure(Exception):
    """Anything the user should see as a plain message rather than a traceback."""


def _read_passphrase(confirm: bool) -> str:
    supplied = os.environ.get(PASSPHRASE_ENV)
    if supplied:
        return envelope.check_passphrase(supplied)

    if not sys.stdin.isatty():
        raise Failure(
            f"No terminal to prompt on. Set {PASSPHRASE_ENV} for unattended runs."
        )

    entered = envelope.check_passphrase(getpass.getpass("Passphrase: "))
    if confirm and entered != getpass.getpass("Confirm passphrase: ").strip():
        raise Failure("Those passphrases do not match.")
    return entered


def _write(path: Path, data: bytes, force: bool) -> Path:
    if path.exists() and not force:
        raise Failure(f"{path} already exists. Pass --force to overwrite it.")
    path.write_bytes(data)
    return path


def _destination(out: str | None, default_name: str, beside: Path) -> Path:
    """Resolve --out, which may name either a directory or a file.

    With no --out the result lands next to the source file rather than in the
    current directory: encrypting something in another folder should not
    scatter output into wherever the shell happens to be sitting.
    """
    if out is None:
        return beside.parent / default_name
    target = Path(out)
    return target / default_name if target.is_dir() else target


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_algorithms(_args: argparse.Namespace) -> int:
    width = max(len(name) for name in ALGORITHMS)
    for name, spec in ALGORITHMS.items():
        tags = []
        if name == DEFAULT_ALGORITHM:
            tags.append("default")
        if spec.educational:
            tags.append("demo only")
        if spec.images_only:
            tags.append("images only")
        if not spec.supports_passphrase:
            tags.append("no passphrase")
        suffix = f"  [{', '.join(tags)}]" if tags else ""
        print(f"{name:<{width}}  {spec.summary}{suffix}")
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    spec = ALGORITHMS.get(args.algorithm)
    if spec is None:
        raise Failure(f"Unknown algorithm: {args.algorithm}")
    if args.passphrase and not spec.supports_passphrase:
        raise Failure(f"{spec.label} has no key for a passphrase to replace.")

    source = Path(args.file)
    if not source.is_file():
        raise Failure(f"No such file: {source}")
    data = source.read_bytes()
    if not data:
        raise Failure("That file is empty.")

    if args.passphrase:
        secret = _read_passphrase(confirm=True)
        cipher_key, mac_key, params = envelope.derive(secret, name=args.kdf)
        ciphertext, material = spec.encrypt(data, key=cipher_key)
        blob = envelope.wrap(
            args.algorithm, source.name, material, ciphertext, params, mac_key
        )
        written = _write(
            _destination(args.out, source.name + envelope.EXTENSION, source), blob, args.force
        )
        print(f"{written}  ({len(blob)} bytes, {spec.label}, passphrase protected)")
        print("No key file: this one carries its own header. Remember the passphrase.")
        return 0

    ciphertext, material = spec.encrypt(data)
    key_bytes = keyfile.dumps(
        keyfile.build(args.algorithm, source.name, material, data)
    )
    payload = _write(
        _destination(args.out, source.name + spec.extension, source), ciphertext, args.force
    )
    key_path = _write(
        _destination(args.out, source.name + ".key.json", source), key_bytes, args.force
    )
    print(f"{payload}  ({len(ciphertext)} bytes, {spec.label})")
    print(f"{key_path}  <- keep this; it is the only way back")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    source = Path(args.file)
    if not source.is_file():
        raise Failure(f"No such file: {source}")
    payload = source.read_bytes()
    if not payload:
        raise Failure("That file is empty.")

    cipher_key = None
    if envelope.is_envelope(payload):
        doc, ciphertext, cipher_key = envelope.unwrap(
            payload, _read_passphrase(confirm=False)
        )
        checked = "passphrase verified, file unmodified"
    else:
        ciphertext = payload
        if args.key:
            key_path = Path(args.key)
            if not key_path.is_file():
                raise Failure(f"No such key file: {key_path}")
            doc = keyfile.parse(key_path.read_bytes())
        elif looks_like_shares(payload):
            # The shares are the secret; there is no key to ask for.
            doc = {"algorithm": "visual_crypto", "material": {}}
        else:
            raise Failure("This file needs its key file. Pass --key.")
        checked = "checksum matched" if doc.get("plaintext_sha256") else "not verified"

    spec = ALGORITHMS[doc["algorithm"]]
    plaintext = spec.decrypt(ciphertext, doc["material"], key=cipher_key)
    keyfile.verify(doc, plaintext)

    name = doc.get("original_filename") or "recovered"
    if spec.lossy:
        name = Path(name).stem + "_stacked.png"
        checked = "shares stacked; black-and-white approximation at double size"

    written = _write(_destination(args.out, name, source), plaintext, args.force)
    print(f"{written}  ({len(plaintext)} bytes, {spec.label}, {checked})")
    return 0


# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="filecrypt",
        description="Encrypt and decrypt files. Same engine as the web app.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("algorithms", help="list the available algorithms").set_defaults(
        handler=cmd_algorithms
    )

    enc = sub.add_parser("encrypt", help="encrypt a file")
    enc.add_argument("file")
    enc.add_argument(
        "--algorithm", "-a", default=DEFAULT_ALGORITHM, choices=list(ALGORITHMS)
    )
    enc.add_argument(
        "--passphrase", "-p", action="store_true",
        help="derive the key from a passphrase and emit one self-contained file",
    )
    enc.add_argument(
        "--kdf", default=envelope.DEFAULT_KDF, choices=list(envelope.KDF_NAMES),
        help="key derivation function for --passphrase (default: %(default)s)",
    )
    enc.add_argument("--out", "-o", help="output file or directory")
    enc.add_argument("--force", "-f", action="store_true", help="overwrite existing files")
    enc.set_defaults(handler=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="decrypt a file")
    dec.add_argument("file")
    dec.add_argument("--key", "-k", help="the .key.json written at encryption time")
    dec.add_argument(
        "--passphrase", "-p", action="store_true",
        help="accepted for symmetry; a self-contained file always prompts anyway",
    )
    dec.add_argument("--out", "-o", help="output file or directory")
    dec.add_argument("--force", "-f", action="store_true", help="overwrite existing files")
    dec.set_defaults(handler=cmd_decrypt)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except (Failure, DecryptionError, VisualCryptoError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
