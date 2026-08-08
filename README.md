# FileCrypt

A local web app that encrypts any file and hands you back the encrypted file
and its key. It runs on your own machine — nothing is uploaded anywhere, no
accounts, no database.

There are two ways to lock a file, and the difference is what you have to keep
afterwards:

| Mode | You get back | You must keep |
| --- | --- | --- |
| **Key file** (default) | the encrypted file + a `.key.json` | the key file |
| **Passphrase** | one self-contained `.fcx` file | the passphrase, in your head |

## Download

```bash
git clone https://github.com/khaledawsd/FileCrypt.git
```

## Setup

Requires Python 3.12 or newer — that is the floor set by the pinned `numpy`,
not a preference.

```bash
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS/Linux

pip install -r requirements.txt
python app.py
```

Open <http://localhost:5000> in your browser.

Optional environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAX_UPLOAD_MB` | `32` | Largest file the app will accept. |
| `FLASK_DEBUG` | unset | Set to `1` for auto-reload and error tracebacks during development. |
| `FILECRYPT_PASSPHRASE` | unset | Read by the CLI for unattended runs, instead of prompting. |

## How it works

Everything happens in one request: you send a file, the server encrypts it in
memory, and sends the result straight back. Nothing is stored. Once the
response is sent, the server has no record of your file, your key, or your
passphrase.

### Key file mode

You get two downloads. The key file is plain JSON recording the algorithm, the
key material, the original filename, and a SHA-256 checksum of the original:

```json
{
  "format": "filecrypt-key",
  "algorithm": "aes",
  "original_filename": "report.pdf",
  "material": { "key": "...base64..." },
  "plaintext_sha256": "..."
}
```

That checksum is how the app tells you a key is wrong instead of just handing
back corrupted data.

### Passphrase mode

You get one file. The key is derived from your passphrase with scrypt rather
than generated randomly, so there is nothing to store alongside it — which
means there is nothing to lose. The file describes itself:

```
"FCP1" | header length (4 bytes) | header JSON | ciphertext | MAC (32 bytes)
```

The header names the algorithm, the original filename, and the scrypt
parameters. Everything except the secret.

The trailing MAC is keyed separately from the cipher and covers every byte
before it. That buys three things: a wrong passphrase is rejected *before* any
decryption is attempted, the header cannot be edited in transit, and every
algorithm gets tamper detection — including the demo ones that have none of
their own.

Note what the envelope deliberately leaves out: the plaintext checksum. In a
key file that is harmless, since whoever holds the key file already holds the
key. Writing it next to the ciphertext instead would hand anyone with the file
a way to confirm guesses about its contents. The MAC does the same job and
reveals nothing.

**There is no recovery.** Forget the passphrase and the file stays encrypted.

## How to use

**Encrypting**

1. Open the Encrypt tab and pick an algorithm (AES-256-GCM is the safe default).
2. Choose *a key file* or *a passphrase*.
3. Drop in a file, or click to browse.
4. Click Encrypt File and download what it gives you — both files in key-file
   mode, one in passphrase mode. Keep a key file somewhere separate from the
   encrypted file.

**Decrypting**

1. Open the Decrypt tab and drop in the encrypted file.
2. The page reads its first bytes and asks for whatever that file actually
   needs: a passphrase, a key file, or — for visual cryptography shares —
   nothing at all.
3. Click Decrypt File and download the result.

## Command line

The `utils` package never imported Flask, so the CLI is a thin shell over the
same engine rather than a second implementation:

```bash
python cli.py algorithms
python cli.py encrypt report.pdf --algorithm aes
python cli.py encrypt report.pdf --passphrase
python cli.py decrypt report.pdf.enc --key report.pdf.key.json
python cli.py decrypt report.pdf.fcx
```

Output lands next to the source file unless you pass `--out`, and existing
files are never overwritten without `--force`. Passphrases are read from a
terminal prompt, never from an argument, so they stay out of shell history and
out of other users' `ps` output. Set `FILECRYPT_PASSPHRASE` for scripted runs.

## Algorithms

| Algorithm | What it is | Recommended? |
| --- | --- | --- |
| AES-256-GCM | Authenticated encryption. Default choice. | Yes |
| Fernet | AES-128-CBC with an HMAC signature. | Yes |
| RSA-2048 (hybrid) | RSA wraps a random AES key; the key file holds the RSA private key. | Yes |
| Blowfish-CBC | Older 64-bit block cipher. Still correct, but outdated. | Use AES instead |
| Chaos (logistic map) | XOR against a keystream generated from a chaotic map. | Demo only |
| DNA coding | Bytes are mapped to DNA-style bases and shuffled using the key. | Demo only |
| Quantum-inspired | Reversible bit operations loosely modeled on quantum gates. | Demo only — broken |
| Visual cryptography | Splits an image into two shares that reveal it when overlaid. | Special case |

The three "demo only" algorithms will recover your file correctly, but they are
demonstrations of an idea rather than reviewed cryptography. The app shows a
warning when you select one. They are not equally bad, and it is worth being
precise about it:

- **Quantum-inspired is broken**, not merely unreviewed. Every operation in it
  is either an XOR or a permutation of bit positions, which makes the whole
  cipher affine over GF(2): `E(p₁) ⊕ E(p₂) = E(p₁ ⊕ p₂) ⊕ E(0)` holds no matter
  what the key is. A single known plaintext/ciphertext pair is enough to break
  it. It is kept because watching a reversible gate circuit run is the point of
  it, not because it protects anything.
- **Chaos and DNA** have no such known structural weakness — but nobody has
  analysed them either, which is the whole reason not to trust them.

Inside a passphrase envelope all three at least gain tamper detection from the
MAC, which they do not have on their own. That does not make them secure.

Visual cryptography works differently from the rest: it only accepts images,
and it does not give back your original file. It produces two share images —
either one alone looks like random noise, and overlaying them (by printing on
transparencies, or uploading both to the Decrypt tab) reveals a
black-and-white version of the original at double its size. That is the nature
of the technique, not a bug. Its key file holds no key, because the shares
themselves are the secret; the Decrypt tab recognises a share archive and does
not ask for one.

## Security notes

- The server processes your file in plaintext while encrypting it. This is not
  end-to-end encryption — it runs locally on your machine, so that "server" is
  you, but be aware of this if you ever expose it over a network.
- Nothing is written to disk and nothing is logged. Responses are sent with
  `Cache-Control: no-store` so a decrypted file does not linger in a cache.
- Responses carry a Content-Security-Policy of `default-src 'self'` with no
  `unsafe-inline`. The page loads no fonts, no CDN scripts, and makes no
  outbound requests, so a successful HTML injection would still have nowhere to
  send a file or a passphrase.
- scrypt parameters in a passphrase file are attacker-controlled and read
  before the MAC can be verified, so they are range-checked. Unbounded, they
  would be a way to make the app allocate arbitrary memory.
- There is no rate limiting or authentication, since this is meant to run
  locally for personal use, not be exposed publicly as-is. In particular
  nothing throttles passphrase attempts; the scrypt cost is what makes guessing
  expensive.

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest -q
ruff check .
```

CI runs both on Linux and Windows across Python 3.12 and 3.13.

## License

MIT — see [LICENSE](LICENSE).
