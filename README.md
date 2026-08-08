# FileCrypt

A local web app that encrypts any file and hands you back the encrypted file
and its key. It runs on your own machine: nothing is uploaded anywhere, no
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

Requires Python 3.12 or newer. That is the floor set by the pinned `numpy`,
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

## Where the encryption happens

Everything happens on your own machine; that is the whole design. You clone
the repo and run it; there is nothing to deploy and nothing to sign up for.
Within that, there are two places code actually runs, and the difference is
worth knowing.

**AES-256-GCM runs in your browser.** It is encrypted with WebCrypto right in
the tab, so no request is made at all. The result panel says so, and you can
confirm it in the network tab: there is nothing there to look at.

**Everything else runs in the local Python process**, the one you started with
`python app.py`. WebCrypto has no Blowfish and no Fernet, and re-implementing
the three educational algorithms in JavaScript would mean two independent
versions of an unreviewed cipher that could quietly disagree about what a file
contains. So those stay in one place. The page tells you which path ran, every
time.

There is one more constraint worth knowing: `crypto.subtle` only exists in a
secure context. Over `https` or `localhost` you get the in-browser path; over
plain `http` to a LAN address the browser disables it entirely and the page
falls back to the local process, saying so.

For AES you can untick *Encrypt in this browser* to force the local-process path; the
only reason to is if you want a KDF other than PBKDF2 (see below).

When the local process does the work: it happens in one request, in memory, and
nothing is stored. Once the response is sent there is no record of your file,
your key, or your passphrase.

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
than generated randomly, so there is nothing to store alongside it, which
means there is nothing to lose. The file describes itself:

```
"FCP1" | header length (4 bytes) | header JSON | ciphertext | MAC (32 bytes)
```

The header names the algorithm, the original filename, and the KDF parameters.
Everything except the secret.

Three key derivation functions are available:

| KDF | When it is used |
| --- | --- |
| **scrypt** | The default for the local app and the CLI. Memory-hard, no extra dependency. |
| **Argon2id** | Opt-in. The current best-practice choice. Not the default only because files written with it cannot be read by builds that predate it. |
| **PBKDF2** | What in-browser encryption uses, because it is the only password KDF WebCrypto offers. The weakest of the three; don't pick it deliberately. |

A file records which one it used, so any of them opens without being told.
Since an unknown KDF name is refused rather than guessed at, adding these
needed no format version bump.

The trailing MAC is keyed separately from the cipher and covers every byte
before it. That buys three things: a wrong passphrase is rejected *before* any
decryption is attempted, the header cannot be edited in transit, and every
algorithm gets tamper detection, including the demo ones that have none of
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
4. Click Encrypt File and download what it gives you: both files in key-file
   mode, one in passphrase mode. Keep a key file somewhere separate from the
   encrypted file.

**Decrypting**

1. Open the Decrypt tab and drop in the encrypted file.
2. The page reads its first bytes and asks for whatever that file actually
   needs: a passphrase, a key file, or (for visual cryptography shares)
   nothing at all.
3. Click Decrypt File and download the result.

## Command line

The `utils` package never imported Flask, so the CLI is a thin shell over the
same engine rather than a second implementation:

```bash
python cli.py algorithms
python cli.py encrypt report.pdf --algorithm aes
python cli.py encrypt report.pdf --passphrase
python cli.py encrypt report.pdf --passphrase --kdf argon2id
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
| Quantum-inspired | Reversible bit operations loosely modeled on quantum gates. | Demo only, broken |
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
- **Chaos and DNA** have no such known structural weakness, but nobody has
  analysed them either, which is the whole reason not to trust them.

Inside a passphrase envelope all three at least gain tamper detection from the
MAC, which they do not have on their own. That does not make them secure.

Visual cryptography works differently from the rest: it only accepts images,
and it does not give back your original file. It produces two share images:
either one alone looks like random noise, and overlaying them (by printing on
transparencies, or uploading both to the Decrypt tab) reveals a
black-and-white version of the original at double its size. That is the nature
of the technique, not a bug. Its key file holds no key, because the shares
themselves are the secret; the Decrypt tab recognises a share archive and does
not ask for one.

## Security notes

- **AES-256-GCM never leaves your browser.** For that path there is no upload
  and nothing outside the tab is involved.
- **Every other algorithm is processed in plaintext by the local Python
  process.** Still your own machine, but worth knowing if you ever put this on
  an address other than localhost.
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
mypy
```

CI runs all three on Linux and Windows across Python 3.12 and 3.13. There is an
opt-in pre-commit hook (`pre-commit install`) that runs ruff, and Dependabot
watches the pins, which is worth having when two of them are crypto libraries.

The file formats are specified in [FORMAT.md](FORMAT.md), byte for byte, so
another implementation can read them without reading the Python.

Two groups of tests are worth knowing about:

- **`tests/vectors/`** holds files encrypted by an earlier build, and
  `test_vectors.py` decrypts them. Every other test encrypts and decrypts in
  one process, which only proves the pair is self-consistent. A change that
  broke both halves identically would pass all of them while making everything
  anyone had already encrypted unreadable. These are the tests that catch that,
  so when one fails, regenerating the vector is almost always the wrong fix.
- **`test_fuzz.py`** throws arbitrary bytes at the three parsers that read
  untrusted input, asserting they only ever raise `DecryptionError`. It found a
  real bug on its first run: a zip holding two non-image `.png` members
  returned a 500 and a stack trace instead of a message.
- **`tests/vectors/webcrypto/`** holds files written by `static/js/crypto.js`
  in a real browser, which `test_webcrypto_vectors.py` reads back in Python.
  There are two implementations of both formats now, and the failure that
  matters is not either one crashing; it is the two drifting apart. Nothing
  else in the suite would notice.

Coverage, if you want it:

```bash
coverage run -m pytest && coverage report --include="utils/*,routes/*,app.py,cli.py"
```

## License

MIT. See [LICENSE](LICENSE).
