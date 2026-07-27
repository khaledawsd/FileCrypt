# FileCrypt

A local web app that encrypts any file and hands you back the encrypted file
and its key. It runs on your own machine — nothing is uploaded anywhere, no
accounts, no database. Lose the key file and the data is gone for good.

## Download

```bash
git clone https://github.com/khaledawsd/FileCrypt.git
cd FileCrypt
```

## Setup

Requires Python 3.9 or newer.

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

## How it works

Everything happens in one request: you send a file, the server encrypts it in
memory, and sends back two things — the encrypted file and a key file. Neither
is stored. Once the response is sent, the server has no record of your file or
your key.

The key file is plain JSON. It records the algorithm used, the key material,
the original filename, and a SHA-256 checksum of the original file:

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

## How to use

**Encrypting a file**

1. Open the Encrypt tab.
2. Pick an algorithm from the dropdown (AES-256-GCM is the safe default).
3. Drop in a file, or click to browse.
4. Click Encrypt File.
5. Download both files it gives you: the encrypted file and the key file.
   Keep them somewhere separate from each other.

**Decrypting a file**

1. Open the Decrypt tab.
2. Drop in the encrypted file.
3. Provide the key — either paste the key file's contents into the text box,
   or upload the key file directly.
4. Click Decrypt File and download the recovered original.

## Algorithms

| Algorithm | What it is | Recommended? |
| --- | --- | --- |
| AES-256-GCM | Authenticated encryption. Default choice. | Yes |
| Fernet | AES-128-CBC with an HMAC signature. | Yes |
| RSA-2048 (hybrid) | RSA wraps a random AES key; the key file holds the RSA private key. | Yes |
| Blowfish-CBC | Older 64-bit block cipher. Still correct, but outdated. | Use AES instead |
| Chaos (logistic map) | XOR against a keystream generated from a chaotic map. | Demo only |
| DNA coding | Bytes are mapped to DNA-style bases and shuffled using the key. | Demo only |
| Quantum-inspired | Reversible bit operations loosely modeled on quantum gates. | Demo only |
| Visual cryptography | Splits an image into two shares that reveal it when overlaid. | Special case |

The three "demo only" algorithms are not real, reviewed cryptography. They
will recover your file correctly, but nobody has studied them for weaknesses —
don't use them to protect anything important. The app shows a warning when you
select one.

Visual cryptography works differently from the rest: it only accepts images,
and it does not give back your original file. It produces two share images —
either one alone looks like random noise, and overlaying them (by printing on
transparencies, or uploading both to the Decrypt tab) reveals a black-and-white
version of the original at double its size. That's the nature of the
technique, not a bug.

## Security notes

- The server processes your file in plaintext while encrypting it. This is
  not end-to-end encryption — it runs locally on your machine, so that
  "server" is you, but be aware of this if you ever expose it over a network.
- Nothing is written to disk and nothing is logged.
- There's no rate limiting or authentication, since this is meant to run
  locally for personal use, not be exposed publicly as-is.

## License

MIT — see [LICENSE](LICENSE).
