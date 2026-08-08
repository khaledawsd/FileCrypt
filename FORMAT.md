# FileCrypt file formats

Two containers, one per mode. This document is the specification: an
independent implementation should be able to read and write both from what is
here, without reading the Python.

Byte offsets are zero-based. Multi-byte integers are big-endian. "Base64" means
standard base64 with padding (RFC 4648 §4) unless stated otherwise.

Both formats have two independent implementations already, `utils/` in Python
and `static/js/crypto.js` in the browser, so this is a description of an
agreement, not of one program's behaviour.

The golden vectors in `tests/vectors/` are the conformance suite. `PLAINTEXT`
in `tests/test_vectors.py` gives the expected decryption of each.
`tests/vectors/webcrypto/` holds files written by the browser implementation
and read back by the Python one; those are what prove the two agree.

---

## 1. Key file mode

Two files: the ciphertext, and a JSON key file. The ciphertext has no header
and no magic bytes; its layout is entirely algorithm-specific (see §3), and
the key file is what says how to read it.

### The key file

UTF-8 JSON, conventionally named `<original>.key.json`.

```json
{
  "format": "filecrypt-key",
  "version": 1,
  "algorithm": "aes",
  "original_filename": "report.pdf",
  "created_at": "2026-08-08T18:12:04+00:00",
  "material": { "key": "base64..." },
  "plaintext_sha256": "hex...",
  "warning": "..."
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `format` | yes | `filecrypt-key`. `cryptoimage-key` is also accepted, from before the project was renamed. |
| `version` | yes | Must be `1`. Anything else is refused. |
| `algorithm` | yes | A key from the algorithm table in §3. |
| `original_filename` | no | Used to name the recovered file. Sanitised on use; never trusted as a path. |
| `created_at` | no | Informational only. |
| `material` | yes | Object. Algorithm-specific; see §3. |
| `plaintext_sha256` | no | Hex SHA-256 of the original bytes. Absent for lossy algorithms. |
| `warning` | no | Present for the educational algorithms. Informational only. |

A reader must reject the file if `format` is unrecognised, `version` is not
`1`, `algorithm` is unknown, or `material` is not an object.

`plaintext_sha256` is checked after decryption. It is what lets the
unauthenticated algorithms report a wrong key instead of returning garbage.
It is safe here because anyone holding the key file already holds the key,
which is exactly why it must **not** be copied into the envelope of §2.

---

## 2. Passphrase mode: the `FCP1` envelope

One self-contained file, conventionally `<original>.fcx`. The key is derived
from a passphrase, so nothing needs to be stored alongside it.

```
offset  size      contents
------  --------  ------------------------------------------------
0       4         magic, ASCII "FCP1"
4       4         header length H, big-endian uint32
8       H         header, UTF-8 JSON
8+H     N         ciphertext, algorithm-specific (§3)
8+H+N   32        MAC, HMAC-SHA256
```

Total length is `8 + H + N + 32`. `N` is whatever remains; it is not stored.

### Header

```json
{
  "format": "filecrypt-envelope",
  "version": 1,
  "algorithm": "aes",
  "original_filename": "report.pdf",
  "created_at": "2026-08-08T18:12:04+00:00",
  "kdf": { "name": "scrypt", "salt": "base64...", "n": 32768, "r": 8, "p": 1 },
  "material": {}
}
```

`material` carries whatever the algorithm needs that is *not* secret-derived;
for every algorithm except RSA that is the empty object, because the key comes
from the passphrase rather than from the file.

There is deliberately no `plaintext_sha256`. Storing a hash of the plaintext
next to the ciphertext would let anyone holding the file confirm guesses about
its contents. The MAC provides integrity without that.

### Key derivation

```
DK         = KDF(passphrase_utf8, salt, dkLen = 64)
cipher_key = DK[0:32]
mac_key    = DK[32:64]
```

One KDF call yields both keys. Running it twice would double a deliberately
expensive operation for no gain: 64 bytes is far more entropy than two 32-byte
keys need.

`kdf.name` selects the function. Three are defined; a reader that does not know
a given name **must refuse the file** rather than guess.

| `name` | Parameters | Defaults for new files |
| --- | --- | --- |
| `scrypt` | `n`, `r`, `p` | 32768, 8, 1 |
| `argon2id` | `time_cost`, `memory_cost` (KiB), `parallelism` | 3, 65536, 4 |
| `pbkdf2` | `iterations` (HMAC-SHA256) | 600000 |

`scrypt` is the default for files written by the server and the CLI.
`argon2id` is opt-in. `pbkdf2` exists because it is the only password KDF
WebCrypto offers, so it is what files encrypted in a browser use; it is the
weakest of the three and should not be chosen otherwise.

A reader **must** bound every parameter before use, because they come from an
untrusted file and are consumed *before* the MAC can be verified; deriving the
MAC key is exactly what they are needed for. scrypt allocates `128 · N · r`
bytes and Argon2 allocates `memory_cost` KiB, so unbounded values are a
memory-exhaustion vector. Accepted ranges:

| Parameter | Range |
| --- | --- |
| `scrypt.n` | a power of two, 2¹⁴ … 2¹⁷ |
| `scrypt.r` | 1 … 16 |
| `scrypt.p` | 1 … 4 |
| `argon2id.time_cost` | 1 … 10 |
| `argon2id.memory_cost` | 8192 … 524288 (KiB) |
| `argon2id.parallelism` | 1 … 8 |
| `pbkdf2.iterations` | 100000 … 5000000 |
| `salt` (all) | 8 … 64 bytes |

Readers should also cap `H` (this implementation uses 64 KiB) and reject a
header length that runs past the end of the buffer.

### MAC

```
MAC = HMAC-SHA256(mac_key, file[0 : len(file) - 32])
```

It covers the magic, the length field, the header, and the ciphertext:
everything before the MAC itself.

**Verify the MAC before attempting decryption.** Doing so means a wrong
passphrase is rejected without running the cipher, the header cannot be edited
in transit, and every algorithm gains tamper detection, including the
educational ones in §3 that have none of their own. Compare in constant time.

---

## 3. Algorithms

`material` contents are for key-file mode. In envelope mode the key comes from
the KDF and `material` is `{}`, except for RSA.

| `algorithm` | Ciphertext layout | `material` (key-file mode) |
| --- | --- | --- |
| `aes` | `nonce(12) ‖ AES-256-GCM(nonce, plaintext)` | `{"key": base64(32 bytes)}` |
| `fernet` | a Fernet token | `{"key": "url-safe base64 string, 44 chars"}` |
| `rsa` | `wrapped(256) ‖ nonce(12) ‖ AES-256-GCM(...)` | `{"private_key": "PEM"}` |
| `blowfish` | `iv(8) ‖ Blowfish-CBC(padded)` | `{"key": base64(32 bytes)}` |
| `chaos` | `plaintext ⊕ keystream`, same length | `{"key": base64(32 bytes)}` |
| `dna` | same length as plaintext | `{"key": base64(32 bytes)}` |
| `quantum` | same length as plaintext | `{"key": base64(32 bytes)}` |
| `visual_crypto` | a ZIP of `share1.png`, `share2.png`, `README.txt` | `{"width": int, "height": int}` |

Notes:

- **fernet** stores its key as the url-safe base64 *string* Fernet itself uses,
  not as base64 of raw bytes like the others. In envelope mode the derived
  32 bytes are url-safe-base64-encoded to form the Fernet key.
- **rsa** wraps a random AES-256-GCM data key with RSA-2048 OAEP (MGF1-SHA256,
  SHA-256, no label). In envelope mode the PEM in `material` is PKCS#8
  encrypted under `cipher_key`, so the header still carries a `private_key`
  entry, an *encrypted* one.
- **blowfish** pads to an 8-byte boundary, always adding at least one byte
  (PKCS#7-style).
- **chaos**, **dna** and **quantum** are unauthenticated stream transforms.
  Outside an envelope, a wrong key is caught only by `plaintext_sha256`.
  `quantum` is affine over GF(2) and is broken under known plaintext; see the
  README.
- **visual_crypto** is lossy. Stacking returns a black-and-white approximation
  at double width and height, not the original file. Its key material holds no
  key (the shares themselves are the secret), so a reader may accept a share
  archive with no key file at all.

---

## 4. Version history

| Container | Version | Notes |
| --- | --- | --- |
| `filecrypt-key` | 1 | Current. Also accepts the `cryptoimage-key` name. |
| `filecrypt-envelope` | 1 | Current. `argon2id` and `pbkdf2` were added to `kdf.name` after the first release; because unknown names are refused rather than guessed at, this needed no version bump. |

Any change that would stop this build reading an existing file requires a
version bump and a new golden vector alongside the old one, which must keep
passing.
