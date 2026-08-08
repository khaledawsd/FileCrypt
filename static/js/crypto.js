/* Client-side encryption, byte-compatible with the Python implementation.
 *
 * When this path runs, the file never leaves the machine: the server sees no
 * request at all. That makes the project's own headline claim literally true
 * rather than true-because-the-server-is-also-you.
 *
 * It covers AES-256-GCM only, and that is not a shortcut. WebCrypto offers no
 * Blowfish and no Fernet, and re-implementing the three educational algorithms
 * here would mean two independent implementations of an unreviewed cipher that
 * could silently disagree about what a file contains. Everything else keeps
 * going to the server, and the UI says which happened.
 *
 * Two constraints shape what follows:
 *
 *   - WebCrypto's only password KDF is PBKDF2. It has no scrypt and no Argon2.
 *     So files written here declare "pbkdf2" in their header, which the server
 *     understands; files the server wrote with scrypt or Argon2id cannot be
 *     opened here and are handed back to it for decryption.
 *   - crypto.subtle exists only in a secure context. Over plain http to
 *     anything but localhost it is undefined, and `available()` returns false
 *     so the caller falls back to the server rather than breaking.
 *
 * Anything in here that changes the bytes on disk must keep
 * tests/test_webcrypto_vectors.py passing -- that is the file that proves the
 * two implementations still agree.
 */
window.FileCryptWeb = (function () {
    "use strict";

    var MAGIC = "FCP1";
    var MAC_BYTES = 32;
    var SALT_BYTES = 16;
    var NONCE_BYTES = 12;
    var KEY_BITS = 512;          // 32-byte cipher key + 32-byte MAC key
    var PBKDF2_ITERATIONS = 600000;
    var KEY_FORMAT = "filecrypt-key";
    var ENVELOPE_FORMAT = "filecrypt-envelope";
    var VERSION = 1;

    var subtle = window.crypto && window.crypto.subtle;

    function available() {
        return Boolean(subtle && window.TextEncoder && window.crypto.getRandomValues);
    }

    /* ------------------------------------------------------------ helpers */

    var utf8 = new TextEncoder();
    var utf8Decode = new TextDecoder();

    function randomBytes(n) {
        return window.crypto.getRandomValues(new Uint8Array(n));
    }

    function concat(parts) {
        var total = parts.reduce(function (n, p) { return n + p.length; }, 0);
        var out = new Uint8Array(total);
        var at = 0;
        parts.forEach(function (p) { out.set(p, at); at += p.length; });
        return out;
    }

    /* Chunked so a large file does not blow the argument limit on apply(). */
    function toBase64(bytes) {
        var chunk = 0x8000;
        var pieces = [];
        for (var i = 0; i < bytes.length; i += chunk) {
            pieces.push(String.fromCharCode.apply(
                null, bytes.subarray(i, i + chunk)
            ));
        }
        return btoa(pieces.join(""));
    }

    function fromBase64(text) {
        var binary = atob(text);
        var out = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
        return out;
    }

    function toHex(bytes) {
        var out = "";
        for (var i = 0; i < bytes.length; i++) {
            out += bytes[i].toString(16).padStart(2, "0");
        }
        return out;
    }

    function uint32(value) {
        var out = new Uint8Array(4);
        new DataView(out.buffer).setUint32(0, value, false);   // big-endian
        return out;
    }

    function readUint32(bytes, offset) {
        return new DataView(
            bytes.buffer, bytes.byteOffset + offset, 4
        ).getUint32(0, false);
    }

    function sha256Hex(bytes) {
        return subtle.digest("SHA-256", bytes).then(function (digest) {
            return toHex(new Uint8Array(digest));
        });
    }

    /* --------------------------------------------------------------- AES */

    function importAesKey(raw) {
        return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
    }

    /* Layout must match utils/encryption_utils.aes_encrypt: nonce then the
     * GCM output, which already carries its 16-byte tag at the end. */
    function aesEncrypt(rawKey, plaintext) {
        var nonce = randomBytes(NONCE_BYTES);
        return importAesKey(rawKey).then(function (key) {
            return subtle.encrypt(
                { name: "AES-GCM", iv: nonce, tagLength: 128 }, key, plaintext
            );
        }).then(function (buffer) {
            return concat([nonce, new Uint8Array(buffer)]);
        });
    }

    function aesDecrypt(rawKey, payload) {
        if (payload.length <= NONCE_BYTES) {
            return Promise.reject(new Error("File is too short to be valid AES output."));
        }
        return importAesKey(rawKey).then(function (key) {
            return subtle.decrypt(
                { name: "AES-GCM", iv: payload.subarray(0, NONCE_BYTES), tagLength: 128 },
                key,
                payload.subarray(NONCE_BYTES)
            );
        }).then(function (buffer) {
            return new Uint8Array(buffer);
        }).catch(function () {
            throw new Error("Wrong key, or the file has been modified.");
        });
    }

    /* --------------------------------------------------------------- KDF */

    /* One derivation yields both keys, matching utils/envelope.derive: the
     * first 32 bytes encrypt, the last 32 authenticate. */
    function deriveKeys(passphrase, salt, iterations) {
        return subtle.importKey(
            "raw", utf8.encode(passphrase), "PBKDF2", false, ["deriveBits"]
        ).then(function (base) {
            return subtle.deriveBits(
                { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" },
                base,
                KEY_BITS
            );
        }).then(function (bits) {
            var material = new Uint8Array(bits);
            return { cipher: material.subarray(0, 32), mac: material.subarray(32, 64) };
        });
    }

    function hmac(rawKey, message) {
        return subtle.importKey(
            "raw", rawKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        ).then(function (key) {
            return subtle.sign("HMAC", key, message);
        }).then(function (buffer) {
            return new Uint8Array(buffer);
        });
    }

    function equal(a, b) {
        if (a.length !== b.length) return false;
        /* Constant time in the length-equal case. The MAC is not a secret the
         * page holds, but there is no reason to leak comparison timing. */
        var diff = 0;
        for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    /* ---------------------------------------------------------- key files */

    function buildKeyFile(rawKey, filename, plaintext) {
        return sha256Hex(plaintext).then(function (digest) {
            return JSON.stringify({
                format: KEY_FORMAT,
                version: VERSION,
                algorithm: "aes",
                original_filename: filename,
                created_at: new Date().toISOString().replace(/\.\d+Z$/, "+00:00"),
                material: { key: toBase64(rawKey) },
                plaintext_sha256: digest
            }, null, 2);
        });
    }

    function parseKeyFile(text) {
        var doc;
        try {
            doc = JSON.parse(text);
        } catch (e) {
            throw new Error(
                "That does not look like a key file. Upload the .key.json file " +
                "you downloaded alongside the encrypted file."
            );
        }
        if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
            throw new Error("That JSON file is not a FileCrypt key file.");
        }
        return doc;
    }

    /* Only AES key files can be handled here; the rest go to the server. */
    function canOpenKeyFile(doc) {
        return Boolean(
            doc && doc.algorithm === "aes" &&
            doc.material && typeof doc.material.key === "string"
        );
    }

    /* ---------------------------------------------------------- envelopes */

    function isEnvelope(bytes) {
        if (bytes.length < MAGIC.length) return false;
        for (var i = 0; i < MAGIC.length; i++) {
            if (bytes[i] !== MAGIC.charCodeAt(i)) return false;
        }
        return true;
    }

    function envelopeHeader(bytes) {
        var prefix = MAGIC.length + 4;
        if (!isEnvelope(bytes) || bytes.length < prefix + MAC_BYTES) return null;
        var headerLen = readUint32(bytes, MAGIC.length);
        if (headerLen <= 0 || bytes.length < prefix + headerLen + MAC_BYTES) return null;
        try {
            return JSON.parse(utf8Decode.decode(bytes.subarray(prefix, prefix + headerLen)));
        } catch (e) {
            return null;
        }
    }

    /* True only for envelopes this page can actually open: AES, and a KDF
     * WebCrypto has. A scrypt or Argon2id file is the server's job. */
    function canOpenEnvelope(bytes) {
        var doc = envelopeHeader(bytes);
        return Boolean(
            doc && doc.format === ENVELOPE_FORMAT && doc.version === VERSION &&
            doc.algorithm === "aes" && doc.kdf && doc.kdf.name === "pbkdf2"
        );
    }

    function wrap(filename, ciphertext, params, macKey) {
        var header = utf8.encode(JSON.stringify({
            format: ENVELOPE_FORMAT,
            version: VERSION,
            algorithm: "aes",
            original_filename: filename,
            created_at: new Date().toISOString().replace(/\.\d+Z$/, "+00:00"),
            kdf: params,
            material: {}
        }, null, 2));

        var body = concat([utf8.encode(MAGIC), uint32(header.length), header, ciphertext]);
        return hmac(macKey, body).then(function (tag) {
            return concat([body, tag]);
        });
    }

    /* ------------------------------------------------------------- public */

    function encryptWithKeyFile(plaintext, filename) {
        var rawKey = randomBytes(32);
        return aesEncrypt(rawKey, plaintext).then(function (ciphertext) {
            return buildKeyFile(rawKey, filename, plaintext).then(function (keyJson) {
                return { payload: ciphertext, keyJson: keyJson };
            });
        });
    }

    function encryptWithPassphrase(plaintext, filename, passphrase) {
        var salt = randomBytes(SALT_BYTES);
        var params = {
            name: "pbkdf2",
            salt: toBase64(salt),
            iterations: PBKDF2_ITERATIONS
        };
        return deriveKeys(passphrase, salt, PBKDF2_ITERATIONS).then(function (keys) {
            return aesEncrypt(keys.cipher, plaintext).then(function (ciphertext) {
                return wrap(filename, ciphertext, params, keys.mac);
            });
        });
    }

    function decryptWithKeyFile(payload, doc) {
        var rawKey;
        try {
            rawKey = fromBase64(doc.material.key);
        } catch (e) {
            throw new Error("The key entry in the key file is malformed.");
        }
        return aesDecrypt(rawKey, payload).then(function (plaintext) {
            if (!doc.plaintext_sha256) {
                return { plaintext: plaintext, verified: "none" };
            }
            return sha256Hex(plaintext).then(function (digest) {
                if (digest !== doc.plaintext_sha256) {
                    throw new Error(
                        "Wrong key: the recovered data does not match the checksum " +
                        "in the key file."
                    );
                }
                return { plaintext: plaintext, verified: "checksum" };
            });
        });
    }

    function decryptWithPassphrase(bytes, passphrase) {
        var doc = envelopeHeader(bytes);
        if (!doc) throw new Error("This file's header is damaged.");

        var prefix = MAGIC.length + 4;
        var headerLen = readUint32(bytes, MAGIC.length);
        var body = bytes.subarray(0, bytes.length - MAC_BYTES);
        var tag = bytes.subarray(bytes.length - MAC_BYTES);
        var salt = fromBase64(doc.kdf.salt);

        return deriveKeys(passphrase, salt, doc.kdf.iterations).then(function (keys) {
            return hmac(keys.mac, body).then(function (expected) {
                /* Checked before any decryption, exactly as the Python does:
                 * a wrong passphrase costs nothing but the derivation. */
                if (!equal(expected, tag)) {
                    throw new Error("Wrong passphrase, or the file has been modified.");
                }
                return aesDecrypt(keys.cipher, body.subarray(prefix + headerLen));
            });
        }).then(function (plaintext) {
            return {
                plaintext: plaintext,
                filename: doc.original_filename || "recovered",
                verified: "mac"
            };
        });
    }

    return {
        available: available,
        isEnvelope: isEnvelope,
        canOpenEnvelope: canOpenEnvelope,
        canOpenKeyFile: canOpenKeyFile,
        parseKeyFile: parseKeyFile,
        encryptWithKeyFile: encryptWithKeyFile,
        encryptWithPassphrase: encryptWithPassphrase,
        decryptWithKeyFile: decryptWithKeyFile,
        decryptWithPassphrase: decryptWithPassphrase
    };
})();
