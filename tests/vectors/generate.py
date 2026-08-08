"""Regenerate the golden vectors in this directory.

    python tests/vectors/generate.py

STOP AND THINK BEFORE RUNNING THIS. These files exist to prove that today's
code can still read files produced by yesterday's code. Regenerating them
rewrites the past: whatever compatibility break they would have caught simply
disappears, and the test goes green for the wrong reason.

There is exactly one good reason to run it -- adding a new algorithm or a new
container that has no vector yet. If a vector for an *existing* format has
started failing, that is the tool telling you a real break happened. Fix the
break.

`legacy.key.json` is not generated. It was written by hand to match the older
`cryptoimage-key` format the app still accepts, and no current code path can
produce one.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from utils import envelope, keyfile  # noqa: E402
from utils.encryption_utils import ALGORITHMS  # noqa: E402

# Deliberately awkward: a null byte, a high byte, multi-byte UTF-8, and a
# trailing newline. Anything that mangles bytes in transit shows up here.
PLAINTEXT = "FileCrypt golden vector\n\x00ÿ binary ✓ unicode\n".encode() * 8
PASSPHRASE = "correct horse battery staple"


def write(path, produce) -> None:
    """Write a vector only if it is missing.

    Skipping existing files is the safety catch: a vector that already exists is
    a record of what an older build produced, and quietly overwriting it is how
    a compatibility break gets erased instead of caught. Delete a file by hand
    if you genuinely mean to replace it.
    """
    if path.exists():
        return
    path.write_bytes(produce())
    print(f"  + {path.name}")


def main() -> None:
    for name, spec in ALGORITHMS.items():
        payload = SAMPLE_PNG if spec.images_only else PLAINTEXT
        print(name)

        def key_file_pair(name=name, spec=spec, payload=payload):
            ciphertext, material = spec.encrypt(payload)
            (HERE / f"{name}.key.json").write_bytes(
                keyfile.dumps(keyfile.build(name, "vector.txt", material, payload))
            )
            return ciphertext

        # The ciphertext and its key file have to be produced together, so the
        # pair is written as a unit keyed on the ciphertext's existence.
        write(HERE / f"{name}.bin", key_file_pair)

        if not spec.supports_passphrase:
            continue

        # One envelope per KDF. scrypt keeps the unsuffixed name it has always
        # had; the others were added later and say so.
        for kdf in envelope.KDF_NAMES:
            suffix = "" if kdf == envelope.DEFAULT_KDF else f".{kdf}"

            def sealed(name=name, spec=spec, payload=payload, kdf=kdf):
                cipher_key, mac_key, params = envelope.derive(PASSPHRASE, name=kdf)
                ciphertext, material = spec.encrypt(payload, key=cipher_key)
                return envelope.wrap(
                    name, "vector.txt", material, ciphertext, params, mac_key
                )

            write(HERE / f"{name}{suffix}.fcx", sealed)


def _sample_png() -> bytes:
    import io

    import numpy as np
    from PIL import Image

    arr = np.zeros((32, 48), dtype=np.uint8)
    arr[6:26, 6:42] = 255
    buf = io.BytesIO()
    Image.fromarray(arr, mode="L").save(buf, format="PNG")
    return buf.getvalue()


SAMPLE_PNG = _sample_png()

if __name__ == "__main__":
    main()
