"""Property tests for the parts that read untrusted input.

`keyfile.parse`, `envelope.unwrap` and `visual_decrypt` are the whole attack
surface: everything else in the app only ever sees bytes those three have
already vetted. Two of them are hand-rolled binary parsing, which is exactly
where off-by-one bounds hide.

The property throughout is the same and it is deliberately narrow: whatever you
feed these, the only exception that may come out is DecryptionError. An
IndexError or a struct.error escaping means a malformed upload reaches the
route's generic handler and becomes a 500 instead of a clear message -- and it
means the bounds check that should have caught it is missing.
"""

import contextlib
import io
import sys
import zipfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from routes.crypto import safe_name
from utils import envelope, keyfile
from utils.encryption_utils import (
    DecryptionError,
    VisualCryptoError,
    looks_like_shares,
    visual_decrypt,
)

PASSPHRASE = "correct horse battery staple"
VECTORS = Path(__file__).resolve().parent / "vectors"

# scrypt is deliberately slow, so anything reaching key derivation blows
# Hypothesis's default per-example deadline. That is the KDF working, not a bug.
slow = settings(
    deadline=None,
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow],
)


# --------------------------------------------------------------- key files

@slow
@given(st.binary(max_size=4096))
def test_key_file_parsing_only_ever_raises_decryption_error(raw):
    try:
        doc = keyfile.parse(raw)
    except DecryptionError:
        return
    # Anything it accepts must be usable without further guarding.
    assert isinstance(doc, dict)
    assert isinstance(doc["material"], dict)
    assert doc["algorithm"]


@slow
@given(st.text(max_size=2048))
def test_key_file_parsing_survives_arbitrary_text(raw):
    with contextlib.suppress(DecryptionError):
        keyfile.parse(raw.encode("utf-8", "surrogatepass"))


@slow
@given(
    st.integers(min_value=0, max_value=400),
    st.integers(min_value=0, max_value=255),
)
def test_mutated_key_files_never_crash(offset, value):
    original = bytearray((VECTORS / "aes.key.json").read_bytes())
    if offset >= len(original):
        return
    original[offset] = value
    with contextlib.suppress(DecryptionError):
        keyfile.parse(bytes(original))


# ---------------------------------------------------------------- envelopes

@slow
@given(st.binary(max_size=2048))
def test_envelope_parsing_only_ever_raises_decryption_error(raw):
    with pytest.raises(DecryptionError):
        envelope.unwrap(raw, PASSPHRASE)


@slow
@given(st.binary(min_size=0, max_size=64))
def test_envelope_with_valid_magic_but_junk_after(tail):
    """Past the magic check is where the hand-rolled length parsing starts."""
    with pytest.raises(DecryptionError):
        envelope.unwrap(b"FCP1" + tail, PASSPHRASE)


@slow
@given(
    st.integers(min_value=0, max_value=2 ** 32 - 1),
    st.binary(max_size=128),
)
def test_declared_header_length_is_not_trusted(declared, body):
    """The length field is attacker-controlled and indexes into the buffer."""
    blob = b"FCP1" + declared.to_bytes(4, "big") + body
    with pytest.raises(DecryptionError):
        envelope.unwrap(blob, PASSPHRASE)


@settings(deadline=None, max_examples=40, suppress_health_check=[HealthCheck.too_slow])
@given(st.integers(min_value=0, max_value=600), st.integers(min_value=1, max_value=255))
def test_mutating_a_real_envelope_is_always_caught_or_correct(offset, delta):
    """Flip a byte anywhere: it must either be detected or change nothing.

    Silently returning different plaintext is the one outcome that must not
    happen, and it is what the MAC exists to prevent.
    """
    from utils.encryption_utils import ALGORITHMS

    original = bytearray((VECTORS / "aes.fcx").read_bytes())
    if offset >= len(original):
        return
    original[offset] ^= delta

    try:
        doc, ciphertext, cipher_key = envelope.unwrap(bytes(original), PASSPHRASE)
    except DecryptionError:
        return  # caught, which is the expected outcome
    # If the MAC somehow passed, the file was not meaningfully altered.
    recovered = ALGORITHMS[doc["algorithm"]].decrypt(
        ciphertext, doc["material"], key=cipher_key
    )
    expected = "FileCrypt golden vector\n\x00ÿ binary ✓ unicode\n".encode() * 8
    assert recovered == expected


# ------------------------------------------------------------ share archives

@slow
@given(st.binary(max_size=2048))
def test_share_detection_never_raises(raw):
    assert isinstance(looks_like_shares(raw), bool)


@slow
@given(st.lists(st.binary(max_size=256), max_size=4))
def test_visual_decrypt_survives_arbitrary_archives(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for i, member in enumerate(members):
            archive.writestr(f"share{i}.png", member)
    try:
        visual_decrypt(buffer.getvalue(), {})
    except (DecryptionError, VisualCryptoError):
        pass
    except Exception as exc:  # the whole point of the test
        pytest.fail(f"unexpected {type(exc).__name__}: {exc}")


# ----------------------------------------------------------------- filenames

@slow
@given(st.text(max_size=400))
def test_safe_name_always_produces_a_usable_filename(supplied):
    result = safe_name(supplied)
    assert result, "must never be empty"
    assert len(result) <= 120
    assert not any(ch in result for ch in '<>:"/\\|?*')
    assert not any(ord(ch) < 32 for ch in result)
    assert result not in (".", "..")
