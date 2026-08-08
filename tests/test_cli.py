"""The command-line front end.

These lean on FILECRYPT_PASSPHRASE rather than driving the prompt, which is the
same path an unattended run would take.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "report.txt"
    path.write_bytes(b"top secret contents\n" * 10)
    return path


@pytest.fixture
def sealed_env(monkeypatch):
    monkeypatch.setenv(cli.PASSPHRASE_ENV, PASSPHRASE)


def test_algorithms_lists_every_one(capsys):
    assert cli.main(["algorithms"]) == 0
    printed = capsys.readouterr().out
    from utils.encryption_utils import ALGORITHMS
    for name in ALGORITHMS:
        assert name in printed


def test_key_file_round_trip(source, tmp_path):
    assert cli.main(["encrypt", str(source), "-a", "aes"]) == 0

    payload = source.with_suffix(".txt.enc")
    key = source.with_suffix(".txt.key.json")
    assert payload.is_file() and key.is_file()

    out = tmp_path / "recovered.txt"
    assert cli.main(["decrypt", str(payload), "-k", str(key), "-o", str(out)]) == 0
    assert out.read_bytes() == source.read_bytes()


def test_passphrase_round_trip(source, tmp_path, sealed_env):
    assert cli.main(["encrypt", str(source), "-p"]) == 0

    sealed = source.with_suffix(".txt.fcx")
    assert sealed.is_file()
    assert not source.with_suffix(".txt.key.json").exists()  # nothing else to keep

    out = tmp_path / "recovered.txt"
    assert cli.main(["decrypt", str(sealed), "-o", str(out)]) == 0
    assert out.read_bytes() == source.read_bytes()


def test_wrong_passphrase_fails(source, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(cli.PASSPHRASE_ENV, PASSPHRASE)
    cli.main(["encrypt", str(source), "-p"])

    monkeypatch.setenv(cli.PASSPHRASE_ENV, "a different passphrase")
    assert cli.main(["decrypt", str(source.with_suffix(".txt.fcx")),
                     "-o", str(tmp_path / "out.txt")]) == 1
    assert "error" in capsys.readouterr().err


def test_short_passphrase_fails(source, monkeypatch, capsys):
    monkeypatch.setenv(cli.PASSPHRASE_ENV, "abc")
    assert cli.main(["encrypt", str(source), "-p"]) == 1
    assert "8 characters" in capsys.readouterr().err


def test_output_lands_beside_the_source_not_the_cwd(source, tmp_path, monkeypatch):
    """Running from elsewhere should not scatter files into the shell's cwd."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    assert cli.main(["encrypt", str(source), "-a", "aes"]) == 0
    assert source.with_suffix(".txt.enc").is_file()
    assert list(elsewhere.iterdir()) == []


def test_out_accepts_a_directory(source, tmp_path):
    target = tmp_path / "out"
    target.mkdir()
    assert cli.main(["encrypt", str(source), "-a", "aes", "-o", str(target)]) == 0
    assert (target / "report.txt.enc").is_file()
    assert (target / "report.txt.key.json").is_file()


def test_existing_files_are_not_clobbered(source, capsys):
    assert cli.main(["encrypt", str(source), "-a", "aes"]) == 0
    assert cli.main(["encrypt", str(source), "-a", "aes"]) == 1
    assert "--force" in capsys.readouterr().err

    assert cli.main(["encrypt", str(source), "-a", "aes", "--force"]) == 0


def test_decrypt_without_a_key_is_refused(source, capsys):
    cli.main(["encrypt", str(source), "-a", "aes"])
    assert cli.main(["decrypt", str(source.with_suffix(".txt.enc"))]) == 1
    assert "--key" in capsys.readouterr().err


def test_shares_need_no_key(tmp_path):
    import io

    import numpy as np
    from PIL import Image

    arr = np.zeros((40, 60), dtype=np.uint8)
    arr[8:32, 8:52] = 255
    picture = tmp_path / "pic.png"
    buf = io.BytesIO()
    Image.fromarray(arr, mode="L").save(buf, format="PNG")
    picture.write_bytes(buf.getvalue())

    assert cli.main(["encrypt", str(picture), "-a", "visual_crypto"]) == 0
    shares = tmp_path / "pic.png.shares.zip"
    assert shares.is_file()

    out = tmp_path / "stacked.png"
    assert cli.main(["decrypt", str(shares), "-o", str(out)]) == 0
    assert out.is_file()


def test_missing_file_is_reported(tmp_path, capsys):
    assert cli.main(["encrypt", str(tmp_path / "nope.txt")]) == 1
    assert "No such file" in capsys.readouterr().err


def test_unknown_algorithm_is_rejected_by_argparse(source):
    with pytest.raises(SystemExit):
        cli.main(["encrypt", str(source), "-a", "made-up"])
