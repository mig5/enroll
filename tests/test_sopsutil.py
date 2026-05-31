from __future__ import annotations

import pytest

from pathlib import Path
from enroll.sopsutil import SopsError, _pgp_arg, find_sops_cmd, require_sops_cmd


def test_find_sops_cmd():
    result = find_sops_cmd()
    if result is None:
        pytest.skip("sops not installed")
    assert result.endswith("sops")


def test_require_sops_cmd():
    exe = require_sops_cmd()
    assert exe is not None
    assert "sops" in exe


def test_require_sops_cmd_raises_when_not_found(monkeypatch):
    import enroll.sopsutil as s

    def fake_find():
        return None

    monkeypatch.setattr(s, "find_sops_cmd", fake_find)

    with pytest.raises(SopsError) as exc_info:
        require_sops_cmd()

    assert "sops" in str(exc_info.value).lower()
    assert "not found" in str(exc_info.value).lower()


def test_pgp_arg_with_empty_fingerprints():
    with pytest.raises(SopsError) as exc_info:
        _pgp_arg([])
    assert "No GPG fingerprints" in str(exc_info.value)


def test_pgp_arg_with_whitespace_fingerprints():
    result = _pgp_arg(["  ", "ABC123", "  DEF456  "])
    assert result == "ABC123,DEF456"


def test_pgp_arg_with_single_fingerprint():
    result = _pgp_arg(["ABC123DEF456"])
    assert result == "ABC123DEF456"


def test_pgp_arg_with_multiple_fingerprints():
    result = _pgp_arg(["ABC123", "DEF456", "GHI789"])
    assert result == "ABC123,DEF456,GHI789"


def test_encrypt_file_binary_success(monkeypatch, tmp_path: Path):
    """Test successful encryption path."""
    # Create source file
    src = tmp_path / "secret.txt"
    src.write_text("secret data", encoding="utf-8")
    dst = tmp_path / "encrypted.sops"

    # Mock subprocess.run to succeed
    class Result:
        returncode = 0
        stdout = b"encrypted data"
        stderr = b""

    def fake_run(cmd, capture_output, check):
        return Result()

    # Mock require_sops_cmd to return a fake path
    def fake_require():
        return "/fake/sops"

    monkeypatch.setattr("enroll.sopsutil.subprocess.run", fake_run)
    monkeypatch.setattr("enroll.sopsutil.require_sops_cmd", fake_require)

    from enroll.sopsutil import encrypt_file_binary

    encrypt_file_binary(src, dst, pgp_fingerprints=["ABC123"])

    assert dst.exists()
    assert dst.read_bytes() == b"encrypted data"


def test_encrypt_file_binary_fails(monkeypatch, tmp_path: Path):
    """Test encryption failure path."""
    src = tmp_path / "secret.txt"
    src.write_text("secret data", encoding="utf-8")
    dst = tmp_path / "encrypted.sops"

    class Result:
        returncode = 1
        stdout = b""
        stderr = b"sops: gpg error"

    def fake_run(cmd, capture_output, check):
        return Result()

    def fake_require():
        return "/fake/sops"

    monkeypatch.setattr("enroll.sopsutil.subprocess.run", fake_run)
    monkeypatch.setattr("enroll.sopsutil.require_sops_cmd", fake_require)

    from enroll.sopsutil import encrypt_file_binary, SopsError

    with pytest.raises(SopsError) as exc_info:
        encrypt_file_binary(src, dst, pgp_fingerprints=["ABC123"])

    assert "encryption failed" in str(exc_info.value).lower()


def test_encrypt_file_binary_chmod_fails(monkeypatch, tmp_path: Path):
    """Test when chmod fails but file is still written."""
    src = tmp_path / "secret.txt"
    src.write_text("secret data", encoding="utf-8")
    dst = tmp_path / "encrypted.sops"

    class Result:
        returncode = 0
        stdout = b"encrypted data"
        stderr = b""

    def fake_run(cmd, capture_output, check):
        return Result()

    def fake_require():
        return "/fake/sops"

    def fake_chmod(path, mode):
        raise OSError("Permission denied")

    monkeypatch.setattr("enroll.sopsutil.subprocess.run", fake_run)
    monkeypatch.setattr("enroll.sopsutil.require_sops_cmd", fake_require)
    monkeypatch.setattr("enroll.sopsutil.os.chmod", fake_chmod)

    from enroll.sopsutil import encrypt_file_binary

    # Should not raise even though chmod fails
    encrypt_file_binary(src, dst, pgp_fingerprints=["ABC123"])

    assert dst.exists()


def test_decrypt_file_binary_to_success(monkeypatch, tmp_path: Path):
    """Test successful decryption path."""
    src = tmp_path / "encrypted.sops"
    src.write_bytes(b"encrypted data")
    dst = tmp_path / "decrypted.txt"

    class Result:
        returncode = 0
        stdout = b"decrypted data"
        stderr = b""

    def fake_run(cmd, capture_output, check):
        return Result()

    def fake_require():
        return "/fake/sops"

    monkeypatch.setattr("enroll.sopsutil.subprocess.run", fake_run)
    monkeypatch.setattr("enroll.sopsutil.require_sops_cmd", fake_require)

    from enroll.sopsutil import decrypt_file_binary_to

    decrypt_file_binary_to(src, dst)

    assert dst.exists()
    assert dst.read_bytes() == b"decrypted data"


def test_decrypt_file_binary_to_fails(monkeypatch, tmp_path: Path):
    """Test decryption failure path."""
    src = tmp_path / "encrypted.sops"
    src.write_bytes(b"encrypted data")
    dst = tmp_path / "decrypted.txt"

    class Result:
        returncode = 1
        stdout = b""
        stderr = b"sops: decryption failed"

    def fake_run(cmd, capture_output, check):
        return Result()

    def fake_require():
        return "/fake/sops"

    monkeypatch.setattr("enroll.sopsutil.subprocess.run", fake_run)
    monkeypatch.setattr("enroll.sopsutil.require_sops_cmd", fake_require)

    from enroll.sopsutil import decrypt_file_binary_to, SopsError

    with pytest.raises(SopsError) as exc_info:
        decrypt_file_binary_to(src, dst)

    assert "decryption failed" in str(exc_info.value).lower()


def test_decrypt_file_binary_to_chmod_fails(monkeypatch, tmp_path: Path):
    """Test when chmod fails during decryption but file is still written."""
    src = tmp_path / "encrypted.sops"
    src.write_bytes(b"encrypted data")
    dst = tmp_path / "decrypted.txt"

    class Result:
        returncode = 0
        stdout = b"decrypted data"
        stderr = b""

    def fake_run(cmd, capture_output, check):
        return Result()

    def fake_require():
        return "/fake/sops"

    def fake_chmod(path, mode):
        raise OSError("Permission denied")

    monkeypatch.setattr("enroll.sopsutil.subprocess.run", fake_run)
    monkeypatch.setattr("enroll.sopsutil.require_sops_cmd", fake_require)
    monkeypatch.setattr("enroll.sopsutil.os.chmod", fake_chmod)

    from enroll.sopsutil import decrypt_file_binary_to

    # Should not raise even though chmod fails
    decrypt_file_binary_to(src, dst)

    assert dst.exists()
