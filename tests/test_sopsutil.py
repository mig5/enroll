from __future__ import annotations

import pytest

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
