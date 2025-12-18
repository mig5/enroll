import stat
from pathlib import Path

import pytest

from enroll.cache import _safe_component, new_harvest_cache_dir
from enroll.ignore import IgnorePolicy
from enroll.sopsutil import (
    SopsError,
    _pgp_arg,
    decrypt_file_binary_to,
    encrypt_file_binary,
)


def test_safe_component_sanitizes_and_bounds_length():
    assert _safe_component("  ") == "unknown"
    assert _safe_component("a/b c") == "a_b_c"
    assert _safe_component("x" * 200) == "x" * 64


def test_new_harvest_cache_dir_uses_xdg_cache_home(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    hc = new_harvest_cache_dir(hint="my host/01")
    assert hc.dir.exists()
    assert "my_host_01" in hc.dir.name
    assert str(hc.dir).startswith(str(tmp_path / "xdg"))
    # best-effort: ensure directory is not world-readable on typical FS
    try:
        mode = stat.S_IMODE(hc.dir.stat().st_mode)
        assert mode & 0o077 == 0
    except OSError:
        pass


def test_ignore_policy_denies_binary_and_sensitive_content(tmp_path: Path):
    p_bin = tmp_path / "binfile"
    p_bin.write_bytes(b"abc\x00def")
    assert IgnorePolicy().deny_reason(str(p_bin)) == "binary_like"

    p_secret = tmp_path / "secret.conf"
    p_secret.write_text("password=foo\n", encoding="utf-8")
    assert IgnorePolicy().deny_reason(str(p_secret)) == "sensitive_content"

    # dangerous mode disables heuristic scanning (but still checks file-ness/size)
    assert IgnorePolicy(dangerous=True).deny_reason(str(p_secret)) is None


def test_ignore_policy_denies_usr_local_shadow_by_glob():
    # This should short-circuit before stat() (path doesn't need to exist).
    assert IgnorePolicy().deny_reason("/usr/local/etc/shadow") == "denied_path"


def test_sops_pgp_arg_and_encrypt_decrypt_roundtrip(tmp_path: Path, monkeypatch):
    assert _pgp_arg(["  ABC ", "DEF"]) == "ABC,DEF"
    with pytest.raises(SopsError):
        _pgp_arg([])

    # Stub out sops and subprocess.
    import enroll.sopsutil as s

    monkeypatch.setattr(s, "require_sops_cmd", lambda: "sops")

    class R:
        def __init__(self, rc: int, out: bytes, err: bytes = b""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    calls = []

    def fake_run(cmd, capture_output, check):
        calls.append(cmd)
        # Return a deterministic payload so we can assert file writes.
        if "--encrypt" in cmd:
            return R(0, b"ENCRYPTED")
        if "--decrypt" in cmd:
            return R(0, b"PLAINTEXT")
        return R(1, b"", b"bad")

    monkeypatch.setattr(s.subprocess, "run", fake_run)

    src = tmp_path / "src.bin"
    src.write_bytes(b"x")
    enc = tmp_path / "out.sops"
    dec = tmp_path / "out.bin"

    encrypt_file_binary(src, enc, pgp_fingerprints=["ABC"], mode=0o600)
    assert enc.read_bytes() == b"ENCRYPTED"

    decrypt_file_binary_to(enc, dec, mode=0o644)
    assert dec.read_bytes() == b"PLAINTEXT"

    # Sanity: we invoked encrypt and decrypt.
    assert any("--encrypt" in c for c in calls)
    assert any("--decrypt" in c for c in calls)
