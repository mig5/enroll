from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_ensure_dir_secure_refuses_symlink(tmp_path: Path):
    from enroll.cache import _ensure_dir_secure

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(RuntimeError):
        _ensure_dir_secure(link)


def test_ensure_dir_secure_ignores_chmod_failures(tmp_path: Path, monkeypatch):
    from enroll.cache import _ensure_dir_secure

    d = tmp_path / "d"

    def boom(_path: str, _mode: int):
        raise OSError("no")

    monkeypatch.setattr(os, "chmod", boom)

    # Should not raise.
    _ensure_dir_secure(d)
    assert d.exists() and d.is_dir()


def test_safe_component_returns_unknown_for_empty_string():
    from enroll.cache import _safe_component

    assert _safe_component("") == "unknown"
    assert _safe_component("   ") == "unknown"


def test_safe_component_truncates_long_strings():
    from enroll.cache import _safe_component

    long_str = "a" * 100
    result = _safe_component(long_str)
    assert len(result) <= 64


def test_safe_component_replaces_special_chars():
    from enroll.cache import _safe_component

    result = _safe_component("hello world!")
    assert result == "hello_world_"


def test_enroll_cache_dir_uses_xdg_cache_home(monkeypatch):
    from enroll.cache import enroll_cache_dir

    monkeypatch.setenv("XDG_CACHE_HOME", "/custom/cache")
    result = enroll_cache_dir()
    assert str(result) == "/custom/cache/enroll"


def test_harvest_cache_state_json_property():
    from enroll.cache import HarvestCache

    cache_dir = HarvestCache(dir=Path("/tmp/test"))
    assert cache_dir.state_json == Path("/tmp/test/state.json")


def test_new_harvest_cache_dir_chmod_fails(tmp_path: Path, monkeypatch):
    from enroll.cache import new_harvest_cache_dir

    def fake_enroll_cache_dir():
        return tmp_path / "enroll"

    def fake_chmod(path, mode):
        raise OSError("no")

    monkeypatch.setattr("enroll.cache.enroll_cache_dir", fake_enroll_cache_dir)
    monkeypatch.setattr(os, "chmod", fake_chmod)

    # Should not raise even though chmod fails
    cache = new_harvest_cache_dir(hint="test")
    assert cache.dir.exists()
    assert isinstance(cache.dir, Path)


def test_enroll_cache_dir_uses_default_when_xdg_not_set(monkeypatch):
    from enroll.cache import enroll_cache_dir

    # Remove XDG_CACHE_HOME if it exists
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    result = enroll_cache_dir()
    assert str(result).endswith("/.local/cache/enroll")
