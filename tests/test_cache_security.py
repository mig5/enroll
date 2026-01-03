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
