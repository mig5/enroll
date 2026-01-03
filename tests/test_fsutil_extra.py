from __future__ import annotations

import os
from pathlib import Path


def test_stat_triplet_falls_back_to_numeric_ids(tmp_path: Path, monkeypatch):
    """If uid/gid cannot be resolved, stat_triplet should return numeric strings."""
    from enroll.fsutil import stat_triplet

    p = tmp_path / "f"
    p.write_text("x", encoding="utf-8")
    os.chmod(p, 0o644)

    import grp
    import pwd

    def _no_user(_uid):  # pragma: no cover - executed via monkeypatch
        raise KeyError

    def _no_group(_gid):  # pragma: no cover - executed via monkeypatch
        raise KeyError

    monkeypatch.setattr(pwd, "getpwuid", _no_user)
    monkeypatch.setattr(grp, "getgrgid", _no_group)

    owner, group, mode = stat_triplet(str(p))

    assert owner.isdigit()
    assert group.isdigit()
    assert mode == "0644"
