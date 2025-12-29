from __future__ import annotations

import hashlib
import os
from pathlib import Path

from enroll.fsutil import file_md5, stat_triplet


def test_file_md5_matches_hashlib(tmp_path: Path):
    p = tmp_path / "x"
    p.write_bytes(b"hello world")
    expected = hashlib.md5(b"hello world").hexdigest()  # nosec
    assert file_md5(str(p)) == expected


def test_stat_triplet_reports_mode(tmp_path: Path):
    p = tmp_path / "x"
    p.write_text("x", encoding="utf-8")
    os.chmod(p, 0o600)

    owner, group, mode = stat_triplet(str(p))
    assert mode == "0600"
    assert owner  # non-empty string
    assert group  # non-empty string
