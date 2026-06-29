from __future__ import annotations

import hashlib
import os
from pathlib import Path

from enroll.fsutil import file_md5, stat_dir_triplet, stat_triplet


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


def test_open_no_follow_path_reads_regular_file(tmp_path: Path):
    from enroll.fsutil import open_no_follow_path

    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    f = nested / "file.txt"
    f.write_text("hello\n", encoding="utf-8")

    fd = open_no_follow_path(str(f))
    try:
        assert os.read(fd, 100) == b"hello\n"
    finally:
        os.close(fd)


def test_open_no_follow_path_refuses_symlinked_parent(tmp_path: Path):
    import errno

    from enroll.fsutil import open_no_follow_path

    real = tmp_path / "real"
    real.mkdir()
    (real / "file.txt").write_text("x\n", encoding="utf-8")
    (tmp_path / "link").symlink_to(real)

    try:
        fd = open_no_follow_path(str(tmp_path / "link" / "file.txt"))
        os.close(fd)
        raise AssertionError("expected OSError for symlinked parent")
    except OSError as e:
        assert e.errno == errno.ELOOP


def test_open_no_follow_path_refuses_symlinked_leaf(tmp_path: Path):
    import errno

    from enroll.fsutil import open_no_follow_path

    target = tmp_path / "target.txt"
    target.write_text("x\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    try:
        fd = open_no_follow_path(str(link))
        os.close(fd)
        raise AssertionError("expected OSError for symlinked leaf")
    except OSError as e:
        assert e.errno == errno.ELOOP


def test_stat_dir_triplet_reports_directory_mode_without_following(tmp_path: Path):
    d = tmp_path / "dir"
    d.mkdir()
    os.chmod(d, 0o750)

    owner, group, mode = stat_dir_triplet(str(d))
    assert mode == "0750"
    assert owner
    assert group


def test_stat_dir_triplet_refuses_symlinked_parent(tmp_path: Path):
    import errno

    real = tmp_path / "real"
    real.mkdir()
    child = real / "child"
    child.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    try:
        stat_dir_triplet(str(link / "child"))
        raise AssertionError("expected OSError for symlinked parent")
    except OSError as e:
        assert e.errno == errno.ELOOP


def test_stat_dir_triplet_refuses_final_symlink(tmp_path: Path):
    import errno

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    try:
        stat_dir_triplet(str(link))
        raise AssertionError("expected OSError for symlinked leaf")
    except OSError as e:
        assert e.errno == errno.ELOOP
