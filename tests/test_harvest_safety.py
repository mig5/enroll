from __future__ import annotations

import os
from pathlib import Path

import pytest

from enroll.capture import capture_file
from enroll.harvest import harvest
from enroll.harvest_types import ExcludedFile, ManagedFile
from enroll.ignore import FileInspection, IgnorePolicy
from enroll.manifest_safety import prepare_manifest_output_dir
from enroll.harvest_safety import OutputSafetyError, prepare_new_private_dir
from enroll.pathfilter import PathFilter


class _RacePolicy(IgnorePolicy):
    def inspect_file(self, path: str):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            st = os.fstat(fd)
            data = os.read(fd, st.st_size)
        finally:
            os.close(fd)
        Path(path).write_bytes(b"changed-after-inspection")
        return None, FileInspection(data=data, stat_result=st)


def test_prepare_new_private_dir_refuses_existing_path(tmp_path: Path):
    out = tmp_path / "bundle"
    out.mkdir()
    with pytest.raises(OutputSafetyError, match="already exists"):
        prepare_new_private_dir(out, label="harvest output")


def test_prepare_new_private_dir_creates_0700(tmp_path: Path):
    out = prepare_new_private_dir(tmp_path / "bundle", label="harvest output")
    assert out.exists()
    assert (out.stat().st_mode & 0o777) == 0o700


def test_harvest_refuses_existing_plaintext_output_dir(tmp_path: Path):
    out = tmp_path / "bundle"
    out.mkdir()
    with pytest.raises(OutputSafetyError, match="already exists"):
        harvest(str(out))


def test_manifest_output_dir_is_private_by_default(tmp_path: Path):
    out = prepare_manifest_output_dir(tmp_path / "manifest")
    assert (out.stat().st_mode & 0o777) == 0o700


def test_capture_file_writes_inspected_bytes_not_later_source(tmp_path: Path):
    source = tmp_path / "source.conf"
    source.write_bytes(b"safe-original")
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    managed: list[ManagedFile] = []
    excluded: list[ExcludedFile] = []
    ok = capture_file(
        bundle_dir=str(bundle),
        role_name="role",
        abs_path=str(source),
        reason="test",
        policy=_RacePolicy(),
        path_filter=PathFilter(),
        managed_out=managed,
        excluded_out=excluded,
    )

    assert ok is True
    artifact = bundle / "artifacts" / "role" / str(source).lstrip("/")
    assert artifact.read_bytes() == b"safe-original"
    assert source.read_bytes() == b"changed-after-inspection"


def test_capture_file_rejects_symlink_source_with_ignore_policy(tmp_path: Path):
    target = tmp_path / "target.conf"
    target.write_text("safe=true\n", encoding="utf-8")
    link = tmp_path / "link.conf"
    link.symlink_to(target)
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    managed: list[ManagedFile] = []
    excluded: list[ExcludedFile] = []
    ok = capture_file(
        bundle_dir=str(bundle),
        role_name="role",
        abs_path=str(link),
        reason="test",
        policy=IgnorePolicy(),
        path_filter=PathFilter(),
        managed_out=managed,
        excluded_out=excluded,
    )

    assert ok is False
    assert managed == []
    assert excluded and excluded[0].reason == "not_regular_file"


def test_prepare_new_private_dir_rejects_symlink_parent(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(OutputSafetyError, match="parent path contains a symlink"):
        prepare_new_private_dir(link / "bundle", label="harvest output")
