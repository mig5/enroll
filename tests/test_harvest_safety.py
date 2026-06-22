from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from enroll.capture import capture_file
from enroll.harvest import harvest
from enroll.harvest_types import ExcludedFile, ManagedFile
from enroll.ignore import FileInspection, IgnorePolicy
from enroll.manifest_safety import prepare_manifest_output_dir
from enroll.harvest_safety import OutputSafetyError, prepare_new_private_dir
from enroll.pathfilter import PathFilter

import enroll.harvest_safety as hs


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


def test_manifest_output_dir_rejects_symlink_parent(tmp_path: Path):
    from enroll.manifest_safety import ManifestOutputError

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(ManifestOutputError, match="parent path contains a symlink"):
        prepare_manifest_output_dir(link / "manifest")


def test_prepare_new_private_dir_rejects_untrusted_root_parent(
    tmp_path: Path, monkeypatch
):
    import enroll.harvest_safety as hs

    untrusted = tmp_path / "untrusted"
    untrusted.mkdir()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            os.chown(untrusted, 65534, -1)
        except OSError:
            pass

    monkeypatch.setattr(hs, "_effective_uid", lambda: 0)
    with pytest.raises(OutputSafetyError, match="not owned by root"):
        prepare_new_private_dir(untrusted / "bundle", label="harvest output")


def test_prepare_new_private_dir_uses_real_euid_despite_os_geteuid_monkeypatch(
    tmp_path: Path, monkeypatch
):
    import enroll.harvest_safety as hs

    monkeypatch.setattr(hs.os, "geteuid", lambda: 0)
    out = prepare_new_private_dir(tmp_path / "bundle", label="harvest output")

    assert out.is_dir()
    assert (out.stat().st_mode & 0o777) == 0o700


def test_write_text_output_file_replaces_final_symlink_not_target(tmp_path: Path):
    from enroll.harvest_safety import write_text_output_file

    target = tmp_path / "target.txt"
    target.write_text("old\n", encoding="utf-8")
    link = tmp_path / "report.txt"
    link.symlink_to(target)

    write_text_output_file(link, "new\n", label="test report")

    assert not link.is_symlink()
    assert link.read_text(encoding="utf-8") == "new\n"
    assert target.read_text(encoding="utf-8") == "old\n"


def test_safe_output_parent_does_not_descend_into_raced_symlink(
    tmp_path: Path, monkeypatch
):
    import enroll.harvest_safety as hs

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    real_mkdir = os.mkdir

    def racing_mkdir(path, mode=0o777, *, dir_fd=None):
        if Path(path) == link and not link.exists():
            link.symlink_to(target, target_is_directory=True)
        if dir_fd is not None:
            return real_mkdir(path, mode, dir_fd=dir_fd)
        return real_mkdir(path, mode)

    monkeypatch.setattr(hs.os, "mkdir", racing_mkdir)

    with pytest.raises(OutputSafetyError, match="parent path contains a symlink"):
        hs.ensure_safe_output_parent(link / "subdir" / "report.txt", label="report")

    assert not (target / "subdir").exists()


def _stat_result(mode: int, *, uid: int = 0) -> os.stat_result:
    return os.stat_result((mode, 1, 1, 1, uid, 0, 0, 0, 0, 0))


def test_effective_uid_handles_missing_geteuid(monkeypatch):
    monkeypatch.setattr(hs, "_OS_GETEUID", None)
    assert hs._effective_uid() is None


def test_effective_uid_handles_geteuid_error(monkeypatch):
    def boom():
        raise OSError("no euid")

    monkeypatch.setattr(hs, "_OS_GETEUID", boom)
    assert hs._effective_uid() is None


def test_trusted_root_parent_skips_checks_when_not_root(monkeypatch):
    monkeypatch.setattr(hs, "_effective_uid", lambda: 1000)
    hs._assert_trusted_root_parent(
        Path("not-a-dir"), _stat_result(stat.S_IFREG | 0o644, uid=1234), label="x"
    )


def test_trusted_root_parent_rejects_non_directory(monkeypatch):
    monkeypatch.setattr(hs, "_effective_uid", lambda: 0)
    with pytest.raises(OutputSafetyError, match="parent is not a directory"):
        hs._assert_trusted_root_parent(
            Path("file"), _stat_result(stat.S_IFREG | 0o644), label="x"
        )


def test_trusted_root_parent_rejects_group_or_world_writable(monkeypatch):
    monkeypatch.setattr(hs, "_effective_uid", lambda: 0)
    with pytest.raises(OutputSafetyError, match="writable by group/other"):
        hs._assert_trusted_root_parent(
            Path("open-dir"), _stat_result(stat.S_IFDIR | 0o777), label="x"
        )


def test_trusted_root_parent_allows_root_owned_sticky_shared_dir(monkeypatch):
    monkeypatch.setattr(hs, "_effective_uid", lambda: 0)
    hs._assert_trusted_root_parent(
        Path("tmp"), _stat_result(stat.S_IFDIR | stat.S_ISVTX | 0o777), label="x"
    )


def test_assert_no_existing_symlink_components_without_root_trust_still_rejects_symlink(
    tmp_path: Path,
):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(OutputSafetyError, match="parent path contains a symlink"):
        hs._assert_no_existing_symlink_components(
            link / "leaf", label="x", require_trusted_root_parents=False
        )


def test_ensure_private_empty_dir_rejects_bad_existing_paths(tmp_path: Path):
    file_path = tmp_path / "file"
    file_path.write_text("x", encoding="utf-8")
    with pytest.raises(OutputSafetyError, match="not a directory"):
        hs.ensure_private_empty_dir(file_path, label="cache")

    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "child").write_text("x", encoding="utf-8")
    with pytest.raises(OutputSafetyError, match="not empty"):
        hs.ensure_private_empty_dir(nonempty, label="cache")

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(OutputSafetyError, match="symlink"):
        hs.ensure_private_empty_dir(link, label="cache")


def test_ensure_private_empty_dir_creates_private_dir(tmp_path: Path):
    out = hs.ensure_private_empty_dir(tmp_path / "new-cache", label="cache")
    assert out.is_dir()
    assert (out.stat().st_mode & 0o777) == 0o700
