from __future__ import annotations

import os
from pathlib import Path

import pytest

from enroll.manifest_safety import (
    ArtifactSafetyError,
    ManifestOutputError,
    copy_safe_artifact_file,
    freeze_directory_bundle,
    iter_safe_artifact_files,
    prepare_manifest_output_dir,
    safe_artifact_file,
)


def test_safe_artifact_file_accepts_regular_file_and_copy(tmp_path: Path):
    bundle = tmp_path / "bundle"
    artifact = bundle / "artifacts" / "role" / "etc" / "app.conf"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("managed=true\n", encoding="utf-8")

    assert safe_artifact_file(bundle, "role", "etc/app.conf") == artifact

    dst = tmp_path / "copy.conf"
    copy_safe_artifact_file(artifact, dst)
    assert dst.read_text(encoding="utf-8") == "managed=true\n"


def test_safe_artifact_file_rejects_unsafe_role_and_src(tmp_path: Path):
    bundle = tmp_path / "bundle"
    with pytest.raises(ArtifactSafetyError, match="must be relative"):
        safe_artifact_file(bundle, "/role", "file")
    with pytest.raises(ArtifactSafetyError, match="unsafe path component"):
        safe_artifact_file(bundle, "role", "../file")
    with pytest.raises(ArtifactSafetyError, match="NUL"):
        safe_artifact_file(bundle, "role", "bad\x00file")


def test_safe_artifact_file_rejects_artifacts_symlink(tmp_path: Path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "artifacts").symlink_to(tmp_path, target_is_directory=True)

    with pytest.raises(ArtifactSafetyError, match="artifacts directory is a symlink"):
        safe_artifact_file(bundle, "role", "file")


def test_safe_artifact_file_rejects_bad_artifact_kinds(tmp_path: Path):
    bundle = tmp_path / "bundle"
    role_dir = bundle / "artifacts" / "role"
    role_dir.mkdir(parents=True)

    target = role_dir / "target"
    target.write_text("x", encoding="utf-8")
    (role_dir / "link").symlink_to(target)
    with pytest.raises(ArtifactSafetyError, match="symlink"):
        safe_artifact_file(bundle, "role", "link")

    (role_dir / "dir-artifact").mkdir()
    with pytest.raises(ArtifactSafetyError, match="not a regular file"):
        safe_artifact_file(bundle, "role", "dir-artifact")

    hardlink = role_dir / "hardlink"
    os.link(target, hardlink)
    with pytest.raises(ArtifactSafetyError, match="hardlinked"):
        safe_artifact_file(bundle, "role", "target")


def test_iter_safe_artifact_files_handles_missing_and_bad_role_dirs(tmp_path: Path):
    bundle = tmp_path / "bundle"
    assert list(iter_safe_artifact_files(bundle, "missing")) == []

    role_file = bundle / "artifacts" / "role"
    role_file.parent.mkdir(parents=True)
    role_file.write_text("not a dir", encoding="utf-8")
    with pytest.raises(ArtifactSafetyError, match="not a directory"):
        list(iter_safe_artifact_files(bundle, "role"))


def test_iter_safe_artifact_files_rejects_symlink_subdir(tmp_path: Path):
    bundle = tmp_path / "bundle"
    role_dir = bundle / "artifacts" / "role"
    role_dir.mkdir(parents=True)
    real = tmp_path / "real"
    real.mkdir()
    (role_dir / "linkdir").symlink_to(real, target_is_directory=True)

    with pytest.raises(ArtifactSafetyError, match="directory is a symlink"):
        list(iter_safe_artifact_files(bundle, "role"))


def _write_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    art = bundle / "artifacts" / "app" / "etc" / "app"
    art.mkdir(parents=True)
    (art / "app.conf").write_text("original-content\n", encoding="utf-8")
    (bundle / "state.json").write_text("{}\n", encoding="utf-8")
    return bundle


def test_freeze_directory_bundle_copies_content(tmp_path: Path):
    bundle = _write_bundle(tmp_path)
    frozen_dir, td = freeze_directory_bundle(bundle)
    try:
        frozen = Path(frozen_dir)
        assert frozen != bundle
        assert (frozen / "state.json").read_text(encoding="utf-8") == "{}\n"
        assert (frozen / "artifacts" / "app" / "etc" / "app" / "app.conf").read_text(
            encoding="utf-8"
        ) == "original-content\n"
        # The frozen copy is a private directory.
        mode = (Path(frozen_dir)).stat().st_mode & 0o777
        assert mode == 0o700
    finally:
        td.cleanup()


def test_freeze_directory_bundle_is_immutable_after_source_swap(tmp_path: Path):
    """The core TOCTOU regression: mutating the source after freezing must not
    change what a consumer reads, and must not let a post-freeze symlink redirect
    reads to a secret."""
    bundle = _write_bundle(tmp_path)
    art_file = bundle / "artifacts" / "app" / "etc" / "app" / "app.conf"

    frozen_dir, td = freeze_directory_bundle(bundle)
    try:
        secret = tmp_path / "secret"
        secret.write_text("TOP-SECRET\n", encoding="utf-8")

        # Attacker swaps the validated regular file for a symlink to a secret and
        # also rewrites another path's content. None of this may affect the frozen
        # copy the consumer actually uses.
        art_file.unlink()
        art_file.symlink_to(secret)

        frozen_file = (
            Path(frozen_dir) / "artifacts" / "app" / "etc" / "app" / "app.conf"
        )
        assert not frozen_file.is_symlink()
        assert frozen_file.read_text(encoding="utf-8") == "original-content\n"
        assert "TOP-SECRET" not in frozen_file.read_text(encoding="utf-8")
    finally:
        td.cleanup()


def test_freeze_directory_bundle_rejects_symlinked_file(tmp_path: Path):
    bundle = _write_bundle(tmp_path)
    secret = tmp_path / "secret"
    secret.write_text("secret\n", encoding="utf-8")
    # A bundle that already contains a symlinked artifact at freeze time is
    # rejected outright rather than silently following it.
    link = bundle / "artifacts" / "app" / "etc" / "app" / "link.conf"
    link.symlink_to(secret)
    with pytest.raises(ArtifactSafetyError, match="symlink"):
        freeze_directory_bundle(bundle)


def test_freeze_directory_bundle_rejects_symlinked_subdir(tmp_path: Path):
    bundle = _write_bundle(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.conf").write_text("x\n", encoding="utf-8")
    (bundle / "artifacts" / "app" / "linkdir").symlink_to(
        outside, target_is_directory=True
    )
    with pytest.raises(ArtifactSafetyError, match="symlink"):
        freeze_directory_bundle(bundle)


def test_freeze_directory_bundle_rejects_symlinked_root(tmp_path: Path):
    bundle = _write_bundle(tmp_path)
    link = tmp_path / "bundle-link"
    link.symlink_to(bundle, target_is_directory=True)

    with pytest.raises(ArtifactSafetyError, match="root is a symlink"):
        freeze_directory_bundle(link)


def test_freeze_directory_bundle_fails_if_discovered_dir_disappears(
    tmp_path: Path, monkeypatch
):
    import enroll.manifest_safety as ms

    bundle = _write_bundle(tmp_path)
    unstable = bundle / "unstable"
    unstable.mkdir()
    real_lstat = ms.Path.lstat

    def fake_lstat(self):
        if self == unstable:
            raise FileNotFoundError(str(self))
        return real_lstat(self)

    monkeypatch.setattr(ms.Path, "lstat", fake_lstat)
    with pytest.raises(ArtifactSafetyError, match="changed while being frozen"):
        freeze_directory_bundle(bundle)


def test_freeze_directory_bundle_fails_if_file_changes_during_read(
    tmp_path: Path, monkeypatch
):
    import enroll.manifest_safety as ms

    bundle = _write_bundle(tmp_path)
    changing = bundle / "state.json"
    real_read = ms.os.read
    changed = False

    def mutating_read(fd: int, size: int) -> bytes:
        nonlocal changed
        data = real_read(fd, size)
        if not changed and data:
            changed = True
            # Same length: size-only checking would miss this in-place rewrite.
            changing.write_bytes(b'{"tampered":1}')
        return data

    monkeypatch.setattr(ms.os, "read", mutating_read)
    with pytest.raises(ArtifactSafetyError, match="changed while being frozen"):
        freeze_directory_bundle(bundle)


def test_freeze_directory_bundle_rejects_hardlinked_file(tmp_path: Path):
    bundle = _write_bundle(tmp_path)
    secret = tmp_path / "secret"
    secret.write_text("secret\n", encoding="utf-8")
    hard = bundle / "artifacts" / "app" / "etc" / "app" / "hard.conf"
    os.link(secret, hard)
    with pytest.raises(ArtifactSafetyError, match="hardlink"):
        freeze_directory_bundle(bundle)


def test_freeze_directory_bundle_rejects_aggregate_size_bomb(
    tmp_path: Path, monkeypatch
):
    import enroll.manifest_safety as ms

    bundle = _write_bundle(tmp_path)
    extra = bundle / "artifacts" / "app" / "etc" / "app" / "extra.conf"
    extra.write_bytes(b"x" * 32)

    # Each file is individually small, but the aggregate must still be bounded.
    monkeypatch.setattr(ms, "_FREEZE_MAX_TOTAL_BYTES", 32)
    with pytest.raises(ArtifactSafetyError, match="total file size exceeds"):
        freeze_directory_bundle(bundle)


def test_freeze_directory_bundle_counts_directories_against_entry_cap(
    tmp_path: Path, monkeypatch
):
    import enroll.manifest_safety as ms

    bundle = _write_bundle(tmp_path)
    (bundle / "empty-a").mkdir()
    (bundle / "empty-b").mkdir()

    # Directory-only trees consume inodes and traversal time too. The old
    # file-only limit allowed an unbounded number of empty directories.
    monkeypatch.setattr(ms, "_FREEZE_MAX_ENTRIES", 2)
    with pytest.raises(ArtifactSafetyError, match="too many filesystem entries"):
        freeze_directory_bundle(bundle)


def test_freeze_directory_bundle_fails_loudly_on_unreadable_subdir(tmp_path: Path):
    """An unreadable subtree must abort the freeze, not silently truncate it.

    Regression test: os.walk() defaults to swallowing directory-listing errors,
    which previously produced a partial frozen bundle with no error. The freeze
    now passes onerror= so a PermissionError aborts with ArtifactSafetyError.
    """
    if os.geteuid() == 0:
        pytest.skip("root can read 0000 directories; cannot simulate the case")

    bundle = _write_bundle(tmp_path)
    locked = bundle / "artifacts" / "app" / "etc" / "app"
    assert locked.is_dir()
    os.chmod(locked, 0o000)
    try:
        with pytest.raises(ArtifactSafetyError, match="could not be fully read"):
            freeze_directory_bundle(bundle)
    finally:
        # Restore perms so tmp_path cleanup can remove the tree.
        os.chmod(locked, 0o755)


class _FakeStat:
    """Minimal stat_result stand-in so interior-dir tests can control uid/mode
    independently of the CI runner's real uid and umask."""

    def __init__(self, real_st, *, uid: int, mode_bits: int | None = None):
        self.st_mode = real_st.st_mode if mode_bits is None else mode_bits
        self.st_uid = uid
        self.st_gid = getattr(real_st, "st_gid", 0)


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_manifest_output_refuses_all_existing_paths(tmp_path, kind):
    out = tmp_path / "output"
    if kind == "directory":
        out.mkdir()
    elif kind == "file":
        out.write_text("keep me")
    else:
        out.symlink_to(tmp_path)
    with pytest.raises(ManifestOutputError, match="already exists"):
        prepare_manifest_output_dir(out)
