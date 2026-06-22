from __future__ import annotations

import os
from pathlib import Path

import pytest

from enroll.manifest_safety import (
    ArtifactSafetyError,
    ManifestOutputError,
    copy_safe_artifact_file,
    iter_safe_artifact_files,
    prepare_manifest_output_dir,
    safe_artifact_file,
    validate_site_fqdn,
)


def test_validate_site_fqdn_accepts_and_normalises_simple_values():
    assert validate_site_fqdn(None) is None
    assert validate_site_fqdn("  ") is None
    assert validate_site_fqdn("host_1.example") == "host_1.example"


@pytest.mark.parametrize(
    "value", ["../host", "host/name", "host\\name", "host\nname", "-bad", ".", ".."]
)
def test_validate_site_fqdn_rejects_path_or_inventory_injection(value: str):
    with pytest.raises(ManifestOutputError):
        validate_site_fqdn(value)


def test_prepare_manifest_output_dir_allows_existing_clean_tree_in_site_mode(
    tmp_path: Path,
):
    out = tmp_path / "site"
    out.mkdir()
    (out / ".git").mkdir()
    (out / ".git" / "ignored-link").symlink_to(tmp_path, target_is_directory=True)

    assert prepare_manifest_output_dir(out, allow_existing=True) == out


def test_prepare_manifest_output_dir_rejects_existing_tree_symlink(tmp_path: Path):
    out = tmp_path / "site"
    out.mkdir()
    (out / "bad-link").symlink_to(tmp_path, target_is_directory=True)

    with pytest.raises(ManifestOutputError, match="contains a symlink"):
        prepare_manifest_output_dir(out, allow_existing=True)


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
