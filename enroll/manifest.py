from __future__ import annotations

import os
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import List, Optional

from .ansible import manifest_from_bundle_dir as manifest_ansible_from_bundle_dir
from .harvest_safety import ensure_safe_output_parent
from .manifest_safety import freeze_directory_bundle, validate_site_fqdn
from .remote import _safe_extract_tar
from .sopsutil import (
    decrypt_file_binary_to,
    encrypt_file_binary,
    require_sops_cmd,
)
from .validate import validate_harvest


_SEMANTIC_SAFETY_WARNING = (
    "This harvest is structurally valid, but Enroll cannot prove it is semantically safe.\n"
    "Only apply manifests generated from harvests whose provenance you trust.\n"
)


def _warn_semantic_safety() -> None:
    sys.stderr.write(_SEMANTIC_SAFETY_WARNING)


def _prepare_bundle_dir(
    bundle: str,
    *,
    sops_mode: bool,
) -> tuple[str, Optional[tempfile.TemporaryDirectory]]:
    """Return (bundle_dir, tempdir).

    - In non-sops mode, `bundle` must be a directory.
    - In sops mode, `bundle` may be a directory (already-decrypted) *or*
      a SOPS-encrypted tarball. In the tarball case we decrypt+extract into
      a secure temp directory.
    """
    p = Path(bundle).expanduser()

    if p.is_dir():
        # A directory bundle may still be writable by an unprivileged user (e.g.
        # root running `manifest` against /tmp/some-harvest). Validation is a
        # point-in-time check, but the renderer/JinjaTurtle re-open artifacts by
        # path afterwards, so a mutable source could be raced. Freeze the bundle
        # into a private 0700 temp copy (no-follow, regular-files-only) and
        # consume that immutable copy instead. Tar/SOPS inputs already get an
        # equivalent private extraction below.
        frozen_dir, td_frozen = freeze_directory_bundle(p, label="harvest bundle")
        return frozen_dir, td_frozen

    if not sops_mode:
        raise RuntimeError(f"Harvest path is not a directory: {p}")

    if not p.exists():
        raise RuntimeError(f"Harvest path not found: {p}")

    # Ensure sops is available early for clear error messages.
    require_sops_cmd()

    td = tempfile.TemporaryDirectory(prefix="enroll-harvest-")
    td_path = Path(td.name)
    try:
        os.chmod(td_path, 0o700)
    except OSError:
        pass

    tar_path = td_path / "harvest.tar.gz"
    out_dir = td_path / "bundle"
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out_dir, 0o700)
    except OSError:
        pass

    decrypt_file_binary_to(p, tar_path, mode=0o600)

    # Extract using the same safe extraction rules as remote harvesting.
    with tarfile.open(tar_path, mode="r:gz") as tf:
        _safe_extract_tar(tf, out_dir)

    return str(out_dir), td


def _resolve_sops_manifest_out_file(out: str) -> Path:
    """Resolve an output *file* path for manifest --sops mode.

    If `out` looks like a directory (or points to an existing directory), we
    place the encrypted manifest bundle inside it as manifest.tar.gz.sops.
    """
    p = Path(out).expanduser()
    if p.exists() and p.is_dir():
        return p / "manifest.tar.gz.sops"
    # Heuristic: treat paths with a suffix as files; otherwise directories.
    if p.suffix:
        return p
    return p / "manifest.tar.gz.sops"


def _tar_dir_to_with_progress(
    src_dir: Path, tar_path: Path, *, desc: str = "tarring"
) -> None:
    """Create a tar.gz of src_dir at tar_path, with a simple per-entry progress display."""
    src_dir = Path(src_dir)
    tar_path = Path(tar_path)
    ensure_safe_output_parent(tar_path, label="manifest tar output")

    # Collect paths (dirs + files)
    paths: list[Path] = [src_dir]
    for root, dirs, files in os.walk(str(src_dir)):
        root_p = Path(root)
        for d in sorted(dirs):
            paths.append(root_p / d)
        for f in sorted(files):
            paths.append(root_p / f)

    total = len(paths)
    is_tty = hasattr(os, "isatty") and os.isatty(2)

    def _print_progress(i: int, p: Path) -> None:
        if not is_tty:
            return
        pct = (i / total * 100.0) if total else 100.0
        rel = "."
        try:
            rel = str(p.relative_to(src_dir))
        except Exception:
            rel = str(p)
        msg = f"{desc}: {i}/{total} ({pct:5.1f}%) {rel}"
        try:
            cols = shutil.get_terminal_size((80, 20)).columns
            msg = msg[: cols - 1]
        except Exception:
            pass  # nosec
        os.write(2, ("\r" + msg).encode("utf-8", errors="replace"))

    with tarfile.open(tar_path, mode="w:gz") as tf:
        prefix = Path("manifest")

        for i, p in enumerate(paths, start=1):
            if p == src_dir:
                arcname = str(prefix)
            else:
                rel = p.relative_to(src_dir)
                arcname = str(prefix / rel)
            tf.add(str(p), arcname=arcname, recursive=False)
            _print_progress(i, p)

    if is_tty:
        os.write(2, b"\n")


def _encrypt_manifest_out_dir_to_sops(
    out_dir: Path, out_file: Path, fps: list[str]
) -> Path:
    """Tar+encrypt the generated manifest output directory into a single .sops file."""
    require_sops_cmd()
    out_file = Path(out_file)
    ensure_safe_output_parent(out_file, label="encrypted manifest output")

    fd, tmp_tgz = tempfile.mkstemp(
        prefix=".enroll-manifest-",
        suffix=".tar.gz",
        dir=str(out_file.parent),
    )
    os.close(fd)
    try:
        _tar_dir_to_with_progress(
            Path(out_dir), Path(tmp_tgz), desc="Bundling manifest"
        )
        encrypt_file_binary(Path(tmp_tgz), out_file, pgp_fingerprints=fps, mode=0o600)
    finally:
        try:
            os.unlink(tmp_tgz)
        except FileNotFoundError:
            pass

    return out_file


def manifest(
    bundle_dir: str,
    out: str,
    *,
    fqdn: Optional[str] = None,
    jinjaturtle: str = "auto",  # auto|on|off
    sops_fingerprints: Optional[List[str]] = None,
    no_common_roles: bool = False,
) -> Optional[str]:
    """Render a configuration-management manifest from a harvest.

    Plain mode:
      - `bundle_dir` must be a directory
      - `out` is a directory written in-place

    SOPS mode (when `sops_fingerprints` is provided):
      - `bundle_dir` may be either a directory (already decrypted) or a SOPS
        encrypted tarball (binary) produced by `harvest --sops`
      - the manifest output is bundled (tar.gz) and encrypted into a single
        SOPS file (binary) at the resolved output path.

    Returns:
      - In SOPS mode: the path to the encrypted manifest bundle (.sops)
      - In plain mode: None
    """
    fqdn = validate_site_fqdn(fqdn)

    sops_mode = bool(sops_fingerprints)

    # Decrypt/extract the harvest bundle if needed.
    resolved_bundle_dir, td_bundle = _prepare_bundle_dir(
        bundle_dir, sops_mode=sops_mode
    )

    td_out: Optional[tempfile.TemporaryDirectory] = None
    try:
        validation = validate_harvest(resolved_bundle_dir)
        if not validation.ok:
            raise RuntimeError(
                "harvest state does not match this Enroll version's schema; "
                "please re-harvest the host with this version of Enroll.\n"
                + validation.to_text().strip()
            )

        _warn_semantic_safety()

        if not sops_mode:
            manifest_ansible_from_bundle_dir(
                resolved_bundle_dir,
                out,
                fqdn=fqdn,
                jinjaturtle=jinjaturtle,
                no_common_roles=no_common_roles,
            )
            return None

        # SOPS mode: generate into a secure temp dir, then tar+encrypt into a single file.
        out_file = _resolve_sops_manifest_out_file(out)

        td_out = tempfile.TemporaryDirectory(prefix="enroll-manifest-")
        tmp_out = Path(td_out.name) / "out"

        manifest_ansible_from_bundle_dir(
            resolved_bundle_dir,
            str(tmp_out),
            fqdn=fqdn,
            jinjaturtle=jinjaturtle,
            no_common_roles=no_common_roles,
        )

        enc = _encrypt_manifest_out_dir_to_sops(
            tmp_out, out_file, list(sops_fingerprints or [])
        )
        return str(enc)

    finally:
        if td_out is not None:
            td_out.cleanup()
        if td_bundle is not None:
            td_bundle.cleanup()
