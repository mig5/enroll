from __future__ import annotations

import errno
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Iterator, Optional, Tuple

from .fsutil import open_no_follow_path
from .harvest_safety import (
    OutputSafetyError,
    ensure_safe_output_parent,
    prepare_new_private_dir,
)


class ArtifactSafetyError(RuntimeError):
    """Raised when a harvest artifact path is unsafe to consume."""


class ManifestOutputError(RuntimeError):
    """Raised when a manifest output path is unsafe to use."""


_SITE_FQDN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")


def validate_site_fqdn(value: str | None) -> str | None:
    """Validate the optional site-mode host name/FQDN.

    Renderers use this value in inventory data and, for Ansible, in output
    paths.  Keep it deliberately conservative so it cannot become a path
    separator, absolute path, YAML/INI newline injection, or shell-ish text in
    generated documentation/commands.
    """

    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if any(ch in text for ch in ("/", "\\", "\x00", "\n", "\r")):
        raise ManifestOutputError(
            "--fqdn contains unsafe path or newline characters; use a simple "
            "host/inventory name"
        )
    if text in {".", ".."} or not _SITE_FQDN_RE.fullmatch(text):
        raise ManifestOutputError(
            "--fqdn must start with a letter or digit and contain only "
            "letters, digits, dot, underscore, or hyphen"
        )
    return text


def _assert_no_output_symlinks(root: Path) -> None:
    """Reject pre-existing symlinks in an output tree we are about to merge into.

    Non-site mode refuses existing output directories entirely.  Site/FQDN modes
    intentionally accumulate multiple nodes into one tree, so reject symlinks in
    the tree before merging to avoid writes being redirected outside *root*.
    Version-control metadata can contain implementation-specific entries and is
    not part of Enroll's generated layout, so it is pruned from this check.
    """

    skip_dirs = {".git", ".hg", ".svn"}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirpath_p = Path(dirpath)

        for dirname in list(dirnames):
            if dirname in skip_dirs:
                dirnames.remove(dirname)
                continue
            p = dirpath_p / dirname
            try:
                st = p.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                raise ManifestOutputError(
                    f"manifest output tree contains a symlink; refusing to merge: {p}"
                )

        for filename in filenames:
            if filename in skip_dirs:
                continue
            p = dirpath_p / filename
            try:
                st = p.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                raise ManifestOutputError(
                    f"manifest output tree contains a symlink; refusing to merge: {p}"
                )


def _safe_relative_path(value: str, *, field: str) -> Path:
    text = str(value or "").strip()
    if not text:
        raise ArtifactSafetyError(f"empty {field}")
    if "\x00" in text:
        raise ArtifactSafetyError(f"{field} contains NUL byte: {text!r}")
    p = Path(text)
    if p.is_absolute():
        raise ArtifactSafetyError(f"{field} must be relative: {text!r}")
    if any(part in {"", ".", ".."} for part in p.parts):
        raise ArtifactSafetyError(f"{field} contains unsafe path component: {text!r}")
    return p


def prepare_manifest_output_dir(
    out_dir: str | Path, *, allow_existing: bool = False
) -> Path:
    """Create a manifest output directory, refusing unsafe root output paths.

    Rendering a manifest may be run by root and may target configuration-
    management trees. Refuse an existing path rather than deleting or merging
    with it by default; callers that intentionally support accumulation, such
    as --fqdn site mode, may allow an existing directory but never a symlink,
    non-directory path, symlinked parent, or root-unsafe parent.
    """

    out = Path(out_dir).expanduser()
    if os.path.lexists(out):
        if not allow_existing:
            raise ManifestOutputError(
                "manifest output path already exists; refusing to overwrite: " f"{out}"
            )
        try:
            ensure_safe_output_parent(
                out / ".enroll-manifest-output-check", label="manifest output"
            )
        except OutputSafetyError as e:
            raise ManifestOutputError(str(e)) from e
        st = out.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise ManifestOutputError(
                f"manifest output path is a symlink; refusing to use: {out}"
            )
        if not out.is_dir():
            raise ManifestOutputError(
                f"manifest output path exists but is not a directory: {out}"
            )
        _assert_no_output_symlinks(out)
        return out
    try:
        return prepare_new_private_dir(out, label="manifest output")
    except OutputSafetyError as e:
        raise ManifestOutputError(str(e)) from e


def _assert_no_symlink_components(path: Path, *, root: Path) -> None:
    """Reject symlinks in any existing path component between root and path."""

    try:
        rel = path.relative_to(root)
    except ValueError as e:
        raise ArtifactSafetyError(f"artifact path escapes artifact root: {path}") from e

    cur = root
    for part in rel.parts:
        cur = cur / part
        try:
            st = cur.lstat()
        except FileNotFoundError:
            # Missing components are handled by the final caller where relevant.
            return
        if stat.S_ISLNK(st.st_mode):
            raise ArtifactSafetyError(f"artifact path contains symlink: {cur}")


def safe_artifact_file(bundle_dir: str | Path, role: str, src_rel: str) -> Path:
    """Return a harvested artifact file path only if it is safe to copy.

    The path must remain under artifacts/<role>, contain no absolute or '..'
    components, contain no symlinks in any path component, and refer to a
    regular, non-hardlinked file.  This deliberately mirrors the tar extraction
    hardening used for remote/SOPS/plain tarball bundles, but applies it to
    directory bundles too.
    """

    role_path = _safe_relative_path(role, field="artifact role")
    src_path = _safe_relative_path(src_rel, field="artifact src_rel")

    artifacts_root = Path(bundle_dir).expanduser() / "artifacts"
    root = artifacts_root / role_path
    candidate = root / src_path

    if artifacts_root.exists():
        st = artifacts_root.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise ArtifactSafetyError(
                f"artifacts directory is a symlink: {artifacts_root}"
            )

    if root.exists():
        _assert_no_symlink_components(root, root=artifacts_root)

    _assert_no_symlink_components(candidate, root=artifacts_root)

    try:
        st = candidate.lstat()
    except FileNotFoundError:
        raise

    if stat.S_ISLNK(st.st_mode):
        raise ArtifactSafetyError(f"artifact is a symlink: {candidate}")
    if not stat.S_ISREG(st.st_mode):
        raise ArtifactSafetyError(f"artifact is not a regular file: {candidate}")
    if st.st_nlink > 1:
        raise ArtifactSafetyError(f"artifact is hardlinked: {candidate}")

    resolved_root = artifacts_root.resolve(strict=True)
    resolved_candidate = candidate.resolve(strict=True)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as e:
        raise ArtifactSafetyError(
            f"artifact path escapes artifact root: {candidate}"
        ) from e

    return candidate


def iter_safe_artifact_files(
    bundle_dir: str | Path, role: str
) -> Iterator[Tuple[Path, str]]:
    """Yield safe artifact files for a role as (path, src_rel)."""

    role_path = _safe_relative_path(role, field="artifact role")
    artifacts_dir = Path(bundle_dir).expanduser() / "artifacts" / role_path
    if not artifacts_dir.exists():
        return
    if not artifacts_dir.is_dir():
        raise ArtifactSafetyError(
            f"artifact role path is not a directory: {artifacts_dir}"
        )

    for root, dirs, files in os.walk(artifacts_dir, followlinks=False):
        root_p = Path(root)
        for dirname in list(dirs):
            p = root_p / dirname
            try:
                st = p.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                raise ArtifactSafetyError(f"artifact directory is a symlink: {p}")
        for filename in files:
            p = root_p / filename
            rel = p.relative_to(artifacts_dir).as_posix()
            yield safe_artifact_file(bundle_dir, role, rel), rel


def copy_safe_artifact_file(src: str | Path, dst: str | Path) -> None:
    """Copy an already validated artifact file without following symlinks."""

    shutil.copy2(src, dst, follow_symlinks=False)


_FREEZE_MAX_FILE_BYTES = 64 * 1024 * 1024
_FREEZE_MAX_FILES = 200_000


def _read_all_no_follow(abs_path: str) -> bytes:
    """Read a regular file's bytes via a no-follow, non-hardlinked open.

    Mirrors the harvest-side capture discipline: open every path component
    without following symlinks, fstat the resulting descriptor, and refuse
    anything that is not a single-linked regular file. This is what makes the
    frozen copy independent of later mutation of the source tree -- the bytes
    are taken from the descriptor we validated, not re-resolved by path.
    """

    fd: Optional[int] = None
    try:
        try:
            fd = open_no_follow_path(abs_path)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise ArtifactSafetyError(
                    f"bundle path contains a symlink component: {abs_path}"
                ) from e
            if e.errno == errno.ENOTDIR:
                raise ArtifactSafetyError(
                    f"bundle path has a non-directory component: {abs_path}"
                ) from e
            raise ArtifactSafetyError(f"unable to read bundle file: {abs_path}") from e

        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ArtifactSafetyError(f"bundle file is not a regular file: {abs_path}")
        if st.st_nlink > 1:
            raise ArtifactSafetyError(f"bundle file is hardlinked: {abs_path}")
        if st.st_size > _FREEZE_MAX_FILE_BYTES:
            raise ArtifactSafetyError(f"bundle file is too large to freeze: {abs_path}")

        chunks: list[bytes] = []
        remaining = int(st.st_size)
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def freeze_directory_bundle(
    bundle_dir: str | Path, *, label: str = "harvest bundle"
) -> Tuple[str, tempfile.TemporaryDirectory]:
    """Copy a directory harvest bundle into a private, immutable-by-attacker tree.

    Validation of a harvest bundle (schema + artifact safety) is point-in-time:
    it proves the tree is safe *at the moment it is checked*. When the bundle
    directory is still writable by an unprivileged user, an attacker can race the
    later consumers (``manifest``/``diff``/``explain`` re-open artifacts by path
    to copy, hash, or feed to JinjaTurtle) and swap a validated regular file for a
    symlink or different file after the check.

    Tar and SOPS inputs already avoid this: Enroll extracts them into a private
    ``0700`` temp directory before validating. Plain *directory* inputs were used
    in place. This helper closes that gap by giving directory inputs the same
    treatment: it copies the bundle into a fresh ``0700`` temp directory using
    no-follow traversal, taking each file's bytes from a validated descriptor
    (no symlinks, no hardlinks, regular files only). The returned copy is what the
    caller should validate and render from, so a subsequent mutation of the
    original directory cannot affect the consumed bundle.

    Returns ``(frozen_bundle_dir, tempdir)``. The caller must keep ``tempdir``
    alive for the lifetime of the bundle use; it cleans up on close.
    """

    src_root = Path(bundle_dir).expanduser()
    if not src_root.is_dir():
        raise ArtifactSafetyError(f"{label} is not a directory: {src_root}")

    td = tempfile.TemporaryDirectory(prefix="enroll-frozen-bundle-")
    try:
        dst_root = Path(td.name) / "bundle"
        dst_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        try:
            os.chmod(dst_root, 0o700)
        except OSError:
            pass

        file_count = 0
        # followlinks=False: do not descend into symlinked directories. Each
        # discovered file is independently re-opened no-follow before copying, so
        # a symlinked directory cannot smuggle content into the frozen tree even
        # if it is swapped in mid-walk.
        for cur, dirs, files in os.walk(src_root, followlinks=False):
            cur_p = Path(cur)

            # Refuse symlinked subdirectories rather than silently skipping them,
            # so a tampered bundle fails loudly instead of producing a partial
            # frozen copy that later diverges from the operator's expectation.
            for dname in list(dirs):
                dp = cur_p / dname
                try:
                    dst = dp.lstat()
                except FileNotFoundError:
                    dirs.remove(dname)
                    continue
                if stat.S_ISLNK(dst.st_mode):
                    raise ArtifactSafetyError(
                        f"{label} contains a symlinked directory: {dp}"
                    )

            rel_dir = cur_p.relative_to(src_root)
            target_dir = dst_root / rel_dir
            target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

            for fname in files:
                file_count += 1
                if file_count > _FREEZE_MAX_FILES:
                    raise ArtifactSafetyError(
                        f"{label} has too many files to freeze safely"
                    )
                src_file = cur_p / fname
                data = _read_all_no_follow(str(src_file))
                dst_file = target_dir / fname
                fd = open_no_follow_path(str(dst_file), write=True, mode=0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)

        return str(dst_root), td
    except BaseException:
        td.cleanup()
        raise
