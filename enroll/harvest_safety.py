from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


class OutputSafetyError(RuntimeError):
    """Raised when an output path is unsafe for root-run plaintext output."""


# Keep a reference to the real euid getter so tests that monkeypatch
# enroll.harvest.os.geteuid do not accidentally make output-safety code
# believe a non-root test process is running as root. Tests that need to
# exercise root behavior can still monkeypatch _effective_uid directly.
_OS_GETEUID = getattr(os, "geteuid", None)


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o700)
    except OSError:
        # Best-effort; callers still benefit from mkdir(mode=0o700) on normal FSes.
        pass


def _effective_uid() -> int | None:
    if _OS_GETEUID is None:
        return None
    try:
        return int(_OS_GETEUID())
    except OSError:
        return None


def _assert_trusted_root_parent(path: Path, st: os.stat_result, *, label: str) -> None:
    """Reject parent directories that are unsafe when Enroll runs as root.

    Enroll deliberately invokes host tools and writes host configuration state,
    so root-run output should not pass through parent directories controlled by
    an unprivileged user. Root-owned sticky shared directories such as /tmp are
    allowed as a boundary, but any existing child below them must still be
    root-owned and non-writable by group/other.
    """

    if _effective_uid() != 0:
        return
    if not stat.S_ISDIR(st.st_mode):
        raise OutputSafetyError(f"{label} parent is not a directory: {path}")
    if st.st_uid != 0:
        raise OutputSafetyError(
            f"{label} parent is not owned by root; refusing root-run output: {path}"
        )
    writable_by_group_or_other = st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    sticky = st.st_mode & stat.S_ISVTX
    if writable_by_group_or_other and not sticky:
        raise OutputSafetyError(
            f"{label} parent is writable by group/other; refusing root-run output: {path}"
        )


def _assert_existing_output_dir_component(path: Path, *, label: str) -> None:
    try:
        st = path.lstat()
    except OSError as e:
        raise OutputSafetyError(f"unable to inspect {label} parent: {path}") from e
    if stat.S_ISLNK(st.st_mode):
        raise OutputSafetyError(
            f"{label} parent path contains a symlink; refusing: {path}"
        )
    _assert_trusted_root_parent(path, st, label=label)


def _mkdir_private_dir_tree(
    path: Path, *, label: str, final_must_be_new: bool = False
) -> Path:
    """Create a directory tree one component at a time with safety checks.

    pathlib.mkdir(parents=True) can traverse a symlink inserted after a parent
    pre-check and create deeper components in the symlink target. Walking one
    component at a time avoids that class of race for root-run output paths.
    """

    out = Path(path).expanduser()
    parts = out.parts
    if not parts:
        return out

    if out.is_absolute():
        cur = Path(parts[0])
        rest = parts[1:]
        _assert_existing_output_dir_component(cur, label=label)
    else:
        cur = Path.cwd()
        rest = parts
        _assert_existing_output_dir_component(cur, label=label)

    for idx, part in enumerate(rest):
        cur = cur / part
        is_final = idx == len(rest) - 1
        if os.path.lexists(cur):
            if is_final and final_must_be_new:
                raise OutputSafetyError(
                    f"{label} path already exists; refusing to overwrite or merge: {cur}"
                )
            _assert_existing_output_dir_component(cur, label=label)
            continue
        try:
            os.mkdir(cur, 0o700)
        except FileExistsError:
            if is_final and final_must_be_new:
                raise OutputSafetyError(
                    f"{label} path already exists; refusing to overwrite or merge: {cur}"
                )
            _assert_existing_output_dir_component(cur, label=label)
            continue
        _chmod_private(cur)
        _assert_existing_output_dir_component(cur, label=label)

    return out


def _assert_no_existing_symlink_components(
    path: Path, *, label: str, require_trusted_root_parents: bool = True
) -> None:
    """Reject unsafe existing parent components of an output path.

    This catches symlink parents for all users. When running as root, it also
    rejects existing parents controlled by an unprivileged user so an attacker
    cannot redirect root output by racing or replacing a parent directory.
    """

    parts = path.parts
    if not parts:
        return

    if path.is_absolute():
        cur = Path(parts[0])
        rest = parts[1:-1]
    else:
        cur = Path.cwd()
        rest = parts[:-1]
        if require_trusted_root_parents:
            _assert_existing_output_dir_component(cur, label=label)

    for part in rest:
        cur = cur / part
        if not os.path.lexists(cur):
            return
        if require_trusted_root_parents:
            _assert_existing_output_dir_component(cur, label=label)
        else:
            try:
                st = cur.lstat()
            except OSError as e:
                raise OutputSafetyError(
                    f"unable to inspect {label} parent: {cur}"
                ) from e
            if stat.S_ISLNK(st.st_mode):
                raise OutputSafetyError(
                    f"{label} parent path contains a symlink; refusing: {cur}"
                )


def ensure_safe_output_parent(path: str | Path, *, label: str = "output") -> Path:
    """Create and validate the parent directory for a root-run output file.

    The parent is checked with the same symlink/root-trust rules as plaintext
    bundle directories. This is for output *files* such as reports and SOPS
    bundles, where replacing an existing regular file is acceptable but
    following attacker-controlled parent paths is not.
    """

    out = Path(path).expanduser()
    parent = out.parent if out.parent != Path("") else Path(".")
    sentinel = parent / ".enroll-output-parent-check"
    _assert_no_existing_symlink_components(sentinel, label=label)
    _mkdir_private_dir_tree(parent, label=label, final_must_be_new=False)
    _assert_no_existing_symlink_components(sentinel, label=label)
    return parent


def write_text_output_file(
    path: str | Path,
    text: str,
    *,
    label: str = "output file",
    mode: int = 0o600,
) -> Path:
    """Safely write a user-facing output text file.

    The write is staged in the destination directory and atomically renamed into
    place. A final-path symlink is replaced rather than followed, while parent
    symlinks or root-unsafe parents are refused by ensure_safe_output_parent().
    """

    out = Path(path).expanduser()
    parent = ensure_safe_output_parent(out, label=label)
    fd, tmp_name = tempfile.mkstemp(prefix=".enroll-output-", dir=str(parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        try:
            os.chmod(tmp_name, mode)
        except OSError:
            pass
        os.replace(tmp_name, out)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
    return out


def prepare_new_private_dir(path: str | Path, *, label: str = "output") -> Path:
    """Create a brand-new private output directory.

    Refuse existing paths, including symlinks. This prevents root-run harvests
    from writing into attacker-precreated directories in shared locations such
    as /tmp, and keeps plaintext bundles private by default.
    """

    out = Path(path).expanduser()
    _assert_no_existing_symlink_components(out, label=label)
    return _mkdir_private_dir_tree(out, label=label, final_must_be_new=True)


def ensure_private_empty_dir(path: str | Path, *, label: str = "output") -> Path:
    """Create or validate a private empty directory.

    This is for internally-generated random cache/temp directories. User-facing
    --out paths should normally use prepare_new_private_dir() instead.
    """

    out = Path(path).expanduser()
    _assert_no_existing_symlink_components(out, label=label)
    if os.path.lexists(out):
        try:
            st = out.lstat()
        except OSError as e:
            raise OutputSafetyError(f"unable to inspect {label} path: {out}") from e
        if stat.S_ISLNK(st.st_mode):
            raise OutputSafetyError(f"{label} path is a symlink; refusing: {out}")
        if not stat.S_ISDIR(st.st_mode):
            raise OutputSafetyError(
                f"{label} path exists but is not a directory: {out}"
            )
        if any(out.iterdir()):
            raise OutputSafetyError(
                f"{label} path is not empty; refusing to merge: {out}"
            )
        _chmod_private(out)
        return out

    return _mkdir_private_dir_tree(out, label=label, final_must_be_new=True)
