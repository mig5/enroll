from __future__ import annotations

import os
import stat
from pathlib import Path


class OutputSafetyError(RuntimeError):
    """Raised when an output path is unsafe for root-run plaintext output."""


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o700)
    except OSError:
        # Best-effort; callers still benefit from mkdir(mode=0o700) on normal FSes.
        pass


def _assert_no_existing_symlink_components(path: Path, *, label: str) -> None:
    """Reject symlinks in existing parent components of an output path."""

    parts = path.parts
    if not parts:
        return

    if path.is_absolute():
        cur = Path(parts[0])
        rest = parts[1:-1]
    else:
        cur = Path.cwd()
        rest = parts[:-1]

    for part in rest:
        cur = cur / part
        if not os.path.lexists(cur):
            return
        try:
            st = cur.lstat()
        except OSError as e:
            raise OutputSafetyError(f"unable to inspect {label} parent: {cur}") from e
        if stat.S_ISLNK(st.st_mode):
            raise OutputSafetyError(
                f"{label} parent path contains a symlink; refusing: {cur}"
            )


def prepare_new_private_dir(path: str | Path, *, label: str = "output") -> Path:
    """Create a brand-new private output directory.

    Refuse existing paths, including symlinks.  This prevents root-run harvests
    from writing into attacker-precreated directories in shared locations such
    as /tmp, and keeps plaintext bundles private by default.
    """

    out = Path(path).expanduser()
    _assert_no_existing_symlink_components(out, label=label)
    if os.path.lexists(out):
        raise OutputSafetyError(
            f"{label} path already exists; refusing to overwrite or merge: {out}"
        )

    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    _chmod_private(out)

    try:
        st = out.lstat()
    except OSError as e:
        raise OutputSafetyError(f"unable to inspect {label} path: {out}") from e
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise OutputSafetyError(f"{label} path is not a real directory: {out}")
    return out


def ensure_private_empty_dir(path: str | Path, *, label: str = "output") -> Path:
    """Create or validate a private empty directory.

    This is for internally-generated random cache/temp directories.  User-facing
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

    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    _chmod_private(out)
    return out
