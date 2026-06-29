from __future__ import annotations

import errno
import hashlib
import os
import stat
from typing import Tuple


def open_no_follow_path(
    path: str,
    *,
    write: bool = False,
    mode: int = 0o600,
    directory: bool = False,
) -> int:
    """Open ``path`` without following a symlink in *any* path component.

    ``O_NOFOLLOW`` only protects the final component of a path. A regular
    file reached through a symlinked *parent* directory (for example a user
    replacing ``~/.ssh`` with a link to a sensitive directory) would still be
    opened by a plain ``os.open(path, O_NOFOLLOW)``.

    This helper resolves the path one component at a time with ``openat``
    semantics:

      - each intermediate component is opened relative to its parent's
        descriptor without following symlinks;
      - the final component is opened with ``O_NOFOLLOW`` (read, or
        ``O_WRONLY | O_CREAT | O_EXCL`` when ``write`` is True).

    The important detail is that intermediate components are opened with
    ``O_PATH | O_NOFOLLOW`` when ``O_PATH`` is available, and then verified
    with ``fstat()``. On Linux, ``O_RDONLY | O_DIRECTORY | O_NOFOLLOW`` is not
    sufficient for this job: a symlink whose target is a directory can still be
    opened as the target directory on some kernels. Opening with ``O_PATH`` and
    checking the resulting descriptor reliably exposes such a component as a
    symlink instead.

    A symlink (or a ``..`` component) anywhere in the path raises
    ``OSError(ELOOP)``. On platforms without ``openat``/``O_DIRECTORY``
    support, this falls back to a single ``O_NOFOLLOW`` open of the whole path,
    which is no worse than the historical behaviour.
    """

    cloexec = getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    o_directory = getattr(os, "O_DIRECTORY", 0)
    o_path = getattr(os, "O_PATH", 0)

    if write and directory:
        raise ValueError("directory=True cannot be combined with write=True")

    if write:
        final_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | cloexec | nofollow
    elif directory and o_path:
        # O_PATH|O_NOFOLLOW opens a final symlink as the symlink object itself
        # on Linux, allowing inspect_dir_no_follow() to reject it via fstat().
        # O_RDONLY|O_DIRECTORY|O_NOFOLLOW can still follow a symlink-to-dir on
        # some kernels/filesystems.
        final_flags = o_path | cloexec | nofollow
    else:
        final_flags = os.O_RDONLY | cloexec | nofollow
        if directory:
            final_flags |= o_directory

    supports_openat = bool(
        o_directory and nofollow and os.open in getattr(os, "supports_dir_fd", set())
    )
    if not supports_openat:
        return os.open(path, final_flags, mode)

    absolute = path.startswith("/")
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if not parts:
        return os.open(path, final_flags, mode)

    *parent_parts, leaf = parts

    # Use O_PATH for directory descriptors when available.  O_PATH descriptors
    # can be used as dir_fd anchors for later openat-style calls, and with
    # O_NOFOLLOW they let us fstat() a symlink component instead of silently
    # following it.  If O_PATH is unavailable, use O_RDONLY and an lstat()
    # pre-check for intermediate components as a best-effort fallback.
    dir_base_flags = (o_path if o_path else os.O_RDONLY) | cloexec | o_directory
    component_flags = (
        (o_path if o_path else os.O_RDONLY) | cloexec | o_directory | nofollow
    )

    dir_fd = os.open("/" if absolute else ".", dir_base_flags)
    try:
        for component in parent_parts:
            if component == "..":
                raise OSError(errno.ELOOP, "unsafe '..' path component", path)

            if not o_path:
                # Best-effort fallback for platforms without O_PATH. This is not
                # as race-resistant as the descriptor-only path, but it avoids
                # known symlink parents where we cannot open the component itself
                # as a non-followed O_PATH descriptor.
                try:
                    st = os.lstat(component, dir_fd=dir_fd)
                except OSError:
                    raise
                if stat.S_ISLNK(st.st_mode):
                    raise OSError(errno.ELOOP, "symlinked path component", path)
                if not stat.S_ISDIR(st.st_mode):
                    raise OSError(errno.ENOTDIR, "non-directory path component", path)

            try:
                next_fd = os.open(component, component_flags, dir_fd=dir_fd)
            except OSError as e:
                if e.errno in {errno.ELOOP, errno.ENOTDIR}:
                    try:
                        st = os.lstat(component, dir_fd=dir_fd)
                    except OSError:
                        raise
                    if stat.S_ISLNK(st.st_mode):
                        raise OSError(
                            errno.ELOOP,
                            "symlinked path component",
                            path,
                        ) from e
                raise

            try:
                st = os.fstat(next_fd)
                if stat.S_ISLNK(st.st_mode):
                    raise OSError(errno.ELOOP, "symlinked path component", path)
                if not stat.S_ISDIR(st.st_mode):
                    raise OSError(errno.ENOTDIR, "non-directory path component", path)
            except Exception:
                os.close(next_fd)
                raise

            os.close(dir_fd)
            dir_fd = next_fd

        if leaf == "..":
            raise OSError(errno.ELOOP, "unsafe '..' path component", path)
        return os.open(leaf, final_flags, mode, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def inspect_dir_no_follow(path: str) -> os.stat_result:
    """Return fstat() metadata for a directory opened without following symlinks.

    Directory metadata capture must have the same TOCTOU properties as file
    capture: inspect the exact object reached through a no-follow descriptor,
    and reject symlink components anywhere in the path.  Path-based
    ``os.stat()`` / ``os.path.isdir()`` checks can be swapped between check and
    use when an include root is attacker-writable; this helper keeps the check
    bound to the opened descriptor.
    """

    fd = open_no_follow_path(path, directory=True)
    try:
        st = os.fstat(fd)
        if stat.S_ISLNK(st.st_mode):
            raise OSError(errno.ELOOP, "symlinked directory path", path)
        if not stat.S_ISDIR(st.st_mode):
            raise OSError(errno.ENOTDIR, "not a directory", path)
        return st
    finally:
        os.close(fd)


def stat_dir_triplet(path: str) -> Tuple[str, str, str]:
    """Return (owner, group, mode) for a safely-opened directory path.

    Unlike :func:`stat_triplet`, this refuses final symlinks and symlinked
    parent components, and derives metadata from the directory descriptor that
    passed those checks.
    """

    return stat_triplet_from_stat(inspect_dir_no_follow(path))


def path_has_symlink_component(path: str) -> bool:
    """Return True if any existing component of *path* is a symlink.

    This is a lightweight discovery-time companion to ``open_no_follow_path``.
    It is intended for directory-walking code paths that must decide whether a
    candidate root is safe to enumerate before opening individual files. Missing
    trailing components are treated as non-symlinks; ``..`` is treated as unsafe
    and therefore reported as a symlink-like component.
    """

    norm = os.path.normpath(path)
    if norm in ("", "."):
        return False

    if os.path.isabs(norm):
        cur = os.sep
        parts = [p for p in norm.split(os.sep) if p]
    else:
        cur = os.getcwd()
        parts = [p for p in norm.split(os.sep) if p]

    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            return True
        cur = os.path.join(cur, part)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            return False
        except OSError:
            # Fail closed for unreadable/racy paths used as discovery roots.
            return True
        if stat.S_ISLNK(st.st_mode):
            return True
    return False


def is_dir_no_symlink_components(path: str) -> bool:
    """Return True only for directories reached without symlink components."""

    if path_has_symlink_component(path):
        return False
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode)


def stat_triplet_from_stat(st: os.stat_result) -> Tuple[str, str, str]:
    """Return (owner, group, mode) for an existing stat result."""

    mode = oct(st.st_mode & 0o7777)[2:].zfill(4)

    import grp
    import pwd

    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return owner, group, mode


def file_md5(path: str) -> str:
    """Return hex MD5 of a file.

    Used for Debian dpkg baseline comparisons.
    """
    h = hashlib.md5()  # nosec
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stat_triplet(path: str) -> Tuple[str, str, str]:
    """Return (owner, group, mode) for a path.

    owner/group are usernames/group names when resolvable, otherwise numeric ids.
    mode is a zero-padded octal string (e.g. "0644").
    """
    return stat_triplet_from_stat(os.stat(path, follow_symlinks=True))
