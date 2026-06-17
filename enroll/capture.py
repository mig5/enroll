from __future__ import annotations

import os
import shutil
import stat
from typing import List, Optional, Set

from .fsutil import stat_triplet
from .harvest_types import ExcludedFile, ManagedFile, ManagedLink
from .ignore import IgnorePolicy
from .pathfilter import PathFilter


def files_differ(a: str, b: str, *, max_bytes: int = 2_000_000) -> bool:
    """Return True if file ``a`` differs from file ``b``.

    Best-effort and conservative: unreadable/missing baselines, non-regular
    files, and unexpectedly large files are treated as different so callers err
    on the side of preserving user state.
    """

    try:
        st_a = os.stat(a, follow_symlinks=True)
    except OSError:
        return True

    if not stat.S_ISREG(st_a.st_mode):
        return True

    try:
        st_b = os.stat(b, follow_symlinks=True)
    except OSError:
        return True

    if not stat.S_ISREG(st_b.st_mode):
        return True

    if st_a.st_size != st_b.st_size:
        return True

    if st_a.st_size > max_bytes:
        return True

    try:
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                ca = fa.read(1024 * 64)
                cb = fb.read(1024 * 64)
                if ca != cb:
                    return True
                if not ca:
                    return False
    except OSError:
        return True


def copy_into_bundle(
    bundle_dir: str, role_name: str, abs_path: str, src_rel: str
) -> None:
    dst = os.path.join(bundle_dir, "artifacts", role_name, src_rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(abs_path, dst)


def capture_file(
    *,
    bundle_dir: str,
    role_name: str,
    abs_path: str,
    reason: str,
    policy: IgnorePolicy,
    path_filter: PathFilter,
    managed_out: List[ManagedFile],
    excluded_out: List[ExcludedFile],
    seen_role: Optional[Set[str]] = None,
    seen_global: Optional[Set[str]] = None,
    metadata: Optional[tuple[str, str, str]] = None,
) -> bool:
    """Try to capture a single file into the bundle.

    Returns True if the file was copied and appended to ``managed_out``.
    ``seen_role`` de-duplicates within a role; ``seen_global`` de-duplicates
    across harvest stages so multiple generated roles do not manage one path.
    """

    if seen_global is not None and abs_path in seen_global:
        return False
    if seen_role is not None and abs_path in seen_role:
        return False

    def _mark_seen() -> None:
        if seen_role is not None:
            seen_role.add(abs_path)
        if seen_global is not None:
            seen_global.add(abs_path)

    if path_filter.is_excluded(abs_path):
        excluded_out.append(ExcludedFile(path=abs_path, reason="user_excluded"))
        _mark_seen()
        return False

    deny = policy.deny_reason(abs_path)
    if deny:
        excluded_out.append(ExcludedFile(path=abs_path, reason=deny))
        _mark_seen()
        return False

    try:
        owner, group, mode = (
            metadata if metadata is not None else stat_triplet(abs_path)
        )
    except OSError:
        excluded_out.append(ExcludedFile(path=abs_path, reason="unreadable"))
        _mark_seen()
        return False

    src_rel = abs_path.lstrip("/")
    try:
        copy_into_bundle(bundle_dir, role_name, abs_path, src_rel)
    except OSError:
        excluded_out.append(ExcludedFile(path=abs_path, reason="unreadable"))
        _mark_seen()
        return False

    managed_out.append(
        ManagedFile(
            path=abs_path,
            src_rel=src_rel,
            owner=owner,
            group=group,
            mode=mode,
            reason=reason,
        )
    )
    _mark_seen()
    return True


USER_SHELL_DOTFILES_WITH_SKEL_BASELINE = [
    (".bashrc", "user_shell_rc"),
    (".profile", "user_profile"),
    (".bash_logout", "user_shell_logout"),
]

USER_SHELL_DOTFILES_WITHOUT_SKEL_BASELINE = [
    (".bash_aliases", "user_shell_aliases"),
]


def capture_user_shell_dotfiles(
    *,
    bundle_dir: str,
    role_name: str,
    home: str,
    skel_dir: str,
    enabled: bool,
    policy: IgnorePolicy,
    path_filter: PathFilter,
    managed_out: List[ManagedFile],
    excluded_out: List[ExcludedFile],
    seen_role: Optional[Set[str]],
    seen_global: Optional[Set[str]],
) -> int:
    """Capture selected per-user shell dotfiles when explicitly enabled."""

    if not enabled:
        return 0

    home = (home or "").rstrip("/")
    if not home or not home.startswith("/"):
        return 0

    captured = 0
    max_compare_bytes = int(getattr(policy, "max_file_bytes", 256_000))

    for rel, reason in USER_SHELL_DOTFILES_WITH_SKEL_BASELINE:
        upath = os.path.join(home, rel)
        if not os.path.isfile(upath) or os.path.islink(upath):
            continue
        skel_path = os.path.join(skel_dir, rel)
        if not files_differ(upath, skel_path, max_bytes=max_compare_bytes):
            continue
        if capture_file(
            bundle_dir=bundle_dir,
            role_name=role_name,
            abs_path=upath,
            reason=reason,
            policy=policy,
            path_filter=path_filter,
            managed_out=managed_out,
            excluded_out=excluded_out,
            seen_role=seen_role,
            seen_global=seen_global,
        ):
            captured += 1

    for rel, reason in USER_SHELL_DOTFILES_WITHOUT_SKEL_BASELINE:
        upath = os.path.join(home, rel)
        if not os.path.isfile(upath) or os.path.islink(upath):
            continue
        if capture_file(
            bundle_dir=bundle_dir,
            role_name=role_name,
            abs_path=upath,
            reason=reason,
            policy=policy,
            path_filter=path_filter,
            managed_out=managed_out,
            excluded_out=excluded_out,
            seen_role=seen_role,
            seen_global=seen_global,
        ):
            captured += 1

    return captured


def capture_link(
    *,
    role_name: str,
    abs_path: str,
    reason: str,
    policy: IgnorePolicy,
    path_filter: PathFilter,
    managed_out: List[ManagedLink],
    excluded_out: List[ExcludedFile],
    seen_role: Optional[Set[str]] = None,
    seen_global: Optional[Set[str]] = None,
) -> bool:
    """Record a symlink for later materialisation by the manifest renderer."""

    if seen_global is not None and abs_path in seen_global:
        return False
    if seen_role is not None and abs_path in seen_role:
        return False

    def _mark_seen() -> None:
        if seen_role is not None:
            seen_role.add(abs_path)
        if seen_global is not None:
            seen_global.add(abs_path)

    if path_filter.is_excluded(abs_path):
        excluded_out.append(ExcludedFile(path=abs_path, reason="user_excluded"))
        _mark_seen()
        return False

    deny_link = getattr(policy, "deny_reason_link", None)
    if callable(deny_link):
        deny = deny_link(abs_path)
    else:
        deny = policy.deny_reason(abs_path)
        if deny in ("not_regular_file", "not_file", "not_regular"):
            deny = None

    if deny:
        excluded_out.append(ExcludedFile(path=abs_path, reason=deny))
        _mark_seen()
        return False

    if not os.path.islink(abs_path):
        excluded_out.append(ExcludedFile(path=abs_path, reason="not_symlink"))
        _mark_seen()
        return False

    try:
        target = os.readlink(abs_path)
    except OSError:
        excluded_out.append(ExcludedFile(path=abs_path, reason="unreadable"))
        _mark_seen()
        return False

    managed_out.append(ManagedLink(path=abs_path, target=target, reason=reason))
    _mark_seen()
    return True
