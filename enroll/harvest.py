from __future__ import annotations

import glob
import os
import re
import shutil
import shlex
import stat
import subprocess  # nosec
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Set, Tuple

from . import accounts as _accounts
from . import systemd as _systemd
from .role_names import avoid_reserved_role_name
from .fsutil import stat_triplet
from .platform import detect_platform, get_backend
from .ignore import IgnorePolicy
from .pathfilter import PathFilter
from .version import get_enroll_version
from .state import write_state

UnitQueryError = _systemd.UnitQueryError


def list_enabled_services() -> List[str]:
    return _systemd.list_enabled_services()


def list_enabled_timers() -> List[str]:
    return _systemd.list_enabled_timers()


def get_unit_info(unit: str) -> Any:
    return _systemd.get_unit_info(unit)


def get_timer_info(timer: str) -> Any:
    return _systemd.get_timer_info(timer)


def collect_non_system_users() -> List[Any]:
    return _accounts.collect_non_system_users()


@dataclass
class ManagedFile:
    path: str
    src_rel: str
    owner: str
    group: str
    mode: str
    reason: str


@dataclass
class ManagedLink:
    """A symlink we want to materialise on the target host.

    For configuration enablement patterns (e.g. sites-enabled), the symlink is
    meaningful state even when the link target is captured elsewhere.
    """

    path: str
    target: str
    reason: str


@dataclass
class ManagedDir:
    path: str
    owner: str
    group: str
    mode: str
    reason: str


@dataclass
class ExcludedFile:
    path: str
    reason: str


@dataclass
class ServiceSnapshot:
    unit: str
    role_name: str
    packages: List[str]
    active_state: Optional[str]
    sub_state: Optional[str]
    unit_file_state: Optional[str]
    condition_result: Optional[str]
    managed_dirs: List[ManagedDir] = field(default_factory=list)
    managed_files: List[ManagedFile] = field(default_factory=list)
    managed_links: List[ManagedLink] = field(default_factory=list)
    excluded: List[ExcludedFile] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class PackageSnapshot:
    package: str
    role_name: str
    section: Optional[str] = None
    managed_dirs: List[ManagedDir] = field(default_factory=list)
    managed_files: List[ManagedFile] = field(default_factory=list)
    managed_links: List[ManagedLink] = field(default_factory=list)
    excluded: List[ExcludedFile] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    has_config: bool = True  # False if package has no config/systemd/cron files


@dataclass
class UsersSnapshot:
    role_name: str
    users: List[dict]
    managed_dirs: List[ManagedDir] = field(default_factory=list)
    managed_files: List[ManagedFile] = field(default_factory=list)
    excluded: List[ExcludedFile] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    user_flatpaks: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    user_flatpak_remotes: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class FlatpakSnapshot:
    role_name: str
    system_flatpaks: List[Dict[str, Any]] = field(default_factory=list)
    remotes: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class SnapSnapshot:
    role_name: str
    system_snaps: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class AptConfigSnapshot:
    role_name: str
    managed_dirs: List[ManagedDir] = field(default_factory=list)
    managed_files: List[ManagedFile] = field(default_factory=list)
    excluded: List[ExcludedFile] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class DnfConfigSnapshot:
    role_name: str
    managed_dirs: List[ManagedDir] = field(default_factory=list)
    managed_files: List[ManagedFile] = field(default_factory=list)
    excluded: List[ExcludedFile] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class EtcCustomSnapshot:
    role_name: str
    managed_dirs: List[ManagedDir] = field(default_factory=list)
    managed_files: List[ManagedFile] = field(default_factory=list)
    excluded: List[ExcludedFile] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class UsrLocalCustomSnapshot:
    role_name: str
    managed_dirs: List[ManagedDir] = field(default_factory=list)
    managed_files: List[ManagedFile] = field(default_factory=list)
    excluded: List[ExcludedFile] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class ExtraPathsSnapshot:
    role_name: str
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    managed_dirs: List[ManagedDir] = field(default_factory=list)
    managed_files: List[ManagedFile] = field(default_factory=list)
    managed_links: List[ManagedLink] = field(default_factory=list)
    excluded: List[ExcludedFile] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class FirewallRuntimeSnapshot:
    role_name: str
    packages: List[str] = field(default_factory=list)
    ipset_save: Optional[str] = None
    ipset_sets: List[str] = field(default_factory=list)
    iptables_v4_save: Optional[str] = None
    iptables_v6_save: Optional[str] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class SysctlSnapshot:
    role_name: str
    managed_files: List[ManagedFile] = field(default_factory=list)
    parameters: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


ALLOWED_UNOWNED_EXTS = {
    ".cfg",
    ".cnf",
    ".conf",
    ".ini",
    ".json",
    ".link",
    ".mount",
    ".netdev",
    ".network",
    ".path",
    ".rules",
    ".service",
    ".socket",
    ".target",
    ".timer",
    ".toml",
    ".yaml",
    ".yml",
    "",  # allow extensionless (common in /etc/default and /etc/init.d)
}

MAX_FILES_CAP = 4000
MAX_UNOWNED_FILES_PER_ROLE = 500


def _files_differ(a: str, b: str, *, max_bytes: int = 2_000_000) -> bool:
    """Return True if file `a` differs from file `b`.

    Best-effort and conservative:
      - If `b` (baseline) does not exist or is not a regular file, treat as
        "different" so we err on the side of capturing user state.
      - If we can't stat/read either file, treat as "different" (capture will
        later be filtered via IgnorePolicy).
      - If files are large, avoid reading them fully.
    """

    try:
        st_a = os.stat(a, follow_symlinks=True)
    except OSError:
        return True

    # Refuse to do content comparisons on non-regular files.
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

    # If it's unexpectedly big, treat as different to avoid expensive reads.
    if st_a.st_size > max_bytes:
        return True

    try:
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                ca = fa.read(1024 * 64)
                cb = fb.read(1024 * 64)
                if ca != cb:
                    return True
                if not ca:  # EOF on both
                    return False
    except OSError:
        return True


def _merge_parent_dirs(
    existing_dirs: List[ManagedDir],
    managed_files: List[ManagedFile],
    *,
    policy: IgnorePolicy,
    extra_paths: Optional[List[str]] = None,
) -> List[ManagedDir]:
    """Ensure parent directories for managed_files are present in managed_dirs.

    This is used so the Ansible manifest can create destination directories with
    explicit owner/group/mode (ansible-lint friendly) without needing a separate
    "mkdir without perms" task.

    We only add the immediate parent directory for each managed file. For
    explicit directory includes (extra_paths), existing_dirs will already
    contain the walked directory tree.
    """
    by_path: Dict[str, ManagedDir] = {
        d.path: d for d in (existing_dirs or []) if d.path
    }

    def _iter_paths() -> List[str]:
        paths: List[str] = []
        for mf in managed_files or []:
            if mf and mf.path:
                paths.append(str(mf.path))
        for p in extra_paths or []:
            if p:
                paths.append(str(p))
        return paths

    for p0 in _iter_paths():
        p = str(p0 or "").rstrip("/")
        if not p:
            continue
        dpath = os.path.dirname(p)
        if not dpath or dpath == "/":
            continue
        if dpath in by_path:
            continue

        # Directory-deny logic: newer IgnorePolicy implementations provide
        # deny_reason_dir(). Older/simple policies (including unit tests) may
        # only implement deny_reason(), which is file-oriented and may return
        # "not_regular_file" for directories.
        deny = None
        deny_dir = getattr(policy, "deny_reason_dir", None)
        if callable(deny_dir):
            deny = deny_dir(dpath)
        else:
            deny = policy.deny_reason(dpath)
            if deny in ("not_regular_file", "not_file", "not_regular"):
                deny = None
        if deny:
            # If the file itself was captured, its parent directory is likely safe,
            # but still respect deny globs for directories to avoid managing
            # sensitive/forbidden trees.
            continue

        try:
            owner, group, mode = stat_triplet(dpath)
        except OSError:
            continue

        by_path[dpath] = ManagedDir(
            path=dpath,
            owner=owner,
            group=group,
            mode=mode,
            reason="parent_of_managed_file",
        )

    return [by_path[k] for k in sorted(by_path)]


# Directories that are shared across many packages.
# Never attribute all unowned files in these trees
# to one single package.
SHARED_ETC_TOPDIRS = {
    "apparmor.d",
    "apt",
    "cron.d",
    "cron.daily",
    "cron.weekly",
    "cron.monthly",
    "cron.hourly",
    "default",
    "init.d",
    "logrotate.d",
    "modprobe.d",
    "network",
    "pam.d",
    "ssh",
    "ssl",
    "sudoers.d",
    "sysctl.d",
    "systemd",
    # RPM-family shared trees
    "dnf",
    "yum",
    "yum.repos.d",
    "sysconfig",
    "pki",
    "firewalld",
}


def _safe_name(s: str) -> str:
    out: List[str] = []
    for ch in s:
        out.append(ch if ch.isalnum() or ch in ("_", "-") else "_")
    return "".join(out).replace("-", "_")


def _role_id(raw: str) -> str:
    # normalise separators first
    s = re.sub(r"[^A-Za-z0-9]+", "_", raw)
    # split CamelCase -> snake_case
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = s.lower()
    s = re.sub(r"_+", "_", s).strip("_")
    if not re.match(r"^[a-z_]", s):
        s = "r_" + s
    return s


def _role_name_from_unit(unit: str) -> str:
    base = _role_id(unit.removesuffix(".service"))
    return avoid_reserved_role_name(_safe_name(base), prefix="service")


def _role_name_from_pkg(pkg: str) -> str:
    return avoid_reserved_role_name(_safe_name(pkg), prefix="package")


def _package_section_from_installations(
    installs: List[Dict[str, str]],
) -> Optional[str]:
    """Return a stable package grouping label from installed package metadata.

    Debian exposes this as ``Section``. RPM-family distributions have a broadly
    similar ``Group`` tag, although modern Fedora/RHEL packages may omit it or
    set it to ``Unspecified``.
    """

    values: Set[str] = set()
    for inst in installs or []:
        value = (inst.get("section") or inst.get("group") or "").strip()
        if not value:
            continue
        if value.lower() in {"(none)", "none", "unspecified"}:
            continue
        values.add(value)

    if not values:
        return None
    return sorted(values)[0]


def _copy_into_bundle(
    bundle_dir: str, role_name: str, abs_path: str, src_rel: str
) -> None:
    dst = os.path.join(bundle_dir, "artifacts", role_name, src_rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(abs_path, dst)


def _capture_file(
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

    Returns True if the file was copied (managed), False otherwise.

    * seen_role: de-dupe within a role (prevents duplicate tasks/records)
    * seen_global: de-dupe across roles/stages (prevents multiple roles copying same path)
    * metadata: optional (owner, group, mode) tuple to avoid re-statting
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
        _copy_into_bundle(bundle_dir, role_name, abs_path, src_rel)
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


def _capture_user_shell_dotfiles(
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
    """Capture selected per-user shell dotfiles when explicitly enabled.

    Shell startup files are useful for reproducing interactive accounts, but they
    commonly contain exported tokens, passwords, command aliases with embedded
    credentials, and other private context. For that reason, automatic capture is
    gated by harvest's dangerous mode. Users who want a narrower safe-mode
    selection can still use --include-path, which lands in the extra_paths role
    and remains subject to IgnorePolicy content checks.
    """

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
        if not _files_differ(upath, skel_path, max_bytes=max_compare_bytes):
            continue
        if _capture_file(
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
        if _capture_file(
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


def _capture_link(
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
    """Try to capture a symlink into the manifest.

    NOTE: Symlinks are *not* copied into artifacts; we record their link target
    and materialise them via ansible.builtin.file state=link.
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

    deny_link = getattr(policy, "deny_reason_link", None)
    if callable(deny_link):
        deny = deny_link(abs_path)
    else:
        # Fallback: apply deny_reason() but treat "not_regular_file" as acceptable
        # for symlinks.
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


def _is_confish(path: str) -> bool:
    base = os.path.basename(path)
    _, ext = os.path.splitext(base)
    return ext in ALLOWED_UNOWNED_EXTS


def _hint_names(unit: str, pkgs: Set[str]) -> Set[str]:
    base = unit.removesuffix(".service")
    hints = {base}
    if "@" in base:
        hints.add(base.split("@", 1)[0])
    hints |= set(pkgs)
    hints |= {h.split(".", 1)[0] for h in list(hints) if "." in h}
    return {h for h in hints if h}


def _add_pkgs_from_etc_topdirs(
    hints: Set[str], topdir_to_pkgs: Dict[str, Set[str]], pkgs: Set[str]
) -> None:
    """Expand a service's package set using dpkg-owned /etc top-level dirs.

    This is a heuristic: many Debian packages split a service across multiple
    packages (e.g. nginx + nginx-common) while sharing a single /etc/<name>
    tree.

    We intentionally *avoid* using shared trees (e.g. /etc/cron.d, /etc/ssl,
    /etc/apparmor.d) to expand package sets, because many unrelated packages
    legitimately install files there.

    We also consider the common ".d" variant (e.g. hint "apparmor" ->
    topdir "apparmor.d") so we can explicitly skip known shared trees.
    """

    for h in hints:
        for top in (h, f"{h}.d"):
            if top in SHARED_ETC_TOPDIRS:
                continue
            for p in topdir_to_pkgs.get(top, set()):
                pkgs.add(p)


def _maybe_add_specific_paths(hints: Set[str], backend) -> List[str]:
    # Delegate to backend-specific conventions (e.g. /etc/default on Debian,
    # /etc/sysconfig on Fedora/RHEL). Always include sysctl.d.
    try:
        return backend.specific_paths_for_hints(hints)
    except Exception:
        # Best-effort fallback (Debian-ish).
        paths: List[str] = []
        for h in hints:
            paths.extend(
                [
                    f"/etc/default/{h}",
                    f"/etc/init.d/{h}",
                    f"/etc/sysctl.d/{h}.conf",
                ]
            )
        return paths


def _scan_unowned_under_roots(
    roots: List[str],
    owned_etc: Set[str],
    limit: int = MAX_UNOWNED_FILES_PER_ROLE,
    *,
    confish_only: bool = True,
) -> List[str]:
    found: List[str] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            if len(found) >= limit:
                return found
            for fn in filenames:
                if len(found) >= limit:
                    return found
                p = os.path.join(dirpath, fn)
                if not p.startswith("/etc/"):
                    continue
                if p in owned_etc:
                    continue
                if not os.path.isfile(p) or os.path.islink(p):
                    continue
                if confish_only and not _is_confish(p):
                    continue
                found.append(p)
    return found


def _topdirs_for_package(pkg: str, pkg_to_etc_paths: Dict[str, List[str]]) -> Set[str]:
    topdirs: Set[str] = set()
    for path in pkg_to_etc_paths.get(pkg, []):
        parts = path.split("/", 3)
        if len(parts) >= 3 and parts[1] == "etc" and parts[2]:
            topdirs.add(parts[2])
    return topdirs


# -------------------------
# System capture helpers
# -------------------------

_APT_SOURCE_GLOBS = [
    "/etc/apt/sources.list",
    "/etc/apt/sources.list.d/*.list",
    "/etc/apt/sources.list.d/*.sources",
]

_APT_MISC_GLOBS = [
    "/etc/apt/apt.conf",
    "/etc/apt/apt.conf.d/*",
    "/etc/apt/preferences",
    "/etc/apt/preferences.d/*",
    "/etc/apt/auth.conf",
    "/etc/apt/auth.conf.d/*",
    "/etc/apt/trusted.gpg",
    "/etc/apt/trusted.gpg.d/*",
    "/etc/apt/keyrings/*",
]

_SYSTEM_CAPTURE_GLOBS: List[tuple[str, str]] = [
    # mounts
    ("/etc/fstab", "system_mounts"),
    ("/etc/crypttab", "system_mounts"),
    # sysctl / modules
    ("/etc/sysctl.conf", "system_sysctl"),
    ("/etc/sysctl.d/*", "system_sysctl"),
    ("/etc/modprobe.d/*", "system_modprobe"),
    ("/etc/modules", "system_modprobe"),
    ("/etc/modules-load.d/*", "system_modprobe"),
    # network
    ("/etc/netplan/*", "system_network"),
    ("/etc/systemd/network/*", "system_network"),
    ("/etc/network/interfaces", "system_network"),
    ("/etc/network/interfaces.d/*", "system_network"),
    ("/etc/resolvconf.conf", "system_network"),
    ("/etc/resolvconf/resolv.conf.d/*", "system_network"),
    ("/etc/NetworkManager/system-connections/*", "system_network"),
    ("/etc/sysconfig/network*", "system_network"),
    ("/etc/sysconfig/network-scripts/*", "system_network"),
    # firewall
    ("/etc/nftables.conf", "system_firewall"),
    ("/etc/nftables.d/*", "system_firewall"),
    ("/etc/iptables/rules.v4", "system_firewall"),
    ("/etc/iptables/rules.v6", "system_firewall"),
    ("/etc/sysconfig/iptables", "system_firewall"),
    ("/etc/sysconfig/ip6tables", "system_firewall"),
    ("/etc/ipset.conf", "system_firewall"),
    ("/etc/ipset/*", "system_firewall"),
    ("/etc/ipset.d/*", "system_firewall"),
    ("/etc/sysconfig/ipset", "system_firewall"),
    ("/etc/default/ipset", "system_firewall"),
    ("/etc/ufw/*", "system_firewall"),
    ("/etc/default/ufw", "system_firewall"),
    ("/etc/firewalld/*", "system_firewall"),
    ("/etc/firewalld/zones/*", "system_firewall"),
    # SELinux
    ("/etc/selinux/config", "system_security"),
    # other
    ("/etc/rc.local", "system_rc"),
]


# Persistent firewall files that are treated as authoritative for their
# respective runtime state. If any matching file exists, the runtime capture
# for that family is retained only as static managed-file harvest output and
# not duplicated through the generated firewall_runtime role.
_PERSISTENT_IPTABLES_V4_GLOBS = [
    "/etc/iptables/rules.v4",
    "/etc/sysconfig/iptables",
]

_PERSISTENT_IPTABLES_V6_GLOBS = [
    "/etc/iptables/rules.v6",
    "/etc/sysconfig/ip6tables",
]

_PERSISTENT_IPSET_GLOBS = [
    "/etc/ipset.conf",
    "/etc/ipset/*",
    "/etc/ipset.d/*",
    "/etc/sysconfig/ipset",
]


def _persistent_firewall_files(globs: List[str]) -> List[str]:
    """Return persistent firewall files matching ``globs``.

    This intentionally uses the same file walking helper as the static system
    capture path so the runtime fallback decision matches what Enroll can
    harvest as managed files.
    """
    seen: Set[str] = set()
    out: List[str] = []
    for spec in globs:
        for path in _iter_matching_files(spec):
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return sorted(out)


def _iter_matching_files(spec: str, *, cap: int = MAX_FILES_CAP) -> List[str]:
    """Expand a glob spec and also walk directories to collect files."""
    out: List[str] = []
    for p in glob.glob(spec):
        if len(out) >= cap:
            break
        if os.path.islink(p):
            continue
        if os.path.isfile(p):
            out.append(p)
            continue
        if os.path.isdir(p):
            for dirpath, _, filenames in os.walk(p):
                for fn in filenames:
                    if len(out) >= cap:
                        break
                    fp = os.path.join(dirpath, fn)
                    if os.path.islink(fp) or not os.path.isfile(fp):
                        continue
                    out.append(fp)
                if len(out) >= cap:
                    break
    return out


def _parse_apt_signed_by(source_files: List[str]) -> Set[str]:
    """Return absolute keyring paths referenced via signed-by / Signed-By."""
    out: Set[str] = set()

    # deb line: deb [signed-by=/usr/share/keyrings/foo.gpg] ...
    re_signed_by = re.compile(r"signed-by\s*=\s*([^\]\s]+)", re.IGNORECASE)
    # deb822: Signed-By: /usr/share/keyrings/foo.gpg
    re_signed_by_hdr = re.compile(r"^\s*Signed-By\s*:\s*(.+)$", re.IGNORECASE)

    for sf in source_files:
        try:
            with open(sf, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue

                    m = re_signed_by_hdr.match(line)
                    if m:
                        val = m.group(1).strip()
                        if val.startswith("|"):
                            continue
                        toks = re.split(r"[\s,]+", val)
                        for t in toks:
                            if t.startswith("/"):
                                out.add(t)
                        continue

                    # Try bracketed options first (common for .list files)
                    if "[" in line and "]" in line:
                        bracket = line.split("[", 1)[1].split("]", 1)[0]
                        for mm in re_signed_by.finditer(bracket):
                            val = mm.group(1).strip().strip("\"'")
                            for t in re.split(r"[\s,]+", val):
                                if t.startswith("/"):
                                    out.add(t)
                        continue

                    # Fallback: signed-by= in whole line
                    for mm in re_signed_by.finditer(line):
                        val = mm.group(1).strip().strip("\"'")
                        for t in re.split(r"[\s,]+", val):
                            if t.startswith("/"):
                                out.add(t)
        except OSError:
            continue

    return out


def _iter_apt_capture_paths() -> List[tuple[str, str]]:
    """Return (path, reason) pairs for APT configuration.

    This captures the full /etc/apt tree (subject to IgnorePolicy at copy time),
    plus any keyrings referenced via signed-by/Signed-By which may live outside
    /etc (e.g. /usr/share/keyrings).
    """
    reasons: Dict[str, str] = {}

    # Capture all regular files under /etc/apt (no symlinks).
    if os.path.isdir("/etc/apt"):
        for dirpath, _, filenames in os.walk("/etc/apt"):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                reasons.setdefault(p, "apt_config")

    # Identify source files explicitly for nicer reasons and keyring discovery.
    apt_sources: List[str] = []
    for g in _APT_SOURCE_GLOBS:
        apt_sources.extend(_iter_matching_files(g))
    for p in sorted(set(apt_sources)):
        reasons[p] = "apt_source"

    # Keyrings in standard locations.
    for g in (
        "/etc/apt/trusted.gpg",
        "/etc/apt/trusted.gpg.d/*",
        "/etc/apt/keyrings/*",
    ):
        for p in _iter_matching_files(g):
            reasons[p] = "apt_keyring"

    # Keyrings referenced by sources (may live outside /etc/apt).
    signed_by = _parse_apt_signed_by(sorted(set(apt_sources)))
    for p in sorted(signed_by):
        if os.path.islink(p) or not os.path.isfile(p):
            continue
        if p.startswith("/etc/apt/"):
            reasons[p] = "apt_keyring"
        else:
            reasons[p] = "apt_signed_by_keyring"

    # De-dup with stable ordering.
    uniq: List[tuple[str, str]] = []
    for p in sorted(reasons.keys()):
        uniq.append((p, reasons[p]))
    return uniq


def _iter_dnf_capture_paths() -> List[tuple[str, str]]:
    """Return (path, reason) pairs for DNF/YUM configuration on RPM systems.

    Captures:
      - /etc/dnf/* (dnf.conf, vars, plugins, modules, automatic)
      - /etc/yum.conf (legacy)
      - /etc/yum.repos.d/*.repo
      - /etc/pki/rpm-gpg/* (GPG key files)
    """
    reasons: Dict[str, str] = {}

    for root, tag in (
        ("/etc/dnf", "dnf_config"),
        ("/etc/yum", "yum_config"),
    ):
        if os.path.isdir(root):
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    p = os.path.join(dirpath, fn)
                    if os.path.islink(p) or not os.path.isfile(p):
                        continue
                    reasons.setdefault(p, tag)

    # Legacy yum.conf.
    if os.path.isfile("/etc/yum.conf") and not os.path.islink("/etc/yum.conf"):
        reasons.setdefault("/etc/yum.conf", "yum_conf")

    # Repositories.
    if os.path.isdir("/etc/yum.repos.d"):
        for p in _iter_matching_files("/etc/yum.repos.d/*.repo"):
            reasons[p] = "yum_repo"

    # RPM GPG keys.
    if os.path.isdir("/etc/pki/rpm-gpg"):
        for dirpath, _, filenames in os.walk("/etc/pki/rpm-gpg"):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                reasons.setdefault(p, "rpm_gpg_key")

    # Stable ordering.
    return [(p, reasons[p]) for p in sorted(reasons.keys())]


def _iter_system_capture_paths() -> List[tuple[str, str]]:
    """Return (path, reason) pairs for essential system config/state (non-APT)."""
    out: List[tuple[str, str]] = []

    for spec, reason in _SYSTEM_CAPTURE_GLOBS:
        for p in _iter_matching_files(spec):
            out.append((p, reason))

    # De-dup while preserving first reason
    seen: Set[str] = set()
    uniq: List[tuple[str, str]] = []
    for p, r in out:
        if p in seen:
            continue
        seen.add(p)
        uniq.append((p, r))
    return uniq


_FIREWALL_CAPTURE_COMMANDS: Dict[str, Tuple[str, ...]] = {
    "ipset_save": ("ipset", "save"),
    "iptables_v4_save": ("iptables-save",),
    "iptables_v6_save": ("ip6tables-save",),
    "sysctl_all": ("sysctl", "-a"),
}


def _run_capture_command(
    command_key: str, *, timeout: int = 10
) -> tuple[Optional[str], Optional[str]]:
    """Return (stdout, error_note) for an allowlisted local state command.

    The command key is resolved through ``_FIREWALL_CAPTURE_COMMANDS`` so this
    helper never executes caller-supplied argv. Commands are run with
    ``shell=False`` explicitly to avoid shell interpretation.
    """
    argv = _FIREWALL_CAPTURE_COMMANDS.get(command_key)
    if argv is None:
        return None, f"Unknown capture command: {command_key}"

    exe = argv[0]
    if shutil.which(exe) is None:
        return None, f"{exe} not found on PATH."

    try:
        proc = subprocess.run(  # nosec
            argv,
            shell=False,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except Exception as e:  # noqa: BLE001
        return None, f"{' '.join(argv)} failed: {e!r}"

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        if len(stderr) > 300:
            stderr = stderr[:297] + "..."
        return (
            None,
            f"{' '.join(argv)} exited {proc.returncode}: {stderr or '(no stderr)'}",
        )

    return proc.stdout or "", None


def _write_generated_artifact(
    bundle_dir: str, role_name: str, src_rel: str, content: str
) -> None:
    """Write a generated harvest artifact that did not exist as a file on disk."""
    dst = os.path.join(bundle_dir, "artifacts", role_name, src_rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "w", encoding="utf-8") as f:
        f.write(content)


_SYSCTL_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SYSCTL_GENERATED_DEST = "/etc/sysctl.d/99-enroll.conf"
_SYSCTL_GENERATED_SRC_REL = "sysctl/99-enroll.conf"

# Writable-looking action/identity keys that are poor candidates for persistent
# config. This avoids generating a file that tries to replay one-shot triggers or
# host identity that should be managed elsewhere (e.g. /etc/hostname).
_SYSCTL_VOLATILE_KEYS = {
    "fs.binfmt_misc.status",
    "kernel.domainname",
    "kernel.hostname",
    "kernel.kexec_load_disabled",
    "kernel.kexec_load_limit_panic",
    "kernel.kexec_load_limit_reboot",
    "kernel.max_rcu_stall_to_panic",
    "kernel.modules_disabled",
    "kernel.ns_last_pid",
    "net.ipv4.route.flush",
    "net.ipv6.route.flush",
    "vm.compact_memory",
    "vm.drop_caches",
    "vm.stat_refresh",
}

_SYSCTL_VOLATILE_PREFIXES = (
    "fs.binfmt_misc.",
    "kernel.sched_domain.",
)

# These are paired with ratio/byte counterparts. The inactive side appears as 0
# when read; replaying that 0 through sysctl -p is noisy and can be rejected by
# kernels that enforce minimum values.
_SYSCTL_SKIP_ZERO_VALUE_KEYS = {
    "vm.dirty_background_bytes",
    "vm.dirty_background_ratio",
    "vm.dirty_bytes",
    "vm.dirty_ratio",
}


def _sysctl_proc_path(key: str) -> str:
    return "/proc/sys/" + key.replace(".", "/")


def _sysctl_key_is_persistable(key: str) -> tuple[bool, str]:
    if not key or not _SYSCTL_KEY_RE.fullmatch(key):
        return False, "invalid key"
    if key in _SYSCTL_VOLATILE_KEYS or any(
        key.startswith(prefix) for prefix in _SYSCTL_VOLATILE_PREFIXES
    ):
        return False, "volatile/action key"

    proc_path = _sysctl_proc_path(key)
    try:
        st = os.stat(proc_path)
    except OSError:
        return False, "no /proc/sys entry"

    if not stat.S_ISREG(st.st_mode):
        return False, "not a regular /proc/sys entry"
    if (stat.S_IMODE(st.st_mode) & 0o222) == 0:
        return False, "read-only /proc/sys entry"
    return True, ""


def _sysctl_entry_is_persistable(key: str, value: str) -> tuple[bool, str]:
    ok, reason = _sysctl_key_is_persistable(key)
    if not ok:
        return ok, reason

    if key in _SYSCTL_SKIP_ZERO_VALUE_KEYS and str(value).strip() == "0":
        return False, "inactive mutually-exclusive zero value"

    return True, ""


def _parse_sysctl_a_output(
    text: str,
    *,
    require_persistable: bool = True,
) -> tuple[Dict[str, str], Dict[str, int]]:
    """Parse `sysctl -a` output into persistable key/value pairs.

    `sysctl -a` includes read-only, write-only, multiline, action-like, and
    host-identity values. Persisting those can create noisy or failing Ansible
    runs, so the default parser keeps only single-line writable-looking keys.
    """

    out: Dict[str, str] = {}
    skipped: Dict[str, int] = {
        "malformed": 0,
        "empty_value": 0,
        "non_persistable": 0,
        "duplicate": 0,
    }

    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
        elif "=" in line:
            key, value = line.split("=", 1)
        else:
            skipped["malformed"] += 1
            continue

        key = key.strip()
        value = value.strip()
        if not key:
            skipped["malformed"] += 1
            continue
        if value == "":
            skipped["empty_value"] += 1
            continue
        if key in out:
            skipped["duplicate"] += 1
            continue
        if require_persistable:
            ok, _reason = _sysctl_entry_is_persistable(key, value)
            if not ok:
                skipped["non_persistable"] += 1
                continue
        out[key] = value

    return dict(sorted(out.items())), skipped


def _render_sysctl_conf(parameters: Dict[str, str], notes: List[str]) -> str:
    lines = [
        "# Generated by Enroll from live sysctl state.",
        "# Review before applying broadly; runtime sysctl state can be host/kernel-specific.",
    ]
    for note in notes:
        lines.append(f"# {note}")
    lines.append("")
    for key, value in sorted((parameters or {}).items()):
        safe_value = str(value).replace("\n", " ").strip()
        lines.append(f"{key} = {safe_value}")
    lines.append("")
    return "\n".join(lines)


def _collect_sysctl_snapshot(bundle_dir: str) -> SysctlSnapshot:
    role_name = "sysctl"
    notes: List[str] = []
    managed_files: List[ManagedFile] = []

    out, err = _run_capture_command("sysctl_all", timeout=20)
    if err:
        notes.append(err)
        return SysctlSnapshot(role_name=role_name, notes=notes)

    parameters, skipped = _parse_sysctl_a_output(out or "")
    if not parameters:
        notes.append("No persistable live sysctl parameters were detected.")
        return SysctlSnapshot(role_name=role_name, parameters=parameters, notes=notes)

    notes.append(f"Captured {len(parameters)} live writable sysctl parameter(s).")
    skipped_total = sum(skipped.values())
    if skipped_total:
        details = ", ".join(f"{k}={v}" for k, v in sorted(skipped.items()) if v)
        notes.append(
            "Skipped "
            f"{skipped_total} sysctl entr{'y' if skipped_total == 1 else 'ies'} "
            f"that were not suitable for persistence ({details})."
        )

    _write_generated_artifact(
        bundle_dir,
        role_name,
        _SYSCTL_GENERATED_SRC_REL,
        _render_sysctl_conf(parameters, notes),
    )
    managed_files.append(
        ManagedFile(
            path=_SYSCTL_GENERATED_DEST,
            src_rel=_SYSCTL_GENERATED_SRC_REL,
            owner="root",
            group="root",
            mode="0644",
            reason="system_sysctl",
        )
    )
    return SysctlSnapshot(
        role_name=role_name,
        managed_files=managed_files,
        parameters=parameters,
        notes=notes,
    )


def _ipset_save_has_state(text: str) -> bool:
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("create ", "add ")):
            return True
    return False


def _parse_ipset_set_names(text: str) -> List[str]:
    names: List[str] = []
    seen: Set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            toks = shlex.split(line)
        except ValueError:
            toks = line.split()
        if len(toks) >= 2 and toks[0] == "create" and toks[1] not in seen:
            seen.add(toks[1])
            names.append(toks[1])
    return names


def _iptables_save_has_state(text: str) -> bool:
    """Return True when iptables-save output contains non-default state."""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*") or line == "COMMIT":
            continue
        if line.startswith(":"):
            parts = line.split()
            chain_name = parts[0][1:] if parts else ""
            policy = parts[1] if len(parts) >= 2 else ""
            # Built-in empty chains usually look like ':INPUT ACCEPT [0:0]'.
            # A changed policy, or any custom chain, is meaningful state.
            if policy not in ("ACCEPT", "-"):
                return True
            if policy == "-" and chain_name:
                return True
            continue
        if line.startswith(("-A ", "-I ", "-N ", "-P ", "-R ")):
            return True
    return False


def _collect_firewall_runtime_snapshot(
    bundle_dir: str,
    *,
    persistent_ipset_files: Optional[List[str]] = None,
    persistent_iptables_v4_files: Optional[List[str]] = None,
    persistent_iptables_v6_files: Optional[List[str]] = None,
) -> FirewallRuntimeSnapshot:
    """Capture live kernel firewall state only when no persistent config exists.

    Enroll also harvests persistent firewall files such as
    /etc/iptables/rules.v4, /etc/iptables/rules.v6, and /etc/ipset.conf as
    managed files. The generated runtime restore role is therefore a fallback:
    it captures each firewall family only when that family has no persistent
    file to avoid generating two roles that try to manage the same state.
    """
    role_name = "firewall_runtime"
    packages: Set[str] = set()
    notes: List[str] = []
    ipset_save_rel: Optional[str] = None
    ipset_sets: List[str] = []
    iptables_v4_rel: Optional[str] = None
    iptables_v6_rel: Optional[str] = None

    persistent_ipset_files = persistent_ipset_files or []
    persistent_iptables_v4_files = persistent_iptables_v4_files or []
    persistent_iptables_v6_files = persistent_iptables_v6_files or []

    if persistent_ipset_files:
        notes.append(
            "Live ipset runtime capture skipped because persistent ipset "
            f"configuration was found: {', '.join(persistent_ipset_files)}"
        )
    else:
        ipset_out, ipset_err = _run_capture_command("ipset_save")
        if ipset_err:
            notes.append(ipset_err)
        elif ipset_out is not None and _ipset_save_has_state(ipset_out):
            ipset_save_rel = "firewall/ipset.save"
            _write_generated_artifact(bundle_dir, role_name, ipset_save_rel, ipset_out)
            ipset_sets = _parse_ipset_set_names(ipset_out)
            packages.add("ipset")

    if persistent_iptables_v4_files:
        notes.append(
            "Live IPv4 iptables runtime capture skipped because persistent "
            f"IPv4 iptables configuration was found: {', '.join(persistent_iptables_v4_files)}"
        )
    else:
        ipt4_out, ipt4_err = _run_capture_command("iptables_v4_save")
        if ipt4_err:
            notes.append(ipt4_err)
        elif ipt4_out is not None and _iptables_save_has_state(ipt4_out):
            iptables_v4_rel = "firewall/iptables.v4"
            _write_generated_artifact(bundle_dir, role_name, iptables_v4_rel, ipt4_out)
            packages.add("iptables")

    if persistent_iptables_v6_files:
        notes.append(
            "Live IPv6 iptables runtime capture skipped because persistent "
            f"IPv6 iptables configuration was found: {', '.join(persistent_iptables_v6_files)}"
        )
    else:
        ipt6_out, ipt6_err = _run_capture_command("iptables_v6_save")
        if ipt6_err:
            notes.append(ipt6_err)
        elif ipt6_out is not None and _iptables_save_has_state(ipt6_out):
            iptables_v6_rel = "firewall/iptables.v6"
            _write_generated_artifact(bundle_dir, role_name, iptables_v6_rel, ipt6_out)
            packages.add("iptables")

    # Package names are intentionally added only when matching live state was
    # captured. Merely having iptables/ipset installed should not create a role.

    return FirewallRuntimeSnapshot(
        role_name=role_name,
        packages=sorted(packages),
        ipset_save=ipset_save_rel,
        ipset_sets=ipset_sets,
        iptables_v4_save=iptables_v4_rel,
        iptables_v6_save=iptables_v6_rel,
        notes=notes,
    )


from .harvest_collectors import (
    CronLogrotateCollector,
    ExtraPathsCollector,
    HarvestContext,
    PackageManagerConfigCollector,
    RuntimeStateCollector,
    ServicePackageCollector,
    UsersCollector,
    UsrLocalCustomCollector,
)


def harvest(
    bundle_dir: str,
    policy: Optional[IgnorePolicy] = None,
    *,
    dangerous: bool = False,
    include_paths: Optional[List[str]] = None,
    exclude_paths: Optional[List[str]] = None,
) -> str:
    # If a policy is not supplied, build one. `--dangerous` relaxes secret
    # detection and deny-glob skipping.
    if policy is None:
        policy = IgnorePolicy(dangerous=dangerous)
    elif dangerous:
        # If callers explicitly provided a policy but also requested
        # dangerous behaviour, honour the CLI intent.
        policy.dangerous = True
    os.makedirs(bundle_dir, exist_ok=True)

    # User-provided includes/excludes. Excludes apply to all harvesting;
    # includes are harvested into an extra role.
    path_filter = PathFilter(include=include_paths or (), exclude=exclude_paths or ())

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "Warning: not running as root; harvest may miss files or metadata.",
            flush=True,
        )

    platform = detect_platform()
    backend = get_backend(platform)

    owned_etc, etc_owner_map, topdir_to_pkgs, pkg_to_etc_paths = (
        backend.build_etc_index()
    )

    # Global de-duplication across roles: each absolute path is captured at most once.
    # This avoids multiple Ansible roles managing the same destination file.
    captured_global: Set[str] = set()

    # -------------------------
    # Cron / logrotate unification
    #
    # If cron/logrotate are installed, capture all related configuration/state into
    # dedicated package roles ("cron" and "logrotate") so the same destination path
    # is never managed by unrelated roles.
    #
    # This includes user-specific crontabs under /var/spool, which means the cron role
    # should be applied after users have been created (handled in manifest ordering).
    # -------------------------

    installed_pkgs = backend.installed_packages() or {}
    installed_names: Set[str] = set(installed_pkgs.keys())

    persistent_ipset_files = _persistent_firewall_files(_PERSISTENT_IPSET_GLOBS)
    persistent_iptables_v4_files = _persistent_firewall_files(
        _PERSISTENT_IPTABLES_V4_GLOBS
    )
    persistent_iptables_v6_files = _persistent_firewall_files(
        _PERSISTENT_IPTABLES_V6_GLOBS
    )

    context = HarvestContext(
        bundle_dir=bundle_dir,
        policy=policy,
        path_filter=path_filter,
        platform=platform,
        backend=backend,
        installed_pkgs=installed_pkgs,
        installed_names=installed_names,
        owned_etc=owned_etc,
        etc_owner_map=etc_owner_map,
        topdir_to_pkgs=topdir_to_pkgs,
        pkg_to_etc_paths=pkg_to_etc_paths,
        captured_global=captured_global,
    )

    runtime_collection = RuntimeStateCollector(
        context,
        persistent_ipset_files=persistent_ipset_files,
        persistent_iptables_v4_files=persistent_iptables_v4_files,
        persistent_iptables_v6_files=persistent_iptables_v6_files,
    ).collect()
    firewall_runtime_snapshot = runtime_collection.firewall_runtime_snapshot
    sysctl_snapshot = runtime_collection.sysctl_snapshot

    # The generated sysctl role owns /etc/sysctl.d/99-enroll.conf; do not also
    # capture an existing file at that path into etc_custom/package roles.
    for mf in sysctl_snapshot.managed_files:
        captured_global.add(mf.path)

    cron_logrotate_collection = CronLogrotateCollector(context).collect()
    cron_pkg = cron_logrotate_collection.cron_pkg
    logrotate_pkg = cron_logrotate_collection.logrotate_pkg
    cron_snapshot = cron_logrotate_collection.cron_snapshot
    logrotate_snapshot = cron_logrotate_collection.logrotate_snapshot

    service_package_collection = ServicePackageCollector(
        context,
        cron_snapshot=cron_snapshot,
        logrotate_snapshot=logrotate_snapshot,
        cron_pkg=cron_pkg,
        logrotate_pkg=logrotate_pkg,
    ).collect()
    service_snaps = service_package_collection.service_snaps
    pkg_snaps = service_package_collection.pkg_snaps
    manual_pkgs = service_package_collection.manual_pkgs
    service_role_aliases = service_package_collection.service_role_aliases
    seen_by_role = service_package_collection.seen_by_role

    # -------------------------
    # Users role, Flatpak and Snap state
    # -------------------------
    users_collection = UsersCollector(context, seen_by_role).collect()
    users_snapshot = users_collection.users_snapshot
    flatpak_snapshot = users_collection.flatpak_snapshot
    snap_snapshot = users_collection.snap_snapshot

    # -------------------------
    # Package manager config role
    #   - Debian: apt_config
    #   - Fedora/RHEL-like: dnf_config
    # -------------------------
    package_manager_config = PackageManagerConfigCollector(
        context, seen_by_role
    ).collect()
    apt_config_snapshot = package_manager_config.apt_config_snapshot
    dnf_config_snapshot = package_manager_config.dnf_config_snapshot

    # -------------------------
    # etc_custom role (unowned /etc files not already attributed elsewhere)
    # -------------------------
    etc_notes: List[str] = []
    etc_excluded: List[ExcludedFile] = []
    etc_managed: List[ManagedFile] = []
    etc_role_name = "etc_custom"

    # Files already captured by earlier roles. Use the global set so we never
    # end up with the same destination path managed by multiple roles.
    already: Set[str] = captured_global

    # Maps for re-attributing shared snippets (cron.d/logrotate.d) to existing roles.
    svc_by_role: Dict[str, ServiceSnapshot] = {s.role_name: s for s in service_snaps}
    pkg_by_role: Dict[str, PackageSnapshot] = {p.role_name: p for p in pkg_snaps}

    # Package name -> role_name for manually-installed package roles.
    pkg_name_to_role: Dict[str, str] = {p.package: p.role_name for p in pkg_snaps}

    # Package name -> list of service role names that reference it.
    pkg_to_service_roles: Dict[str, List[str]] = {}
    for s in service_snaps:
        for pkg in s.packages:
            pkg_to_service_roles.setdefault(pkg, []).append(s.role_name)

    # Alias -> role mapping used as a fallback when package ownership is missing.
    # Prefer service roles over package roles when both would match.
    alias_ranked: Dict[str, tuple[int, str]] = {}

    def _add_alias(alias: str, role_name: str, *, priority: int) -> None:
        key = _safe_name(alias)
        if not key:
            return
        cur = alias_ranked.get(key)
        if (
            cur is None
            or priority < cur[0]
            or (priority == cur[0] and role_name < cur[1])
        ):
            alias_ranked[key] = (priority, role_name)

    for role_name, aliases in service_role_aliases.items():
        for a in aliases:
            _add_alias(a, role_name, priority=0)

    for p in pkg_snaps:
        _add_alias(p.package, p.role_name, priority=1)

    def _target_role_for_shared_snippet(path: str) -> Optional[tuple[str, str]]:
        """If `path` is a shared snippet, return (role_name, reason) to attach to.

        This is used primarily for /etc/logrotate.d/* and /etc/cron.d/* where
        files are "owned" by many packages but people tend to reason about them
        per service.

        Resolution order:
        1) package owner -> service role (if any service references the package)
        2) package owner -> package role (manual package role exists)
        3) basename/stem alias match -> preferred role
        """
        if path.startswith("/etc/logrotate.d/"):
            tag = "logrotate_snippet"
        elif path.startswith("/etc/cron.d/"):
            tag = "cron_snippet"
        else:
            return None

        base = os.path.basename(path)
        candidates: List[str] = [base]
        if "." in base:
            candidates.append(base.split(".", 1)[0])

        seen: Set[str] = set()
        uniq: List[str] = []
        for c in candidates:
            if c and c not in seen:
                seen.add(c)
                uniq.append(c)

        pkg = backend.owner_of_path(path)
        if pkg:
            svc_roles = sorted(set(pkg_to_service_roles.get(pkg, [])))
            if svc_roles:
                # If multiple service roles reference the same package, prefer
                # the role that most closely matches the snippet name (basename
                # or stem). This avoids surprising attributions such as an
                # AppArmor loader role "claiming" a cron/logrotate snippet
                # that is clearly named after another package/service.
                if len(svc_roles) > 1:
                    # Direct role-name matches first.
                    for c in [pkg, *uniq]:
                        rn = _safe_name(c)
                        if rn in svc_roles:
                            return (rn, tag)
                    # Next, use the alias map if it points at one of the roles.
                    for c in [pkg, *uniq]:
                        hit = alias_ranked.get(_safe_name(c))
                        if hit is not None and hit[1] in svc_roles:
                            return (hit[1], tag)

                # Deterministic fallback: lowest role name.
                return (svc_roles[0], tag)
            pkg_role = pkg_name_to_role.get(pkg)
            if pkg_role:
                return (pkg_role, tag)

        for c in uniq:
            key = _safe_name(c)
            hit = alias_ranked.get(key)
            if hit is not None:
                return (hit[1], tag)

        return None

    def _lists_for_role(role_name: str) -> tuple[List[ManagedFile], List[ExcludedFile]]:
        if role_name in svc_by_role:
            snap = svc_by_role[role_name]
            return (snap.managed_files, snap.excluded)
        if role_name in pkg_by_role:
            snap = pkg_by_role[role_name]
            return (snap.managed_files, snap.excluded)
        # Fallback (shouldn't normally happen): attribute to etc_custom.
        return (etc_managed, etc_excluded)

    # Capture essential system config/state (even if package-owned).
    etc_role_seen = seen_by_role.setdefault(etc_role_name, set())
    for path, reason in _iter_system_capture_paths():
        if path in already:
            continue

        target = _target_role_for_shared_snippet(path)
        if target is not None:
            role_for_copy, reason_for_role = target
            managed_out, excluded_out = _lists_for_role(role_for_copy)
            role_seen = seen_by_role.setdefault(role_for_copy, set())
        else:
            role_for_copy, reason_for_role = (etc_role_name, reason)
            managed_out, excluded_out = (etc_managed, etc_excluded)
            role_seen = etc_role_seen

        _capture_file(
            bundle_dir=bundle_dir,
            role_name=role_for_copy,
            abs_path=path,
            reason=reason_for_role,
            policy=policy,
            path_filter=path_filter,
            managed_out=managed_out,
            excluded_out=excluded_out,
            seen_role=role_seen,
            seen_global=captured_global,
        )

    # Walk /etc for remaining unowned config-ish files
    scanned = 0
    for dirpath, _, filenames in os.walk("/etc"):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if backend.is_pkg_config_path(path):
                continue
            if path in already:
                continue
            if path in owned_etc:
                continue
            if not os.path.isfile(path) or os.path.islink(path):
                continue
            if not _is_confish(path):
                continue

            target = _target_role_for_shared_snippet(path)
            if target is not None:
                role_for_copy, reason_for_role = target
                managed_out, excluded_out = _lists_for_role(role_for_copy)
                role_seen = seen_by_role.setdefault(role_for_copy, set())
            else:
                role_for_copy, reason_for_role = (etc_role_name, "custom_unowned")
                managed_out, excluded_out = (etc_managed, etc_excluded)
                role_seen = etc_role_seen

            if _capture_file(
                bundle_dir=bundle_dir,
                role_name=role_for_copy,
                abs_path=path,
                reason=reason_for_role,
                policy=policy,
                path_filter=path_filter,
                managed_out=managed_out,
                excluded_out=excluded_out,
                seen_role=role_seen,
                seen_global=captured_global,
            ):
                scanned += 1
            if scanned >= MAX_FILES_CAP:
                etc_notes.append(
                    f"Reached file cap ({MAX_FILES_CAP}) while scanning /etc for unowned files."
                )
                break
        if scanned >= MAX_FILES_CAP:
            break

    etc_custom_snapshot = EtcCustomSnapshot(
        role_name=etc_role_name,
        managed_files=etc_managed,
        excluded=etc_excluded,
        notes=etc_notes,
    )

    # -------------------------
    # usr_local_custom and extra_paths roles
    # -------------------------
    already_all: Set[str] = set(already)
    for mf in etc_managed:
        already_all.add(mf.path)

    usr_local_custom_snapshot = UsrLocalCustomCollector(
        context,
        seen_by_role,
        already_all,
    ).collect()

    extra_paths_snapshot = ExtraPathsCollector(
        context,
        seen_by_role,
        already_all,
        include_paths=include_paths,
        exclude_paths=exclude_paths,
    ).collect()

    # -------------------------
    # Inventory: packages (SBOM-ish)
    # -------------------------
    installed = installed_pkgs

    manual_set: Set[str] = set(manual_pkgs or [])

    pkg_units: Dict[str, Set[str]] = {}
    pkg_roles_map: Dict[str, Set[str]] = {}

    for svc in service_snaps:
        for p in svc.packages:
            pkg_units.setdefault(p, set()).add(svc.unit)
            pkg_roles_map.setdefault(p, set()).add(svc.role_name)

    pkg_role_names: Dict[str, List[str]] = {}
    for ps in pkg_snaps:
        pkg_roles_map.setdefault(ps.package, set()).add(ps.role_name)
        pkg_role_names.setdefault(ps.package, []).append(ps.role_name)

    pkg_names: Set[str] = set()
    pkg_names |= manual_set
    pkg_names |= set(pkg_units.keys())
    pkg_names |= {ps.package for ps in pkg_snaps}
    pkg_names |= set(firewall_runtime_snapshot.packages or [])

    packages_inventory: Dict[str, Dict[str, object]] = {}
    for pkg in sorted(pkg_names):
        installs = installed.get(pkg, []) or []
        arches = sorted({i.get("arch") for i in installs if i.get("arch")})
        vers = sorted({i.get("version") for i in installs if i.get("version")})
        version: Optional[str] = vers[0] if len(vers) == 1 else None
        section = _package_section_from_installations(installs)

        observed: List[Dict[str, str]] = []
        if pkg in manual_set:
            observed.append({"kind": "user_installed"})
        for unit in sorted(pkg_units.get(pkg, set())):
            observed.append({"kind": "systemd_unit", "ref": unit})
        for rn in sorted(set(pkg_role_names.get(pkg, []))):
            observed.append({"kind": "package_role", "ref": rn})
        if pkg in set(firewall_runtime_snapshot.packages or []):
            observed.append(
                {"kind": "firewall_runtime", "ref": firewall_runtime_snapshot.role_name}
            )
            pkg_roles_map.setdefault(pkg, set()).add(
                firewall_runtime_snapshot.role_name
            )

        roles = sorted(pkg_roles_map.get(pkg, set()))

        packages_inventory[pkg] = {
            "version": version,
            "arches": arches,
            "installations": installs,
            "section": section,
            "observed_via": observed,
            "roles": roles,
        }

    # Ensure every role has explicit managed_dirs for parent directories of managed files.
    # This lets the manifest create directories with owner/group/mode (ansible-lint friendly)
    # without a separate "mkdir without perms" task.
    users_snapshot.managed_dirs = _merge_parent_dirs(
        users_snapshot.managed_dirs, users_snapshot.managed_files, policy=policy
    )
    for s in service_snaps:
        s.managed_dirs = _merge_parent_dirs(
            s.managed_dirs,
            s.managed_files,
            policy=policy,
            extra_paths=[ml.path for ml in (s.managed_links or [])],
        )
    for p in pkg_snaps:
        p.managed_dirs = _merge_parent_dirs(
            p.managed_dirs,
            p.managed_files,
            policy=policy,
            extra_paths=[ml.path for ml in (p.managed_links or [])],
        )

    if apt_config_snapshot:
        apt_config_snapshot.managed_dirs = _merge_parent_dirs(
            apt_config_snapshot.managed_dirs,
            apt_config_snapshot.managed_files,
            policy=policy,
        )
    if dnf_config_snapshot:
        dnf_config_snapshot.managed_dirs = _merge_parent_dirs(
            dnf_config_snapshot.managed_dirs,
            dnf_config_snapshot.managed_files,
            policy=policy,
        )
    if etc_custom_snapshot:
        etc_custom_snapshot.managed_dirs = _merge_parent_dirs(
            etc_custom_snapshot.managed_dirs,
            etc_custom_snapshot.managed_files,
            policy=policy,
        )
    if usr_local_custom_snapshot:
        usr_local_custom_snapshot.managed_dirs = _merge_parent_dirs(
            usr_local_custom_snapshot.managed_dirs,
            usr_local_custom_snapshot.managed_files,
            policy=policy,
        )
    if extra_paths_snapshot:
        extra_paths_snapshot.managed_dirs = _merge_parent_dirs(
            extra_paths_snapshot.managed_dirs,
            extra_paths_snapshot.managed_files,
            policy=policy,
        )

    state = {
        "enroll": {
            "version": get_enroll_version(),
            "harvest_time": time.time_ns(),
        },
        "host": {
            "hostname": os.uname().nodename,
            "os": platform.os_family,
            "pkg_backend": backend.name,
            "os_release": platform.os_release,
        },
        "inventory": {
            "packages": packages_inventory,
        },
        "roles": {
            "users": asdict(users_snapshot),
            "flatpak": asdict(flatpak_snapshot),
            "snap": asdict(snap_snapshot),
            "services": [asdict(s) for s in service_snaps],
            "packages": [asdict(p) for p in pkg_snaps],
            "apt_config": asdict(apt_config_snapshot),
            "dnf_config": asdict(dnf_config_snapshot),
            "firewall_runtime": asdict(firewall_runtime_snapshot),
            "sysctl": asdict(sysctl_snapshot),
            "etc_custom": asdict(etc_custom_snapshot),
            "usr_local_custom": asdict(usr_local_custom_snapshot),
            "extra_paths": asdict(extra_paths_snapshot),
        },
    }

    return str(write_state(bundle_dir, state))
