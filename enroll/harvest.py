from __future__ import annotations

import glob
import json
import os
import re
import shutil
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set

from .systemd import (
    list_enabled_services,
    list_enabled_timers,
    get_unit_info,
    get_timer_info,
    UnitQueryError,
)
from .fsutil import stat_triplet
from .platform import detect_platform, get_backend
from .ignore import IgnorePolicy
from .pathfilter import PathFilter, expand_includes
from .accounts import collect_non_system_users
from .version import get_enroll_version


@dataclass
class ManagedFile:
    path: str
    src_rel: str
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
    managed_files: List[ManagedFile]
    excluded: List[ExcludedFile]
    notes: List[str]


@dataclass
class PackageSnapshot:
    package: str
    role_name: str
    managed_files: List[ManagedFile]
    excluded: List[ExcludedFile]
    notes: List[str]


@dataclass
class UsersSnapshot:
    role_name: str
    users: List[dict]
    managed_files: List[ManagedFile]
    excluded: List[ExcludedFile]
    notes: List[str]


@dataclass
class AptConfigSnapshot:
    role_name: str
    managed_files: List[ManagedFile]
    excluded: List[ExcludedFile]
    notes: List[str]


@dataclass
class DnfConfigSnapshot:
    role_name: str
    managed_files: List[ManagedFile]
    excluded: List[ExcludedFile]
    notes: List[str]


@dataclass
class EtcCustomSnapshot:
    role_name: str
    managed_files: List[ManagedFile]
    excluded: List[ExcludedFile]
    notes: List[str]


@dataclass
class UsrLocalCustomSnapshot:
    role_name: str
    managed_files: List[ManagedFile]
    excluded: List[ExcludedFile]
    notes: List[str]


@dataclass
class ExtraPathsSnapshot:
    role_name: str
    include_patterns: List[str]
    exclude_patterns: List[str]
    managed_files: List[ManagedFile]
    excluded: List[ExcludedFile]
    notes: List[str]


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
    return _safe_name(base)


def _role_name_from_pkg(pkg: str) -> str:
    return _safe_name(pkg)


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
    # logrotate
    ("/etc/logrotate.conf", "system_logrotate"),
    ("/etc/logrotate.d/*", "system_logrotate"),
    # sysctl / modules
    ("/etc/sysctl.conf", "system_sysctl"),
    ("/etc/sysctl.d/*", "system_sysctl"),
    ("/etc/modprobe.d/*", "system_modprobe"),
    ("/etc/modules", "system_modprobe"),
    ("/etc/modules-load.d/*", "system_modprobe"),
    # cron
    ("/etc/crontab", "system_cron"),
    ("/etc/cron.d/*", "system_cron"),
    ("/etc/anacrontab", "system_cron"),
    ("/etc/anacron/*", "system_cron"),
    ("/var/spool/cron/crontabs/*", "system_cron"),
    ("/var/spool/crontabs/*", "system_cron"),
    ("/var/spool/cron/*", "system_cron"),
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
    ("/etc/ufw/*", "system_firewall"),
    ("/etc/default/ufw", "system_firewall"),
    ("/etc/firewalld/*", "system_firewall"),
    ("/etc/firewalld/zones/*", "system_firewall"),
    # SELinux
    ("/etc/selinux/config", "system_security"),
    # other
    ("/etc/rc.local", "system_rc"),
]


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
    # Service roles
    # -------------------------
    service_snaps: List[ServiceSnapshot] = []
    # Track alias strings (service names, package names, stems) that should map
    # back to the service role for shared snippet attribution (cron.d/logrotate.d).
    service_role_aliases: Dict[str, Set[str]] = {}
    # De-dupe per-role captures (avoids duplicate tasks in manifest generation).
    seen_by_role: Dict[str, Set[str]] = {}
    # Managed/excluded lists keyed by role so helper services can attribute shared
    # configuration to their parent service role.
    managed_by_role: Dict[str, List[ManagedFile]] = {}
    excluded_by_role: Dict[str, List[ExcludedFile]] = {}

    enabled_services = list_enabled_services()
    enabled_set = set(enabled_services)

    def _service_sort_key(unit: str) -> tuple[int, str, str]:
        # Prefer "parent" services over helpers (e.g. NetworkManager.service before
        # NetworkManager-dispatcher.service) so shared config lands in the main role.
        base = unit.removesuffix(".service")
        base = base.split("@", 1)[0]
        return (base.count("-"), base.lower(), unit.lower())

    def _parent_service_unit(unit: str) -> Optional[str]:
        # If unit name contains '-' segments, treat dashed prefixes as potential parents.
        # Example: NetworkManager-dispatcher.service -> NetworkManager.service (if enabled).
        if not unit.endswith(".service"):
            return None
        base = unit.removesuffix(".service")
        base = base.split("@", 1)[0]
        parts = base.split("-")
        for i in range(len(parts) - 1, 0, -1):
            cand = "-".join(parts[:i]) + ".service"
            if cand in enabled_set:
                return cand
        return None

    parent_unit_for: Dict[str, str] = {}
    for u in enabled_services:
        pu = _parent_service_unit(u)
        if pu:
            parent_unit_for[u] = pu

    for unit in sorted(enabled_services, key=_service_sort_key):
        role = _role_name_from_unit(unit)
        parent_unit = parent_unit_for.get(unit)
        parent_role = _role_name_from_unit(parent_unit) if parent_unit else None

        try:
            ui = get_unit_info(unit)
        except UnitQueryError as e:
            # Even when we can't query the unit, keep a minimal alias mapping so
            # shared snippets can still be attributed to this role by name.
            service_role_aliases.setdefault(role, _hint_names(unit, set()) | {role})
            seen_by_role.setdefault(role, set())
            managed = managed_by_role.setdefault(role, [])
            excluded = excluded_by_role.setdefault(role, [])
            service_snaps.append(
                ServiceSnapshot(
                    unit=unit,
                    role_name=role,
                    packages=[],
                    active_state=None,
                    sub_state=None,
                    unit_file_state=None,
                    condition_result=None,
                    managed_files=managed,
                    excluded=excluded,
                    notes=[str(e)],
                )
            )
            continue

        pkgs: Set[str] = set()
        notes: List[str] = []
        excluded = excluded_by_role.setdefault(role, [])
        managed = managed_by_role.setdefault(role, [])
        candidates: Dict[str, str] = {}

        if ui.fragment_path:
            p = backend.owner_of_path(ui.fragment_path)
            if p:
                pkgs.add(p)

        for exe in ui.exec_paths:
            p = backend.owner_of_path(exe)
            if p:
                pkgs.add(p)

        for pth in ui.dropin_paths:
            if pth.startswith("/etc/"):
                candidates[pth] = "systemd_dropin"

        for ef in ui.env_files:
            ef = ef.lstrip("-")
            if any(ch in ef for ch in "*?["):
                for g in glob.glob(ef):
                    if g.startswith("/etc/") and os.path.isfile(g):
                        candidates[g] = "systemd_envfile"
            else:
                if ef.startswith("/etc/") and os.path.isfile(ef):
                    candidates[ef] = "systemd_envfile"

        hints = _hint_names(unit, pkgs)
        _add_pkgs_from_etc_topdirs(hints, topdir_to_pkgs, pkgs)
        # Keep a stable set of aliases for this service role. Include current
        # packages as well, so that package-named snippets (e.g. cron.d or
        # logrotate.d entries) can still be attributed back to this service.
        service_role_aliases[role] = set(hints) | set(pkgs) | {role}

        for sp in _maybe_add_specific_paths(hints, backend):
            if not os.path.exists(sp):
                continue
            if sp in etc_owner_map:
                pkgs.add(etc_owner_map[sp])
            else:
                candidates.setdefault(sp, "custom_specific_path")

        for pkg in sorted(pkgs):
            etc_paths = pkg_to_etc_paths.get(pkg, [])
            for path, reason in backend.modified_paths(pkg, etc_paths).items():
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                if backend.is_pkg_config_path(path):
                    continue
                candidates.setdefault(path, reason)

        # Capture custom/unowned files living under /etc/<name> for this service.
        #
        # Historically we only captured "config-ish" files (by extension). That
        # misses important runtime-generated artifacts like certificates and
        # key material under service directories (e.g. /etc/openvpn/*.crt).
        #
        # To avoid exploding output for shared trees (e.g. /etc/systemd), keep
        # the older "config-ish only" behaviour for known shared topdirs.
        any_roots: List[str] = []
        confish_roots: List[str] = []
        for h in hints:
            roots_for_h = [f"/etc/{h}", f"/etc/{h}.d"]
            if h in SHARED_ETC_TOPDIRS:
                confish_roots.extend(roots_for_h)
            else:
                any_roots.extend(roots_for_h)

        found: List[str] = []
        found.extend(
            _scan_unowned_under_roots(
                any_roots,
                owned_etc,
                limit=MAX_UNOWNED_FILES_PER_ROLE,
                confish_only=False,
            )
        )
        if len(found) < MAX_UNOWNED_FILES_PER_ROLE:
            found.extend(
                _scan_unowned_under_roots(
                    confish_roots,
                    owned_etc,
                    limit=MAX_UNOWNED_FILES_PER_ROLE - len(found),
                    confish_only=True,
                )
            )
        for pth in found:
            candidates.setdefault(pth, "custom_unowned")

        if not pkgs and not candidates:
            notes.append(
                "No packages or /etc candidates detected (unexpected for enabled service)."
            )

        # De-dupe within this role while capturing. This also avoids emitting
        # duplicate Ansible tasks for the same destination path.
        # Attribute shared /etc config to the parent service role when this unit looks
        # like a helper (e.g. NetworkManager-dispatcher.service -> NetworkManager.service).
        for path, reason in sorted(candidates.items()):
            dest_role = role
            if (
                parent_role
                and path.startswith("/etc/")
                and reason not in ("systemd_dropin", "systemd_envfile")
            ):
                dest_role = parent_role

            dest_managed = managed_by_role.setdefault(dest_role, [])
            dest_excluded = excluded_by_role.setdefault(dest_role, [])
            dest_seen = seen_by_role.setdefault(dest_role, set())
            _capture_file(
                bundle_dir=bundle_dir,
                role_name=dest_role,
                abs_path=path,
                reason=reason,
                policy=policy,
                path_filter=path_filter,
                managed_out=dest_managed,
                excluded_out=dest_excluded,
                seen_role=dest_seen,
                seen_global=captured_global,
            )

        service_snaps.append(
            ServiceSnapshot(
                unit=unit,
                role_name=role,
                packages=sorted(pkgs),
                active_state=ui.active_state,
                sub_state=ui.sub_state,
                unit_file_state=ui.unit_file_state,
                condition_result=ui.condition_result,
                managed_files=managed,
                excluded=excluded,
                notes=notes,
            )
        )

    # -------------------------
    # Enabled systemd timers
    #
    # Timers are typically related to a service/package, so we try to attribute
    # timer unit overrides to their associated role rather than creating a
    # standalone timer role. If we can't attribute a timer, it will fall back
    # to etc_custom (if it's a custom /etc unit).
    # -------------------------
    timer_extra_by_pkg: Dict[str, List[str]] = {}
    try:
        enabled_timers = list_enabled_timers()
    except Exception:
        enabled_timers = []

    service_snap_by_unit: Dict[str, ServiceSnapshot] = {
        s.unit: s for s in service_snaps
    }

    for t in sorted(enabled_timers):
        try:
            ti = get_timer_info(t)
        except Exception:  # nosec
            continue

        timer_paths: List[str] = []
        for pth in [ti.fragment_path, *ti.dropin_paths, *ti.env_files]:
            if not pth:
                continue
            if not pth.startswith("/etc/"):
                # Prefer capturing only custom/overridden units.
                continue
            if os.path.islink(pth) or not os.path.isfile(pth):
                continue
            timer_paths.append(pth)

        if not timer_paths:
            continue

        # Primary attribution: timer -> trigger service role
        snap = None
        if ti.trigger_unit:
            snap = service_snap_by_unit.get(ti.trigger_unit)

        if snap is not None:
            role_seen = seen_by_role.setdefault(snap.role_name, set())
            for path in timer_paths:
                _capture_file(
                    bundle_dir=bundle_dir,
                    role_name=snap.role_name,
                    abs_path=path,
                    reason="related_timer",
                    policy=policy,
                    path_filter=path_filter,
                    managed_out=snap.managed_files,
                    excluded_out=snap.excluded,
                    seen_role=role_seen,
                    seen_global=captured_global,
                )
            continue

        # Secondary attribution: associate timer overrides with a package role
        # (useful when a timer triggers a service that isn't enabled).
        pkgs: Set[str] = set()
        if ti.fragment_path:
            p = backend.owner_of_path(ti.fragment_path)
            if p:
                pkgs.add(p)
        if ti.trigger_unit and ti.trigger_unit.endswith(".service"):
            try:
                ui = get_unit_info(ti.trigger_unit)
                if ui.fragment_path:
                    p = backend.owner_of_path(ui.fragment_path)
                    if p:
                        pkgs.add(p)
                for exe in ui.exec_paths:
                    p = backend.owner_of_path(exe)
                    if p:
                        pkgs.add(p)
            except Exception:  # nosec
                pass

        for pkg in pkgs:
            timer_extra_by_pkg.setdefault(pkg, []).extend(timer_paths)

    # -------------------------
    # Manually installed package roles
    # -------------------------
    manual_pkgs = backend.list_manual_packages()
    # Avoid duplicate roles: if a manual package is already managed by any service role, skip its pkg_<name> role.
    covered_by_services: Set[str] = set()
    for s in service_snaps:
        for p in s.packages:
            covered_by_services.add(p)

    manual_pkgs_skipped: List[str] = []
    pkg_snaps: List[PackageSnapshot] = []

    for pkg in sorted(manual_pkgs):
        if pkg in covered_by_services:
            manual_pkgs_skipped.append(pkg)
            continue
        role = _role_name_from_pkg(pkg)
        notes: List[str] = []
        excluded: List[ExcludedFile] = []
        managed: List[ManagedFile] = []
        candidates: Dict[str, str] = {}

        for tpath in timer_extra_by_pkg.get(pkg, []):
            candidates.setdefault(tpath, "related_timer")

        etc_paths = pkg_to_etc_paths.get(pkg, [])
        for path, reason in backend.modified_paths(pkg, etc_paths).items():
            if not os.path.isfile(path) or os.path.islink(path):
                continue
            if backend.is_pkg_config_path(path):
                continue
            candidates.setdefault(path, reason)

        topdirs = _topdirs_for_package(pkg, pkg_to_etc_paths)
        roots: List[str] = []
        # Collect candidate directories plus backend-specific common files.
        for td in sorted(topdirs):
            if td in SHARED_ETC_TOPDIRS:
                continue
            if backend.is_pkg_config_path(f"/etc/{td}/") or backend.is_pkg_config_path(
                f"/etc/{td}"
            ):
                continue
            roots.extend([f"/etc/{td}", f"/etc/{td}.d"])
        roots.extend(_maybe_add_specific_paths(set(topdirs), backend))

        # Capture any custom/unowned files under /etc/<topdir> for this
        # manually-installed package. This may include runtime-generated
        # artifacts like certificates, key files, and helper scripts which are
        # not owned by any .deb.
        for pth in _scan_unowned_under_roots(
            [r for r in roots if os.path.isdir(r)],
            owned_etc,
            confish_only=False,
        ):
            candidates.setdefault(pth, "custom_unowned")

        for r in roots:
            if os.path.isfile(r) and not os.path.islink(r):
                if r not in owned_etc and _is_confish(r):
                    candidates.setdefault(r, "custom_specific_path")

        role_seen = seen_by_role.setdefault(role, set())
        for path, reason in sorted(candidates.items()):
            _capture_file(
                bundle_dir=bundle_dir,
                role_name=role,
                abs_path=path,
                reason=reason,
                policy=policy,
                path_filter=path_filter,
                managed_out=managed,
                excluded_out=excluded,
                seen_role=role_seen,
                seen_global=captured_global,
            )

        if not pkg_to_etc_paths.get(pkg, []) and not managed:
            notes.append("No /etc files detected for this package.")

        pkg_snaps.append(
            PackageSnapshot(
                package=pkg,
                role_name=role,
                managed_files=managed,
                excluded=excluded,
                notes=notes,
            )
        )

    # -------------------------
    # Users role (non-system users)
    # -------------------------
    users_notes: List[str] = []
    users_excluded: List[ExcludedFile] = []
    users_managed: List[ManagedFile] = []
    users_list: List[dict] = []

    try:
        user_records = collect_non_system_users()
    except Exception as e:
        user_records = []
        users_notes.append(f"Failed to enumerate users: {e!r}")

    users_role_name = "users"
    users_role_seen = seen_by_role.setdefault(users_role_name, set())

    for u in user_records:
        users_list.append(
            {
                "name": u.name,
                "uid": u.uid,
                "gid": u.gid,
                "gecos": u.gecos,
                "home": u.home,
                "shell": u.shell,
                "primary_group": u.primary_group,
                "supplementary_groups": u.supplementary_groups,
            }
        )

        # Copy only safe SSH public material: authorized_keys + *.pub
        for sf in u.ssh_files:
            reason = (
                "authorized_keys"
                if sf.endswith("/authorized_keys")
                else "ssh_public_key"
            )
            _capture_file(
                bundle_dir=bundle_dir,
                role_name=users_role_name,
                abs_path=sf,
                reason=reason,
                policy=policy,
                path_filter=path_filter,
                managed_out=users_managed,
                excluded_out=users_excluded,
                seen_role=users_role_seen,
                seen_global=captured_global,
            )

    users_snapshot = UsersSnapshot(
        role_name=users_role_name,
        users=users_list,
        managed_files=users_managed,
        excluded=users_excluded,
        notes=users_notes,
    )

    # -------------------------
    # Package manager config role
    #   - Debian: apt_config
    #   - Fedora/RHEL-like: dnf_config
    # -------------------------
    apt_notes: List[str] = []
    apt_excluded: List[ExcludedFile] = []
    apt_managed: List[ManagedFile] = []
    dnf_notes: List[str] = []
    dnf_excluded: List[ExcludedFile] = []
    dnf_managed: List[ManagedFile] = []

    apt_role_name = "apt_config"
    dnf_role_name = "dnf_config"

    if backend.name == "dpkg":
        apt_role_seen = seen_by_role.setdefault(apt_role_name, set())
        for path, reason in _iter_apt_capture_paths():
            _capture_file(
                bundle_dir=bundle_dir,
                role_name=apt_role_name,
                abs_path=path,
                reason=reason,
                policy=policy,
                path_filter=path_filter,
                managed_out=apt_managed,
                excluded_out=apt_excluded,
                seen_role=apt_role_seen,
                seen_global=captured_global,
            )
    elif backend.name == "rpm":
        dnf_role_seen = seen_by_role.setdefault(dnf_role_name, set())
        for path, reason in _iter_dnf_capture_paths():
            _capture_file(
                bundle_dir=bundle_dir,
                role_name=dnf_role_name,
                abs_path=path,
                reason=reason,
                policy=policy,
                path_filter=path_filter,
                managed_out=dnf_managed,
                excluded_out=dnf_excluded,
                seen_role=dnf_role_seen,
                seen_global=captured_global,
            )

    apt_config_snapshot = AptConfigSnapshot(
        role_name=apt_role_name,
        managed_files=apt_managed,
        excluded=apt_excluded,
        notes=apt_notes,
    )
    dnf_config_snapshot = DnfConfigSnapshot(
        role_name=dnf_role_name,
        managed_files=dnf_managed,
        excluded=dnf_excluded,
        notes=dnf_notes,
    )

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
    # usr_local_custom role (/usr/local/etc + /usr/local/bin scripts)
    # -------------------------
    ul_notes: List[str] = []
    ul_excluded: List[ExcludedFile] = []
    ul_managed: List[ManagedFile] = []
    ul_role_name = "usr_local_custom"

    # Extend the already-captured set with etc_custom.
    already_all: Set[str] = set(already)
    for mf in etc_managed:
        already_all.add(mf.path)

    def _scan_usr_local_tree(
        root: str, *, require_executable: bool, cap: int, reason: str
    ) -> None:
        scanned = 0
        if not os.path.isdir(root):
            return
        role_seen = seen_by_role.setdefault(ul_role_name, set())
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                path = os.path.join(dirpath, fn)
                if path in already_all:
                    continue
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                try:
                    owner, group, mode = stat_triplet(path)
                except OSError:
                    ul_excluded.append(ExcludedFile(path=path, reason="unreadable"))
                    continue

                if require_executable:
                    try:
                        if (int(mode, 8) & 0o111) == 0:
                            continue
                    except ValueError:
                        # If mode parsing fails, be conservative and skip.
                        continue

                if _capture_file(
                    bundle_dir=bundle_dir,
                    role_name=ul_role_name,
                    abs_path=path,
                    reason=reason,
                    policy=policy,
                    path_filter=path_filter,
                    managed_out=ul_managed,
                    excluded_out=ul_excluded,
                    seen_role=role_seen,
                    seen_global=captured_global,
                    metadata=(owner, group, mode),
                ):
                    already_all.add(path)
                    scanned += 1
                if scanned >= cap:
                    ul_notes.append(f"Reached file cap ({cap}) while scanning {root}.")
                    return

    # /usr/local/etc: capture all non-binary regular files (filtered by IgnorePolicy)
    _scan_usr_local_tree(
        "/usr/local/etc",
        require_executable=False,
        cap=MAX_FILES_CAP,
        reason="usr_local_etc_custom",
    )

    # /usr/local/bin: capture executable scripts only (skip non-executable text)
    _scan_usr_local_tree(
        "/usr/local/bin",
        require_executable=True,
        cap=MAX_FILES_CAP,
        reason="usr_local_bin_script",
    )

    usr_local_custom_snapshot = UsrLocalCustomSnapshot(
        role_name=ul_role_name,
        managed_files=ul_managed,
        excluded=ul_excluded,
        notes=ul_notes,
    )

    # -------------------------
    # extra_paths role (user-requested includes)
    # -------------------------
    extra_notes: List[str] = []
    extra_excluded: List[ExcludedFile] = []
    extra_managed: List[ManagedFile] = []
    extra_role_name = "extra_paths"
    extra_role_seen = seen_by_role.setdefault(extra_role_name, set())

    include_specs = list(include_paths or [])
    exclude_specs = list(exclude_paths or [])

    if include_specs:
        extra_notes.append("User include patterns:")
        extra_notes.extend([f"- {p}" for p in include_specs])
    if exclude_specs:
        extra_notes.append("User exclude patterns:")
        extra_notes.extend([f"- {p}" for p in exclude_specs])

    included_files: List[str] = []
    if include_specs:
        files, inc_notes = expand_includes(
            path_filter.iter_include_patterns(),
            exclude=path_filter,
            max_files=MAX_FILES_CAP,
        )
        included_files = files
        extra_notes.extend(inc_notes)

    for path in included_files:
        if path in already_all:
            continue

        if _capture_file(
            bundle_dir=bundle_dir,
            role_name=extra_role_name,
            abs_path=path,
            reason="user_include",
            policy=policy,
            path_filter=path_filter,
            managed_out=extra_managed,
            excluded_out=extra_excluded,
            seen_role=extra_role_seen,
            seen_global=captured_global,
        ):
            already_all.add(path)

    extra_paths_snapshot = ExtraPathsSnapshot(
        role_name=extra_role_name,
        include_patterns=include_specs,
        exclude_patterns=exclude_specs,
        managed_files=extra_managed,
        excluded=extra_excluded,
        notes=extra_notes,
    )

    # -------------------------
    # Inventory: packages (SBOM-ish)
    # -------------------------
    installed = backend.installed_packages() or {}

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

    packages_inventory: Dict[str, Dict[str, object]] = {}
    for pkg in sorted(pkg_names):
        installs = installed.get(pkg, []) or []
        arches = sorted({i.get("arch") for i in installs if i.get("arch")})
        vers = sorted({i.get("version") for i in installs if i.get("version")})
        version: Optional[str] = vers[0] if len(vers) == 1 else None

        observed: List[Dict[str, str]] = []
        if pkg in manual_set:
            observed.append({"kind": "user_installed"})
        for unit in sorted(pkg_units.get(pkg, set())):
            observed.append({"kind": "systemd_unit", "ref": unit})
        for rn in sorted(set(pkg_role_names.get(pkg, []))):
            observed.append({"kind": "package_role", "ref": rn})

        roles = sorted(pkg_roles_map.get(pkg, set()))

        packages_inventory[pkg] = {
            "version": version,
            "arches": arches,
            "installations": installs,
            "observed_via": observed,
            "roles": roles,
        }

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
            "services": [asdict(s) for s in service_snaps],
            "packages": [asdict(p) for p in pkg_snaps],
            "apt_config": asdict(apt_config_snapshot),
            "dnf_config": asdict(dnf_config_snapshot),
            "etc_custom": asdict(etc_custom_snapshot),
            "usr_local_custom": asdict(usr_local_custom_snapshot),
            "extra_paths": asdict(extra_paths_snapshot),
        },
    }

    state_path = os.path.join(bundle_dir, "state.json")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    return state_path
