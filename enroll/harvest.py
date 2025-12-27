from __future__ import annotations

import glob
import json
import os
import re
import shutil
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set

from .systemd import (
    list_enabled_services,
    list_enabled_timers,
    get_unit_info,
    get_timer_info,
    UnitQueryError,
)
from .debian import (
    build_dpkg_etc_index,
    dpkg_owner,
    file_md5,
    list_manual_packages,
    parse_status_conffiles,
    read_pkg_md5sums,
    stat_triplet,
)
from .ignore import IgnorePolicy
from .pathfilter import PathFilter, expand_includes
from .accounts import collect_non_system_users


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
    ".cnf",
    ".conf",
    ".cfg",
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

# Directories that are shared across many packages; never attribute unowned files in these trees to a single package.
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
    for h in hints:
        for p in topdir_to_pkgs.get(h, set()):
            pkgs.add(p)


def _maybe_add_specific_paths(hints: Set[str]) -> List[str]:
    paths: List[str] = []
    for h in hints:
        paths.extend(
            [
                f"/etc/default/{h}",
                f"/etc/init.d/{h}",
                f"/etc/sysctl.d/{h}.conf",
                f"/etc/logrotate.d/{h}",
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
    # network
    ("/etc/netplan/*", "system_network"),
    ("/etc/systemd/network/*", "system_network"),
    ("/etc/network/interfaces", "system_network"),
    ("/etc/network/interfaces.d/*", "system_network"),
    ("/etc/resolvconf.conf", "system_network"),
    ("/etc/resolvconf/resolv.conf.d/*", "system_network"),
    # firewall
    ("/etc/nftables.conf", "system_firewall"),
    ("/etc/nftables.d/*", "system_firewall"),
    ("/etc/iptables/rules.v4", "system_firewall"),
    ("/etc/iptables/rules.v6", "system_firewall"),
    ("/etc/ufw/*", "system_firewall"),
    ("/etc/default/ufw", "system_firewall"),
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
        # dangerous behavior, honour the CLI intent.
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

    owned_etc, etc_owner_map, topdir_to_pkgs, pkg_to_etc_paths = build_dpkg_etc_index()
    conffiles_by_pkg = parse_status_conffiles()

    # -------------------------
    # Service roles
    # -------------------------
    service_snaps: List[ServiceSnapshot] = []
    for unit in list_enabled_services():
        role = _role_name_from_unit(unit)

        try:
            ui = get_unit_info(unit)
        except UnitQueryError as e:
            service_snaps.append(
                ServiceSnapshot(
                    unit=unit,
                    role_name=role,
                    packages=[],
                    active_state=None,
                    sub_state=None,
                    unit_file_state=None,
                    condition_result=None,
                    managed_files=[],
                    excluded=[],
                    notes=[str(e)],
                )
            )
            continue

        pkgs: Set[str] = set()
        notes: List[str] = []
        excluded: List[ExcludedFile] = []
        managed: List[ManagedFile] = []
        candidates: Dict[str, str] = {}

        if ui.fragment_path:
            p = dpkg_owner(ui.fragment_path)
            if p:
                pkgs.add(p)

        for exe in ui.exec_paths:
            p = dpkg_owner(exe)
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

        for sp in _maybe_add_specific_paths(hints):
            if not os.path.exists(sp):
                continue
            if sp in etc_owner_map:
                pkgs.add(etc_owner_map[sp])
            else:
                candidates.setdefault(sp, "custom_specific_path")

        for pkg in sorted(pkgs):
            conff = conffiles_by_pkg.get(pkg, {})
            md5sums = read_pkg_md5sums(pkg)
            for path in pkg_to_etc_paths.get(pkg, []):
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                if path.startswith("/etc/apt/"):
                    continue
                if path in conff:
                    # Only capture conffiles when they differ from the package default.
                    try:
                        current = file_md5(path)
                    except OSError:
                        continue
                    if current != conff[path]:
                        candidates.setdefault(path, "modified_conffile")
                    continue
                rel = path.lstrip("/")
                baseline = md5sums.get(rel)
                if baseline:
                    try:
                        current = file_md5(path)
                    except OSError:
                        continue
                    if current != baseline:
                        candidates.setdefault(path, "modified_packaged_file")

        # Capture custom/unowned files living under /etc/<name> for this service.
        #
        # Historically we only captured "config-ish" files (by extension). That
        # misses important runtime-generated artifacts like certificates and
        # key material under service directories (e.g. /etc/openvpn/*.crt).
        #
        # To avoid exploding output for shared trees (e.g. /etc/systemd), keep
        # the older "config-ish only" behavior for known shared topdirs.
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

        for path, reason in sorted(candidates.items()):
            if path_filter.is_excluded(path):
                excluded.append(ExcludedFile(path=path, reason="user_excluded"))
                continue
            deny = policy.deny_reason(path)
            if deny:
                excluded.append(ExcludedFile(path=path, reason=deny))
                continue
            try:
                owner, group, mode = stat_triplet(path)
            except OSError:
                excluded.append(ExcludedFile(path=path, reason="unreadable"))
                continue
            src_rel = path.lstrip("/")
            try:
                _copy_into_bundle(bundle_dir, role, path, src_rel)
            except OSError:
                excluded.append(ExcludedFile(path=path, reason="unreadable"))
                continue
            managed.append(
                ManagedFile(
                    path=path,
                    src_rel=src_rel,
                    owner=owner,
                    group=group,
                    mode=mode,
                    reason=reason,
                )
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

    for t in enabled_timers:
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
            for path in timer_paths:
                if path_filter.is_excluded(path):
                    snap.excluded.append(
                        ExcludedFile(path=path, reason="user_excluded")
                    )
                    continue
                deny = policy.deny_reason(path)
                if deny:
                    snap.excluded.append(ExcludedFile(path=path, reason=deny))
                    continue
                try:
                    owner, group, mode = stat_triplet(path)
                except OSError:
                    snap.excluded.append(ExcludedFile(path=path, reason="unreadable"))
                    continue
                src_rel = path.lstrip("/")
                try:
                    _copy_into_bundle(bundle_dir, snap.role_name, path, src_rel)
                except OSError:
                    snap.excluded.append(ExcludedFile(path=path, reason="unreadable"))
                    continue
                snap.managed_files.append(
                    ManagedFile(
                        path=path,
                        src_rel=src_rel,
                        owner=owner,
                        group=group,
                        mode=mode,
                        reason="related_timer",
                    )
                )
            continue

        # Secondary attribution: associate timer overrides with a package role
        # (useful when a timer triggers a service that isn't enabled).
        pkgs: Set[str] = set()
        if ti.fragment_path:
            p = dpkg_owner(ti.fragment_path)
            if p:
                pkgs.add(p)
        if ti.trigger_unit and ti.trigger_unit.endswith(".service"):
            try:
                ui = get_unit_info(ti.trigger_unit)
                if ui.fragment_path:
                    p = dpkg_owner(ui.fragment_path)
                    if p:
                        pkgs.add(p)
                for exe in ui.exec_paths:
                    p = dpkg_owner(exe)
                    if p:
                        pkgs.add(p)
            except Exception:  # nosec
                pass

        for pkg in pkgs:
            timer_extra_by_pkg.setdefault(pkg, []).extend(timer_paths)

    # -------------------------
    # Manually installed package roles
    # -------------------------
    manual_pkgs = list_manual_packages()
    # Avoid duplicate roles: if a manual package is already managed by any service role, skip its pkg_<name> role.
    covered_by_services: Set[str] = set()
    for s in service_snaps:
        for p in s.packages:
            covered_by_services.add(p)

    manual_pkgs_skipped: List[str] = []
    pkg_snaps: List[PackageSnapshot] = []

    for pkg in manual_pkgs:
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

        conff = conffiles_by_pkg.get(pkg, {})
        md5sums = read_pkg_md5sums(pkg)

        for path in pkg_to_etc_paths.get(pkg, []):
            if not os.path.isfile(path) or os.path.islink(path):
                continue
            if path.startswith("/etc/apt/"):
                continue
            if path in conff:
                try:
                    current = file_md5(path)
                except OSError:
                    continue
                if current != conff[path]:
                    candidates.setdefault(path, "modified_conffile")
                continue
            rel = path.lstrip("/")
            baseline = md5sums.get(rel)
            if baseline:
                try:
                    current = file_md5(path)
                except OSError:
                    continue
                if current != baseline:
                    candidates.setdefault(path, "modified_packaged_file")

        topdirs = _topdirs_for_package(pkg, pkg_to_etc_paths)
        roots: List[str] = []
        for td in sorted(topdirs):
            if td in SHARED_ETC_TOPDIRS:
                continue
            roots.extend([f"/etc/{td}", f"/etc/{td}.d"])
            roots.extend([f"/etc/default/{td}"])
            roots.extend([f"/etc/init.d/{td}"])
            roots.extend([f"/etc/logrotate.d/{td}"])
            roots.extend([f"/etc/sysctl.d/{td}.conf"])

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

        for path, reason in sorted(candidates.items()):
            if path_filter.is_excluded(path):
                excluded.append(ExcludedFile(path=path, reason="user_excluded"))
                continue
            deny = policy.deny_reason(path)
            if deny:
                excluded.append(ExcludedFile(path=path, reason=deny))
                continue
            try:
                owner, group, mode = stat_triplet(path)
            except OSError:
                excluded.append(ExcludedFile(path=path, reason="unreadable"))
                continue
            src_rel = path.lstrip("/")
            try:
                _copy_into_bundle(bundle_dir, role, path, src_rel)
            except OSError:
                excluded.append(ExcludedFile(path=path, reason="unreadable"))
                continue
            managed.append(
                ManagedFile(
                    path=path,
                    src_rel=src_rel,
                    owner=owner,
                    group=group,
                    mode=mode,
                    reason=reason,
                )
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
            if path_filter.is_excluded(sf):
                users_excluded.append(ExcludedFile(path=sf, reason="user_excluded"))
                continue
            deny = policy.deny_reason(sf)
            if deny:
                users_excluded.append(ExcludedFile(path=sf, reason=deny))
                continue
            try:
                owner, group, mode = stat_triplet(sf)
            except OSError:
                users_excluded.append(ExcludedFile(path=sf, reason="unreadable"))
                continue
            src_rel = sf.lstrip("/")
            try:
                _copy_into_bundle(bundle_dir, users_role_name, sf, src_rel)
            except OSError:
                users_excluded.append(ExcludedFile(path=sf, reason="unreadable"))
                continue
            reason = (
                "authorized_keys"
                if sf.endswith("/authorized_keys")
                else "ssh_public_key"
            )
            users_managed.append(
                ManagedFile(
                    path=sf,
                    src_rel=src_rel,
                    owner=owner,
                    group=group,
                    mode=mode,
                    reason=reason,
                )
            )

    users_snapshot = UsersSnapshot(
        role_name=users_role_name,
        users=users_list,
        managed_files=users_managed,
        excluded=users_excluded,
        notes=users_notes,
    )

    # -------------------------
    # apt_config role (APT configuration and keyrings)
    # -------------------------
    apt_notes: List[str] = []
    apt_excluded: List[ExcludedFile] = []
    apt_managed: List[ManagedFile] = []
    apt_role_name = "apt_config"

    for path, reason in _iter_apt_capture_paths():
        if path_filter.is_excluded(path):
            apt_excluded.append(ExcludedFile(path=path, reason="user_excluded"))
            continue

        deny = policy.deny_reason(path)
        if deny:
            apt_excluded.append(ExcludedFile(path=path, reason=deny))
            continue

        try:
            owner, group, mode = stat_triplet(path)
        except OSError:
            apt_excluded.append(ExcludedFile(path=path, reason="unreadable"))
            continue

        src_rel = path.lstrip("/")
        try:
            _copy_into_bundle(bundle_dir, apt_role_name, path, src_rel)
        except OSError:
            apt_excluded.append(ExcludedFile(path=path, reason="unreadable"))
            continue

        apt_managed.append(
            ManagedFile(
                path=path,
                src_rel=src_rel,
                owner=owner,
                group=group,
                mode=mode,
                reason=reason,
            )
        )

    apt_config_snapshot = AptConfigSnapshot(
        role_name=apt_role_name,
        managed_files=apt_managed,
        excluded=apt_excluded,
        notes=apt_notes,
    )

    # -------------------------
    # etc_custom role (unowned /etc files not already attributed elsewhere)
    # -------------------------
    etc_notes: List[str] = []
    etc_excluded: List[ExcludedFile] = []
    etc_managed: List[ManagedFile] = []
    etc_role_name = "etc_custom"

    # Build a set of files already captured by other roles.
    already: Set[str] = set()
    for s in service_snaps:
        for mf in s.managed_files:
            already.add(mf.path)
    for p in pkg_snaps:
        for mf in p.managed_files:
            already.add(mf.path)
    for mf in users_managed:
        already.add(mf.path)
    for mf in apt_managed:
        already.add(mf.path)

    # Maps for re-attributing shared snippets (cron.d/logrotate.d) to existing roles.
    svc_by_role: Dict[str, ServiceSnapshot] = {s.role_name: s for s in service_snaps}
    pkg_by_role: Dict[str, PackageSnapshot] = {p.role_name: p for p in pkg_snaps}

    def _target_role_for_shared_snippet(path: str) -> Optional[tuple[str, str]]:
        """If `path` is a shared snippet, return (role_name, reason) to attach to."""
        base = os.path.basename(path)

        # Try full filename and stem (before first dot).
        candidates: List[str] = [base]
        if "." in base:
            candidates.append(base.split(".", 1)[0])

        seen: Set[str] = set()
        uniq: List[str] = []
        for c in candidates:
            if c and c not in seen:
                seen.add(c)
                uniq.append(c)

        if path.startswith("/etc/logrotate.d/"):
            for c in uniq:
                rn = _safe_name(c)
                if rn in svc_by_role or rn in pkg_by_role:
                    return (rn, "logrotate_snippet")
            return None

        if path.startswith("/etc/cron.d/"):
            for c in uniq:
                rn = _safe_name(c)
                if rn in svc_by_role or rn in pkg_by_role:
                    return (rn, "cron_snippet")
            return None

        return None

    # Capture essential system config/state (even if package-owned).
    for path, reason in _iter_system_capture_paths():
        if path in already:
            continue

        target = _target_role_for_shared_snippet(path)

        if path_filter.is_excluded(path):
            if target:
                rn, _ = target
                if rn in svc_by_role:
                    svc_by_role[rn].excluded.append(
                        ExcludedFile(path=path, reason="user_excluded")
                    )
                elif rn in pkg_by_role:
                    pkg_by_role[rn].excluded.append(
                        ExcludedFile(path=path, reason="user_excluded")
                    )
            else:
                etc_excluded.append(ExcludedFile(path=path, reason="user_excluded"))
            already.add(path)
            continue

        deny = policy.deny_reason(path)
        if deny:
            if target:
                rn, _ = target
                if rn in svc_by_role:
                    svc_by_role[rn].excluded.append(
                        ExcludedFile(path=path, reason=deny)
                    )
                elif rn in pkg_by_role:
                    pkg_by_role[rn].excluded.append(
                        ExcludedFile(path=path, reason=deny)
                    )
            else:
                etc_excluded.append(ExcludedFile(path=path, reason=deny))
            already.add(path)
            continue

        try:
            owner, group, mode = stat_triplet(path)
        except OSError:
            if target:
                rn, _ = target
                if rn in svc_by_role:
                    svc_by_role[rn].excluded.append(
                        ExcludedFile(path=path, reason="unreadable")
                    )
                elif rn in pkg_by_role:
                    pkg_by_role[rn].excluded.append(
                        ExcludedFile(path=path, reason="unreadable")
                    )
            else:
                etc_excluded.append(ExcludedFile(path=path, reason="unreadable"))
            already.add(path)
            continue

        src_rel = path.lstrip("/")
        role_for_copy = etc_role_name
        reason_for_role = reason
        if target:
            role_for_copy, reason_for_role = target

        try:
            _copy_into_bundle(bundle_dir, role_for_copy, path, src_rel)
        except OSError:
            if target:
                rn, _ = target
                if rn in svc_by_role:
                    svc_by_role[rn].excluded.append(
                        ExcludedFile(path=path, reason="unreadable")
                    )
                elif rn in pkg_by_role:
                    pkg_by_role[rn].excluded.append(
                        ExcludedFile(path=path, reason="unreadable")
                    )
            else:
                etc_excluded.append(ExcludedFile(path=path, reason="unreadable"))
            already.add(path)
            continue

        mf = ManagedFile(
            path=path,
            src_rel=src_rel,
            owner=owner,
            group=group,
            mode=mode,
            reason=reason_for_role,
        )
        if target:
            rn, _ = target
            if rn in svc_by_role:
                svc_by_role[rn].managed_files.append(mf)
            elif rn in pkg_by_role:
                pkg_by_role[rn].managed_files.append(mf)
        else:
            etc_managed.append(mf)

        already.add(path)

    # Walk /etc for remaining unowned config-ish files
    scanned = 0
    for dirpath, _, filenames in os.walk("/etc"):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if path.startswith("/etc/apt/"):
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

            if path_filter.is_excluded(path):
                if target:
                    rn, _ = target
                    if rn in svc_by_role:
                        svc_by_role[rn].excluded.append(
                            ExcludedFile(path=path, reason="user_excluded")
                        )
                    elif rn in pkg_by_role:
                        pkg_by_role[rn].excluded.append(
                            ExcludedFile(path=path, reason="user_excluded")
                        )
                else:
                    etc_excluded.append(ExcludedFile(path=path, reason="user_excluded"))
                already.add(path)
                continue

            deny = policy.deny_reason(path)
            if deny:
                if target:
                    rn, _ = target
                    if rn in svc_by_role:
                        svc_by_role[rn].excluded.append(
                            ExcludedFile(path=path, reason=deny)
                        )
                    elif rn in pkg_by_role:
                        pkg_by_role[rn].excluded.append(
                            ExcludedFile(path=path, reason=deny)
                        )
                else:
                    etc_excluded.append(ExcludedFile(path=path, reason=deny))
                already.add(path)
                continue

            try:
                owner, group, mode = stat_triplet(path)
            except OSError:
                if target:
                    rn, _ = target
                    if rn in svc_by_role:
                        svc_by_role[rn].excluded.append(
                            ExcludedFile(path=path, reason="unreadable")
                        )
                    elif rn in pkg_by_role:
                        pkg_by_role[rn].excluded.append(
                            ExcludedFile(path=path, reason="unreadable")
                        )
                else:
                    etc_excluded.append(ExcludedFile(path=path, reason="unreadable"))
                already.add(path)
                continue

            src_rel = path.lstrip("/")
            role_for_copy = etc_role_name
            reason_for_role = "custom_unowned"
            if target:
                role_for_copy, reason_for_role = target

            try:
                _copy_into_bundle(bundle_dir, role_for_copy, path, src_rel)
            except OSError:
                if target:
                    rn, _ = target
                    if rn in svc_by_role:
                        svc_by_role[rn].excluded.append(
                            ExcludedFile(path=path, reason="unreadable")
                        )
                    elif rn in pkg_by_role:
                        pkg_by_role[rn].excluded.append(
                            ExcludedFile(path=path, reason="unreadable")
                        )
                else:
                    etc_excluded.append(ExcludedFile(path=path, reason="unreadable"))
                already.add(path)
                continue

            mf = ManagedFile(
                path=path,
                src_rel=src_rel,
                owner=owner,
                group=group,
                mode=mode,
                reason=reason_for_role,
            )
            if target:
                rn, _ = target
                if rn in svc_by_role:
                    svc_by_role[rn].managed_files.append(mf)
                elif rn in pkg_by_role:
                    pkg_by_role[rn].managed_files.append(mf)
            else:
                etc_managed.append(mf)
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
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                path = os.path.join(dirpath, fn)
                if path in already_all:
                    continue
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                if require_executable:
                    try:
                        owner, group, mode = stat_triplet(path)
                    except OSError:
                        ul_excluded.append(ExcludedFile(path=path, reason="unreadable"))
                        continue
                    try:
                        if (int(mode, 8) & 0o111) == 0:
                            continue
                    except ValueError:
                        # If mode parsing fails, be conservative and skip.
                        continue
                else:
                    try:
                        owner, group, mode = stat_triplet(path)
                    except OSError:
                        ul_excluded.append(ExcludedFile(path=path, reason="unreadable"))
                        continue

                if path_filter.is_excluded(path):
                    ul_excluded.append(ExcludedFile(path=path, reason="user_excluded"))
                    continue

                deny = policy.deny_reason(path)
                if deny:
                    ul_excluded.append(ExcludedFile(path=path, reason=deny))
                    continue

                src_rel = path.lstrip("/")
                try:
                    _copy_into_bundle(bundle_dir, ul_role_name, path, src_rel)
                except OSError:
                    ul_excluded.append(ExcludedFile(path=path, reason="unreadable"))
                    continue

                ul_managed.append(
                    ManagedFile(
                        path=path,
                        src_rel=src_rel,
                        owner=owner,
                        group=group,
                        mode=mode,
                        reason=reason,
                    )
                )

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

        if path_filter.is_excluded(path):
            extra_excluded.append(ExcludedFile(path=path, reason="user_excluded"))
            continue

        deny = policy.deny_reason(path)
        if deny:
            extra_excluded.append(ExcludedFile(path=path, reason=deny))
            continue

        try:
            owner, group, mode = stat_triplet(path)
        except OSError:
            extra_excluded.append(ExcludedFile(path=path, reason="unreadable"))
            continue

        src_rel = path.lstrip("/")
        try:
            _copy_into_bundle(bundle_dir, extra_role_name, path, src_rel)
        except OSError:
            extra_excluded.append(ExcludedFile(path=path, reason="unreadable"))
            continue

        extra_managed.append(
            ManagedFile(
                path=path,
                src_rel=src_rel,
                owner=owner,
                group=group,
                mode=mode,
                reason="user_include",
            )
        )
        already_all.add(path)

    extra_paths_snapshot = ExtraPathsSnapshot(
        role_name=extra_role_name,
        include_patterns=include_specs,
        exclude_patterns=exclude_specs,
        managed_files=extra_managed,
        excluded=extra_excluded,
        notes=extra_notes,
    )

    state = {
        "host": {"hostname": os.uname().nodename, "os": "debian"},
        "users": asdict(users_snapshot),
        "services": [asdict(s) for s in service_snaps],
        "manual_packages": manual_pkgs,
        "manual_packages_skipped": manual_pkgs_skipped,
        "package_roles": [asdict(p) for p in pkg_snaps],
        "apt_config": asdict(apt_config_snapshot),
        "etc_custom": asdict(etc_custom_snapshot),
        "usr_local_custom": asdict(usr_local_custom_snapshot),
        "extra_paths": asdict(extra_paths_snapshot),
    }

    state_path = os.path.join(bundle_dir, "state.json")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    return state_path
