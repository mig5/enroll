from __future__ import annotations

import glob
import json
import os
import shutil
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set

from .systemd import list_enabled_services, get_unit_info, UnitQueryError
from .debian import (
    build_dpkg_etc_index,
    dpkg_owner,
    file_md5,
    list_manual_packages,
    parse_status_conffiles,
    read_pkg_md5sums,
    stat_triplet,
)
from .secrets import SecretPolicy
from .accounts import collect_non_system_users, UserRecord



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


ALLOWED_UNOWNED_EXTS = {
    ".conf", ".cfg", ".ini", ".cnf", ".yaml", ".yml", ".json", ".toml",
    ".rules", ".service", ".socket", ".timer", ".target", ".path", ".mount",
    ".network", ".netdev", ".link",
    "",  # allow extensionless (common in /etc/default and /etc/init.d)
}

MAX_UNOWNED_FILES_PER_ROLE = 400


def _safe_name(s: str) -> str:
    out: List[str] = []
    for ch in s:
        out.append(ch if ch.isalnum() or ch in ("_", "-") else "_")
    return "".join(out).replace("-", "_")


def _role_name_from_unit(unit: str) -> str:
    base = unit.removesuffix(".service")
    return _safe_name(base)


def _role_name_from_pkg(pkg: str) -> str:
    return "pkg_" + _safe_name(pkg)


def _copy_into_bundle(bundle_dir: str, role_name: str, abs_path: str, src_rel: str) -> None:
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


def _add_pkgs_from_etc_topdirs(hints: Set[str], topdir_to_pkgs: Dict[str, Set[str]], pkgs: Set[str]) -> None:
    for h in hints:
        for p in topdir_to_pkgs.get(h, set()):
            pkgs.add(p)


def _maybe_add_specific_paths(hints: Set[str]) -> List[str]:
    paths: List[str] = []
    for h in hints:
        paths.extend([
            f"/etc/default/{h}",
            f"/etc/init.d/{h}",
            f"/etc/sysctl.d/{h}.conf",
            f"/etc/logrotate.d/{h}",
        ])
    return paths


def _scan_unowned_under_roots(roots: List[str], owned_etc: Set[str], limit: int = MAX_UNOWNED_FILES_PER_ROLE) -> List[str]:
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
                if not _is_confish(p):
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


def harvest(bundle_dir: str, policy: Optional[SecretPolicy] = None) -> str:
    policy = policy or SecretPolicy()
    os.makedirs(bundle_dir, exist_ok=True)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Warning: not running as root; harvest may miss files or metadata.", flush=True)

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
            service_snaps.append(ServiceSnapshot(
                unit=unit,
                role_name=role,
                packages=[],
                managed_files=[],
                excluded=[],
                notes=[str(e)],
            ))
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

        roots: List[str] = []
        for h in hints:
            roots.extend([f"/etc/{h}", f"/etc/{h}.d"])
        for pth in _scan_unowned_under_roots(roots, owned_etc):
            candidates.setdefault(pth, "custom_unowned")

        if not pkgs and not candidates:
            notes.append("No packages or /etc candidates detected (unexpected for enabled service).")

        for path, reason in sorted(candidates.items()):
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
            managed.append(ManagedFile(
                path=path,
                src_rel=src_rel,
                owner=owner,
                group=group,
                mode=mode,
                reason=reason,
            ))

        service_snaps.append(ServiceSnapshot(
            unit=unit,
            role_name=role,
            packages=sorted(pkgs),
            managed_files=managed,
            excluded=excluded,
            notes=notes,
        ))

    # -------------------------
    # Manual package roles
    # -------------------------
    manual_pkgs = list_manual_packages()
    pkg_snaps: List[PackageSnapshot] = []

    for pkg in manual_pkgs:
        role = _role_name_from_pkg(pkg)
        notes: List[str] = []
        excluded: List[ExcludedFile] = []
        managed: List[ManagedFile] = []
        candidates: Dict[str, str] = {}

        conff = conffiles_by_pkg.get(pkg, {})
        md5sums = read_pkg_md5sums(pkg)

        for path in pkg_to_etc_paths.get(pkg, []):
            if not os.path.isfile(path) or os.path.islink(path):
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
            roots.extend([f"/etc/{td}", f"/etc/{td}.d"])
            roots.extend([f"/etc/default/{td}"])
            roots.extend([f"/etc/init.d/{td}"])
            roots.extend([f"/etc/logrotate.d/{td}"])
            roots.extend([f"/etc/sysctl.d/{td}.conf"])

        for pth in _scan_unowned_under_roots([r for r in roots if os.path.isdir(r)], owned_etc):
            candidates.setdefault(pth, "custom_unowned")

        for r in roots:
            if os.path.isfile(r) and not os.path.islink(r):
                if r not in owned_etc and _is_confish(r):
                    candidates.setdefault(r, "custom_specific_path")

        for path, reason in sorted(candidates.items()):
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
            managed.append(ManagedFile(
                path=path,
                src_rel=src_rel,
                owner=owner,
                group=group,
                mode=mode,
                reason=reason,
            ))

        if not pkg_to_etc_paths.get(pkg, []) and not managed:
            notes.append("No /etc files detected for this package (may be a meta package).")

        pkg_snaps.append(PackageSnapshot(
            package=pkg,
            role_name=role,
            managed_files=managed,
            excluded=excluded,
            notes=notes,
        ))

    # -------------------------
    # Users role (non-system users)
    # -------------------------
    users_notes: List[str] = []
    users_excluded: List[ExcludedFile] = []
    users_managed: List[ManagedFile] = []
    users_list: List[dict] = []

    try:
        us
    except Exception as e:
        user_records = []
        users_notes.append(f"Failed to enumerate users: {e!r}")

    users_role_name = "users"

    for u in user_records:
        users_list.append({
            "name": u.name,
            "uid": u.uid,
            "gid": u.gid,
            "gecos": u.gecos,
            "home": u.home,
            "shell": u.shell,
            "primary_group": u.primary_group,
            "supplementary_groups": u.supplementary_groups,
        })

        # Copy authorized_keys
        for sf in u.ssh_files:
            deny = policy.deny_reason(sf)
            if deny:
                users_excluded.append(ExcludedFile(path=sf, reason=deny))
                continue

            # Force safe modes; still record current owner/group for reference.
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

            reason = "authorized_keys" if sf.endswith("/authorized_keys") else "ssh_public_key"
            users_managed.append(ManagedFile(
                path=sf,
                src_rel=src_rel,
                owner=owner,
                group=group,
                mode=mode,
                reason=reason,
            ))

    users_snapshot = UsersSnapshot(
        role_name=users_role_name,
        users=users_list,
        managed_files=users_managed,
        excluded=users_excluded,
        notes=users_notes,
    )

    state = {
        "host": {"hostname": os.uname().nodename, "os": "debian"},
        "users": asdict(users_snapshot),
        "services": [asdict(s) for s in service_snaps],
        "manual_packages": manual_pkgs,
        "package_roles": [asdict(p) for p in pkg_snaps],
    }

    state_path = os.path.join(bundle_dir, "state.json")
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    return state_path
