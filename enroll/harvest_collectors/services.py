from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from .. import harvest as h
from ..harvest import ExcludedFile, ManagedFile, PackageSnapshot, ServiceSnapshot
from ..systemd import UnitQueryError
from .context import HarvestCollector, HarvestContext
from .cron_logrotate import CronLogrotateCollector, _is_cron_path, _is_logrotate_path


@dataclass
class ServicePackageCollection:
    service_snaps: List[ServiceSnapshot]
    pkg_snaps: List[PackageSnapshot]
    manual_pkgs: List[str]
    simple_packages: List[str]
    manual_pkgs_skipped: List[str]
    service_role_aliases: Dict[str, Set[str]]
    seen_by_role: Dict[str, Set[str]]


class ServicePackageCollector(HarvestCollector):
    """Collect service-attributed and manually-installed package snapshots."""

    def __init__(
        self,
        context: HarvestContext,
        *,
        cron_snapshot: Optional[PackageSnapshot] = None,
        logrotate_snapshot: Optional[PackageSnapshot] = None,
        cron_pkg: Optional[str] = None,
        logrotate_pkg: Optional[str] = None,
    ) -> None:
        super().__init__(context)
        self.cron_snapshot = cron_snapshot
        self.logrotate_snapshot = logrotate_snapshot
        self.cron_pkg = cron_pkg
        self.logrotate_pkg = logrotate_pkg
        self.service_role_aliases: Dict[str, Set[str]] = {}
        self.seen_by_role: Dict[str, Set[str]] = {}
        self.managed_by_role: Dict[str, List[ManagedFile]] = {}
        self.excluded_by_role: Dict[str, List[ExcludedFile]] = {}

    def collect(self) -> ServicePackageCollection:
        service_snaps, timer_extra_by_pkg = self._collect_service_snapshots()
        pkg_snaps, manual_pkgs, simple_packages, manual_pkgs_skipped = (
            self._collect_package_snapshots(
                service_snaps,
                timer_extra_by_pkg,
            )
        )
        self._capture_common_enabled_symlinks(service_snaps, pkg_snaps)
        return ServicePackageCollection(
            service_snaps=service_snaps,
            pkg_snaps=pkg_snaps,
            manual_pkgs=manual_pkgs,
            simple_packages=simple_packages,
            manual_pkgs_skipped=manual_pkgs_skipped,
            service_role_aliases=self.service_role_aliases,
            seen_by_role=self.seen_by_role,
        )

    def _collect_service_snapshots(
        self,
    ) -> tuple[List[ServiceSnapshot], Dict[str, List[str]]]:
        backend = self.context.backend
        service_snaps: List[ServiceSnapshot] = []

        enabled_services = h.list_enabled_services()
        if self.cron_snapshot is not None or self.logrotate_snapshot is not None:
            blocked_roles = set()
            if self.cron_snapshot is not None:
                blocked_roles.add(CronLogrotateCollector.cron_role_name)
            if self.logrotate_snapshot is not None:
                blocked_roles.add(CronLogrotateCollector.logrotate_role_name)
            enabled_services = [
                u
                for u in enabled_services
                if h._role_name_from_unit(u) not in blocked_roles
            ]
        enabled_set = set(enabled_services)

        def service_sort_key(unit: str) -> tuple[int, str, str]:
            base = unit.removesuffix(".service")
            base = base.split("@", 1)[0]
            return (base.count("-"), base.lower(), unit.lower())

        def parent_service_unit(unit: str) -> Optional[str]:
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

        parent_unit_for = {
            u: pu for u in enabled_services if (pu := parent_service_unit(u))
        }

        for unit in sorted(enabled_services, key=service_sort_key):
            role = h._role_name_from_unit(unit)
            parent_unit = parent_unit_for.get(unit)
            parent_role = h._role_name_from_unit(parent_unit) if parent_unit else None

            try:
                ui = h.get_unit_info(unit)
            except UnitQueryError as e:
                self.service_role_aliases.setdefault(
                    role, h._hint_names(unit, set()) | {role}
                )
                self.seen_by_role.setdefault(role, set())
                managed = self.managed_by_role.setdefault(role, [])
                excluded = self.excluded_by_role.setdefault(role, [])
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
            excluded = self.excluded_by_role.setdefault(role, [])
            managed = self.managed_by_role.setdefault(role, [])
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

            for env_file in ui.env_files:
                env_file = env_file.lstrip("-")
                if any(ch in env_file for ch in "*?["):
                    for g in glob.glob(env_file):
                        if g.startswith("/etc/") and os.path.isfile(g):
                            candidates[g] = "systemd_envfile"
                elif env_file.startswith("/etc/") and os.path.isfile(env_file):
                    candidates[env_file] = "systemd_envfile"

            hints = h._hint_names(unit, pkgs)
            h._add_pkgs_from_etc_topdirs(hints, self.context.topdir_to_pkgs, pkgs)
            self.service_role_aliases[role] = set(hints) | set(pkgs) | {role}

            for sp in h._maybe_add_specific_paths(hints, backend):
                if not os.path.exists(sp):
                    continue
                if sp in self.context.etc_owner_map:
                    pkgs.add(self.context.etc_owner_map[sp])
                else:
                    candidates.setdefault(sp, "custom_specific_path")

            for pkg in sorted(pkgs):
                etc_paths = self.context.pkg_to_etc_paths.get(pkg, [])
                for path, reason in backend.modified_paths(pkg, etc_paths).items():
                    if not os.path.isfile(path) or os.path.islink(path):
                        continue
                    if self.cron_snapshot is not None and _is_cron_path(path):
                        continue
                    if self.logrotate_snapshot is not None and _is_logrotate_path(path):
                        continue
                    if backend.is_pkg_config_path(path):
                        continue
                    candidates.setdefault(path, reason)

            any_roots: List[str] = []
            confish_roots: List[str] = []
            for hint in hints:
                roots_for_hint = [f"/etc/{hint}", f"/etc/{hint}.d"]
                if hint in h.SHARED_ETC_TOPDIRS:
                    confish_roots.extend(roots_for_hint)
                else:
                    any_roots.extend(roots_for_hint)

            found: List[str] = []
            found.extend(
                h._scan_unowned_under_roots(
                    any_roots,
                    self.context.owned_etc,
                    limit=h.MAX_UNOWNED_FILES_PER_ROLE,
                    confish_only=False,
                )
            )
            if len(found) < h.MAX_UNOWNED_FILES_PER_ROLE:
                found.extend(
                    h._scan_unowned_under_roots(
                        confish_roots,
                        self.context.owned_etc,
                        limit=h.MAX_UNOWNED_FILES_PER_ROLE - len(found),
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
                dest_role = role
                if (
                    parent_role
                    and path.startswith("/etc/")
                    and reason not in ("systemd_dropin", "systemd_envfile")
                ):
                    dest_role = parent_role

                dest_managed = self.managed_by_role.setdefault(dest_role, [])
                dest_excluded = self.excluded_by_role.setdefault(dest_role, [])
                dest_seen = self.seen_by_role.setdefault(dest_role, set())
                h._capture_file(
                    bundle_dir=self.context.bundle_dir,
                    role_name=dest_role,
                    abs_path=path,
                    reason=reason,
                    policy=self.context.policy,
                    path_filter=self.context.path_filter,
                    managed_out=dest_managed,
                    excluded_out=dest_excluded,
                    seen_role=dest_seen,
                    seen_global=self.context.captured_global,
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

        timer_extra_by_pkg = self._collect_timer_overrides(service_snaps)
        return service_snaps, timer_extra_by_pkg

    def _collect_timer_overrides(
        self,
        service_snaps: List[ServiceSnapshot],
    ) -> Dict[str, List[str]]:
        backend = self.context.backend
        timer_extra_by_pkg: Dict[str, List[str]] = {}
        try:
            enabled_timers = h.list_enabled_timers()
        except Exception:
            enabled_timers = []

        service_snap_by_unit = {s.unit: s for s in service_snaps}

        for timer in sorted(enabled_timers):
            try:
                ti = h.get_timer_info(timer)
            except Exception:  # nosec
                continue

            timer_paths: List[str] = []
            for pth in [ti.fragment_path, *ti.dropin_paths, *ti.env_files]:
                if not pth:
                    continue
                if not pth.startswith("/etc/"):
                    continue
                if os.path.islink(pth) or not os.path.isfile(pth):
                    continue
                timer_paths.append(pth)

            if not timer_paths:
                continue

            snap = (
                service_snap_by_unit.get(ti.trigger_unit) if ti.trigger_unit else None
            )
            if snap is not None:
                role_seen = self.seen_by_role.setdefault(snap.role_name, set())
                for path in timer_paths:
                    h._capture_file(
                        bundle_dir=self.context.bundle_dir,
                        role_name=snap.role_name,
                        abs_path=path,
                        reason="related_timer",
                        policy=self.context.policy,
                        path_filter=self.context.path_filter,
                        managed_out=snap.managed_files,
                        excluded_out=snap.excluded,
                        seen_role=role_seen,
                        seen_global=self.context.captured_global,
                    )
                continue

            pkgs: Set[str] = set()
            if ti.fragment_path:
                p = backend.owner_of_path(ti.fragment_path)
                if p:
                    pkgs.add(p)
            if ti.trigger_unit and ti.trigger_unit.endswith(".service"):
                try:
                    ui = h.get_unit_info(ti.trigger_unit)
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

        return timer_extra_by_pkg

    def _collect_package_snapshots(
        self,
        service_snaps: List[ServiceSnapshot],
        timer_extra_by_pkg: Dict[str, List[str]],
    ) -> tuple[List[PackageSnapshot], List[str], List[str], List[str]]:
        backend = self.context.backend
        manual_pkgs = backend.list_manual_packages()
        covered_by_services: Set[str] = set()
        for snap in service_snaps:
            covered_by_services.update(snap.packages)

        manual_pkgs_skipped: List[str] = []
        pkg_snaps: List[PackageSnapshot] = []
        simple_packages: List[str] = []

        if self.cron_snapshot is not None:
            pkg_snaps.append(self.cron_snapshot)
        if self.logrotate_snapshot is not None:
            pkg_snaps.append(self.logrotate_snapshot)

        for pkg in sorted(manual_pkgs):
            if pkg in covered_by_services:
                manual_pkgs_skipped.append(pkg)
                continue
            if self.cron_snapshot is not None and pkg == self.cron_pkg:
                manual_pkgs_skipped.append(pkg)
                continue
            if self.logrotate_snapshot is not None and pkg == self.logrotate_pkg:
                manual_pkgs_skipped.append(pkg)
                continue

            role = h._role_name_from_pkg(pkg)
            notes: List[str] = []
            excluded: List[ExcludedFile] = []
            managed: List[ManagedFile] = []
            candidates: Dict[str, str] = {}

            for tpath in timer_extra_by_pkg.get(pkg, []):
                candidates.setdefault(tpath, "related_timer")

            etc_paths = self.context.pkg_to_etc_paths.get(pkg, [])
            for path, reason in backend.modified_paths(pkg, etc_paths).items():
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                if self.cron_snapshot is not None and _is_cron_path(path):
                    continue
                if self.logrotate_snapshot is not None and _is_logrotate_path(path):
                    continue
                if backend.is_pkg_config_path(path):
                    continue
                candidates.setdefault(path, reason)

            topdirs = h._topdirs_for_package(pkg, self.context.pkg_to_etc_paths)
            roots: List[str] = []
            for topdir in sorted(topdirs):
                if topdir in h.SHARED_ETC_TOPDIRS:
                    continue
                if backend.is_pkg_config_path(
                    f"/etc/{topdir}/"
                ) or backend.is_pkg_config_path(f"/etc/{topdir}"):
                    continue
                roots.extend([f"/etc/{topdir}", f"/etc/{topdir}.d"])
            roots.extend(h._maybe_add_specific_paths(set(topdirs), backend))

            for pth in h._scan_unowned_under_roots(
                [r for r in roots if os.path.isdir(r)],
                self.context.owned_etc,
                confish_only=False,
            ):
                candidates.setdefault(pth, "custom_unowned")

            for root in roots:
                if os.path.isfile(root) and not os.path.islink(root):
                    if root not in self.context.owned_etc and h._is_confish(root):
                        candidates.setdefault(root, "custom_specific_path")

            role_seen = self.seen_by_role.setdefault(role, set())
            for path, reason in sorted(candidates.items()):
                h._capture_file(
                    bundle_dir=self.context.bundle_dir,
                    role_name=role,
                    abs_path=path,
                    reason=reason,
                    policy=self.context.policy,
                    path_filter=self.context.path_filter,
                    managed_out=managed,
                    excluded_out=excluded,
                    seen_role=role_seen,
                    seen_global=self.context.captured_global,
                )

            has_config = bool(managed or excluded)
            if not has_config:
                notes.append(
                    "No changed or custom configuration detected for this package."
                )
                simple_packages.append(pkg)

            pkg_snaps.append(
                PackageSnapshot(
                    package=pkg,
                    role_name=role,
                    section=h._package_section_from_installations(
                        self.context.installed_pkgs.get(pkg, [])
                    ),
                    managed_files=managed,
                    managed_links=[],
                    excluded=excluded,
                    notes=notes,
                    has_config=has_config,
                )
            )

        return pkg_snaps, manual_pkgs, simple_packages, manual_pkgs_skipped

    def _find_role_snapshot(
        self,
        role_name: str,
        service_snaps: List[ServiceSnapshot],
        pkg_snaps: List[PackageSnapshot],
    ):
        for snap in service_snaps:
            if snap.role_name == role_name:
                return snap
        for snap in pkg_snaps:
            if snap.role_name == role_name:
                return snap
        return None

    def _capture_enabled_symlinks_for_role(
        self,
        role_name: str,
        dirs: List[str],
        service_snaps: List[ServiceSnapshot],
        pkg_snaps: List[PackageSnapshot],
    ) -> None:
        snap = self._find_role_snapshot(role_name, service_snaps, pkg_snaps)
        if snap is None:
            return

        role_seen = self.seen_by_role.setdefault(role_name, set())
        for directory in dirs:
            if not os.path.isdir(directory):
                continue
            for pth in sorted(glob.glob(os.path.join(directory, "*"))):
                if not os.path.islink(pth):
                    continue
                h._capture_link(
                    role_name=role_name,
                    abs_path=pth,
                    reason="enabled_symlink",
                    policy=self.context.policy,
                    path_filter=self.context.path_filter,
                    managed_out=snap.managed_links,
                    excluded_out=snap.excluded,
                    seen_role=role_seen,
                    seen_global=self.context.captured_global,
                )

    def _capture_common_enabled_symlinks(
        self,
        service_snaps: List[ServiceSnapshot],
        pkg_snaps: List[PackageSnapshot],
    ) -> None:
        self._capture_enabled_symlinks_for_role(
            "nginx",
            ["/etc/nginx/modules-enabled", "/etc/nginx/sites-enabled"],
            service_snaps,
            pkg_snaps,
        )
        self._capture_enabled_symlinks_for_role(
            "apache2",
            [
                "/etc/apache2/conf-enabled",
                "/etc/apache2/mods-enabled",
                "/etc/apache2/sites-enabled",
            ],
            service_snaps,
            pkg_snaps,
        )
