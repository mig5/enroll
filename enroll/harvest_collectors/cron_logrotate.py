from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional, Set

from .. import harvest as h
from ..harvest import ExcludedFile, ManagedFile, PackageSnapshot
from .context import HarvestCollector


def _pick_installed(installed_names: Set[str], candidates: List[str]) -> Optional[str]:
    for candidate in candidates:
        if candidate in installed_names:
            return candidate
    return None


def _is_cron_path(path: str) -> bool:
    return (
        path == "/etc/crontab"
        or path == "/etc/anacrontab"
        or path in ("/etc/cron.allow", "/etc/cron.deny")
        or path.startswith("/etc/cron.")
        or path.startswith("/etc/cron.d/")
        or path.startswith("/etc/anacron/")
        or path.startswith("/var/spool/cron/")
        or path.startswith("/var/spool/crontabs/")
        or path.startswith("/var/spool/anacron/")
    )


def _is_logrotate_path(path: str) -> bool:
    return path == "/etc/logrotate.conf" or path.startswith("/etc/logrotate.d/")


_CRON_CAPTURE_GLOBS = [
    "/etc/crontab",
    "/etc/cron.d/*",
    "/etc/cron.hourly/*",
    "/etc/cron.daily/*",
    "/etc/cron.weekly/*",
    "/etc/cron.monthly/*",
    "/etc/cron.allow",
    "/etc/cron.deny",
    "/etc/anacrontab",
    "/etc/anacron/*",
    # user crontabs / spool state
    "/var/spool/cron/*",
    "/var/spool/cron/crontabs/*",
    "/var/spool/crontabs/*",
    "/var/spool/anacron/*",
]

_LOGROTATE_CAPTURE_GLOBS = [
    "/etc/logrotate.conf",
    "/etc/logrotate.d/*",
]


@dataclass
class CronLogrotateCollection:
    cron_pkg: Optional[str]
    logrotate_pkg: Optional[str]
    cron_snapshot: Optional[PackageSnapshot]
    logrotate_snapshot: Optional[PackageSnapshot]


class CronLogrotateCollector(HarvestCollector):
    """Collect dedicated cron/logrotate package roles before general packages."""

    cron_role_name = "cron"
    logrotate_role_name = "logrotate"

    def collect(self) -> CronLogrotateCollection:
        cron_pkg = _pick_installed(
            self.context.installed_names,
            ["cron", "cronie", "cronie-anacron", "vixie-cron", "fcron"],
        )
        logrotate_pkg = _pick_installed(self.context.installed_names, ["logrotate"])

        cron_snapshot = self._collect_cron_snapshot(cron_pkg) if cron_pkg else None
        logrotate_snapshot = (
            self._collect_logrotate_snapshot(logrotate_pkg) if logrotate_pkg else None
        )
        return CronLogrotateCollection(
            cron_pkg=cron_pkg,
            logrotate_pkg=logrotate_pkg,
            cron_snapshot=cron_snapshot,
            logrotate_snapshot=logrotate_snapshot,
        )

    def _collect_cron_snapshot(self, cron_pkg: str) -> PackageSnapshot:
        managed: List[ManagedFile] = []
        excluded: List[ExcludedFile] = []
        notes: List[str] = []
        seen: Set[str] = set()

        for spec in _CRON_CAPTURE_GLOBS:
            for path in h._iter_matching_files(spec):
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                h._capture_file(
                    bundle_dir=self.context.bundle_dir,
                    role_name=self.cron_role_name,
                    abs_path=path,
                    reason="system_cron",
                    policy=self.context.policy,
                    path_filter=self.context.path_filter,
                    managed_out=managed,
                    excluded_out=excluded,
                    seen_role=seen,
                    seen_global=self.context.captured_global,
                )

        return PackageSnapshot(
            package=cron_pkg,
            role_name=self.cron_role_name,
            section=h._package_section_from_installations(
                self.context.installed_pkgs.get(cron_pkg, [])
            ),
            managed_files=managed,
            excluded=excluded,
            notes=notes,
        )

    def _collect_logrotate_snapshot(self, logrotate_pkg: str) -> PackageSnapshot:
        managed: List[ManagedFile] = []
        excluded: List[ExcludedFile] = []
        notes: List[str] = []
        seen: Set[str] = set()

        for spec in _LOGROTATE_CAPTURE_GLOBS:
            for path in h._iter_matching_files(spec):
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                h._capture_file(
                    bundle_dir=self.context.bundle_dir,
                    role_name=self.logrotate_role_name,
                    abs_path=path,
                    reason="system_logrotate",
                    policy=self.context.policy,
                    path_filter=self.context.path_filter,
                    managed_out=managed,
                    excluded_out=excluded,
                    seen_role=seen,
                    seen_global=self.context.captured_global,
                )

        return PackageSnapshot(
            package=logrotate_pkg,
            role_name=self.logrotate_role_name,
            section=h._package_section_from_installations(
                self.context.installed_pkgs.get(logrotate_pkg, [])
            ),
            managed_files=managed,
            excluded=excluded,
            notes=notes,
        )
