from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set

from ..capture import capture_file
from ..harvest_types import (
    AptConfigSnapshot,
    DnfConfigSnapshot,
    ExcludedFile,
    ManagedFile,
)
from ..system_paths import iter_apt_capture_paths, iter_dnf_capture_paths
from .context import HarvestCollector, HarvestContext


@dataclass
class PackageManagerConfigCollection:
    apt_config_snapshot: AptConfigSnapshot
    dnf_config_snapshot: DnfConfigSnapshot


class PackageManagerConfigCollector(HarvestCollector):
    """Collect package-manager configuration into existing role snapshots."""

    def __init__(
        self, context: HarvestContext, seen_by_role: Dict[str, Set[str]]
    ) -> None:
        super().__init__(context)
        self.seen_by_role = seen_by_role

    def collect(self) -> PackageManagerConfigCollection:
        apt_notes: List[str] = []
        apt_excluded: List[ExcludedFile] = []
        apt_managed: List[ManagedFile] = []
        dnf_notes: List[str] = []
        dnf_excluded: List[ExcludedFile] = []
        dnf_managed: List[ManagedFile] = []

        apt_role_name = "apt_config"
        dnf_role_name = "dnf_config"

        if self.context.backend.name == "dpkg":
            apt_role_seen = self.seen_by_role.setdefault(apt_role_name, set())
            for path, reason in iter_apt_capture_paths():
                capture_file(
                    bundle_dir=self.context.bundle_dir,
                    role_name=apt_role_name,
                    abs_path=path,
                    reason=reason,
                    policy=self.context.policy,
                    path_filter=self.context.path_filter,
                    managed_out=apt_managed,
                    excluded_out=apt_excluded,
                    seen_role=apt_role_seen,
                    seen_global=self.context.captured_global,
                )
        elif self.context.backend.name == "rpm":
            dnf_role_seen = self.seen_by_role.setdefault(dnf_role_name, set())
            for path, reason in iter_dnf_capture_paths():
                capture_file(
                    bundle_dir=self.context.bundle_dir,
                    role_name=dnf_role_name,
                    abs_path=path,
                    reason=reason,
                    policy=self.context.policy,
                    path_filter=self.context.path_filter,
                    managed_out=dnf_managed,
                    excluded_out=dnf_excluded,
                    seen_role=dnf_role_seen,
                    seen_global=self.context.captured_global,
                )

        return PackageManagerConfigCollection(
            apt_config_snapshot=AptConfigSnapshot(
                role_name=apt_role_name,
                managed_files=apt_managed,
                excluded=apt_excluded,
                notes=apt_notes,
            ),
            dnf_config_snapshot=DnfConfigSnapshot(
                role_name=dnf_role_name,
                managed_files=dnf_managed,
                excluded=dnf_excluded,
                notes=dnf_notes,
            ),
        )
