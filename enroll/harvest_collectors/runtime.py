from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional

from .. import harvest as h
from ..harvest_types import FirewallRuntimeSnapshot, SysctlSnapshot
from .context import HarvestCollector, HarvestContext


@dataclass
class RuntimeStateCollection:
    firewall_runtime_snapshot: FirewallRuntimeSnapshot
    sysctl_snapshot: SysctlSnapshot


class RuntimeStateCollector(HarvestCollector):
    """Collect root-only live runtime state that has generated roles."""

    def __init__(
        self,
        context: HarvestContext,
        *,
        harvest_firewall: bool = False,
        harvest_sysctl: bool = False,
        persistent_ipset_files: Optional[List[str]] = None,
        persistent_iptables_v4_files: Optional[List[str]] = None,
        persistent_iptables_v6_files: Optional[List[str]] = None,
    ) -> None:
        super().__init__(context)
        self.harvest_firewall = harvest_firewall
        self.harvest_sysctl = harvest_sysctl
        self.persistent_ipset_files = persistent_ipset_files or []
        self.persistent_iptables_v4_files = persistent_iptables_v4_files or []
        self.persistent_iptables_v6_files = persistent_iptables_v6_files or []

    def collect(self) -> RuntimeStateCollection:
        running_as_root = not hasattr(os, "geteuid") or os.geteuid() == 0
        if not running_as_root:
            return RuntimeStateCollection(
                firewall_runtime_snapshot=FirewallRuntimeSnapshot(
                    role_name="firewall_runtime",
                    notes=[
                        "Live ipset/iptables runtime capture skipped because harvest "
                        "is not running as root."
                    ],
                ),
                sysctl_snapshot=SysctlSnapshot(
                    role_name="sysctl",
                    notes=[
                        "Live sysctl runtime capture skipped because harvest is not "
                        "running as root."
                    ],
                ),
            )

        firewall_runtime_snapshot = FirewallRuntimeSnapshot(
            role_name="firewall_runtime",
            notes=[
                "Live firewall capture disabled; use --harvest-firewall to opt in. Persistent configuration is still harvested normally."
            ],
        )
        if self.harvest_firewall:
            firewall_runtime_snapshot = h._collect_firewall_runtime_snapshot(
                self.context.bundle_dir,
                path_filter=self.context.path_filter,
                persistent_ipset_files=self.persistent_ipset_files,
                persistent_iptables_v4_files=self.persistent_iptables_v4_files,
                persistent_iptables_v6_files=self.persistent_iptables_v6_files,
            )
            firewall_runtime_snapshot.notes.append(
                "Custom persistence (rc.local, scripts, other firewall managers) cannot be ruled out. "
                "Review before applying a snapshot or enabling firewall_runtime_persist."
            )
        sysctl_snapshot = SysctlSnapshot(
            role_name="sysctl",
            notes=[
                "Live sysctl capture disabled; use --harvest-sysctl to opt in. Persistent configuration is still harvested normally."
            ],
        )
        if self.harvest_sysctl:
            sysctl_snapshot = h._collect_sysctl_snapshot(
                self.context.bundle_dir,
                path_filter=self.context.path_filter,
            )
            sysctl_snapshot.notes.append(
                "Live values may be temporary and may overlap /etc/sysctl.conf or sysctl.d files. "
                "Review generated 99-enroll.conf precedence before applying."
            )
        return RuntimeStateCollection(
            firewall_runtime_snapshot=firewall_runtime_snapshot,
            sysctl_snapshot=sysctl_snapshot,
        )
