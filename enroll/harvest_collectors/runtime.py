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
        persistent_ipset_files: Optional[List[str]] = None,
        persistent_iptables_v4_files: Optional[List[str]] = None,
        persistent_iptables_v6_files: Optional[List[str]] = None,
    ) -> None:
        super().__init__(context)
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

        firewall_runtime_snapshot = h._collect_firewall_runtime_snapshot(
            self.context.bundle_dir,
            path_filter=self.context.path_filter,
            persistent_ipset_files=self.persistent_ipset_files,
            persistent_iptables_v4_files=self.persistent_iptables_v4_files,
            persistent_iptables_v6_files=self.persistent_iptables_v6_files,
        )
        sysctl_snapshot = h._collect_sysctl_snapshot(
            self.context.bundle_dir, path_filter=self.context.path_filter
        )
        return RuntimeStateCollection(
            firewall_runtime_snapshot=firewall_runtime_snapshot,
            sysctl_snapshot=sysctl_snapshot,
        )
