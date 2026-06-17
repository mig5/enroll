from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


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
class ContainerImagesSnapshot:
    role_name: str
    images: List[Dict[str, Any]] = field(default_factory=list)
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
