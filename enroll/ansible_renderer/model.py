from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from ..cm import CMModule, package_section_label, section_label_for_packages
from ..role_names import avoid_reserved_role_name


@dataclass
class AnsibleRoleCollection:
    services: List[Dict[str, Any]]
    packages: List[Dict[str, Any]]
    common_role_groups: Dict[str, List[Dict[str, Any]]]


class AnsibleRole(CMModule):
    """Ansible-specific view of a renderer-neutral CMModule."""

    def __init__(
        self,
        role_name: str,
        *,
        var_prefix: Optional[str] = None,
        section_label: Optional[str] = None,
        grouped: bool = False,
    ) -> None:
        super().__init__(role_name=role_name, module_name=role_name)
        self.var_prefix = var_prefix or role_name
        self.section_label = section_label
        self.grouped = grouped
        self.entries: List[Dict[str, Any]] = []
        self.excluded: List[Dict[str, Any]] = []
        self.origin_lines: List[str] = []

    def add_package_snapshot(self, snap: Dict[str, Any]) -> None:
        pkg = str(snap.get("package") or "").strip()
        source_role = str(snap.get("role_name") or pkg or self.role_name)
        self.entries.append({"kind": "package", "snapshot": snap})
        if pkg:
            self.packages.add(pkg)
            self.origin_lines.append(f"package `{pkg}` from role `{source_role}`")
        self.add_managed_content(snap)

    def add_service_snapshot(self, snap: Dict[str, Any]) -> None:
        unit = str(snap.get("unit") or "").strip()
        source_role = str(snap.get("role_name") or unit or self.role_name)
        self.entries.append({"kind": "service", "snapshot": snap})
        for pkg in snap.get("packages", []) or []:
            pkg_s = str(pkg or "").strip()
            if pkg_s:
                self.packages.add(pkg_s)
        if unit:
            unit_file_state = str(snap.get("unit_file_state") or "")
            self.services.setdefault(
                unit,
                {
                    "name": unit,
                    "manage": True,
                    "enabled": unit_file_state in ("enabled", "enabled-runtime"),
                    "state": (
                        "started" if snap.get("active_state") == "active" else "stopped"
                    ),
                },
            )
            self.origin_lines.append(f"service `{unit}` from role `{source_role}`")
        self.add_managed_content(snap)

    def add_managed_content(self, snap: Dict[str, Any]) -> None:
        for d in self.managed_dirs_from_snapshot(snap):
            path = str(d.get("path") or "").strip()
            self.add_managed_dir(
                path,
                dest=path,
                owner=d.get("owner") or "root",
                group=d.get("group") or "root",
                mode=d.get("mode") or "0755",
            )

        for mf in self.managed_files_from_snapshot(snap):
            path = str(mf.get("path") or "").strip()
            src_rel = str(mf.get("src_rel") or "").strip()
            if not path or not src_rel:
                continue
            self.add_managed_file(
                path,
                dest=path,
                src_rel=src_rel,
                owner=mf.get("owner") or "root",
                group=mf.get("group") or "root",
                mode=mf.get("mode") or "0644",
                reason=mf.get("reason") or "managed_file",
            )

        for ml in self.managed_links_from_snapshot(snap):
            path = str(ml.get("path") or "").strip()
            target = str(ml.get("target") or "").strip()
            if not path or not target:
                continue
            self.add_managed_link(path, dest=path, src=target)

        self.excluded.extend(snap.get("excluded", []) or [])
        self.add_snapshot_notes(snap)

    @property
    def sorted_packages(self) -> List[str]:
        return sorted(self.packages)

    @property
    def systemd_units_var(self) -> List[Dict[str, Any]]:
        return [self.services[k] for k in sorted(self.services)]


class AnsibleManifestPlan:
    """Track generated Ansible roles without scattering category lists."""

    _ORDER = (
        "apt_config",
        "dnf_config",
        "package",
        "service",
        "etc_custom",
        "usr_local_custom",
        "extra_paths",
        "flatpak",
        "snap",
        "container_images",
        "users",
        "tail_package",
        "sysctl",
        "firewall_runtime",
    )

    def __init__(self) -> None:
        self._roles: Dict[str, List[str]] = {category: [] for category in self._ORDER}
        self._tail_packages: List[str] = []

    def add(self, category: str, role: str) -> None:
        if category not in self._roles:
            raise ValueError(f"unknown Ansible role category: {category}")
        if role and role not in self._roles[category]:
            self._roles[category].append(role)

    def roles(self, category: str) -> List[str]:
        return list(self._roles.get(category, []))

    def has(self, category: str, role: str) -> bool:
        return role in self._roles.get(category, [])

    def mark_tail_package(self, role: str) -> None:
        if self.has("package", role) and role not in self._tail_packages:
            self._tail_packages.append(role)

    def ordered_roles(self) -> List[str]:
        tail = set(self._tail_packages)
        package_roles = [r for r in self._roles["package"] if r not in tail]
        out: List[str] = []
        for category in self._ORDER:
            if category == "package":
                out.extend(package_roles)
            elif category == "tail_package":
                out.extend(self._tail_packages)
            else:
                out.extend(self._roles[category])
        return out


def _role_id(raw: str) -> str:
    """Return an Ansible-safe role identifier from an arbitrary label."""

    s = re.sub(r"[^A-Za-z0-9]+", "_", raw or "misc")
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = s.lower()
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "misc"
    if not re.match(r"^[a-z_]", s):
        s = "r_" + s
    return s


def _section_role_name(label: str, occupied_roles: Set[str]) -> str:
    """Create a stable section role name, avoiding generated-role collisions."""

    base = avoid_reserved_role_name(_role_id(label), prefix="section")
    role = base if base not in occupied_roles else f"section_{base}"
    n = 2
    while role in occupied_roles:
        role = f"section_{base}_{n}"
        n += 1
    occupied_roles.add(role)
    return role


def _collect_ansible_roles(
    roles: Dict[str, Any],
    inventory_packages: Dict[str, Any],
    *,
    use_common_roles: bool,
) -> AnsibleRoleCollection:
    services = roles.get("services", []) or []
    packages = roles.get("packages", []) or []
    common_role_groups: Dict[str, List[Dict[str, Any]]] = {}

    if use_common_roles:
        for svc in services:
            label = section_label_for_packages(
                svc.get("packages", []) or [], inventory_packages
            )
            common_role_groups.setdefault(label, []).append(
                {"kind": "service", "snapshot": svc}
            )
        for pr in packages:
            label = package_section_label(pr, inventory_packages)
            common_role_groups.setdefault(label, []).append(
                {"kind": "package", "snapshot": pr}
            )
        return AnsibleRoleCollection(
            services=[], packages=[], common_role_groups=common_role_groups
        )

    return AnsibleRoleCollection(
        services=services,
        packages=packages,
        common_role_groups=common_role_groups,
    )
