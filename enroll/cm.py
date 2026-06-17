from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Set

from .state import load_state, state_path, write_state


@dataclass
class CMModule:
    """Renderer-neutral configuration-management resource group.

    A CMModule is intentionally small: it captures the resources that a target
    renderer can turn into Ansible tasks, Puppet resources, etc.
    The renderer may still decide how to name/include/order the group.
    """

    role_name: str
    module_name: str
    packages: Set[str] = field(default_factory=set)
    groups: Set[str] = field(default_factory=set)
    users: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    dirs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    links: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    services: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def has_resources(self) -> bool:
        return bool(
            self.packages
            or self.groups
            or self.users
            or self.dirs
            or self.files
            or self.links
            or self.services
            or self.notes
        )

    @staticmethod
    def state_path(bundle_dir: str | Path) -> Path:
        """Return the canonical state.json path for a harvest bundle."""

        return state_path(bundle_dir)

    @classmethod
    def load_state(cls, bundle_dir: str | Path) -> Dict[str, Any]:
        """Load state.json for a renderer using the shared bundle state loader."""

        return load_state(bundle_dir)

    @classmethod
    def _load_state(cls, bundle_dir: str | Path) -> Dict[str, Any]:
        """Backward-compatible alias for renderer subclasses."""

        return cls.load_state(bundle_dir)

    @classmethod
    def write_state(
        cls,
        bundle_dir: str | Path,
        state: Mapping[str, Any],
        *,
        indent: int = 2,
        sort_keys: bool = True,
    ) -> Path:
        """Write state.json using the shared bundle state writer."""

        return write_state(bundle_dir, state, indent=indent, sort_keys=sort_keys)

    @staticmethod
    def _snapshot_items(snap: Dict[str, Any], key: str) -> Iterator[Dict[str, Any]]:
        values = snap.get(key) or []
        if not isinstance(values, list):
            return
        for item in values:
            if isinstance(item, dict):
                yield item

    @classmethod
    def managed_dirs_from_snapshot(
        cls, snap: Dict[str, Any]
    ) -> Iterator[Dict[str, Any]]:
        return cls._snapshot_items(snap, "managed_dirs")

    @classmethod
    def managed_files_from_snapshot(
        cls, snap: Dict[str, Any]
    ) -> Iterator[Dict[str, Any]]:
        return cls._snapshot_items(snap, "managed_files")

    @classmethod
    def managed_links_from_snapshot(
        cls, snap: Dict[str, Any]
    ) -> Iterator[Dict[str, Any]]:
        return cls._snapshot_items(snap, "managed_links")

    def add_managed_dir(
        self,
        path: str,
        *,
        owner: Any = "root",
        group: Any = "root",
        mode: Any = "0755",
        **attrs: Any,
    ) -> None:
        if not path:
            return
        data: Dict[str, Any] = {
            "owner": owner or "root",
            "group": group or "root",
            "mode": mode or "0755",
        }
        data.update(attrs)
        self.dirs.setdefault(path, data)

    def add_managed_file(
        self,
        path: str,
        *,
        owner: Any = "root",
        group: Any = "root",
        mode: Any = "0644",
        **attrs: Any,
    ) -> None:
        if not path:
            return
        data: Dict[str, Any] = {
            "owner": owner or "root",
            "group": group or "root",
            "mode": mode or "0644",
        }
        data.update(attrs)
        self.files.setdefault(path, data)

    def add_managed_link(self, path: str, **attrs: Any) -> None:
        if path:
            self.links.setdefault(path, attrs)

    def add_snapshot_notes(self, snap: Dict[str, Any]) -> None:
        self.notes.extend(str(n) for n in (snap.get("notes", []) or []))

    def remove_directory_resource_conflicts(self) -> None:
        for path in set(self.files) | set(self.links):
            self.dirs.pop(path, None)


def package_section_label(
    package_role: Dict[str, Any], inventory_packages: Dict[str, Any]
) -> str:
    """Return the Debian Section/RPM Group label for a package role."""

    pkg = str(package_role.get("package") or "").strip()
    inv = inventory_packages.get(pkg) or {}
    candidates: List[str] = []

    for value in (package_role.get("section"), inv.get("section"), inv.get("group")):
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())

    for inst in inv.get("installations", []) or []:
        if not isinstance(inst, dict):
            continue
        for key in ("section", "group"):
            value = inst.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append(value.strip())

    for value in candidates:
        if value.lower() not in {"(none)", "none", "unspecified"}:
            return value
    return "misc"


def section_label_for_packages(
    packages: List[str], inventory_packages: Dict[str, Any]
) -> str:
    """Return a stable section/group label for a set of packages."""

    for pkg in packages or []:
        label = package_section_label({"package": pkg}, inventory_packages)
        if label and label.lower() != "misc":
            return label
    return "misc"


def role_order_key(role: str) -> tuple[int, str]:
    # Keep broadly similar ordering to generated Ansible playbooks: package/config
    # scaffolding first, then services/users, then host-specific runtime state.
    priority = {
        "apt_config": 10,
        "dnf_config": 11,
        "etc_custom": 80,
        "usr_local_custom": 81,
        "extra_paths": 82,
        "container_images": 88,
        "users": 90,
        "sysctl": 95,
        "firewall_runtime": 99,
    }
    return (priority.get(role, 50), role)


def _drop_duplicate_set_items(
    module: CMModule,
    values: Set[str],
    seen: Set[str],
    resource_type: str,
) -> Set[str]:
    kept: Set[str] = set()
    for value in sorted(values):
        if value in seen:
            module.notes.append(
                f"Skipped duplicate {resource_type}[{value}] already emitted earlier in this catalog."
            )
            continue
        kept.add(value)
        seen.add(value)
    return kept


def _drop_duplicate_mapping_items(
    module: CMModule,
    values: Dict[str, Dict[str, Any]],
    seen: Set[str],
    resource_type: str,
    *,
    excluded_titles: Set[str] | None = None,
    excluded_reason: str = "conflicts with another resource",
) -> Dict[str, Dict[str, Any]]:
    kept: Dict[str, Dict[str, Any]] = {}
    excluded_titles = excluded_titles or set()
    for title, attrs in values.items():
        if title in excluded_titles:
            module.notes.append(f"Skipped {resource_type}[{title}]: {excluded_reason}.")
            continue
        if title in seen:
            module.notes.append(
                f"Skipped duplicate {resource_type}[{title}] already emitted earlier in this catalog."
            )
            continue
        kept[title] = attrs
        seen.add(title)
    return kept


def resolve_catalog_conflicts(modules: Iterable[CMModule]) -> None:
    """Resolve global catalog conflicts before renderer output.

    Puppet compiles a single resource catalog. Ansible can tolerate the same
    package, service, or parent directory appearing in more than one role;
    catalog targets cannot. Resolve those conflicts in the shared model rather
    than deleting renderer output after the fact.
    """

    ordered = list(modules)
    concrete_file_paths: Set[str] = set()
    for module in ordered:
        concrete_file_paths.update(module.files)
        concrete_file_paths.update(module.links)

    seen_packages: Set[str] = set()
    seen_groups: Set[str] = set()
    seen_users: Set[str] = set()
    seen_dirs: Set[str] = set()
    seen_files: Set[str] = set()
    seen_links: Set[str] = set()
    seen_services: Set[str] = set()

    for module in ordered:
        module.packages = _drop_duplicate_set_items(
            module, module.packages, seen_packages, "Package"
        )
        module.groups = _drop_duplicate_set_items(
            module, module.groups, seen_groups, "Group"
        )
        module.users = _drop_duplicate_mapping_items(
            module, module.users, seen_users, "User"
        )
        module.dirs = _drop_duplicate_mapping_items(
            module,
            module.dirs,
            seen_dirs,
            "File",
            excluded_titles=concrete_file_paths,
            excluded_reason="a file or link with the same path is emitted in this catalog",
        )
        module.files = _drop_duplicate_mapping_items(
            module, module.files, seen_files | seen_links, "File"
        )
        seen_files.update(module.files)
        module.links = _drop_duplicate_mapping_items(
            module, module.links, seen_links | seen_files, "File"
        )
        seen_links.update(module.links)
        module.services = _drop_duplicate_mapping_items(
            module, module.services, seen_services, "Service"
        )
