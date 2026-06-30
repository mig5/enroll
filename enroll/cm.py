from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Set,
)

from .state import load_state, state_path, write_state


@dataclass
class CMModule:
    """Renderer-neutral configuration-management resource group.

    A CMModule is intentionally small: it captures the resources that the
    renderer turns into Ansible tasks. The renderer may still decide how to
    name/include/order the group.
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
    firewall_runtime: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    managed_owner_attr: ClassVar[str] = "owner"
    firewall_runtime_dir: ClassVar[str] = "/etc/enroll/firewall"
    firewall_runtime_artifacts: ClassVar[tuple[tuple[str, str, str], ...]] = (
        ("ipset_save", "ipset.save", "0600"),
        ("iptables_v4_save", "iptables.v4", "0600"),
        ("iptables_v6_save", "iptables.v6", "0600"),
    )

    def has_core_resources(self) -> bool:
        return bool(
            self.packages
            or self.groups
            or self.users
            or self.dirs
            or self.files
            or self.links
            or self.services
            or self.firewall_runtime
            or self.notes
        )

    def has_resources(self) -> bool:
        return self.has_core_resources()

    def has_resources_or_attrs(self, *attrs: str) -> bool:
        """Return true if core resources or named renderer extras are present."""

        return self.has_core_resources() or any(
            bool(getattr(self, attr, None)) for attr in attrs
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

    @staticmethod
    def package_name_from_snapshot(snap: Dict[str, Any]) -> str:
        return str(snap.get("package") or "").strip()

    @staticmethod
    def package_names_from_snapshot(snap: Dict[str, Any]) -> Iterator[str]:
        for pkg in snap.get("packages", []) or []:
            pkg_s = str(pkg or "").strip()
            if pkg_s:
                yield pkg_s

    def add_package_snapshot(self, snap: Dict[str, Any]) -> None:
        pkg = self.package_name_from_snapshot(snap)
        if pkg:
            self.packages.add(pkg)

    def add_service_packages_from_snapshot(self, snap: Dict[str, Any]) -> None:
        self.packages.update(self.package_names_from_snapshot(snap))

    def service_unit_from_snapshot(self, snap: Dict[str, Any]) -> str:
        return str(snap.get("unit") or "").strip()

    def service_enabled_from_snapshot(self, snap: Dict[str, Any]) -> bool:
        unit_file_state = str(snap.get("unit_file_state") or "")
        return unit_file_state in ("enabled", "enabled-runtime")

    def service_state_from_snapshot(
        self,
        snap: Dict[str, Any],
        *,
        running: str,
        stopped: str,
    ) -> str:
        return running if snap.get("active_state") == "active" else stopped

    def add_service_snapshot_state(
        self,
        snap: Dict[str, Any],
        *,
        state_key: str,
        running: str,
        stopped: str,
        include_manage: bool = False,
    ) -> None:
        """Add the common systemd service parts, parameterised per renderer."""

        self.add_service_packages_from_snapshot(snap)
        unit = self.service_unit_from_snapshot(snap)
        if not unit:
            return

        data: Dict[str, Any] = {
            "name": unit,
            state_key: self.service_state_from_snapshot(
                snap, running=running, stopped=stopped
            ),
            "enable": self.service_enabled_from_snapshot(snap),
        }
        if include_manage:
            data["manage"] = True
        self.services[unit] = data

    @staticmethod
    def normalise_flatpak_item(
        item: Any,
        *,
        method: str,
        user: str | None = None,
        home: str | None = None,
    ) -> Dict[str, Any]:
        if isinstance(item, dict):
            out = dict(item)
        elif isinstance(item, str):
            out = {"name": item}
        else:
            out = {"name": str(item)}

        out["method"] = str(out.get("method") or method or "system").strip() or "system"
        if user and not out.get("user"):
            out["user"] = user
        if home and not out.get("home"):
            out["home"] = home
        ref = str(out.get("ref") or "").strip()
        if ref and not out.get("name"):
            out["name"] = ref.rsplit("/", 1)[-1]
        name = str(out.get("name") or out.get("app_id") or "").strip()
        if name:
            out["name"] = name
        remote = str(out.get("remote") or "").strip()
        if remote:
            out["remote"] = remote
        branch = str(out.get("branch") or out.get("origin") or "").strip()
        if branch:
            out["branch"] = branch
        if ref:
            out["ref"] = ref
        return out

    @staticmethod
    def normalise_flatpak_remote(item: Any) -> Dict[str, Any]:
        if isinstance(item, dict):
            out = dict(item)
        else:
            out = {"name": str(item)}
        name = str(out.get("name") or out.get("remote") or "").strip()
        url = str(out.get("url") or out.get("from_url") or "").strip()
        method = (
            str(out.get("method") or out.get("scope") or "system").strip() or "system"
        )
        if name:
            out["name"] = name
        if url:
            out["url"] = url
        out["method"] = "user" if method == "user" else "system"
        return out

    @staticmethod
    def normalise_snap_item(item: Any) -> Dict[str, Any]:
        if isinstance(item, dict):
            out = dict(item)
        elif isinstance(item, str):
            out = {"name": item}
        else:
            out = {"name": str(item)}

        name = str(out.get("name") or "").strip()
        if name:
            out["name"] = name
        channel = str(out.get("tracking") or out.get("channel") or "").strip()
        if channel:
            out["channel"] = channel
        raw_notes = out.get("notes") or []
        if isinstance(raw_notes, str):
            raw_notes = [raw_notes]
        notes = [str(note).lower() for note in raw_notes]
        confinement = str(out.get("confinement") or "").strip().lower()
        out["classic"] = bool(
            out.get("classic")
            or confinement == "classic"
            or any("classic" in note for note in notes)
        )
        out["devmode"] = bool(
            out.get("devmode")
            or any("devmode" in note or "dev mode" in note for note in notes)
        )
        out["dangerous"] = bool(
            out.get("dangerous") or any("dangerous" in note for note in notes)
        )
        revision = str(out.get("revision") or "").strip()
        if revision and not channel:
            out["revision"] = revision
        return out

    def prepare_flatpak_remote(self, item: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def prepare_flatpak_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def prepare_snap_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    @staticmethod
    def user_records_from_snapshot(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for raw in snap.get("users", []) or []:
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("name") or "").strip()
            if not name:
                continue
            primary_group = str(raw.get("primary_group") or name).strip()
            supplementary = sorted(
                {
                    str(group).strip()
                    for group in (raw.get("supplementary_groups") or [])
                    if str(group).strip()
                }
            )
            records.append(
                {
                    "name": name,
                    "uid": raw.get("uid"),
                    "gid": raw.get("gid"),
                    "primary_group": primary_group,
                    "home": raw.get("home") or f"/home/{name}",
                    "shell": raw.get("shell"),
                    "gecos": raw.get("gecos"),
                    "supplementary_groups": supplementary,
                }
            )
        return records

    @staticmethod
    def user_group_names_from_records(records: Iterable[Mapping[str, Any]]) -> Set[str]:
        groups: Set[str] = set()
        for record in records:
            primary_group = str(record.get("primary_group") or "").strip()
            if primary_group:
                groups.add(primary_group)
            groups.update(
                str(group).strip()
                for group in (record.get("supplementary_groups") or [])
                if str(group).strip()
            )
        return groups

    @staticmethod
    def package_service_entries(
        roles: Mapping[str, Any],
        inventory_packages: Mapping[str, Any],
        *,
        use_common_roles: bool,
    ) -> Iterator[Dict[str, Any]]:
        for svc in roles.get("services", []) or []:
            if not isinstance(svc, dict):
                continue
            own_label = str(svc.get("role_name") or svc.get("unit") or "service")
            role_label = (
                section_label_for_packages(
                    svc.get("packages", []) or [], inventory_packages
                )
                if use_common_roles
                else own_label
            )
            yield {"kind": "service", "snapshot": svc, "role_label": role_label}

        for pkg in roles.get("packages", []) or []:
            if not isinstance(pkg, dict):
                continue
            own_label = str(pkg.get("role_name") or pkg.get("package") or "package")
            role_label = (
                package_section_label(pkg, inventory_packages)
                if use_common_roles
                else own_label
            )
            yield {"kind": "package", "snapshot": pkg, "role_label": role_label}

    @staticmethod
    def active_service_units_by_package(
        entries: Iterable[Mapping[str, Any]],
    ) -> Dict[str, List[Dict[str, str]]]:
        """Return active service units keyed by the packages that produced them.

        Renderers use this when a package-owned managed file should refresh the
        service that package provides. The helper is deliberately conservative:
        stopped/inactive services are not included, and ambiguous package->many
        service mappings are left to the renderer/caller to resolve.
        """

        by_package: Dict[str, List[Dict[str, str]]] = {}
        for entry in entries:
            if str(entry.get("kind") or "package") != "service":
                continue
            snap = entry.get("snapshot") or {}
            if not isinstance(snap, Mapping):
                continue
            unit = str(snap.get("unit") or "").strip()
            if not unit or str(snap.get("active_state") or "") != "active":
                continue
            role_name = str(snap.get("role_name") or unit).strip()
            for pkg in snap.get("packages", []) or []:
                package = str(pkg or "").strip()
                if package:
                    by_package.setdefault(package, []).append(
                        {"unit": unit, "role_name": role_name}
                    )
        for package, services in list(by_package.items()):
            seen: Set[str] = set()
            unique: List[Dict[str, str]] = []
            for svc in services:
                unit = svc.get("unit") or ""
                if unit and unit not in seen:
                    seen.add(unit)
                    unique.append(svc)
            by_package[package] = sorted(unique, key=lambda svc: svc.get("unit", ""))
        return by_package

    @staticmethod
    def active_service_units_for_package_snapshot(
        package_snapshot: Mapping[str, Any],
        service_units_by_package: Mapping[str, List[Dict[str, str]]],
    ) -> List[str]:
        """Return active service units that a package snapshot can safely refresh.

        If one active service is associated with the package, return it. If
        several are associated, only return a role-name match; otherwise avoid
        guessing and return no services. This prevents package-level config from
        recreating the old broad-restart problem.
        """

        package = str(package_snapshot.get("package") or "").strip()
        if not package:
            return []
        services = list(service_units_by_package.get(package) or [])
        if len(services) == 1:
            unit = services[0].get("unit") or ""
            return [unit] if unit else []

        role_name = str(package_snapshot.get("role_name") or "").strip()
        if role_name:
            matched = [
                svc.get("unit") or ""
                for svc in services
                if svc.get("role_name") == role_name and svc.get("unit")
            ]
            if matched:
                return sorted(set(matched))
        return []

    def add_user_flatpaks_snapshot(self, snap: Dict[str, Any]) -> None:
        home_by_user = {
            str(u.get("name")): str(u.get("home") or "")
            for u in (snap.get("users", []) or [])
            if isinstance(u, dict) and u.get("name")
        }
        for remote in snap.get("user_flatpak_remotes", []) or []:
            item = self.normalise_flatpak_remote(remote)
            user = str(item.get("user") or "").strip()
            if user and not item.get("home"):
                item["home"] = home_by_user.get(user) or f"/home/{user}"
            if item.get("method") == "user" and item.get("name") and item.get("url"):
                self.flatpak_remotes.append(  # type: ignore[attr-defined]
                    self.prepare_flatpak_remote(item)
                )
        for uname, flatpaks in (snap.get("user_flatpaks", {}) or {}).items():
            user = str(uname)
            for fp in flatpaks or []:
                item = self.normalise_flatpak_item(
                    fp, method="user", user=user, home=home_by_user.get(user) or None
                )
                if item.get("name"):
                    self.flatpaks.append(  # type: ignore[attr-defined]
                        self.prepare_flatpak_item(item)
                    )

    def add_flatpak_snapshot(self, snap: Dict[str, Any]) -> None:
        for remote in snap.get("remotes", []) or []:
            item = self.normalise_flatpak_remote(remote)
            if item.get("name") and item.get("url"):
                self.flatpak_remotes.append(  # type: ignore[attr-defined]
                    self.prepare_flatpak_remote(item)
                )
        for fp in snap.get("system_flatpaks", []) or []:
            item = self.normalise_flatpak_item(fp, method="system")
            if item.get("name"):
                self.flatpaks.append(  # type: ignore[attr-defined]
                    self.prepare_flatpak_item(item)
                )
        self.add_snapshot_notes(snap)

    def add_snap_snapshot(self, snap: Dict[str, Any]) -> None:
        for raw in snap.get("system_snaps", []) or []:
            item = self.normalise_snap_item(raw)
            if item.get("name"):
                self.snaps.append(  # type: ignore[attr-defined]
                    self.prepare_snap_item(item)
                )
        self.add_snapshot_notes(snap)

    def firewall_runtime_snapshot_has_artifacts(self, snap: Mapping[str, Any]) -> bool:
        return any(
            str(snap.get(key) or "").strip()
            for key, _dest, _mode in self.firewall_runtime_artifacts
        )

    def firewall_runtime_source_refs(self, snap: Mapping[str, Any]) -> Dict[str, str]:
        return {
            key: str(snap.get(key) or "").strip()
            for key, _dest, _mode in self.firewall_runtime_artifacts
            if str(snap.get(key) or "").strip()
        }

    def firewall_runtime_dest_path(self, dest_name: str) -> str:
        return f"{self.firewall_runtime_dir}/{dest_name}"

    def firewall_runtime_ipset_sets(self, snap: Mapping[str, Any]) -> List[str]:
        return [
            str(x).strip() for x in (snap.get("ipset_sets") or []) if str(x).strip()
        ]

    @staticmethod
    def shell_quote(value: Any) -> str:
        return shlex.quote(str(value or ""))

    def firewall_ipset_restore_cmd(self, path: str, sets: List[str]) -> str:
        flush_parts = [f"ipset flush {self.shell_quote(name)} || true" for name in sets]
        flush = "; ".join(flush_parts)
        restore = f"ipset restore -exist < {self.shell_quote(path)}"
        if flush:
            return f"/bin/sh -c {self.shell_quote(flush + '; ' + restore)}"
        return f"/bin/sh -c {self.shell_quote(restore)}"

    def firewall_runtime_commands(self, runtime: Mapping[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        ipset_path = str(runtime.get("ipset_save") or "")
        if ipset_path:
            sets = [str(x) for x in (runtime.get("ipset_sets") or []) if str(x)]
            out["ipset_restore_cmd"] = self.firewall_ipset_restore_cmd(ipset_path, sets)
        ipt4_path = str(runtime.get("iptables_v4_save") or "")
        if ipt4_path:
            out["iptables_v4_restore_cmd"] = (
                f"iptables-restore {self.shell_quote(ipt4_path)}"
            )
        ipt6_path = str(runtime.get("iptables_v6_save") or "")
        if ipt6_path:
            out["iptables_v6_restore_cmd"] = (
                f"ip6tables-restore {self.shell_quote(ipt6_path)}"
            )
        return out

    def _managed_owner_attrs(self, owner: Any) -> Dict[str, Any]:
        return {self.managed_owner_attr: owner or "root"}

    def add_firewall_runtime_snapshot(
        self,
        snap: Dict[str, Any],
        *,
        bundle_dir: str,
        artifact_role: str,
        files_dir: Path,
        copy_artifact: Callable[..., str | None],
        source_uri: Callable[[str, str], str],
        file_prefix: str | None = None,
        dir_attrs: Mapping[str, Any] | None = None,
        file_attrs: Mapping[str, Any] | None = None,
    ) -> None:
        """Add captured live firewall state using renderer-supplied file hooks."""

        self.add_service_packages_from_snapshot(snap)
        attrs: Dict[str, Any] = {
            **self._managed_owner_attrs("root"),
            "group": "root",
            "mode": "0750",
            "reason": "firewall_runtime",
        }
        if dir_attrs:
            attrs.update(dir_attrs)
        self.add_managed_dir(self.firewall_runtime_dir, **attrs)

        runtime: Dict[str, Any] = {}
        for key, dest_name, mode in self.firewall_runtime_artifacts:
            src_rel = str(snap.get(key) or "").strip()
            if not src_rel:
                continue
            role_rel = copy_artifact(
                bundle_dir,
                artifact_role,
                src_rel,
                files_dir,
                dst_prefix=file_prefix,
            )
            if not role_rel:
                self.notes.append(
                    f"Firewall runtime artifact {src_rel!r} was referenced but not found."
                )
                continue
            file_data: Dict[str, Any] = {
                **self._managed_owner_attrs("root"),
                "group": "root",
                "mode": mode,
                "source": source_uri(self.module_name, role_rel),
                "reason": "firewall_runtime",
            }
            if file_attrs:
                file_data.update(file_attrs)
            dest = self.firewall_runtime_dest_path(dest_name)
            self.add_managed_file(dest, **file_data)
            runtime[key] = dest

        ipset_sets = self.firewall_runtime_ipset_sets(snap)
        if ipset_sets:
            runtime["ipset_sets"] = ipset_sets
        if runtime:
            runtime.update(self.firewall_runtime_commands(runtime))
            self.firewall_runtime.update(runtime)
        self.add_snapshot_notes(snap)

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
        "enroll_runtime": 94,
        "sysctl": 95,
        "firewall_runtime": 99,
    }
    return (priority.get(role, 50), role)


# Control characters (excluding ordinary tab) that must never reach generated
# documentation. A raw newline/carriage return in a harvested value would let it
# break out of a Markdown list item or code span and inject new document
# structure (a fake heading, a misleading link/command block); other C0/C1
# control bytes can smuggle terminal escape sequences when the README is printed.
_MARKDOWN_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize_markdown_text(value: Any) -> str:
    """Neutralise harvested text before it is spliced into generated Markdown.

    Generated docs (the Ansible ``README.md``) embed harvested, attacker-
    influenceable values such as the host name and captured file paths. These
    are not executed by Ansible, but a value containing a newline, carriage
    return, backtick, or control byte could otherwise break out of its
    surrounding list item / code span and inject misleading Markdown structure
    (a forged heading, a deceptive ``[link](...)``/command block) or a terminal
    escape sequence when the file is viewed. This collapses any whitespace run
    (including newlines and tabs) to a single space, drops other control bytes,
    and replaces backticks with a similar-looking single quote so a value can
    never escape an inline code span. It is deliberately lossy: the README is a
    human-readable summary, and faithful representation of hostile bytes there
    is not a goal.
    """

    text = str(value)
    # Collapse any run of whitespace (newlines, CR, tabs, spaces) to one space so
    # a harvested value stays on a single Markdown line / inside one code span.
    text = re.sub(r"\s+", " ", text)
    # Drop remaining control characters that survived the whitespace collapse.
    text = _MARKDOWN_CONTROL_RE.sub("", text)
    # A backtick would close an inline code span and let following characters be
    # interpreted as Markdown; swap it for a visually-similar acute accent.
    text = text.replace("`", "\u00b4")
    return text.strip()


def markdown_list(items: Iterable[Any], *, empty: str = "None.") -> str:
    """Render already-composed Markdown list lines.

    Callers that embed harvested values (``snapshot_note_lines``,
    ``snapshot_excluded_lines``, ``path_reason_lines``) sanitise those values
    with :func:`sanitize_markdown_text` before composing each line, so this
    helper only joins lines it is given. It still drops empty entries.
    """

    values = [str(item) for item in items if str(item).strip()]
    return "\n".join(f"- {item}" for item in values) or f"- {empty}"


def path_reason_lines(
    items: Iterable[Mapping[str, Any]], *, source_key: str = "path"
) -> List[str]:
    lines: List[str] = []
    for item in items or []:
        path = sanitize_markdown_text(item.get(source_key) or "")
        if not path:
            continue
        reason = sanitize_markdown_text(item.get("reason") or "")
        lines.append(f"{path} ({reason})" if reason else path)
    return lines


def iter_role_snapshots(roles: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    for value in roles.values():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, Mapping):
                    yield item
        elif isinstance(value, Mapping):
            yield value


def snapshot_note_lines(roles: Mapping[str, Any]) -> List[str]:
    notes: List[str] = []
    for snap in iter_role_snapshots(roles):
        source = sanitize_markdown_text(
            snap.get("role_name") or snap.get("unit") or snap.get("package") or "role"
        )
        notes.extend(
            f"`{source}`: {sanitize_markdown_text(note)}"
            for note in snap.get("notes", []) or []
        )
    return notes


def snapshot_excluded_lines(roles: Mapping[str, Any]) -> List[str]:
    excluded: List[str] = []
    for snap in iter_role_snapshots(roles):
        source = sanitize_markdown_text(
            snap.get("role_name") or snap.get("unit") or snap.get("package") or "role"
        )
        for line in path_reason_lines(snap.get("excluded", []) or []):
            excluded.append(f"`{source}`: {line}")
    return excluded


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
    """Resolve global catalog conflicts in the shared model.

    Deduplicates the same package, service, or parent directory appearing in
    more than one role. The Ansible renderer tolerates such duplicates, but this
    helper remains available for any catalog-style consumer of the shared model.
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
