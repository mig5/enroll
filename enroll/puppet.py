from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import yaml

from .cm import (
    CMModule,
    package_section_label,
    resolve_catalog_conflicts,
    role_order_key,
    section_label_for_packages,
)
from .state import inventory_packages_from_state, roles_from_state


class PuppetRole(CMModule):
    """Puppet-specific view of a renderer-neutral CMModule."""

    def __init__(self, role_name: str) -> None:
        super().__init__(
            role_name=role_name,
            module_name=_puppet_name(role_name, fallback="enroll_role"),
        )

    def add_package_snapshot(self, snap: Dict[str, Any]) -> None:
        pkg = str(snap.get("package") or "").strip()
        if pkg:
            self.packages.add(pkg)

    def add_service_snapshot(self, snap: Dict[str, Any]) -> None:
        for pkg in snap.get("packages", []) or []:
            pkg_s = str(pkg or "").strip()
            if pkg_s:
                self.packages.add(pkg_s)
        unit = str(snap.get("unit") or "").strip()
        if unit:
            unit_file_state = str(snap.get("unit_file_state") or "")
            self.services[unit] = {
                "name": unit,
                "ensure": (
                    "running" if snap.get("active_state") == "active" else "stopped"
                ),
                "enable": unit_file_state in ("enabled", "enabled-runtime"),
            }

    def add_users_snapshot(self, snap: Dict[str, Any]) -> None:
        for u in snap.get("users", []) or []:
            if not isinstance(u, dict):
                continue
            name = str(u.get("name") or "").strip()
            if not name:
                continue
            primary_group = str(u.get("primary_group") or name).strip()
            if primary_group:
                self.groups.add(primary_group)
            supplementary = sorted(
                {
                    str(g).strip()
                    for g in (u.get("supplementary_groups") or [])
                    if str(g).strip()
                }
            )
            self.groups.update(supplementary)
            self.users[name] = {
                "name": name,
                "uid": u.get("uid"),
                "gid": u.get("gid"),
                "primary_group": primary_group or None,
                "home": u.get("home") or f"/home/{name}",
                "shell": u.get("shell"),
                "gecos": u.get("gecos"),
                "supplementary_groups": supplementary,
            }

        if snap.get("user_flatpaks") or snap.get("user_flatpak_remotes"):
            self.notes.append(
                "Per-user Flatpak resources were detected but are not yet rendered as native Puppet resources."
            )

    def add_managed_content(
        self,
        snap: Dict[str, Any],
        *,
        bundle_dir: str,
        artifact_role: str,
        module_files_dir: Path,
        file_prefix: Optional[str] = None,
    ) -> None:
        for d in self.managed_dirs_from_snapshot(snap):
            path = str(d.get("path") or "").strip()
            self.add_managed_dir(
                path,
                owner=d.get("owner") or "root",
                group=d.get("group") or "root",
                mode=d.get("mode") or "0755",
                reason=d.get("reason") or "managed_dir",
            )

        for mf in self.managed_files_from_snapshot(snap):
            path = str(mf.get("path") or "").strip()
            src_rel = str(mf.get("src_rel") or "").strip()
            if not path or not src_rel:
                continue
            module_rel = _copy_artifact(
                bundle_dir,
                artifact_role,
                src_rel,
                module_files_dir,
                dst_prefix=file_prefix,
            )
            if not module_rel:
                self.notes.append(
                    f"Skipped {path}: harvested artifact {artifact_role}/{src_rel} was not present."
                )
                continue
            self.add_managed_file(
                path,
                owner=mf.get("owner") or "root",
                group=mf.get("group") or "root",
                mode=mf.get("mode") or "0644",
                source=_source_uri(self.module_name, module_rel),
                reason=mf.get("reason") or "managed_file",
            )

        for ml in self.managed_links_from_snapshot(snap):
            path = str(ml.get("path") or "").strip()
            target = str(ml.get("target") or "").strip()
            if not path or not target:
                continue
            self.add_managed_link(
                path,
                target=target,
                reason=ml.get("reason") or "managed_link",
            )

        self.remove_directory_resource_conflicts()


# https://help.puppet.com/core/current/Content/PuppetCore/lang_reserved_words.htm
_RESERVED_PUPPET_NAMES = {
    "and",
    "application",
    "attr",
    "case",
    "component",
    "consumes",
    "default",
    "define",
    "elsif",
    "environment",
    "false",
    "function",
    "if",
    "import",
    "in",
    "init",
    "inherits",
    "node",
    "or",
    "private",
    "produces",
    "regexp",
    "site",
    "true",
    "type",
    "undef",
    "unit",
    "unless",
}


def _puppet_name(raw: str, *, fallback: str = "role") -> str:
    s = re.sub(r"[^A-Za-z0-9_]+", "_", raw or fallback)
    s = re.sub(r"_+", "_", s).strip("_").lower()
    if not s:
        s = fallback
    if not re.match(r"^[a-z]", s):
        s = f"{fallback}_{s}"
    if s in _RESERVED_PUPPET_NAMES:
        s = f"{fallback}_{s}"
    return s


def _pp_quote(value: Any) -> str:
    s = str(value)
    s = s.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{s}'"


def _pp_bool(value: bool) -> str:
    return "true" if bool(value) else "false"


def _pp_array(values: Iterable[Any]) -> str:
    return "[" + ", ".join(_pp_quote(v) for v in values) + "]"


def _resource(
    lines: List[str], rtype: str, title: str, attrs: List[Tuple[str, str]]
) -> None:
    lines.append(f"  {rtype} {{ {_pp_quote(title)}:")
    for key, value in attrs:
        lines.append(f"    {key} => {value},")
    lines.append("  }")
    lines.append("")


def _copy_artifact(
    bundle_dir: str,
    role: str,
    src_rel: str,
    dst_files_dir: Path,
    *,
    dst_prefix: Optional[str] = None,
) -> Optional[str]:
    if not role or not src_rel:
        return None
    src = Path(bundle_dir) / "artifacts" / role / src_rel
    if not src.is_file():
        return None
    module_rel = Path(dst_prefix or "") / src_rel
    dst = dst_files_dir / module_rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return module_rel.as_posix()


def _source_uri(module_name: str, module_rel: str) -> str:
    return f"puppet:///modules/{module_name}/{module_rel}"


def _add_flatpak_snap_notes(roles: Dict[str, Any], out: Dict[str, PuppetRole]) -> None:
    flatpak = roles.get("flatpak") or {}
    if isinstance(flatpak, dict) and (
        flatpak.get("system_flatpaks") or flatpak.get("remotes")
    ):
        prole = out.setdefault("flatpak", PuppetRole("flatpak"))
        prole.notes.append(
            "Flatpak resources were detected but are not yet rendered as native Puppet resources."
        )
    snap = roles.get("snap") or {}
    if isinstance(snap, dict) and snap.get("system_snaps"):
        prole = out.setdefault("snap", PuppetRole("snap"))
        prole.notes.append(
            "Snap resources were detected but are not yet rendered as native Puppet resources."
        )


def _node_data_filename(fqdn: str) -> str:
    """Return a safe Hiera node-data filename for an FQDN/certname."""

    name = str(fqdn or "").strip().replace("/", "_").replace("\\", "_")
    return f"{name or 'node'}.yaml"


def _node_file_prefix(fqdn: str) -> str:
    """Return a safe module-files prefix for node-specific artifacts."""

    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(fqdn or "").strip())
    name = name.strip("._-") or "node"
    return f"nodes/{name}"


def _collect_puppet_roles(
    state: Dict[str, Any],
    bundle_dir: str,
    modules_dir: Path,
    *,
    fqdn: Optional[str] = None,
    no_common_roles: bool = False,
) -> List[PuppetRole]:
    roles = roles_from_state(state)
    inventory_packages = inventory_packages_from_state(state)
    use_common_modules = not fqdn and not no_common_roles
    node_file_prefix = _node_file_prefix(fqdn) if fqdn else None
    out: Dict[str, PuppetRole] = {}

    def ensure_role(role_name: str) -> PuppetRole:
        role_name = _puppet_name(role_name, fallback="enroll_role")
        return out.setdefault(role_name, PuppetRole(role_name))

    for key in (
        "apt_config",
        "dnf_config",
        "etc_custom",
        "usr_local_custom",
        "extra_paths",
        "sysctl",
    ):
        snap = roles.get(key) or {}
        if not isinstance(snap, dict):
            continue
        role_name = _puppet_name(
            str(snap.get("role_name") or key), fallback="enroll_role"
        )
        prole = ensure_role(role_name)
        module_files_dir = modules_dir / prole.module_name / "files"
        prole.add_managed_content(
            snap,
            bundle_dir=bundle_dir,
            artifact_role=str(snap.get("role_name") or key),
            module_files_dir=module_files_dir,
            file_prefix=node_file_prefix,
        )

    users_snap = roles.get("users") or {}
    if isinstance(users_snap, dict):
        role_name = _puppet_name(
            str(users_snap.get("role_name") or "users"), fallback="enroll_role"
        )
        prole = ensure_role(role_name)
        prole.add_users_snapshot(users_snap)
        prole.add_managed_content(
            users_snap,
            bundle_dir=bundle_dir,
            artifact_role=str(users_snap.get("role_name") or "users"),
            module_files_dir=modules_dir / prole.module_name / "files",
            file_prefix=node_file_prefix,
        )

    for svc in roles.get("services", []) or []:
        if not isinstance(svc, dict):
            continue
        original_role_name = _puppet_name(
            str(svc.get("role_name") or svc.get("unit") or "service"),
            fallback="service",
        )
        if use_common_modules:
            role_name = _puppet_name(
                section_label_for_packages(
                    [
                        str(p).strip()
                        for p in (svc.get("packages") or [])
                        if str(p).strip()
                    ],
                    inventory_packages,
                ),
                fallback="package_group",
            )
        else:
            role_name = original_role_name
        prole = ensure_role(role_name)
        prole.add_service_snapshot(svc)
        prole.add_managed_content(
            svc,
            bundle_dir=bundle_dir,
            artifact_role=str(svc.get("role_name") or original_role_name),
            module_files_dir=modules_dir / prole.module_name / "files",
            file_prefix=node_file_prefix,
        )

    for pkg in roles.get("packages", []) or []:
        if not isinstance(pkg, dict):
            continue
        original_role_name = _puppet_name(
            str(pkg.get("role_name") or pkg.get("package") or "package"),
            fallback="package",
        )
        if use_common_modules:
            role_name = _puppet_name(
                package_section_label(pkg, inventory_packages),
                fallback="package_group",
            )
        else:
            role_name = original_role_name
        prole = ensure_role(role_name)
        prole.add_package_snapshot(pkg)
        prole.add_managed_content(
            pkg,
            bundle_dir=bundle_dir,
            artifact_role=str(pkg.get("role_name") or original_role_name),
            module_files_dir=modules_dir / prole.module_name / "files",
            file_prefix=node_file_prefix,
        )

    fw = roles.get("firewall_runtime") or {}
    if isinstance(fw, dict):
        has_fw = (
            fw.get("ipset_save")
            or fw.get("iptables_v4_save")
            or fw.get("iptables_v6_save")
        )
        packages = [
            str(p).strip() for p in (fw.get("packages") or []) if str(p).strip()
        ]
        if has_fw or packages:
            prole = ensure_role(str(fw.get("role_name") or "firewall_runtime"))
            prole.packages.update(packages)
            if has_fw:
                prole.notes.append(
                    "Live firewall runtime snapshots were detected but are not yet rendered as Puppet resources."
                )

    _add_flatpak_snap_notes(roles, out)

    puppet_roles = sorted(out.values(), key=lambda r: role_order_key(r.role_name))
    resolve_catalog_conflicts(puppet_roles)
    return [r for r in puppet_roles if r.has_resources()]


def _render_role_class(prole: PuppetRole) -> str:
    has_sysctl_conf = "/etc/sysctl.d/99-enroll.conf" in prole.files
    if has_sysctl_conf:
        lines: List[str] = [
            "# Generated by Enroll from harvest state.",
            f"class {prole.module_name} (",
            "  Boolean $sysctl_apply = true,",
            "  Boolean $sysctl_ignore_apply_errors = true,",
            ") {",
            "",
        ]
    else:
        lines = [
            "# Generated by Enroll from harvest state.",
            f"class {prole.module_name} {{",
            "",
        ]

    for package in sorted(prole.packages):
        _resource(lines, "package", package, [("ensure", _pp_quote("installed"))])

    for group in sorted(prole.groups):
        _resource(lines, "group", group, [("ensure", _pp_quote("present"))])

    for user in [prole.users[k] for k in sorted(prole.users)]:
        attrs: List[Tuple[str, str]] = [
            ("ensure", _pp_quote("present")),
            ("managehome", _pp_bool(True)),
        ]
        if user.get("uid") is not None:
            attrs.append(("uid", _pp_quote(user["uid"])))
        if user.get("primary_group"):
            attrs.append(("gid", _pp_quote(user["primary_group"])))
        if user.get("home"):
            attrs.append(("home", _pp_quote(user["home"])))
        if user.get("shell"):
            attrs.append(("shell", _pp_quote(user["shell"])))
        if user.get("gecos"):
            attrs.append(("comment", _pp_quote(user["gecos"])))
        if user.get("supplementary_groups"):
            attrs.append(("groups", _pp_array(user["supplementary_groups"])))
            attrs.append(("membership", _pp_quote("minimum")))
        _resource(lines, "user", user["name"], attrs)

    for path, d in sorted(prole.dirs.items()):
        _resource(
            lines,
            "file",
            path,
            [
                ("ensure", _pp_quote("directory")),
                ("owner", _pp_quote(d.get("owner") or "root")),
                ("group", _pp_quote(d.get("group") or "root")),
                ("mode", _pp_quote(d.get("mode") or "0755")),
            ],
        )

    for path, f in sorted(prole.files.items()):
        _resource(
            lines,
            "file",
            path,
            [
                ("ensure", _pp_quote("file")),
                ("source", _pp_quote(f.get("source") or "")),
                ("owner", _pp_quote(f.get("owner") or "root")),
                ("group", _pp_quote(f.get("group") or "root")),
                ("mode", _pp_quote(f.get("mode") or "0644")),
            ],
        )

    for path, lnk in sorted(prole.links.items()):
        _resource(
            lines,
            "file",
            path,
            [
                ("ensure", _pp_quote("link")),
                ("target", _pp_quote(lnk.get("target") or "")),
            ],
        )

    for svc in [prole.services[k] for k in sorted(prole.services)]:
        _resource(
            lines,
            "service",
            svc["name"],
            [
                ("ensure", _pp_quote(svc["ensure"])),
                ("enable", _pp_bool(bool(svc["enable"]))),
            ],
        )

    if has_sysctl_conf:
        lines.append("  if $sysctl_apply {")
        lines.append("    exec { 'enroll-apply-sysctl':")
        lines.append("      command     => $sysctl_ignore_apply_errors ? {")
        lines.append(
            "        true    => \"/bin/sh -c 'sysctl -e -p /etc/sysctl.d/99-enroll.conf || true'\","
        )
        lines.append("        default => 'sysctl -e -p /etc/sysctl.d/99-enroll.conf',")
        lines.append("      },")
        lines.append("      path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],")
        lines.append("      refreshonly => true,")
        lines.append("      subscribe   => File['/etc/sysctl.d/99-enroll.conf'],")
        lines.append("    }")
        lines.append("  }")
        lines.append("")

    if prole.notes:
        lines.append("  # Notes and limitations")
        for note in prole.notes:
            lines.append(f"  # - {note}")
        lines.append("")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _attrs_with_ensure(
    attrs: Dict[str, Any], ensure: str, *, allowed: Set[str]
) -> Dict[str, Any]:
    """Return only Puppet resource attributes, dropping Enroll metadata."""
    out = {"ensure": ensure}
    for key in sorted(allowed):
        if key in attrs and attrs[key] is not None:
            out[key] = attrs[key]
    return out


def _role_hiera_values(prole: PuppetRole) -> Dict[str, Any]:
    """Return Automatic Parameter Lookup data for one generated module."""

    data: Dict[str, Any] = {}
    prefix = f"{prole.module_name}::"

    if prole.packages:
        data[f"{prefix}packages"] = sorted(prole.packages)

    if prole.groups:
        data[f"{prefix}groups"] = {
            group: {"ensure": "present"} for group in sorted(prole.groups)
        }

    if prole.users:
        users: Dict[str, Dict[str, Any]] = {}
        for name in sorted(prole.users):
            user = prole.users[name]
            attrs: Dict[str, Any] = {"ensure": "present", "managehome": True}
            if user.get("uid") is not None:
                attrs["uid"] = user["uid"]
            if user.get("primary_group"):
                attrs["gid"] = user["primary_group"]
            if user.get("home"):
                attrs["home"] = user["home"]
            if user.get("shell"):
                attrs["shell"] = user["shell"]
            if user.get("gecos"):
                attrs["comment"] = user["gecos"]
            if user.get("supplementary_groups"):
                attrs["groups"] = list(user["supplementary_groups"])
                attrs["membership"] = "minimum"
            users[name] = attrs
        data[f"{prefix}users"] = users

    if prole.dirs:
        data[f"{prefix}dirs"] = {
            path: _attrs_with_ensure(
                prole.dirs[path],
                "directory",
                allowed={"owner", "group", "mode"},
            )
            for path in sorted(prole.dirs)
        }

    if prole.files:
        data[f"{prefix}files"] = {
            path: _attrs_with_ensure(
                prole.files[path],
                "file",
                allowed={"source", "owner", "group", "mode"},
            )
            for path in sorted(prole.files)
        }

    if prole.links:
        data[f"{prefix}links"] = {
            path: _attrs_with_ensure(
                prole.links[path],
                "link",
                allowed={"target"},
            )
            for path in sorted(prole.links)
        }

    if prole.services:
        data[f"{prefix}services"] = {
            name: {
                "ensure": prole.services[name].get("ensure") or "stopped",
                "enable": bool(prole.services[name].get("enable")),
            }
            for name in sorted(prole.services)
        }

    if prole.notes:
        data[f"{prefix}notes"] = list(prole.notes)

    if "/etc/sysctl.d/99-enroll.conf" in prole.files:
        data[f"{prefix}sysctl_apply"] = True
        data[f"{prefix}sysctl_ignore_apply_errors"] = True

    return data


def _render_hiera_role_class(prole: PuppetRole) -> str:
    """Render a reusable, data-driven Puppet class for --fqdn/Hiera mode."""

    lines: List[str] = [
        "# Generated by Enroll from harvest state.",
        "# Resource data is supplied by Hiera Automatic Parameter Lookup.",
        f"class {prole.module_name} (",
        "  Array[String] $packages = [],",
        "  Hash[String, Hash] $groups = {},",
        "  Hash[String, Hash] $users = {},",
        "  Hash[String, Hash] $dirs = {},",
        "  Hash[String, Hash] $files = {},",
        "  Hash[String, Hash] $links = {},",
        "  Hash[String, Hash] $services = {},",
        "  Array[String] $notes = [],",
        "  Boolean $sysctl_apply = true,",
        "  Boolean $sysctl_ignore_apply_errors = true,",
        ") {",
        "",
        "  $packages.each |String $package_name| {",
        "    package { $package_name:",
        "      ensure => 'installed',",
        "    }",
        "  }",
        "",
        "  $groups.each |String $resource_title, Hash $attrs| {",
        "    group { $resource_title:",
        "      * => $attrs,",
        "    }",
        "  }",
        "",
        "  $users.each |String $resource_title, Hash $attrs| {",
        "    user { $resource_title:",
        "      * => $attrs,",
        "    }",
        "  }",
        "",
        "  $dirs.each |String $resource_title, Hash $attrs| {",
        "    file { $resource_title:",
        "      * => $attrs,",
        "    }",
        "  }",
        "",
        "  $files.each |String $resource_title, Hash $attrs| {",
        "    file { $resource_title:",
        "      * => $attrs,",
        "    }",
        "  }",
        "",
        "  $links.each |String $resource_title, Hash $attrs| {",
        "    file { $resource_title:",
        "      * => $attrs,",
        "    }",
        "  }",
        "",
        "  $services.each |String $resource_title, Hash $attrs| {",
        "    service { $resource_title:",
        "      * => $attrs,",
        "    }",
        "  }",
        "",
        "  if $sysctl_apply and '/etc/sysctl.d/99-enroll.conf' in $files {",
        "    exec { 'enroll-apply-sysctl':",
        "      command     => $sysctl_ignore_apply_errors ? {",
        "        true    => \"/bin/sh -c 'sysctl -e -p /etc/sysctl.d/99-enroll.conf || true'\",",
        "        default => 'sysctl -e -p /etc/sysctl.d/99-enroll.conf',",
        "      },",
        "      path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],",
        "      refreshonly => true,",
        "      subscribe   => File['/etc/sysctl.d/99-enroll.conf'],",
        "    }",
        "  }",
        "",
        "  # Generated notes are supplied through the $notes parameter for review.",
        "}",
        "",
    ]
    return "\n".join(lines)


def _render_site_pp(puppet_roles: List[PuppetRole], fqdn: Optional[str]) -> str:
    node_name = _pp_quote(fqdn) if fqdn else "default"
    if not puppet_roles:
        return f"node {node_name} {{\n  # No Puppet classes were generated from this harvest.\n}}\n"
    includes = "\n".join(f"  include {r.module_name}" for r in puppet_roles)
    return f"node {node_name} {{\n{includes}\n}}\n"


def _render_hiera_site_pp(node_names: List[str]) -> str:
    lines: List[str] = [
        "# Generated by Enroll from harvest state.",
        "# Per-node class lists and resources are read from Hiera data.",
        "",
    ]
    for node_name in node_names:
        lines.extend(
            [
                f"node {_pp_quote(node_name)} {{",
                "  $enroll_classes = lookup('enroll::classes', Array[String], 'unique', [])",
                "  $enroll_classes.each |String $enroll_class| {",
                "    include $enroll_class",
                "  }",
                "}",
                "",
            ]
        )
    lines.extend(
        [
            "node default {",
            "  $enroll_classes = lookup('enroll::classes', Array[String], 'unique', [])",
            "  $enroll_classes.each |String $enroll_class| {",
            "    include $enroll_class",
            "  }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _render_hiera_yaml() -> str:
    data = {
        "version": 5,
        "defaults": {"datadir": "data", "data_hash": "yaml_data"},
        "hierarchy": [
            {
                "name": "Enroll trusted certname node data",
                "path": "nodes/%{trusted.certname}.yaml",
            },
            {
                "name": "Enroll networking FQDN node data",
                "path": "nodes/%{facts.networking.fqdn}.yaml",
            },
            {"name": "Enroll common data", "path": "common.yaml"},
        ],
    }
    return yaml.safe_dump(data, sort_keys=False, explicit_start=True)


def _write_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=True, explicit_start=True),
        encoding="utf-8",
    )


def _write_hiera_node_data(
    out: Path, fqdn: str, puppet_roles: List[PuppetRole]
) -> Path:
    node_data: Dict[str, Any] = {
        "enroll::classes": [r.module_name for r in puppet_roles]
    }
    for prole in puppet_roles:
        node_data.update(_role_hiera_values(prole))
    node_path = out / "data" / "nodes" / _node_data_filename(fqdn)
    _write_yaml(node_path, node_data)
    common_path = out / "data" / "common.yaml"
    if not common_path.exists():
        _write_yaml(common_path, {"enroll::classes": []})
    return node_path


def _hiera_node_names(out: Path) -> List[str]:
    nodes_dir = out / "data" / "nodes"
    if not nodes_dir.is_dir():
        return []
    out_names: Set[str] = set()
    for path in nodes_dir.glob("*.yaml"):
        out_names.add(path.name[: -len(".yaml")])
    return sorted(out_names)


def _write_metadata(module_dir: Path, module_name: str) -> None:
    (module_dir / "metadata.json").write_text(
        json.dumps(
            {
                "name": f"enroll-{module_name}",
                "version": "0.1.0",
                "author": "Enroll",
                "summary": f"Generated Enroll Puppet module for {module_name}",
                "license": "UNLICENSED",
                "source": "",
                "dependencies": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _render_readme(
    state: Dict[str, Any],
    puppet_roles: List[PuppetRole],
    *,
    fqdn: Optional[str] = None,
    node_names: Optional[List[str]] = None,
) -> str:
    host = state.get("host", {}) if isinstance(state.get("host"), dict) else {}
    hostname = host.get("hostname") or "unknown"
    hiera_mode = bool(fqdn)
    role_lines = (
        "\n".join(
            f"- `{r.module_name}` from Enroll role `{r.role_name}`"
            for r in puppet_roles
        )
        or "- None."
    )
    node_lines = "\n".join(f"- `{n}`" for n in (node_names or [])) or "- None."
    notes: List[str] = []
    for r in puppet_roles:
        for note in r.notes:
            notes.append(f"`{r.module_name}`: {note}")
    notes_text = "\n".join(f"- {n}" for n in notes) or "- None."
    if hiera_mode:
        layout = f"""- `manifests/site.pp` declares node blocks and includes classes listed in Hiera key `enroll::classes`.
- `hiera.yaml` configures per-node lookup from `data/nodes/%{{trusted.certname}}.yaml` with a fallback to `data/common.yaml`.
- `data/nodes/{_node_data_filename(fqdn or '')}` contains this node's class list and class parameter data.
- `modules/<role>/manifests/init.pp` contains reusable, data-driven classes.
- `modules/<role>/files/nodes/<fqdn>/...` contains node-specific harvested file artifacts, avoiding clashes between hosts."""
        apply = f"""Run from this generated output directory, passing the node certname so Hiera selects the right node data:

```bash
sudo puppet apply --modulepath ./modules --hiera_config ./hiera.yaml --certname {fqdn} manifests/site.pp --noop
```

For Puppet agent/control-repo use, place this output where `hiera.yaml`, `data/`, `manifests/`, and `modules/` form the environment root. Re-running Enroll with another `--fqdn` into the same output directory adds or replaces that node's YAML without deleting existing node data."""
    else:
        layout = """- `manifests/site.pp` declares a `node` block and includes the generated classes in manifest order.
- `modules/<role>/manifests/init.pp` contains resources for each generated Enroll role/snapshot or common package group.
- `modules/<role>/files/` contains harvested file artifacts for that role or group.
- Generated module names avoid Puppet reserved words such as `default`."""
        apply = """Run from this generated output directory so Puppet can find `./modules`, or pass an absolute module path:

```bash
sudo puppet apply --modulepath ./modules manifests/site.pp --noop
```

```bash
sudo puppet apply --modulepath /path/to/generated/modules /path/to/generated/manifests/site.pp --noop
```"""
    return f"""# Enroll Puppet manifest

Generated by Enroll from harvest data for `{hostname}`.

This Puppet target reuses the existing harvest state without changing harvesting behaviour.

## Layout

{layout}

## Known nodes

{node_lines if hiera_mode else '- Non-Hiera single-node output.'}

## Generated modules

{role_lines}

## Apply / check

{apply}

## Generated resources

- Native packages observed in package and service snapshots.
- Local users and groups from the users snapshot.
- Managed directories, files, and symlinks from harvested roles.
- Basic service enablement/running-state resources.
- `/etc/sysctl.d/99-enroll.conf` plus a refresh-only sysctl apply exec when present.

## Current limitations

- Flatpak, Snap, and live firewall runtime snapshots are listed as notes when present rather than rendered as Puppet resources.
- JinjaTurtle templating is currently Ansible-oriented and is not applied to Puppet output.
- Review generated resources before applying them broadly across unlike hosts.

## Notes

{notes_text}
"""


class PuppetManifestRenderer:
    """Render Puppet modules and site manifest from a harvest bundle."""

    def __init__(
        self,
        bundle_dir: str,
        out_dir: str,
        *,
        fqdn: Optional[str] = None,
        no_common_roles: bool = False,
    ) -> None:
        self.bundle_dir = bundle_dir
        self.out_dir = out_dir
        self.fqdn = fqdn
        self.no_common_roles = no_common_roles

    def render(self) -> None:
        """Render Puppet modules/site.pp from a harvest bundle."""

        bundle_dir = self.bundle_dir
        out_dir = self.out_dir
        fqdn = self.fqdn
        no_common_roles = self.no_common_roles

        state = PuppetRole.load_state(bundle_dir)
        out = Path(out_dir)
        hiera_mode = bool(fqdn)
        if out.exists() and not hiera_mode:
            shutil.rmtree(out)
        manifests_dir = out / "manifests"
        modules_dir = out / "modules"
        manifests_dir.mkdir(parents=True, exist_ok=True)
        modules_dir.mkdir(parents=True, exist_ok=True)

        puppet_roles = _collect_puppet_roles(
            state,
            bundle_dir,
            modules_dir,
            fqdn=fqdn,
            no_common_roles=no_common_roles,
        )
        for prole in puppet_roles:
            module_dir = modules_dir / prole.module_name
            module_manifests = module_dir / "manifests"
            module_files = module_dir / "files"
            module_manifests.mkdir(parents=True, exist_ok=True)
            module_files.mkdir(parents=True, exist_ok=True)
            (module_manifests / "init.pp").write_text(
                (
                    _render_hiera_role_class(prole)
                    if hiera_mode
                    else _render_role_class(prole)
                ),
                encoding="utf-8",
            )
            _write_metadata(module_dir, prole.module_name)

        node_names: List[str] = []
        if hiera_mode and fqdn:
            (out / "hiera.yaml").write_text(_render_hiera_yaml(), encoding="utf-8")
            _write_hiera_node_data(out, fqdn, puppet_roles)
            node_names = _hiera_node_names(out)
            (manifests_dir / "site.pp").write_text(
                _render_hiera_site_pp(node_names), encoding="utf-8"
            )
        else:
            (manifests_dir / "site.pp").write_text(
                _render_site_pp(puppet_roles, fqdn), encoding="utf-8"
            )
        (out / "README.md").write_text(
            _render_readme(
                state,
                puppet_roles,
                fqdn=fqdn,
                node_names=node_names,
            ),
            encoding="utf-8",
        )


def manifest_from_bundle_dir(
    bundle_dir: str,
    out_dir: str,
    *,
    fqdn: Optional[str] = None,
    no_common_roles: bool = False,
) -> None:
    PuppetManifestRenderer(
        bundle_dir,
        out_dir,
        fqdn=fqdn,
        no_common_roles=no_common_roles,
    ).render()
