from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


def _load_state(bundle_dir: str) -> Dict[str, Any]:
    with open(os.path.join(bundle_dir, "state.json"), "r", encoding="utf-8") as f:
        return json.load(f)


_RESERVED_PUPPET_NAMES = {
    "application",
    "class",
    "default",
    "define",
    "import",
    "inherits",
    "node",
    "site",
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
    bundle_dir: str, role: str, src_rel: str, dst_files_dir: Path
) -> Optional[str]:
    if not role or not src_rel:
        return None
    src = Path(bundle_dir) / "artifacts" / role / src_rel
    if not src.is_file():
        return None
    dst = dst_files_dir / src_rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return Path(src_rel).as_posix()


def _source_uri(module_name: str, module_rel: str) -> str:
    return f"puppet:///modules/{module_name}/{module_rel}"


def _roles(state: Dict[str, Any]) -> Dict[str, Any]:
    roles = state.get("roles")
    return roles if isinstance(roles, dict) else {}


def _inventory_packages(state: Dict[str, Any]) -> Dict[str, Any]:
    inventory = state.get("inventory")
    if not isinstance(inventory, dict):
        return {}
    packages = inventory.get("packages")
    return packages if isinstance(packages, dict) else {}


def _package_section_label(
    package_role: Dict[str, Any], inventory_packages: Dict[str, Any]
) -> str:
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


def _section_label_for_packages(
    packages: List[str], inventory_packages: Dict[str, Any]
) -> str:
    for pkg in packages or []:
        label = _package_section_label({"package": pkg}, inventory_packages)
        if label and label.lower() != "misc":
            return label
    return "misc"


class _PuppetRole:
    def __init__(self, role_name: str) -> None:
        self.role_name = role_name
        self.module_name = _puppet_name(role_name, fallback="enroll_role")
        self.packages: Set[str] = set()
        self.groups: Set[str] = set()
        self.users: Dict[str, Dict[str, Any]] = {}
        self.dirs: Dict[str, Dict[str, Any]] = {}
        self.files: Dict[str, Dict[str, Any]] = {}
        self.links: Dict[str, Dict[str, Any]] = {}
        self.services: Dict[str, Dict[str, Any]] = {}
        self.notes: List[str] = []

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


def _role_order_key(role: str) -> tuple[int, str]:
    # Keep broadly similar ordering to generated Ansible playbooks: package/config
    # scaffolding first, then services/users, then host-specific runtime state.
    priority = {
        "apt_config": 10,
        "dnf_config": 11,
        "etc_custom": 80,
        "usr_local_custom": 81,
        "extra_paths": 82,
        "users": 90,
        "sysctl": 95,
        "firewall_runtime": 99,
    }
    return (priority.get(role, 50), role)


def _add_managed_content(
    prole: _PuppetRole,
    snap: Dict[str, Any],
    *,
    bundle_dir: str,
    artifact_role: str,
    module_files_dir: Path,
) -> None:
    for d in snap.get("managed_dirs", []) or []:
        if not isinstance(d, dict):
            continue
        path = str(d.get("path") or "").strip()
        if not path:
            continue
        prole.dirs.setdefault(
            path,
            {
                "owner": d.get("owner") or "root",
                "group": d.get("group") or "root",
                "mode": d.get("mode") or "0755",
                "reason": d.get("reason") or "managed_dir",
            },
        )

    for mf in snap.get("managed_files", []) or []:
        if not isinstance(mf, dict):
            continue
        path = str(mf.get("path") or "").strip()
        src_rel = str(mf.get("src_rel") or "").strip()
        if not path or not src_rel:
            continue
        module_rel = _copy_artifact(
            bundle_dir, artifact_role, src_rel, module_files_dir
        )
        if not module_rel:
            prole.notes.append(
                f"Skipped {path}: harvested artifact {artifact_role}/{src_rel} was not present."
            )
            continue
        prole.files.setdefault(
            path,
            {
                "owner": mf.get("owner") or "root",
                "group": mf.get("group") or "root",
                "mode": mf.get("mode") or "0644",
                "source": _source_uri(prole.module_name, module_rel),
                "reason": mf.get("reason") or "managed_file",
            },
        )

    for ml in snap.get("managed_links", []) or []:
        if not isinstance(ml, dict):
            continue
        path = str(ml.get("path") or "").strip()
        target = str(ml.get("target") or "").strip()
        if not path or not target:
            continue
        prole.links.setdefault(
            path,
            {
                "target": target,
                "reason": ml.get("reason") or "managed_link",
            },
        )

    for path in set(prole.files) | set(prole.links):
        prole.dirs.pop(path, None)


def _build_users_role(prole: _PuppetRole, snap: Dict[str, Any]) -> None:
    for u in snap.get("users", []) or []:
        if not isinstance(u, dict):
            continue
        name = str(u.get("name") or "").strip()
        if not name:
            continue
        primary_group = str(u.get("primary_group") or name).strip()
        if primary_group:
            prole.groups.add(primary_group)
        supplementary = sorted(
            {
                str(g).strip()
                for g in (u.get("supplementary_groups") or [])
                if str(g).strip()
            }
        )
        prole.groups.update(supplementary)
        prole.users[name] = {
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
        prole.notes.append(
            "Per-user Flatpak resources were detected but are not yet rendered as native Puppet resources."
        )


def _build_service_role(prole: _PuppetRole, snap: Dict[str, Any]) -> None:
    for pkg in snap.get("packages", []) or []:
        pkg_s = str(pkg or "").strip()
        if pkg_s:
            prole.packages.add(pkg_s)
    unit = str(snap.get("unit") or "").strip()
    if unit:
        unit_file_state = str(snap.get("unit_file_state") or "")
        prole.services[unit] = {
            "name": unit,
            "ensure": "running" if snap.get("active_state") == "active" else "stopped",
            "enable": unit_file_state in ("enabled", "enabled-runtime"),
        }


def _build_package_role(prole: _PuppetRole, snap: Dict[str, Any]) -> None:
    pkg = str(snap.get("package") or "").strip()
    if pkg:
        prole.packages.add(pkg)


def _add_flatpak_snap_notes(roles: Dict[str, Any], out: Dict[str, _PuppetRole]) -> None:
    flatpak = roles.get("flatpak") or {}
    if isinstance(flatpak, dict) and (
        flatpak.get("system_flatpaks") or flatpak.get("remotes")
    ):
        prole = out.setdefault("flatpak", _PuppetRole("flatpak"))
        prole.notes.append(
            "Flatpak resources were detected but are not yet rendered as native Puppet resources."
        )
    snap = roles.get("snap") or {}
    if isinstance(snap, dict) and snap.get("system_snaps"):
        prole = out.setdefault("snap", _PuppetRole("snap"))
        prole.notes.append(
            "Snap resources were detected but are not yet rendered as native Puppet resources."
        )


def _collect_puppet_roles(
    state: Dict[str, Any],
    bundle_dir: str,
    modules_dir: Path,
    *,
    fqdn: Optional[str] = None,
    no_common_roles: bool = False,
) -> List[_PuppetRole]:
    roles = _roles(state)
    inventory_packages = _inventory_packages(state)
    use_common_modules = not fqdn and not no_common_roles
    out: Dict[str, _PuppetRole] = {}

    def ensure_role(role_name: str) -> _PuppetRole:
        role_name = _puppet_name(role_name, fallback="enroll_role")
        return out.setdefault(role_name, _PuppetRole(role_name))

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
        _add_managed_content(
            prole,
            snap,
            bundle_dir=bundle_dir,
            artifact_role=str(snap.get("role_name") or key),
            module_files_dir=module_files_dir,
        )

    users_snap = roles.get("users") or {}
    if isinstance(users_snap, dict):
        role_name = _puppet_name(
            str(users_snap.get("role_name") or "users"), fallback="enroll_role"
        )
        prole = ensure_role(role_name)
        _build_users_role(prole, users_snap)
        _add_managed_content(
            prole,
            users_snap,
            bundle_dir=bundle_dir,
            artifact_role=str(users_snap.get("role_name") or "users"),
            module_files_dir=modules_dir / prole.module_name / "files",
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
                _section_label_for_packages(
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
        _build_service_role(prole, svc)
        _add_managed_content(
            prole,
            svc,
            bundle_dir=bundle_dir,
            artifact_role=str(svc.get("role_name") or original_role_name),
            module_files_dir=modules_dir / prole.module_name / "files",
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
                _package_section_label(pkg, inventory_packages),
                fallback="package_group",
            )
        else:
            role_name = original_role_name
        prole = ensure_role(role_name)
        _build_package_role(prole, pkg)
        _add_managed_content(
            prole,
            pkg,
            bundle_dir=bundle_dir,
            artifact_role=str(pkg.get("role_name") or original_role_name),
            module_files_dir=modules_dir / prole.module_name / "files",
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

    puppet_roles = sorted(out.values(), key=lambda r: _role_order_key(r.role_name))
    _dedupe_puppet_roles(puppet_roles)
    return [r for r in puppet_roles if r.has_resources()]


def _dedupe_puppet_roles(puppet_roles: List[_PuppetRole]) -> None:
    """Remove duplicate catalog resources across generated Puppet classes.

    Ansible can repeat the same directory task in multiple roles. Puppet cannot:
    a resource title such as File['/etc/default'] may appear only once in the
    compiled catalog. Keep the first declaration in manifest order and drop
    later duplicates.
    """

    concrete_file_paths: Set[str] = set()
    for prole in puppet_roles:
        concrete_file_paths.update(prole.files)
        concrete_file_paths.update(prole.links)

    seen_packages: Set[str] = set()
    seen_groups: Set[str] = set()
    seen_users: Set[str] = set()
    seen_dirs: Set[str] = set()
    seen_files: Set[str] = set()
    seen_links: Set[str] = set()
    seen_services: Set[str] = set()

    for prole in puppet_roles:
        prole.packages = {p for p in prole.packages if p not in seen_packages}
        seen_packages.update(prole.packages)

        prole.groups = {g for g in prole.groups if g not in seen_groups}
        seen_groups.update(prole.groups)

        prole.users = {k: v for k, v in prole.users.items() if k not in seen_users}
        seen_users.update(prole.users)

        prole.dirs = {
            k: v
            for k, v in prole.dirs.items()
            if k not in seen_dirs and k not in concrete_file_paths
        }
        seen_dirs.update(prole.dirs)

        prole.files = {
            k: v
            for k, v in prole.files.items()
            if k not in seen_files and k not in seen_links
        }
        seen_files.update(prole.files)

        prole.links = {
            k: v
            for k, v in prole.links.items()
            if k not in seen_links and k not in seen_files
        }
        seen_links.update(prole.links)

        prole.services = {
            k: v for k, v in prole.services.items() if k not in seen_services
        }
        seen_services.update(prole.services)


def _render_role_class(prole: _PuppetRole) -> str:
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


def _render_site_pp(puppet_roles: List[_PuppetRole], fqdn: Optional[str]) -> str:
    node_name = _pp_quote(fqdn) if fqdn else "default"
    if not puppet_roles:
        return f"node {node_name} {{\n  # No Puppet classes were generated from this harvest.\n}}\n"
    includes = "\n".join(f"  include {r.module_name}" for r in puppet_roles)
    return f"node {node_name} {{\n{includes}\n}}\n"


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


def _render_readme(state: Dict[str, Any], puppet_roles: List[_PuppetRole]) -> str:
    host = state.get("host", {}) if isinstance(state.get("host"), dict) else {}
    hostname = host.get("hostname") or "unknown"
    role_lines = (
        "\n".join(
            f"- `{r.module_name}` from Enroll role `{r.role_name}`"
            for r in puppet_roles
        )
        or "- None."
    )
    notes: List[str] = []
    for r in puppet_roles:
        for note in r.notes:
            notes.append(f"`{r.module_name}`: {note}")
    notes_text = "\n".join(f"- {n}" for n in notes) or "- None."
    return f"""# Enroll Puppet manifest

Generated by Enroll from harvest data for `{hostname}`.

This Puppet target reuses the existing harvest state without changing harvesting behaviour.

## Layout

- `manifests/site.pp` declares a `node` block and includes the generated classes in manifest order.
- `modules/<role>/manifests/init.pp` contains resources for each generated Enroll role/snapshot or common package group.
- `modules/<role>/files/` contains harvested file artifacts for that role or group.
- Generated module names avoid Puppet reserved words such as `default`.

## Generated modules

{role_lines}

## Apply / check

Run from this generated output directory so Puppet can find `./modules`, or pass an absolute module path:

```bash
sudo puppet apply --modulepath ./modules manifests/site.pp --noop
```

```bash
sudo puppet apply --modulepath /path/to/generated/modules /path/to/generated/manifests/site.pp --noop
```

## Generated resources

- Native packages observed in package and service snapshots.
- Local users and groups from the users snapshot.
- Managed directories, files, and symlinks from harvested roles.
- Basic service enablement/running-state resources.
- `/etc/sysctl.d/99-enroll.conf` plus a refresh-only sysctl apply exec when present.

## Current limitations

- Flatpak, Snap, and live firewall runtime snapshots are listed as notes when present rather than rendered as Puppet resources.
- JinjaTurtle templating is Ansible-oriented and is not applied to Puppet output.
- Review generated resources before applying them broadly across unlike hosts.

## Notes

{notes_text}
"""


def manifest_puppet_from_bundle_dir(
    bundle_dir: str,
    out_dir: str,
    *,
    fqdn: Optional[str] = None,
    no_common_roles: bool = False,
) -> None:
    """Render Puppet modules/site.pp from a harvest bundle."""

    state = _load_state(bundle_dir)
    out = Path(out_dir)
    if out.exists():
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
            _render_role_class(prole), encoding="utf-8"
        )
        _write_metadata(module_dir, prole.module_name)

    (manifests_dir / "site.pp").write_text(
        _render_site_pp(puppet_roles, fqdn), encoding="utf-8"
    )
    (out / "README.md").write_text(
        _render_readme(state, puppet_roles), encoding="utf-8"
    )
