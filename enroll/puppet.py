from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
                bundle_dir, artifact_role, src_rel, module_files_dir
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


def _render_site_pp(puppet_roles: List[PuppetRole], fqdn: Optional[str]) -> str:
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


def _render_readme(state: Dict[str, Any], puppet_roles: List[PuppetRole]) -> str:
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
