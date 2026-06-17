from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .cm import (
    CMModule,
    package_section_label,
    resolve_catalog_conflicts,
    role_order_key,
    section_label_for_packages,
)
from .state import inventory_packages_from_state, roles_from_state


class SaltRole(CMModule):
    """Salt-specific view of a renderer-neutral CMModule."""

    def __init__(self, role_name: str) -> None:
        super().__init__(
            role_name=role_name,
            module_name=_salt_name(role_name, fallback="enroll_role"),
        )

    @property
    def sls_name(self) -> str:
        return f"roles.{self.module_name}"

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
                "state": "running" if snap.get("active_state") == "active" else "dead",
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
            user_data: Dict[str, Any] = {
                "name": name,
                "uid": u.get("uid"),
                "gid": primary_group or u.get("gid"),
                "home": u.get("home") or f"/home/{name}",
                "shell": u.get("shell"),
                "groups": supplementary,
            }
            user_data.update(_gecos_attrs(u.get("gecos")))
            self.users[name] = user_data

        if snap.get("user_flatpaks") or snap.get("user_flatpak_remotes"):
            self.notes.append(
                "Per-user Flatpak resources were detected but are not rendered as native Salt states."
            )

    def add_managed_content(
        self,
        snap: Dict[str, Any],
        *,
        bundle_dir: str,
        artifact_role: str,
        role_files_dir: Path,
        file_prefix: Optional[str] = None,
    ) -> None:
        for d in self.managed_dirs_from_snapshot(snap):
            path = str(d.get("path") or "").strip()
            self.add_managed_dir(
                path,
                user=d.get("owner") or "root",
                group=d.get("group") or "root",
                mode=d.get("mode") or "0755",
                makedirs=True,
                reason=d.get("reason") or "managed_dir",
            )

        for mf in self.managed_files_from_snapshot(snap):
            path = str(mf.get("path") or "").strip()
            src_rel = str(mf.get("src_rel") or "").strip()
            if not path or not src_rel:
                continue
            role_rel = _copy_artifact(
                bundle_dir,
                artifact_role,
                src_rel,
                role_files_dir,
                dst_prefix=file_prefix,
            )
            if not role_rel:
                self.notes.append(
                    f"Skipped {path}: harvested artifact {artifact_role}/{src_rel} was not present."
                )
                continue
            self.add_managed_file(
                path,
                user=mf.get("owner") or "root",
                group=mf.get("group") or "root",
                mode=mf.get("mode") or "0644",
                source=_source_uri(self.module_name, role_rel),
                makedirs=True,
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
                force=False,
                makedirs=True,
                reason=ml.get("reason") or "managed_link",
            )

        self.remove_directory_resource_conflicts()


_RESERVED_SALT_NAMES = {"top", "init", "files", "pillar", "states", "roles"}


def _salt_name(raw: str, *, fallback: str = "role") -> str:
    s = re.sub(r"[^A-Za-z0-9_]+", "_", raw or fallback)
    s = re.sub(r"_+", "_", s).strip("_").lower()
    if not s:
        s = fallback
    if not re.match(r"^[a-z_]", s):
        s = f"{fallback}_{s}"
    if s in _RESERVED_SALT_NAMES:
        s = f"{fallback}_{s}"
    return s


def _state_id(prefix: str, value: Any, *, role: str = "") -> str:
    label = re.sub(r"[^A-Za-z0-9_]+", "_", str(value or "item").strip().lower())
    label = re.sub(r"_+", "_", label).strip("_") or "item"
    digest = hashlib.sha1(
        str(value).encode("utf-8", errors="replace")
    ).hexdigest()[  # nosec B324
        :8
    ]  # nosec B324
    parts = ["enroll", prefix]
    if role:
        parts.append(role)
    parts.extend([label[:40], digest])
    return "_".join(parts)


def _yaml_quote(value: Any) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _yaml_bool(value: Any) -> str:
    return "true" if bool(value) else "false"


def _clean_gecos_part(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def _gecos_attrs(value: Any) -> Dict[str, str]:
    """Return Salt user.present-safe GECOS fields.

    Linux passwd GECOS is comma-separated. Passing the raw field as Salt's
    ``fullname`` can fail for values such as ``Node,,,`` because Salt validates
    commas inside individual GECOS subfields. Split it into Salt's native
    fields instead.
    """

    raw = str(value or "")
    if not raw.strip():
        return {}
    parts = raw.split(",", 4)
    keys = ("fullname", "roomnumber", "workphone", "homephone", "other")
    out: Dict[str, str] = {}
    for key, part in zip(keys, parts):
        cleaned = _clean_gecos_part(part)
        if cleaned:
            out[key] = cleaned
    return out


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
    role_rel = Path(dst_prefix or "") / src_rel
    dst = dst_files_dir / role_rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return role_rel.as_posix()


def _source_uri(module_name: str, role_rel: str) -> str:
    return f"salt://roles/{module_name}/files/{role_rel}"


def _node_file_prefix(fqdn: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(fqdn or "").strip())
    name = name.strip("._-") or "node"
    return f"nodes/{name}"


def _node_sls_basename(fqdn: str) -> str:
    raw = str(fqdn or "node").strip() or "node"
    name = re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_").lower() or "node"
    digest = hashlib.sha1(
        raw.encode("utf-8", errors="replace")
    ).hexdigest()[  # nosec B324
        :8
    ]  # nosec B324
    return f"{name}_{digest}"


def _add_flatpak_snap_notes(roles: Dict[str, Any], out: Dict[str, SaltRole]) -> None:
    flatpak = roles.get("flatpak") or {}
    if isinstance(flatpak, dict) and (
        flatpak.get("system_flatpaks") or flatpak.get("remotes")
    ):
        srole = out.setdefault("flatpak", SaltRole("flatpak"))
        srole.notes.append(
            "Flatpak resources were detected but are not rendered as native Salt states."
        )
    snap = roles.get("snap") or {}
    if isinstance(snap, dict) and snap.get("system_snaps"):
        srole = out.setdefault("snap", SaltRole("snap"))
        srole.notes.append(
            "Snap resources were detected but are not rendered as native Salt states."
        )


def _collect_salt_roles(
    state: Dict[str, Any],
    bundle_dir: str,
    states_dir: Path,
    *,
    fqdn: Optional[str] = None,
    no_common_roles: bool = False,
) -> List[SaltRole]:
    roles = roles_from_state(state)
    inventory_packages = inventory_packages_from_state(state)
    use_common_roles = not fqdn and not no_common_roles
    node_file_prefix = _node_file_prefix(fqdn) if fqdn else None
    out: Dict[str, SaltRole] = {}

    def ensure_role(role_name: str) -> SaltRole:
        role_name = _salt_name(role_name, fallback="enroll_role")
        return out.setdefault(role_name, SaltRole(role_name))

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
        role_name = _salt_name(
            str(snap.get("role_name") or key), fallback="enroll_role"
        )
        srole = ensure_role(role_name)
        srole.add_managed_content(
            snap,
            bundle_dir=bundle_dir,
            artifact_role=str(snap.get("role_name") or key),
            role_files_dir=states_dir / "roles" / srole.module_name / "files",
            file_prefix=node_file_prefix,
        )

    users_snap = roles.get("users") or {}
    if isinstance(users_snap, dict):
        role_name = _salt_name(
            str(users_snap.get("role_name") or "users"), fallback="enroll_role"
        )
        srole = ensure_role(role_name)
        srole.add_users_snapshot(users_snap)
        srole.add_managed_content(
            users_snap,
            bundle_dir=bundle_dir,
            artifact_role=str(users_snap.get("role_name") or "users"),
            role_files_dir=states_dir / "roles" / srole.module_name / "files",
            file_prefix=node_file_prefix,
        )

    for svc in roles.get("services", []) or []:
        if not isinstance(svc, dict):
            continue
        original_role_name = _salt_name(
            str(svc.get("role_name") or svc.get("unit") or "service"),
            fallback="service",
        )
        if use_common_roles:
            role_name = _salt_name(
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
        srole = ensure_role(role_name)
        srole.add_service_snapshot(svc)
        srole.add_managed_content(
            svc,
            bundle_dir=bundle_dir,
            artifact_role=str(svc.get("role_name") or original_role_name),
            role_files_dir=states_dir / "roles" / srole.module_name / "files",
            file_prefix=node_file_prefix,
        )

    for pkg in roles.get("packages", []) or []:
        if not isinstance(pkg, dict):
            continue
        original_role_name = _salt_name(
            str(pkg.get("role_name") or pkg.get("package") or "package"),
            fallback="package",
        )
        if use_common_roles:
            role_name = _salt_name(
                package_section_label(pkg, inventory_packages),
                fallback="package_group",
            )
        else:
            role_name = original_role_name
        srole = ensure_role(role_name)
        srole.add_package_snapshot(pkg)
        srole.add_managed_content(
            pkg,
            bundle_dir=bundle_dir,
            artifact_role=str(pkg.get("role_name") or original_role_name),
            role_files_dir=states_dir / "roles" / srole.module_name / "files",
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
            srole = ensure_role(str(fw.get("role_name") or "firewall_runtime"))
            srole.packages.update(packages)
            if has_fw:
                srole.notes.append(
                    "Live firewall runtime snapshots were detected but are not rendered as Salt states."
                )

    _add_flatpak_snap_notes(roles, out)

    salt_roles = sorted(out.values(), key=lambda r: role_order_key(r.role_name))
    resolve_catalog_conflicts(salt_roles)
    return [r for r in salt_roles if r.has_resources()]


def _render_static_role(srole: SaltRole) -> str:
    lines: List[str] = ["# Generated by Enroll from harvest state.", ""]

    for package in sorted(srole.packages):
        lines.extend(
            [
                f"{_state_id('pkg', package, role=srole.module_name)}:",
                "  pkg.installed:",
                f"    - name: {_yaml_quote(package)}",
                "",
            ]
        )

    for group in sorted(srole.groups):
        lines.extend(
            [
                f"{_state_id('group', group, role=srole.module_name)}:",
                "  group.present:",
                f"    - name: {_yaml_quote(group)}",
                "",
            ]
        )

    for name in sorted(srole.users):
        user = srole.users[name]
        lines.extend(
            [
                f"{_state_id('user', name, role=srole.module_name)}:",
                "  user.present:",
                f"    - name: {_yaml_quote(name)}",
            ]
        )
        if user.get("uid") is not None:
            lines.append(f"    - uid: {user['uid']}")
        if user.get("gid") is not None:
            lines.append(f"    - gid: {_yaml_quote(user['gid'])}")
        if user.get("home"):
            lines.append(f"    - home: {_yaml_quote(user['home'])}")
        if user.get("shell"):
            lines.append(f"    - shell: {_yaml_quote(user['shell'])}")
        for gecos_key in ("fullname", "roomnumber", "workphone", "homephone", "other"):
            if user.get(gecos_key):
                lines.append(f"    - {gecos_key}: {_yaml_quote(user[gecos_key])}")
        if user.get("groups"):
            lines.append("    - groups:")
            for group in user.get("groups") or []:
                lines.append(f"      - {_yaml_quote(group)}")
            lines.append("    - remove_groups: false")
        lines.append("")

    for path, attrs in sorted(srole.dirs.items()):
        lines.extend(
            [
                f"{_yaml_quote(path)}:",
                "  file.directory:",
                f"    - user: {_yaml_quote(attrs.get('user') or attrs.get('owner') or 'root')}",
                f"    - group: {_yaml_quote(attrs.get('group') or 'root')}",
                f"    - mode: {_yaml_quote(str(attrs.get('mode') or '0755'))}",
                "    - makedirs: true",
                "",
            ]
        )

    for path, attrs in sorted(srole.files.items()):
        lines.extend(
            [
                f"{_yaml_quote(path)}:",
                "  file.managed:",
                f"    - source: {_yaml_quote(attrs.get('source') or '')}",
                f"    - user: {_yaml_quote(attrs.get('user') or attrs.get('owner') or 'root')}",
                f"    - group: {_yaml_quote(attrs.get('group') or 'root')}",
                f"    - mode: {_yaml_quote(str(attrs.get('mode') or '0644'))}",
                "    - makedirs: true",
                "",
            ]
        )

    for path, attrs in sorted(srole.links.items()):
        lines.extend(
            [
                f"{_yaml_quote(path)}:",
                "  file.symlink:",
                f"    - target: {_yaml_quote(attrs.get('target') or '')}",
                f"    - force: {_yaml_bool(attrs.get('force', False))}",
                "    - makedirs: true",
                "",
            ]
        )

    for name in sorted(srole.services):
        svc = srole.services[name]
        state_fun = "running" if svc.get("state") == "running" else "dead"
        lines.extend(
            [
                f"{_state_id('service', name, role=srole.module_name)}:",
                f"  service.{state_fun}:",
                f"    - name: {_yaml_quote(svc.get('name') or name)}",
                f"    - enable: {_yaml_bool(svc.get('enable', False))}",
                "",
            ]
        )

    if "/etc/sysctl.d/99-enroll.conf" in srole.files:
        lines.extend(
            [
                f"{_state_id('cmd', 'apply_sysctl', role=srole.module_name)}:",
                "  cmd.run:",
                "    - name: sysctl -e -p /etc/sysctl.d/99-enroll.conf || true",
                "    - onchanges:",
                "      - file: /etc/sysctl.d/99-enroll.conf",
                "",
            ]
        )

    if srole.notes:
        lines.append("# Notes and limitations")
        for note in srole.notes:
            lines.append(f"# - {note}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _role_pillar_values(srole: SaltRole) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    if srole.packages:
        data["packages"] = sorted(srole.packages)
    if srole.groups:
        data["groups"] = {group: {} for group in sorted(srole.groups)}
    if srole.users:
        users: Dict[str, Dict[str, Any]] = {}
        for name in sorted(srole.users):
            raw = srole.users[name]
            attrs: Dict[str, Any] = {}
            for key in (
                "uid",
                "gid",
                "home",
                "shell",
                "fullname",
                "roomnumber",
                "workphone",
                "homephone",
                "other",
            ):
                if raw.get(key) is not None:
                    attrs[key] = raw[key]
            if raw.get("groups"):
                attrs["groups"] = list(raw["groups"])
                attrs["remove_groups"] = False
            users[name] = attrs
        data["users"] = users
    if srole.dirs:
        data["dirs"] = {
            path: {
                "user": attrs.get("user") or attrs.get("owner") or "root",
                "group": attrs.get("group") or "root",
                "mode": str(attrs.get("mode") or "0755"),
                "makedirs": True,
            }
            for path, attrs in sorted(srole.dirs.items())
        }
    if srole.files:
        data["files"] = {
            path: {
                "source": attrs.get("source") or "",
                "user": attrs.get("user") or attrs.get("owner") or "root",
                "group": attrs.get("group") or "root",
                "mode": str(attrs.get("mode") or "0644"),
                "makedirs": True,
            }
            for path, attrs in sorted(srole.files.items())
        }
    if srole.links:
        data["links"] = {
            path: {
                "target": attrs.get("target") or "",
                "force": bool(attrs.get("force", False)),
                "makedirs": True,
            }
            for path, attrs in sorted(srole.links.items())
        }
    if srole.services:
        data["services"] = {
            name: {
                "name": svc.get("name") or name,
                "state": "running" if svc.get("state") == "running" else "dead",
                "enable": bool(svc.get("enable", False)),
            }
            for name, svc in sorted(srole.services.items())
        }
    if "/etc/sysctl.d/99-enroll.conf" in srole.files:
        data["sysctl_apply"] = True
    if srole.notes:
        data["notes"] = list(srole.notes)
    return data


def _render_pillar_role(srole: SaltRole) -> str:
    role_key = srole.module_name
    lines = [
        "# Generated by Enroll from harvest state.",
        f"{{% set role = salt['pillar.get']('enroll:roles:{role_key}', {{}}) %}}",
        "",
        "{% for package_name in role.get('packages', []) %}",
        f"enroll_pkg_{role_key}_{{{{ loop.index }}}}:",
        "  pkg.installed:",
        "    - name: {{ package_name|yaml_dquote }}",
        "{% endfor %}",
        "",
        "{% for group_name, group_attrs in role.get('groups', {}).items() %}",
        f"enroll_group_{role_key}_{{{{ loop.index }}}}:",
        "  group.present:",
        "    - name: {{ group_name|yaml_dquote }}",
        "{% endfor %}",
        "",
        "{% for user_name, user_attrs in role.get('users', {}).items() %}",
        f"enroll_user_{role_key}_{{{{ loop.index }}}}:",
        "  user.present:",
        "    - name: {{ user_name|yaml_dquote }}",
        "{% if user_attrs.get('uid') is not none %}",
        "    - uid: {{ user_attrs.get('uid') }}",
        "{% endif %}",
        "{% if user_attrs.get('gid') is not none %}",
        "    - gid: {{ user_attrs.get('gid')|yaml_dquote }}",
        "{% endif %}",
        "{% if user_attrs.get('home') %}",
        "    - home: {{ user_attrs.get('home')|yaml_dquote }}",
        "{% endif %}",
        "{% if user_attrs.get('shell') %}",
        "    - shell: {{ user_attrs.get('shell')|yaml_dquote }}",
        "{% endif %}",
        "{% for gecos_key in ['fullname', 'roomnumber', 'workphone', 'homephone', 'other'] %}",
        "{% if user_attrs.get(gecos_key) %}",
        "    - {{ gecos_key }}: {{ user_attrs.get(gecos_key)|yaml_dquote }}",
        "{% endif %}",
        "{% endfor %}",
        "{% if user_attrs.get('groups') %}",
        "    - groups:",
        "{% for group_name in user_attrs.get('groups', []) %}",
        "      - {{ group_name|yaml_dquote }}",
        "{% endfor %}",
        "    - remove_groups: {{ user_attrs.get('remove_groups', False)|yaml_encode }}",
        "{% endif %}",
        "{% endfor %}",
        "",
        "{% for path, attrs in role.get('dirs', {}).items() %}",
        "{{ path|yaml_dquote }}:",
        "  file.directory:",
        "    - user: {{ attrs.get('user', 'root')|yaml_dquote }}",
        "    - group: {{ attrs.get('group', 'root')|yaml_dquote }}",
        "    - mode: {{ attrs.get('mode', '0755')|string|yaml_dquote }}",
        "    - makedirs: {{ attrs.get('makedirs', True)|yaml_encode }}",
        "{% endfor %}",
        "",
        "{% for path, attrs in role.get('files', {}).items() %}",
        "{{ path|yaml_dquote }}:",
        "  file.managed:",
        "    - source: {{ attrs.get('source', '')|yaml_dquote }}",
        "    - user: {{ attrs.get('user', 'root')|yaml_dquote }}",
        "    - group: {{ attrs.get('group', 'root')|yaml_dquote }}",
        "    - mode: {{ attrs.get('mode', '0644')|string|yaml_dquote }}",
        "    - makedirs: {{ attrs.get('makedirs', True)|yaml_encode }}",
        "{% endfor %}",
        "",
        "{% for path, attrs in role.get('links', {}).items() %}",
        "{{ path|yaml_dquote }}:",
        "  file.symlink:",
        "    - target: {{ attrs.get('target', '')|yaml_dquote }}",
        "    - force: {{ attrs.get('force', False)|yaml_encode }}",
        "    - makedirs: {{ attrs.get('makedirs', True)|yaml_encode }}",
        "{% endfor %}",
        "",
        "{% for service_id, svc in role.get('services', {}).items() %}",
        f"enroll_service_{role_key}_{{{{ loop.index }}}}:",
        "  service.{{ 'running' if svc.get('state') == 'running' else 'dead' }}:",
        "    - name: {{ svc.get('name', service_id)|yaml_dquote }}",
        "    - enable: {{ svc.get('enable', False)|yaml_encode }}",
        "{% endfor %}",
        "",
        "{% if role.get('sysctl_apply') and '/etc/sysctl.d/99-enroll.conf' in role.get('files', {}) %}",
        f"enroll_apply_sysctl_{role_key}:",
        "  cmd.run:",
        "    - name: sysctl -e -p /etc/sysctl.d/99-enroll.conf || true",
        "    - onchanges:",
        "      - file: /etc/sysctl.d/99-enroll.conf",
        "{% endif %}",
        "",
        "{% if role.get('notes') %}",
        "# Notes and limitations",
        "{% for note in role.get('notes', []) %}",
        "# - {{ note }}",
        "{% endfor %}",
        "{% endif %}",
        "",
    ]
    return "\n".join(lines).rstrip() + "\n"


def _write_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=True, explicit_start=True),
        encoding="utf-8",
    )


def _load_yaml_mapping(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        obj = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _write_top(path: Path, mapping: Dict[str, List[str]]) -> None:
    data = {
        "base": {target: list(values) for target, values in sorted(mapping.items())}
    }
    _write_yaml(path, data)


def _read_top(path: Path) -> Dict[str, List[str]]:
    data = _load_yaml_mapping(path)
    base = data.get("base") if isinstance(data.get("base"), dict) else {}
    out: Dict[str, List[str]] = {}
    for target, values in base.items():
        if isinstance(values, list):
            out[str(target)] = [str(v) for v in values if isinstance(v, str)]
    return out


def _write_state_top(
    states_dir: Path, target: str, sls_names: List[str], *, preserve: bool
) -> None:
    top_path = states_dir / "top.sls"
    mapping = _read_top(top_path) if preserve else {}
    mapping[target] = list(sls_names)
    _write_top(top_path, mapping)


def _write_pillar_top(pillar_dir: Path, fqdn: str, node_sls: str) -> None:
    top_path = pillar_dir / "top.sls"
    mapping = _read_top(top_path)
    mapping[fqdn] = [node_sls]
    _write_top(top_path, mapping)


def _write_pillar_node_data(
    pillar_dir: Path, fqdn: str, salt_roles: List[SaltRole]
) -> Path:
    node_base = _node_sls_basename(fqdn)
    node_path = pillar_dir / "nodes" / f"{node_base}.sls"
    data = {
        "enroll": {
            "classes": [r.sls_name for r in salt_roles],
            "roles": {r.module_name: _role_pillar_values(r) for r in salt_roles},
        }
    }
    _write_yaml(node_path, data)
    _write_pillar_top(pillar_dir, fqdn, f"nodes.{node_base}")
    return node_path


def _clean_node_artifacts(states_dir: Path, fqdn: str) -> None:
    prefix = Path(_node_file_prefix(fqdn))
    nodes_rel = prefix.parts
    for files_dir in (states_dir / "roles").glob("*/files"):
        target = files_dir.joinpath(*nodes_rel)
        if target.exists():
            shutil.rmtree(target)


def _write_master_config(out: Path) -> None:
    config_dir = out / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "master.d" / "enroll.conf").parent.mkdir(parents=True, exist_ok=True)
    (config_dir / "master.d" / "enroll.conf").write_text(
        "# Generated by Enroll. Copy or merge into /etc/salt/master.d/enroll.conf.\n"
        "file_roots:\n"
        "  base:\n"
        "    - /srv/salt\n"
        "pillar_roots:\n"
        "  base:\n"
        "    - /srv/pillar\n",
        encoding="utf-8",
    )


def _render_readme(
    state: Dict[str, Any],
    salt_roles: List[SaltRole],
    *,
    fqdn: Optional[str] = None,
    node_path: Optional[Path] = None,
) -> str:
    host = state.get("host", {}) if isinstance(state.get("host"), dict) else {}
    hostname = host.get("hostname") or "unknown"
    role_lines = (
        "\n".join(
            f"- `{r.sls_name}` from Enroll role `{r.role_name}`" for r in salt_roles
        )
        or "- None."
    )
    notes: List[str] = []
    for r in salt_roles:
        for note in r.notes:
            notes.append(f"`{r.sls_name}`: {note}")
    notes_text = "\n".join(f"- {n}" for n in notes) or "- None."

    if fqdn:
        node_display = (
            node_path.relative_to(Path(node_path).parents[1]).as_posix()
            if node_path
            else "pillar/nodes/<node>.sls"
        )
        layout = f"""- `states/top.sls` targets minion `{fqdn}` to this node's generated role SLS files.
- `pillar/top.sls` targets minion `{fqdn}` to `{node_display}`.
- `pillar/nodes/*.sls` contains per-minion resource data under `enroll:roles:<role>`.
- `states/roles/<role>/init.sls` contains reusable, data-driven Salt states.
- `states/roles/<role>/files/nodes/<fqdn>/...` contains node-specific harvested file artifacts."""
        apply = f"""For a local dry run using the generated tree:

```bash
sudo salt-call --local --file-root ./states --pillar-root ./pillar --id {fqdn} state.apply test=True
```

For master/minion use, copy or sync `states/` to your Salt state tree, copy or sync `pillar/` to your pillar tree, refresh pillar, then apply the highstate or the selected SLS files to minion `{fqdn}`."""
    else:
        layout = """- `states/top.sls` targets `*` to the generated role SLS files.
- `states/roles/<role>/init.sls` contains concrete Salt states for each generated Enroll role/snapshot or common package group.
- `states/roles/<role>/files/` contains harvested file artifacts for that role or group.
- `config/master.d/enroll.conf` documents the expected Salt `file_roots` and `pillar_roots` layout if copied under `/srv`."""
        apply = """For a local dry run using the generated tree:

```bash
sudo salt-call --local --file-root ./states state.apply test=True
```

For master/minion use, copy or sync `states/` to your Salt state tree and apply highstate or the selected SLS files."""

    return f"""# Enroll Salt manifest

Generated by Enroll from harvest data for `{hostname}`.

This Salt target reuses the existing harvest state without changing harvesting behaviour.

## Layout

{layout}

## Generated SLS roles

{role_lines}

## Apply / check

{apply}

## Generated resources

- Native packages observed in package and service snapshots.
- Local users and groups from the users snapshot.
- Managed directories, files, and symlinks from harvested roles.
- Basic service enablement/running-state resources.
- `/etc/sysctl.d/99-enroll.conf` plus an `onchanges` sysctl apply command when present.

## Current limitations

- Flatpak, Snap, and live firewall runtime snapshots are listed as notes when present rather than rendered as Salt states.
- JinjaTurtle templating is currently Ansible-oriented and is not applied to Salt output.
- Review generated resources before applying them broadly across unlike hosts.

## Notes

{notes_text}
"""


class SaltManifestRenderer:
    """Render Salt state/pillar trees from a harvest bundle."""

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
        state = SaltRole.load_state(self.bundle_dir)
        out = Path(self.out_dir)
        states_dir = out / "states"
        pillar_dir = out / "pillar"
        fqdn_mode = bool(self.fqdn)

        if out.exists() and not fqdn_mode:
            shutil.rmtree(out)
        states_dir.mkdir(parents=True, exist_ok=True)
        if fqdn_mode:
            pillar_dir.mkdir(parents=True, exist_ok=True)
            _clean_node_artifacts(states_dir, str(self.fqdn))

        salt_roles = _collect_salt_roles(
            state,
            self.bundle_dir,
            states_dir,
            fqdn=self.fqdn,
            no_common_roles=self.no_common_roles,
        )

        for srole in salt_roles:
            role_dir = states_dir / "roles" / srole.module_name
            role_dir.mkdir(parents=True, exist_ok=True)
            (role_dir / "init.sls").write_text(
                _render_pillar_role(srole) if fqdn_mode else _render_static_role(srole),
                encoding="utf-8",
            )

        node_path: Optional[Path] = None
        if fqdn_mode and self.fqdn:
            node_path = _write_pillar_node_data(pillar_dir, self.fqdn, salt_roles)
            _write_state_top(
                states_dir,
                self.fqdn,
                [r.sls_name for r in salt_roles],
                preserve=True,
            )
        else:
            _write_state_top(
                states_dir,
                "*",
                [r.sls_name for r in salt_roles],
                preserve=False,
            )
        _write_master_config(out)
        (out / "README.md").write_text(
            _render_readme(state, salt_roles, fqdn=self.fqdn, node_path=node_path),
            encoding="utf-8",
        )


def manifest_from_bundle_dir(
    bundle_dir: str,
    out_dir: str,
    *,
    fqdn: Optional[str] = None,
    no_common_roles: bool = False,
) -> None:
    SaltManifestRenderer(
        bundle_dir,
        out_dir,
        fqdn=fqdn,
        no_common_roles=no_common_roles,
    ).render()
