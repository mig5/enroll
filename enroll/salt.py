from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import yaml

from .cm import (
    CMModule,
    resolve_catalog_conflicts,
    role_order_key,
    markdown_list,
)
from .jinjaturtle import jinjify_artifact, resolve_jinjaturtle_mode
from .state import inventory_packages_from_state, roles_from_state
from .yamlutil import yaml_dump_mapping, yaml_load_mapping_file


class SaltRole(CMModule):
    """Salt-specific view of a renderer-neutral CMModule."""

    managed_owner_attr = "user"

    def __init__(self, role_name: str) -> None:
        super().__init__(
            role_name=role_name,
            module_name=_salt_name(role_name, fallback="enroll_role"),
        )
        self.container_images: List[Dict[str, Any]] = []
        self.flatpak_remotes: List[Dict[str, Any]] = []
        self.flatpaks: List[Dict[str, Any]] = []
        self.snaps: List[Dict[str, Any]] = []

    def has_resources(self) -> bool:
        return self.has_resources_or_attrs(
            "container_images", "flatpak_remotes", "flatpaks", "snaps"
        )

    @property
    def sls_name(self) -> str:
        return f"roles.{self.module_name}"

    def add_service_snapshot(self, snap: Dict[str, Any]) -> None:
        self.add_service_snapshot_state(
            snap, state_key="state", running="running", stopped="dead"
        )
        unit = self.service_unit_from_snapshot(snap)
        if unit in self.services:
            self.services[unit]["state_id"] = _state_id(
                "service", unit, role=self.module_name
            )

    def add_users_snapshot(self, snap: Dict[str, Any]) -> None:
        records = self.user_records_from_snapshot(snap)
        self.groups.update(self.user_group_names_from_records(records))
        for record in records:
            name = str(record.get("name") or "")
            user_data: Dict[str, Any] = {
                "name": name,
                "uid": record.get("uid"),
                "gid": record.get("primary_group") or record.get("gid"),
                "home": record.get("home"),
                "shell": record.get("shell"),
                "groups": record.get("supplementary_groups") or [],
            }
            user_data.update(_gecos_attrs(record.get("gecos")))
            self.users[name] = user_data

        self.add_user_flatpaks_snapshot(snap)

    def prepare_flatpak_remote(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return _prepare_flatpak_remote(item)

    def prepare_flatpak_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return _prepare_flatpak_item(item)

    def prepare_snap_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return _prepare_snap_item(item)

    def add_firewall_runtime_snapshot(
        self,
        snap: Dict[str, Any],
        *,
        bundle_dir: str,
        artifact_role: str,
        role_files_dir: Path,
        file_prefix: Optional[str] = None,
    ) -> None:
        super().add_firewall_runtime_snapshot(
            snap,
            bundle_dir=bundle_dir,
            artifact_role=artifact_role,
            files_dir=role_files_dir,
            copy_artifact=_copy_artifact,
            source_uri=_source_uri,
            file_prefix=file_prefix,
            dir_attrs={"require": [{"file": "/etc/enroll"}]},
        )

    def add_container_images_snapshot(self, snap: Dict[str, Any]) -> None:
        for raw in snap.get("images", []) or []:
            if not isinstance(raw, dict):
                continue
            engine = str(raw.get("engine") or "").strip().lower()
            pull_ref = str(raw.get("pull_ref") or "").strip()
            if engine not in {"docker", "podman"}:
                continue
            if not pull_ref:
                tags = ", ".join(str(t) for t in (raw.get("repo_tags") or []) if t)
                label = tags or str(raw.get("image_id") or "unknown image")
                self.notes.append(
                    f"Container image {label} has no RepoDigest; exact Salt pull state was not rendered."
                )
                continue
            item = dict(raw)
            item["engine"] = engine
            item["pull_ref"] = pull_ref
            item["scope"] = str(item.get("scope") or "system").strip() or "system"
            item["tag_aliases"] = [
                dict(alias)
                for alias in (item.get("tag_aliases") or [])
                if isinstance(alias, dict) and alias.get("ref")
            ]
            item["pull_cmd"] = _container_pull_cmd(engine, pull_ref)
            item["pull_unless"] = _container_exists_cmd(engine, pull_ref)
            for alias in item["tag_aliases"]:
                alias_ref = str(alias.get("ref") or "")
                alias["tag_cmd"] = _container_tag_cmd(engine, pull_ref, alias_ref)
                alias["tag_unless"] = _container_tag_matches_cmd(
                    engine, pull_ref, alias_ref
                )
            self.container_images.append(item)
        for note in snap.get("notes", []) or []:
            self.notes.append(str(note))

    def add_managed_content(
        self,
        snap: Dict[str, Any],
        *,
        bundle_dir: str,
        artifact_role: str,
        role_files_dir: Path,
        file_prefix: Optional[str] = None,
        jt_exe: Optional[str] = None,
        jt_enabled: bool = False,
        overwrite_templates: bool = True,
        watch_services: Optional[List[str]] = None,
        watch_service_states: Optional[List[str]] = None,
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

        watch_state_ids = _service_watch_state_ids(
            self.module_name,
            watch_services=watch_services,
            watch_service_states=watch_service_states,
        )

        for mf in self.managed_files_from_snapshot(snap):
            path = str(mf.get("path") or "").strip()
            src_rel = str(mf.get("src_rel") or "").strip()
            if not path or not src_rel:
                continue

            template = _jinjify_managed_file(
                bundle_dir,
                artifact_role,
                src_rel,
                path,
                role_files_dir.parent,
                jt_exe=jt_exe,
                jt_enabled=jt_enabled,
                overwrite_templates=overwrite_templates,
            )
            if template is not None:
                tmpl_rel, context = template
                attrs: Dict[str, Any] = {
                    "user": mf.get("owner") or "root",
                    "group": mf.get("group") or "root",
                    "mode": mf.get("mode") or "0644",
                    "source": _template_source_uri(self.module_name, tmpl_rel),
                    "template": "jinja",
                    "context": context,
                    "makedirs": True,
                    "reason": mf.get("reason") or "managed_file",
                }
                if watch_state_ids and not path.startswith("/etc/systemd/system/"):
                    attrs["watch_in"] = [
                        {"service": state_id} for state_id in watch_state_ids
                    ]
                self.add_managed_file(path, **attrs)
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
            attrs = {
                "user": mf.get("owner") or "root",
                "group": mf.get("group") or "root",
                "mode": mf.get("mode") or "0644",
                "source": _source_uri(self.module_name, role_rel),
                "makedirs": True,
                "reason": mf.get("reason") or "managed_file",
            }
            if watch_state_ids and not path.startswith("/etc/systemd/system/"):
                attrs["watch_in"] = [
                    {"service": state_id} for state_id in watch_state_ids
                ]
            self.add_managed_file(path, **attrs)

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


def _plain_salt_data(value: Any) -> Any:
    """Return data made from plain JSON/YAML-safe containers.

    Salt's Jinja ``yaml_encode`` filter cannot represent Salt/PyYAML
    ``OrderedDict`` values.  Normalise generated template contexts before we
    write static SLS or pillar data, and before passing context to file.managed.
    """

    if isinstance(value, Mapping):
        return {str(key): _plain_salt_data(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_plain_salt_data(item) for item in value]
    if isinstance(value, tuple):
        return [_plain_salt_data(item) for item in value]
    if isinstance(value, set):
        return sorted(_plain_salt_data(item) for item in value)
    return value


_TO_JSON_FILTER_RE = re.compile(
    r"{{\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)\s*"
    r"\|\s*to_json\s*\([^)]*\)\s*}}"
)


def _saltify_jinjaturtle_template(
    template_text: str, context: Dict[str, Any]
) -> Tuple[str, Dict[str, Any]]:
    """Translate JinjaTurtle's Ansible-oriented Jinja into Salt-safe Jinja.

    JinjaTurtle emits Ansible's ``to_json`` filter for JSON/TOML values. Salt's
    Jinja environment does not provide that filter.  For ordinary generated
    context variables, pre-render a JSON string and substitute a plain variable
    reference.  For loop-local expressions such as ``item`` or ``item.name`` we
    fall back to Jinja's built-in ``tojson`` filter.
    """

    salt_context = _plain_salt_data(context)

    def replace(match: re.Match[str]) -> str:
        expr = match.group(1)
        if "." not in expr and expr in salt_context:
            json_var = f"{expr}__enroll_json"
            salt_context[json_var] = json.dumps(salt_context[expr], ensure_ascii=False)
            return "{{ " + json_var + " }}"
        return "{{ " + expr + " | tojson }}"

    return _TO_JSON_FILTER_RE.sub(replace, template_text), salt_context


def _service_watch_state_ids(
    role_name: str,
    *,
    watch_services: Optional[Iterable[str]] = None,
    watch_service_states: Optional[Iterable[str]] = None,
) -> List[str]:
    """Return de-duplicated Salt service state ids for watch_in requisites."""

    out: List[str] = []
    seen = set()
    for state_id in watch_service_states or []:
        value = str(state_id or "").strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    for unit in watch_services or []:
        unit_s = str(unit or "").strip()
        if not unit_s:
            continue
        value = _state_id("service", unit_s, role=role_name)
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _active_service_state_ids_by_unit(
    entries: Iterable[Dict[str, Any]],
) -> Dict[str, str]:
    """Return generated Salt service state ids keyed by active systemd unit."""

    by_unit: Dict[str, str] = {}
    for entry in entries:
        if str(entry.get("kind") or "package") != "service":
            continue
        snap = entry.get("snapshot") or {}
        if not isinstance(snap, dict):
            continue
        unit = str(snap.get("unit") or "").strip()
        if not unit or str(snap.get("active_state") or "") != "active":
            continue
        source_label = str(snap.get("role_name") or snap.get("unit") or "service")
        role_name = _salt_name(
            str(entry.get("role_label") or source_label), fallback="service"
        )
        by_unit.setdefault(unit, _state_id("service", unit, role=role_name))
    return by_unit


def _yaml_quote(value: Any) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _yaml_bool(value: Any) -> str:
    return "true" if bool(value) else "false"


def _shell_quote(value: Any) -> str:
    return shlex.quote(str(value or ""))


def _container_pull_cmd(engine: str, pull_ref: str) -> str:
    return f"{engine} pull {_shell_quote(pull_ref)}"


def _container_exists_cmd(engine: str, ref: str) -> str:
    if engine == "podman":
        return f"podman image exists {_shell_quote(ref)}"
    return f"docker image inspect {_shell_quote(ref)} >/dev/null 2>&1"


def _container_image_id_expr(engine: str, ref: str) -> str:
    """Return a shell expression that extracts an inspected image ID.

    Salt renders SLS files through Jinja before YAML, so Docker's normal
    format template cannot be emitted literally without careful escaping. Use
    JSON output plus sed instead; it avoids Go-template braces in generated
    Salt states and pillar data.
    """

    sed_id = (
        r"sed -n 's/^[[:space:]]*\"Id\":[[:space:]]*\"\([^\"]*\)\".*/\1/p' "
        r"| head -n 1"
    )
    return (
        f"{_shell_quote(engine)} image inspect {_shell_quote(ref)} "
        f"2>/dev/null | {sed_id}"
    )


def _container_tag_matches_cmd(engine: str, pull_ref: str, tag_ref: str) -> str:
    """Return a shell guard that is true only when tag_ref points at pull_ref."""

    return (
        f'test "$({_container_image_id_expr(engine, tag_ref)})" '
        f'= "$({_container_image_id_expr(engine, pull_ref)})"'
    )


def _container_tag_cmd(engine: str, pull_ref: str, tag_ref: str) -> str:
    return f"{engine} tag {_shell_quote(pull_ref)} {_shell_quote(tag_ref)}"


def _flatpak_scope(item: Dict[str, Any]) -> str:
    return "--user" if str(item.get("method") or "system") == "user" else "--system"


def _flatpak_home(item: Dict[str, Any]) -> Optional[str]:
    user = str(item.get("user") or "").strip()
    if not user:
        return None
    return str(item.get("home") or f"/home/{user}")


def _flatpak_env(item: Dict[str, Any]) -> Dict[str, str]:
    home = _flatpak_home(item)
    if not home:
        return {}
    return {"HOME": home, "XDG_DATA_HOME": f"{home}/.local/share"}


def _flatpak_remote_exists_cmd(item: Dict[str, Any]) -> str:
    return (
        f"flatpak {_flatpak_scope(item)} remote-list --columns=name "
        f"| grep -Fx -- {_shell_quote(item.get('name'))}"
    )


def _flatpak_remote_add_cmd(item: Dict[str, Any]) -> str:
    return (
        f"flatpak {_flatpak_scope(item)} remote-add --if-not-exists "
        f"{_shell_quote(item.get('name'))} {_shell_quote(item.get('url'))}"
    )


def _flatpak_ref(item: Dict[str, Any]) -> str:
    ref = str(item.get("ref") or "").strip()
    if ref:
        return ref
    return str(item.get("name") or "").strip()


def _flatpak_exists_cmd(item: Dict[str, Any]) -> str:
    return f"flatpak {_flatpak_scope(item)} info {_shell_quote(_flatpak_ref(item))} >/dev/null 2>&1"


def _flatpak_install_cmd(item: Dict[str, Any]) -> str:
    args = ["flatpak", _flatpak_scope(item), "install", "-y"]
    remote = str(item.get("remote") or "").strip()
    if remote:
        args.append(remote)
    args.append(_flatpak_ref(item))
    return " ".join(_shell_quote(arg) for arg in args)


def _prepare_flatpak_remote(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    method = str(out.get("method") or "system")
    user = str(out.get("user") or "")
    name = str(out.get("name") or "")
    out["state_id"] = _state_id("flatpak_remote", f"{method}:{user}:{name}")
    out["add_cmd"] = _flatpak_remote_add_cmd(out)
    out["exists_cmd"] = _flatpak_remote_exists_cmd(out)
    out["env"] = _flatpak_env(out)
    return out


def _prepare_flatpak_item(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    method = str(out.get("method") or "system")
    user = str(out.get("user") or "")
    ref = _flatpak_ref(out)
    out["state_id"] = _state_id("flatpak", f"{method}:{user}:{ref}")
    out["install_cmd"] = _flatpak_install_cmd(out)
    out["exists_cmd"] = _flatpak_exists_cmd(out)
    out["env"] = _flatpak_env(out)
    return out


def _snap_exists_cmd(item: Dict[str, Any]) -> str:
    return f"snap list {_shell_quote(item.get('name'))} >/dev/null 2>&1"


def _snap_install_cmd(item: Dict[str, Any]) -> str:
    args = ["snap", "install", str(item.get("name") or "")]
    channel = str(item.get("channel") or "").strip()
    revision = str(item.get("revision") or "").strip()
    if channel:
        args.append(f"--channel={channel}")
    elif revision:
        args.append(f"--revision={revision}")
    if item.get("classic"):
        args.append("--classic")
    if item.get("devmode"):
        args.append("--devmode")
    if item.get("dangerous"):
        args.append("--dangerous")
    return " ".join(_shell_quote(arg) for arg in args if str(arg))


def _prepare_snap_item(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    name = str(out.get("name") or "")
    out["state_id"] = _state_id("snap", name)
    out["install_cmd"] = _snap_install_cmd(out)
    out["exists_cmd"] = _snap_exists_cmd(out)
    return out


def _append_firewall_runtime_states(lines: List[str], runtime: Dict[str, Any]) -> None:
    specs = [
        (
            "ipset",
            "ipset_save",
            "ipset_restore_cmd",
            "enroll_firewall_runtime_ipset_restore",
        ),
        (
            "iptables_v4",
            "iptables_v4_save",
            "iptables_v4_restore_cmd",
            "enroll_firewall_runtime_iptables_v4_restore",
        ),
        (
            "iptables_v6",
            "iptables_v6_save",
            "iptables_v6_restore_cmd",
            "enroll_firewall_runtime_iptables_v6_restore",
        ),
    ]
    for _family, path_key, cmd_key, state_id in specs:
        path = str(runtime.get(path_key) or "")
        command = str(runtime.get(cmd_key) or "")
        if not path or not command:
            continue
        lines.extend(
            [
                f"{state_id}:",
                "  cmd.run:",
                f"    - name: {_yaml_quote(command)}",
                "    - onchanges:",
                f"      - file: {_yaml_quote(path)}",
                "",
            ]
        )


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


def _template_source_uri(module_name: str, tmpl_rel: str) -> str:
    return f"salt://roles/{module_name}/templates/{tmpl_rel}"


def _jinjify_managed_file(
    bundle_dir: str,
    artifact_role: str,
    src_rel: str,
    dest_path: str,
    role_dir: Path,
    *,
    jt_exe: Optional[str],
    jt_enabled: bool,
    overwrite_templates: bool,
) -> Optional[Tuple[str, Dict[str, Any]]]:
    converted = jinjify_artifact(
        bundle_dir,
        artifact_role,
        src_rel,
        dest_path,
        role_dir / "templates",
        jt_exe=jt_exe,
        jt_enabled=jt_enabled,
        overwrite_templates=overwrite_templates,
    )
    if converted is None:
        return None

    template_text, context = _saltify_jinjaturtle_template(
        converted.template_text, converted.context
    )
    template_path = role_dir / "templates" / converted.template_rel
    if template_text != converted.template_text:
        existing = (
            template_path.read_text(encoding="utf-8") if template_path.exists() else ""
        )
        if (
            overwrite_templates
            or not template_path.exists()
            or _TO_JSON_FILTER_RE.search(existing)
        ):
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(template_text, encoding="utf-8")

    return converted.template_rel, context


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


def _collect_salt_roles(
    state: Dict[str, Any],
    bundle_dir: str,
    states_dir: Path,
    *,
    fqdn: Optional[str] = None,
    no_common_roles: bool = False,
    jt_exe: Optional[str] = None,
    jt_enabled: bool = False,
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
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=not bool(fqdn),
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
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=not bool(fqdn),
        )

    package_service_entries = list(
        CMModule.package_service_entries(
            roles, inventory_packages, use_common_roles=use_common_roles
        )
    )
    service_units_by_package = CMModule.active_service_units_by_package(
        package_service_entries
    )
    service_state_ids_by_unit = _active_service_state_ids_by_unit(
        package_service_entries
    )

    for entry in package_service_entries:
        snap = entry.get("snapshot") or {}
        kind = str(entry.get("kind") or "package")
        fallback = "service" if kind == "service" else "package"
        source_label = str(
            snap.get("role_name") or snap.get("unit") or snap.get("package") or fallback
        )
        original_role_name = _salt_name(source_label, fallback=fallback)
        role_name = _salt_name(
            str(entry.get("role_label") or source_label),
            fallback="package_group" if use_common_roles else fallback,
        )
        srole = ensure_role(role_name)
        watch_services: List[str] = []
        watch_service_states: List[str] = []
        if kind == "service":
            srole.add_service_snapshot(snap)
            unit = str(snap.get("unit") or "").strip()
            if unit and str(snap.get("active_state") or "") == "active":
                watch_services = [unit]
        else:
            srole.add_package_snapshot(snap)
            watch_services = CMModule.active_service_units_for_package_snapshot(
                snap, service_units_by_package
            )
            watch_service_states = [
                service_state_ids_by_unit[unit]
                for unit in watch_services
                if unit in service_state_ids_by_unit
            ]
            if watch_service_states:
                watch_services = []
        srole.add_managed_content(
            snap,
            bundle_dir=bundle_dir,
            artifact_role=str(snap.get("role_name") or original_role_name),
            role_files_dir=states_dir / "roles" / srole.module_name / "files",
            file_prefix=node_file_prefix,
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=not bool(fqdn),
            watch_services=watch_services,
            watch_service_states=watch_service_states,
        )

    container_images = roles.get("container_images") or {}
    if isinstance(container_images, dict) and (
        container_images.get("images") or container_images.get("notes")
    ):
        srole = ensure_role(
            str(container_images.get("role_name") or "container_images")
        )
        srole.add_container_images_snapshot(container_images)

    fw = roles.get("firewall_runtime") or {}
    if isinstance(fw, dict):
        has_fw = (
            fw.get("ipset_save")
            or fw.get("iptables_v4_save")
            or fw.get("iptables_v6_save")
        )
        if has_fw:
            runtime_role = ensure_role("enroll_runtime")
            runtime_role.add_managed_dir(
                "/etc/enroll",
                user="root",
                group="root",
                mode="0750",
                reason="enroll_runtime",
            )
            role_name = str(fw.get("role_name") or "firewall_runtime")
            srole = ensure_role(role_name)
            srole.add_firewall_runtime_snapshot(
                fw,
                bundle_dir=bundle_dir,
                artifact_role=role_name,
                role_files_dir=states_dir / "roles" / srole.module_name / "files",
                file_prefix=node_file_prefix,
            )

    flatpak = roles.get("flatpak") or {}
    if isinstance(flatpak, dict) and (
        flatpak.get("system_flatpaks") or flatpak.get("remotes") or flatpak.get("notes")
    ):
        srole = ensure_role(str(flatpak.get("role_name") or "flatpak"))
        srole.add_flatpak_snapshot(flatpak)

    snap = roles.get("snap") or {}
    if isinstance(snap, dict) and (snap.get("system_snaps") or snap.get("notes")):
        srole = ensure_role(str(snap.get("role_name") or "snap"))
        srole.add_snap_snapshot(snap)

    salt_roles = sorted(out.values(), key=lambda r: role_order_key(r.role_name))
    resolve_catalog_conflicts(salt_roles)
    return [r for r in salt_roles if r.has_resources()]


def _append_yaml_value(lines: List[str], key: str, value: Any, *, indent: int) -> None:
    prefix = " " * indent
    if isinstance(value, dict):
        dumped = yaml.safe_dump(
            _plain_salt_data(value), sort_keys=True, default_flow_style=False
        ).rstrip()
        if not dumped:
            lines.append(f"{prefix}- {key}: {{}}")
            return
        lines.append(f"{prefix}- {key}:")
        for line in dumped.splitlines():
            lines.append(f"{prefix}    {line}")
        return
    lines.append(f"{prefix}- {key}: {_yaml_quote(value)}")


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
            ]
        )
        if attrs.get("require"):
            lines.append("    - require:")
            for req in attrs.get("require") or []:
                if isinstance(req, dict):
                    for req_kind, req_name in req.items():
                        lines.append(f"      - {req_kind}: {_yaml_quote(req_name)}")
        lines.append("")

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
            ]
        )
        if attrs.get("template"):
            lines.append(f"    - template: {_yaml_quote(attrs.get('template'))}")
        if attrs.get("context"):
            _append_yaml_value(lines, "context", attrs.get("context"), indent=4)
        if attrs.get("watch_in"):
            lines.append("    - watch_in:")
            for req in attrs.get("watch_in") or []:
                if isinstance(req, dict):
                    for req_kind, req_name in req.items():
                        lines.append(f"      - {req_kind}: {_yaml_quote(req_name)}")
        lines.append("")

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
                f"{svc.get('state_id') or _state_id('service', name, role=srole.module_name)}:",
                f"  service.{state_fun}:",
                f"    - name: {_yaml_quote(svc.get('name') or name)}",
                f"    - enable: {_yaml_bool(svc.get('enable', False))}",
                "",
            ]
        )

    flatpak_remote_state_ids: Dict[Tuple[str, str, str], str] = {}
    for remote in srole.flatpak_remotes:
        name = str(remote.get("name") or "").strip()
        url = str(remote.get("url") or "").strip()
        if not name or not url:
            continue
        state_id = str(
            remote.get("state_id")
            or _state_id("flatpak_remote", name, role=srole.module_name)
        )
        key = (
            str(remote.get("method") or "system"),
            str(remote.get("user") or ""),
            name,
        )
        flatpak_remote_state_ids[key] = state_id
        lines.extend(
            [
                f"{state_id}:",
                "  cmd.run:",
                f"    - name: {_yaml_quote(remote.get('add_cmd') or _flatpak_remote_add_cmd(remote))}",
                f"    - unless: {_yaml_quote(remote.get('exists_cmd') or _flatpak_remote_exists_cmd(remote))}",
            ]
        )
        remote_user = str(remote.get("user") or "")
        if remote_user:
            lines.append(f"    - runas: {_yaml_quote(remote_user)}")
        env = remote.get("env") or {}
        if env:
            lines.append("    - env:")
            for key_name, value in sorted(env.items()):
                lines.append(f"      - {key_name}: {_yaml_quote(value)}")
        if remote_user and remote_user in srole.users:
            lines.extend(
                [
                    "    - require:",
                    f"      - user: {_state_id('user', remote_user, role=srole.module_name)}",
                ]
            )
        lines.append("")

    for app in srole.flatpaks:
        ref = _flatpak_ref(app)
        if not ref:
            continue
        state_id = str(
            app.get("state_id") or _state_id("flatpak", ref, role=srole.module_name)
        )
        method = str(app.get("method") or "system")
        user = str(app.get("user") or "")
        remote_name = str(app.get("remote") or "")
        require_entries: List[Tuple[str, str]] = []
        if user and user in srole.users:
            require_entries.append(
                ("user", _state_id("user", user, role=srole.module_name))
            )
        if remote_name:
            remote_state_id = flatpak_remote_state_ids.get((method, user, remote_name))
            if remote_state_id:
                require_entries.append(("cmd", remote_state_id))
        lines.extend(
            [
                f"{state_id}:",
                "  cmd.run:",
                f"    - name: {_yaml_quote(app.get('install_cmd') or _flatpak_install_cmd(app))}",
                f"    - unless: {_yaml_quote(app.get('exists_cmd') or _flatpak_exists_cmd(app))}",
            ]
        )
        if app.get("user"):
            lines.append(f"    - runas: {_yaml_quote(app.get('user'))}")
        env = app.get("env") or {}
        if env:
            lines.append("    - env:")
            for key_name, value in sorted(env.items()):
                lines.append(f"      - {key_name}: {_yaml_quote(value)}")
        if require_entries:
            lines.append("    - require:")
            for req_kind, req_name in require_entries:
                lines.append(f"      - {req_kind}: {req_name}")
        lines.append("")

    for snap in srole.snaps:
        name = str(snap.get("name") or "").strip()
        if not name:
            continue
        lines.extend(
            [
                f"{snap.get('state_id') or _state_id('snap', name, role=srole.module_name)}:",
                "  cmd.run:",
                f"    - name: {_yaml_quote(snap.get('install_cmd') or _snap_install_cmd(snap))}",
                f"    - unless: {_yaml_quote(snap.get('exists_cmd') or _snap_exists_cmd(snap))}",
                "",
            ]
        )

    for idx, image in enumerate(srole.container_images, start=1):
        engine = str(image.get("engine") or "").strip()
        pull_ref = str(image.get("pull_ref") or "").strip()
        if not engine or not pull_ref:
            continue
        if engine == "docker":
            pull_state_id = _state_id("docker_pull", pull_ref, role=srole.module_name)
            lines.extend(
                [
                    f"{pull_state_id}:",
                    "  cmd.run:",
                    f"    - name: {_yaml_quote(image.get('pull_cmd') or _container_pull_cmd(engine, pull_ref))}",
                    f"    - unless: {_yaml_quote(image.get('pull_unless') or _container_exists_cmd(engine, pull_ref))}",
                    "",
                ]
            )
            for alias in image.get("tag_aliases") or []:
                tag_ref = str(alias.get("ref") or "").strip()
                if not tag_ref:
                    continue
                lines.extend(
                    [
                        f"{_state_id('docker_tag', tag_ref, role=srole.module_name)}:",
                        "  cmd.run:",
                        f"    - name: {_yaml_quote(alias.get('tag_cmd') or _container_tag_cmd(engine, pull_ref, tag_ref))}",
                        f"    - unless: {_yaml_quote(alias.get('tag_unless') or _container_tag_matches_cmd(engine, pull_ref, tag_ref))}",
                        "    - require:",
                        f"      - cmd: {pull_state_id}",
                        "",
                    ]
                )
        elif engine == "podman":
            pull_state_id = _state_id("podman_pull", pull_ref, role=srole.module_name)
            lines.extend(
                [
                    f"{pull_state_id}:",
                    "  cmd.run:",
                    f"    - name: {_yaml_quote(image.get('pull_cmd') or _container_pull_cmd(engine, pull_ref))}",
                    f"    - unless: {_yaml_quote(image.get('pull_unless') or _container_exists_cmd(engine, pull_ref))}",
                    "",
                ]
            )
            for alias in image.get("tag_aliases") or []:
                tag_ref = str(alias.get("ref") or "").strip()
                if not tag_ref:
                    continue
                lines.extend(
                    [
                        f"{_state_id('podman_tag', tag_ref, role=srole.module_name)}:",
                        "  cmd.run:",
                        f"    - name: {_yaml_quote(alias.get('tag_cmd') or _container_tag_cmd(engine, pull_ref, tag_ref))}",
                        f"    - unless: {_yaml_quote(alias.get('tag_unless') or _container_exists_cmd(engine, tag_ref))}",
                        "    - require:",
                        f"      - cmd: {pull_state_id}",
                        "",
                    ]
                )

    if srole.firewall_runtime:
        _append_firewall_runtime_states(lines, srole.firewall_runtime)

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
                **({"require": attrs.get("require")} if attrs.get("require") else {}),
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
                **(
                    {"template": attrs.get("template")} if attrs.get("template") else {}
                ),
                **(
                    {"context": _plain_salt_data(attrs.get("context"))}
                    if attrs.get("context")
                    else {}
                ),
                **(
                    {"watch_in": attrs.get("watch_in")} if attrs.get("watch_in") else {}
                ),
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
                "state_id": svc.get("state_id")
                or _state_id("service", name, role=srole.module_name),
            }
            for name, svc in sorted(srole.services.items())
        }
    if "/etc/sysctl.d/99-enroll.conf" in srole.files:
        data["sysctl_apply"] = True
    if srole.flatpak_remotes:
        data["flatpak_remotes"] = list(srole.flatpak_remotes)
    if srole.flatpaks:
        data["flatpaks"] = list(srole.flatpaks)
    if srole.snaps:
        data["snaps"] = list(srole.snaps)
    if srole.container_images:
        data["container_images"] = list(srole.container_images)
    if srole.firewall_runtime:
        data["firewall_runtime"] = dict(srole.firewall_runtime)
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
        "{% if attrs.get('require') %}",
        "    - require:",
        "{% for req in attrs.get('require', []) %}",
        "{% for req_kind, req_name in req.items() %}",
        "      - {{ req_kind }}: {{ req_name|yaml_dquote }}",
        "{% endfor %}",
        "{% endfor %}",
        "{% endif %}",
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
        "{% if attrs.get('template') %}",
        "    - template: {{ attrs.get('template')|yaml_dquote }}",
        "{% endif %}",
        "{% if attrs.get('context') %}",
        "    - context: {{ attrs.get('context')|tojson }}",
        "{% endif %}",
        "{% if attrs.get('watch_in') %}",
        "    - watch_in:",
        "{% for req in attrs.get('watch_in') %}",
        "{% for req_kind, req_name in req.items() %}",
        "      - {{ req_kind }}: {{ req_name|yaml_dquote }}",
        "{% endfor %}",
        "{% endfor %}",
        "{% endif %}",
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
        "{{ svc.get('state_id') or ('enroll_service_"
        + role_key
        + "_' ~ loop.index|string) }}:",
        "  service.{{ 'running' if svc.get('state') == 'running' else 'dead' }}:",
        "    - name: {{ svc.get('name', service_id)|yaml_dquote }}",
        "    - enable: {{ svc.get('enable', False)|yaml_encode }}",
        "{% endfor %}",
        "",
        "{% for remote in role.get('flatpak_remotes', []) %}",
        "{{ remote.get('state_id') }}:",
        "  cmd.run:",
        "    - name: {{ remote.get('add_cmd')|yaml_dquote }}",
        "    - unless: {{ remote.get('exists_cmd')|yaml_dquote }}",
        "{% if remote.get('user') %}",
        "    - runas: {{ remote.get('user')|yaml_dquote }}",
        "{% endif %}",
        "{% if remote.get('env') %}",
        "    - env:",
        "{% for env_key, env_value in remote.get('env', {}).items() %}",
        "      - {{ env_key }}: {{ env_value|yaml_dquote }}",
        "{% endfor %}",
        "{% endif %}",
        "{% endfor %}",
        "",
        "{% for app in role.get('flatpaks', []) %}",
        "{{ app.get('state_id') }}:",
        "  cmd.run:",
        "    - name: {{ app.get('install_cmd')|yaml_dquote }}",
        "    - unless: {{ app.get('exists_cmd')|yaml_dquote }}",
        "{% if app.get('user') %}",
        "    - runas: {{ app.get('user')|yaml_dquote }}",
        "{% endif %}",
        "{% if app.get('env') %}",
        "    - env:",
        "{% for env_key, env_value in app.get('env', {}).items() %}",
        "      - {{ env_key }}: {{ env_value|yaml_dquote }}",
        "{% endfor %}",
        "{% endif %}",
        "{% endfor %}",
        "",
        "{% for snap in role.get('snaps', []) %}",
        "{{ snap.get('state_id') }}:",
        "  cmd.run:",
        "    - name: {{ snap.get('install_cmd')|yaml_dquote }}",
        "    - unless: {{ snap.get('exists_cmd')|yaml_dquote }}",
        "{% endfor %}",
        "",
        "{% for image in role.get('container_images', []) %}",
        "{% if image.get('engine') == 'docker' and image.get('pull_ref') %}",
        f"enroll_docker_pull_{role_key}_{{{{ loop.index }}}}:",
        "  cmd.run:",
        "    - name: {{ image.get('pull_cmd')|yaml_dquote }}",
        "    - unless: {{ image.get('pull_unless')|yaml_dquote }}",
        "{% set image_loop = loop.index %}",
        "{% for alias in image.get('tag_aliases', []) %}",
        f"enroll_docker_tag_{role_key}_{{{{ image_loop }}}}_{{{{ loop.index }}}}:",
        "  cmd.run:",
        "    - name: {{ alias.get('tag_cmd')|yaml_dquote }}",
        "    - unless: {{ alias.get('tag_unless')|yaml_dquote }}",
        "    - require:",
        f"      - cmd: enroll_docker_pull_{role_key}_{{{{ image_loop }}}}",
        "{% endfor %}",
        "{% elif image.get('engine') == 'podman' and image.get('pull_ref') %}",
        f"enroll_podman_pull_{role_key}_{{{{ loop.index }}}}:",
        "  cmd.run:",
        "    - name: {{ image.get('pull_cmd')|yaml_dquote }}",
        "    - unless: {{ image.get('pull_unless')|yaml_dquote }}",
        "{% set image_loop = loop.index %}",
        "{% for alias in image.get('tag_aliases', []) %}",
        f"enroll_podman_tag_{role_key}_{{{{ image_loop }}}}_{{{{ loop.index }}}}:",
        "  cmd.run:",
        "    - name: {{ alias.get('tag_cmd')|yaml_dquote }}",
        "    - unless: {{ alias.get('tag_unless')|yaml_dquote }}",
        "    - require:",
        f"      - cmd: enroll_podman_pull_{role_key}_{{{{ image_loop }}}}",
        "{% endfor %}",
        "{% endif %}",
        "{% endfor %}",
        "",
        "{% set firewall_runtime = role.get('firewall_runtime', {}) %}",
        "{% if firewall_runtime.get('ipset_restore_cmd') %}",
        "enroll_firewall_runtime_ipset_restore:",
        "  cmd.run:",
        "    - name: {{ firewall_runtime.get('ipset_restore_cmd')|yaml_dquote }}",
        "    - onchanges:",
        "      - file: {{ firewall_runtime.get('ipset_save')|yaml_dquote }}",
        "{% endif %}",
        "",
        "{% if firewall_runtime.get('iptables_v4_restore_cmd') %}",
        "enroll_firewall_runtime_iptables_v4_restore:",
        "  cmd.run:",
        "    - name: {{ firewall_runtime.get('iptables_v4_restore_cmd')|yaml_dquote }}",
        "    - onchanges:",
        "      - file: {{ firewall_runtime.get('iptables_v4_save')|yaml_dquote }}",
        "{% endif %}",
        "",
        "{% if firewall_runtime.get('iptables_v6_restore_cmd') %}",
        "enroll_firewall_runtime_iptables_v6_restore:",
        "  cmd.run:",
        "    - name: {{ firewall_runtime.get('iptables_v6_restore_cmd')|yaml_dquote }}",
        "    - onchanges:",
        "      - file: {{ firewall_runtime.get('iptables_v6_save')|yaml_dquote }}",
        "{% endif %}",
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
        yaml_dump_mapping(data, sort_keys=True, explicit_start=True),
        encoding="utf-8",
    )


def _load_yaml_mapping(path: Path) -> Dict[str, Any]:
    return yaml_load_mapping_file(path)


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
    role_lines = markdown_list(
        f"`{r.sls_name}` from Enroll role `{r.role_name}`" for r in salt_roles
    )
    notes_text = markdown_list(
        f"`{r.sls_name}`: {note}" for r in salt_roles for note in r.notes
    )

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
- Docker images by digest using guarded `docker pull` / `docker tag` command states.
- Podman images by digest using guarded `podman pull` / `podman tag` command states.
- Flatpak remotes and applications using guarded `flatpak remote-add` / `flatpak install` command states.
- Snap applications using guarded `snap install` command states.
- Live firewall runtime snapshots using staged `/etc/enroll/firewall/*` files and guarded restore command states.

## Current limitations

- JinjaTurtle templating is applied on a best-effort basis for file formats it recognises; unrecognised files are copied literally.
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
        jinjaturtle: str = "auto",
    ) -> None:
        self.bundle_dir = bundle_dir
        self.out_dir = out_dir
        self.fqdn = fqdn
        self.no_common_roles = no_common_roles
        self.jt_exe, self.jt_enabled = resolve_jinjaturtle_mode(jinjaturtle)

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
            jt_exe=self.jt_exe,
            jt_enabled=self.jt_enabled,
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
    jinjaturtle: str = "auto",
) -> None:
    SaltManifestRenderer(
        bundle_dir,
        out_dir,
        fqdn=fqdn,
        no_common_roles=no_common_roles,
        jinjaturtle=jinjaturtle,
    ).render()
