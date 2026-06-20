from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import yaml

from .cm import (
    CMModule,
    resolve_catalog_conflicts,
    role_order_key,
    markdown_list,
)
from .state import inventory_packages_from_state, roles_from_state


class PuppetRole(CMModule):
    """Puppet-specific view of a renderer-neutral CMModule."""

    def __init__(self, role_name: str) -> None:
        super().__init__(
            role_name=role_name,
            module_name=_puppet_name(role_name, fallback="enroll_role"),
        )
        self.container_images: List[Dict[str, Any]] = []
        self.flatpak_remotes: List[Dict[str, Any]] = []
        self.flatpaks: List[Dict[str, Any]] = []
        self.snaps: List[Dict[str, Any]] = []

    def has_resources(self) -> bool:
        return self.has_resources_or_attrs(
            "container_images", "flatpak_remotes", "flatpaks", "snaps"
        )

    def add_service_snapshot(self, snap: Dict[str, Any]) -> None:
        self.add_service_snapshot_state(
            snap, state_key="ensure", running="running", stopped="stopped"
        )

    def add_users_snapshot(self, snap: Dict[str, Any]) -> None:
        records = self.user_records_from_snapshot(snap)
        self.groups.update(self.user_group_names_from_records(records))
        for record in records:
            name = str(record.get("name") or "")
            self.users[name] = {
                "name": name,
                "uid": record.get("uid"),
                "gid": record.get("gid"),
                "primary_group": record.get("primary_group") or None,
                "home": record.get("home"),
                "shell": record.get("shell"),
                "gecos": record.get("gecos"),
                "supplementary_groups": record.get("supplementary_groups") or [],
            }

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
        module_files_dir: Path,
        file_prefix: Optional[str] = None,
    ) -> None:
        super().add_firewall_runtime_snapshot(
            snap,
            bundle_dir=bundle_dir,
            artifact_role=artifact_role,
            files_dir=module_files_dir,
            copy_artifact=_copy_artifact,
            source_uri=_source_uri,
            file_prefix=file_prefix,
            dir_attrs={"require": "File['/etc/enroll']"},
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
                    f"Container image {label} has no RepoDigest; exact Puppet pull resource was not rendered."
                )
                continue
            item = dict(raw)
            item["engine"] = engine
            item["pull_ref"] = pull_ref
            item["scope"] = str(item.get("scope") or "system").strip() or "system"
            image_name, image_digest = _split_digest_ref(pull_ref)
            item["image"] = image_name
            item["image_digest"] = image_digest
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
                alias["tag_unless"] = _container_exists_cmd(engine, alias_ref)
            self.container_images.append(item)
        for note in snap.get("notes", []) or []:
            self.notes.append(str(note))

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


def _shell_quote(value: Any) -> str:
    return shlex.quote(str(value or ""))


def _split_digest_ref(value: Any) -> Tuple[str, Optional[str]]:
    text = str(value or "").strip()
    if "@" not in text:
        return text, None
    image, digest = text.split("@", 1)
    return image, digest


def _container_pull_cmd(engine: str, pull_ref: str) -> str:
    return f"{engine} pull {_shell_quote(pull_ref)}"


def _container_exists_cmd(engine: str, ref: str) -> str:
    if engine == "podman":
        return f"podman image exists {_shell_quote(ref)}"
    return f"docker image inspect {_shell_quote(ref)} >/dev/null 2>&1"


def _container_tag_cmd(engine: str, pull_ref: str, tag_ref: str) -> str:
    return f"{engine} tag {_shell_quote(pull_ref)} {_shell_quote(tag_ref)}"


def _flatpak_scope(item: Dict[str, Any]) -> str:
    return "--user" if str(item.get("method") or "system") == "user" else "--system"


def _flatpak_home(item: Dict[str, Any]) -> Optional[str]:
    user = str(item.get("user") or "").strip()
    if not user:
        return None
    return str(item.get("home") or f"/home/{user}")


def _flatpak_exec_env(item: Dict[str, Any]) -> List[str]:
    home = _flatpak_home(item)
    if not home:
        return []
    return [f"HOME={home}", f"XDG_DATA_HOME={home}/.local/share"]


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
    out["state_id"] = _state_title("flatpak-remote", f"{method}-{user}-{name}")
    out["add_cmd"] = _flatpak_remote_add_cmd(out)
    out["exists_cmd"] = _flatpak_remote_exists_cmd(out)
    out["environment"] = _flatpak_exec_env(out)
    return out


def _prepare_flatpak_item(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    method = str(out.get("method") or "system")
    user = str(out.get("user") or "")
    ref = _flatpak_ref(out)
    out["state_id"] = _state_title("flatpak", f"{method}-{user}-{ref}")
    out["install_cmd"] = _flatpak_install_cmd(out)
    out["exists_cmd"] = _flatpak_exists_cmd(out)
    out["environment"] = _flatpak_exec_env(out)
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
    out["state_id"] = _state_title("snap", name)
    out["install_cmd"] = _snap_install_cmd(out)
    out["exists_cmd"] = _snap_exists_cmd(out)
    return out


def _pp_array(values: Iterable[Any]) -> str:
    return "[" + ", ".join(_pp_quote(v) for v in values) + "]"


def _puppet_exec_attrs(
    command: str,
    unless: str,
    *,
    item: Optional[Dict[str, Any]] = None,
    require: Optional[str] = None,
) -> List[Tuple[str, str]]:
    attrs: List[Tuple[str, str]] = [
        ("command", _pp_quote(command)),
        ("unless", _pp_quote(unless)),
        ("path", "['/usr/bin', '/bin']"),
    ]
    if item:
        user = str(item.get("user") or "").strip()
        if user:
            attrs.append(("user", _pp_quote(user)))
            env = item.get("environment") or _flatpak_exec_env(item)
            if env:
                attrs.append(("environment", _pp_array(env)))
    if require:
        attrs.append(("require", require))
    return attrs


def _resource(
    lines: List[str], rtype: str, title: str, attrs: List[Tuple[str, str]]
) -> None:
    lines.append(f"  {rtype} {{ {_pp_quote(title)}:")
    for key, value in attrs:
        lines.append(f"    {key} => {value},")
    lines.append("  }")
    lines.append("")


def _state_title(prefix: str, value: Any) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "item")).strip("-._")
    if not safe:
        safe = "item"
    if len(safe) > 64:
        digest = hashlib.sha1(
            str(value).encode("utf-8", errors="replace")
        ).hexdigest()[  # nosec B324
            :8
        ]
        safe = safe[:48] + "-" + digest
    return f"enroll-{prefix}-{safe}"


def _render_firewall_runtime_execs(
    lines: List[str], runtime: Dict[str, Any], *, indent: str = "  "
) -> None:
    specs = [
        (
            "ipset",
            "ipset_save",
            "ipset_restore_cmd",
            "enroll-firewall-runtime-ipset-restore",
        ),
        (
            "iptables_v4",
            "iptables_v4_save",
            "iptables_v4_restore_cmd",
            "enroll-firewall-runtime-iptables-v4-restore",
        ),
        (
            "iptables_v6",
            "iptables_v6_save",
            "iptables_v6_restore_cmd",
            "enroll-firewall-runtime-iptables-v6-restore",
        ),
    ]
    for _family, path_key, cmd_key, title in specs:
        path = str(runtime.get(path_key) or "")
        command = str(runtime.get(cmd_key) or "")
        if not path or not command:
            continue
        attrs: List[Tuple[str, str]] = [
            ("command", _pp_quote(command)),
            ("path", "['/sbin', '/usr/sbin', '/bin', '/usr/bin']"),
            ("refreshonly", "true"),
            ("subscribe", f"File[{_pp_quote(path)}]"),
        ]
        lines.append(f"{indent}exec {{ {_pp_quote(title)}:")
        for key, value in attrs:
            lines.append(f"{indent}  {key} => {value},")
        lines.append(f"{indent}}}")
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

    for entry in CMModule.package_service_entries(
        roles, inventory_packages, use_common_roles=use_common_modules
    ):
        snap = entry.get("snapshot") or {}
        kind = str(entry.get("kind") or "package")
        fallback = "service" if kind == "service" else "package"
        source_label = str(
            snap.get("role_name") or snap.get("unit") or snap.get("package") or fallback
        )
        original_role_name = _puppet_name(source_label, fallback=fallback)
        role_name = _puppet_name(
            str(entry.get("role_label") or source_label),
            fallback="package_group" if use_common_modules else fallback,
        )
        prole = ensure_role(role_name)
        if kind == "service":
            prole.add_service_snapshot(snap)
        else:
            prole.add_package_snapshot(snap)
        prole.add_managed_content(
            snap,
            bundle_dir=bundle_dir,
            artifact_role=str(snap.get("role_name") or original_role_name),
            module_files_dir=modules_dir / prole.module_name / "files",
            file_prefix=node_file_prefix,
        )

    container_images = roles.get("container_images") or {}
    if isinstance(container_images, dict) and (
        container_images.get("images") or container_images.get("notes")
    ):
        prole = ensure_role(
            str(container_images.get("role_name") or "container_images")
        )
        prole.add_container_images_snapshot(container_images)

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
                owner="root",
                group="root",
                mode="0750",
                reason="enroll_runtime",
            )
            role_name = str(fw.get("role_name") or "firewall_runtime")
            prole = ensure_role(role_name)
            prole.add_firewall_runtime_snapshot(
                fw,
                bundle_dir=bundle_dir,
                artifact_role=role_name,
                module_files_dir=modules_dir / prole.module_name / "files",
                file_prefix=node_file_prefix,
            )

    flatpak = roles.get("flatpak") or {}
    if isinstance(flatpak, dict) and (
        flatpak.get("system_flatpaks") or flatpak.get("remotes") or flatpak.get("notes")
    ):
        prole = ensure_role(str(flatpak.get("role_name") or "flatpak"))
        prole.add_flatpak_snapshot(flatpak)

    snap = roles.get("snap") or {}
    if isinstance(snap, dict) and (snap.get("system_snaps") or snap.get("notes")):
        prole = ensure_role(str(snap.get("role_name") or "snap"))
        prole.add_snap_snapshot(snap)

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
                *([("require", str(d.get("require")))] if d.get("require") else []),
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

    flatpak_remote_titles: Dict[Tuple[str, str, str], str] = {}
    for remote in prole.flatpak_remotes:
        name = str(remote.get("name") or "").strip()
        url = str(remote.get("url") or "").strip()
        if not name or not url:
            continue
        title = str(remote.get("state_id") or _state_title("flatpak-remote", name))
        key = (
            str(remote.get("method") or "system"),
            str(remote.get("user") or ""),
            name,
        )
        flatpak_remote_titles[key] = title
        remote_user = str(remote.get("user") or "").strip()
        remote_require = None
        if remote_user and remote_user in prole.users:
            remote_require = f"User[{_pp_quote(remote_user)}]"
        _resource(
            lines,
            "exec",
            title,
            _puppet_exec_attrs(
                str(remote.get("add_cmd") or _flatpak_remote_add_cmd(remote)),
                str(remote.get("exists_cmd") or _flatpak_remote_exists_cmd(remote)),
                item=remote,
                require=remote_require,
            ),
        )

    for app in prole.flatpaks:
        ref = _flatpak_ref(app)
        if not ref:
            continue
        title = str(app.get("state_id") or _state_title("flatpak", ref))
        requires: List[str] = []
        user = str(app.get("user") or "").strip()
        if user:
            requires.append(f"User[{_pp_quote(user)}]")
        remote = str(app.get("remote") or "").strip()
        if remote:
            remote_title = flatpak_remote_titles.get(
                (str(app.get("method") or "system"), user, remote)
            )
            if remote_title:
                requires.append(f"Exec[{_pp_quote(remote_title)}]")
        require_expr = None
        if len(requires) == 1:
            require_expr = requires[0]
        elif requires:
            require_expr = "[" + ", ".join(requires) + "]"
        _resource(
            lines,
            "exec",
            title,
            _puppet_exec_attrs(
                str(app.get("install_cmd") or _flatpak_install_cmd(app)),
                str(app.get("exists_cmd") or _flatpak_exists_cmd(app)),
                item=app,
                require=require_expr,
            ),
        )

    for snap in prole.snaps:
        name = str(snap.get("name") or "").strip()
        if not name:
            continue
        _resource(
            lines,
            "exec",
            str(snap.get("state_id") or _state_title("snap", name)),
            _puppet_exec_attrs(
                str(snap.get("install_cmd") or _snap_install_cmd(snap)),
                str(snap.get("exists_cmd") or _snap_exists_cmd(snap)),
            ),
        )

    for image in prole.container_images:
        engine = str(image.get("engine") or "").strip()
        pull_ref = str(image.get("pull_ref") or "").strip()
        if not engine or not pull_ref:
            continue
        if engine == "docker":
            pull_title = _state_title("docker-pull", pull_ref)
            _resource(
                lines,
                "exec",
                pull_title,
                [
                    (
                        "command",
                        _pp_quote(
                            image.get("pull_cmd")
                            or _container_pull_cmd(engine, pull_ref)
                        ),
                    ),
                    (
                        "unless",
                        _pp_quote(
                            image.get("pull_unless")
                            or _container_exists_cmd(engine, pull_ref)
                        ),
                    ),
                    ("path", "['/usr/bin', '/bin']"),
                ],
            )
            for alias in image.get("tag_aliases") or []:
                tag_ref = str(alias.get("ref") or "").strip()
                if not tag_ref:
                    continue
                _resource(
                    lines,
                    "exec",
                    _state_title("docker-tag", tag_ref),
                    [
                        (
                            "command",
                            _pp_quote(
                                alias.get("tag_cmd")
                                or _container_tag_cmd(engine, pull_ref, tag_ref)
                            ),
                        ),
                        (
                            "unless",
                            _pp_quote(
                                alias.get("tag_unless")
                                or _container_exists_cmd(engine, tag_ref)
                            ),
                        ),
                        ("path", "['/usr/bin', '/bin']"),
                        ("require", f"Exec[{_pp_quote(pull_title)}]"),
                    ],
                )
        elif engine == "podman":
            _resource(
                lines,
                "exec",
                _state_title("podman-pull", pull_ref),
                [
                    (
                        "command",
                        _pp_quote(
                            image.get("pull_cmd")
                            or _container_pull_cmd(engine, pull_ref)
                        ),
                    ),
                    (
                        "unless",
                        _pp_quote(
                            image.get("pull_unless")
                            or _container_exists_cmd(engine, pull_ref)
                        ),
                    ),
                    ("path", "['/usr/bin', '/bin']"),
                ],
            )
            for alias in image.get("tag_aliases") or []:
                tag_ref = str(alias.get("ref") or "").strip()
                if not tag_ref:
                    continue
                _resource(
                    lines,
                    "exec",
                    _state_title("podman-tag", tag_ref),
                    [
                        (
                            "command",
                            _pp_quote(
                                alias.get("tag_cmd")
                                or _container_tag_cmd(engine, pull_ref, tag_ref)
                            ),
                        ),
                        (
                            "unless",
                            _pp_quote(
                                alias.get("tag_unless")
                                or _container_exists_cmd(engine, tag_ref)
                            ),
                        ),
                        ("path", "['/usr/bin', '/bin']"),
                        (
                            "require",
                            f"Exec[{_pp_quote(_state_title('podman-pull', pull_ref))}]",
                        ),
                    ],
                )

    if prole.firewall_runtime:
        _render_firewall_runtime_execs(lines, prole.firewall_runtime)

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
                allowed={"owner", "group", "mode", "require"},
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

    if prole.flatpak_remotes:
        data[f"{prefix}flatpak_remotes"] = list(prole.flatpak_remotes)
    if prole.flatpaks:
        data[f"{prefix}flatpaks"] = list(prole.flatpaks)
    if prole.snaps:
        data[f"{prefix}snaps"] = list(prole.snaps)
    if prole.container_images:
        data[f"{prefix}container_images"] = list(prole.container_images)
    if prole.firewall_runtime:
        data[f"{prefix}firewall_runtime"] = dict(prole.firewall_runtime)

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
        "  Array[Hash] $flatpak_remotes = [],",
        "  Array[Hash] $flatpaks = [],",
        "  Array[Hash] $snaps = [],",
        "  Array[Hash] $container_images = [],",
        "  Hash $firewall_runtime = {},",
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
        "  $flatpak_remotes.each |Integer $idx, Hash $remote| {",
        "    exec { $remote['state_id']:",
        "      command => $remote['add_cmd'],",
        "      unless  => $remote['exists_cmd'],",
        "      path    => ['/usr/bin', '/bin'],",
        "      user    => $remote['user'],",
        "      environment => $remote['environment'],",
        "    }",
        "  }",
        "",
        "  $flatpaks.each |Integer $idx, Hash $app| {",
        "    exec { $app['state_id']:",
        "      command => $app['install_cmd'],",
        "      unless  => $app['exists_cmd'],",
        "      path    => ['/usr/bin', '/bin'],",
        "      user    => $app['user'],",
        "      environment => $app['environment'],",
        "    }",
        "  }",
        "",
        "  $snaps.each |Integer $idx, Hash $snap| {",
        "    exec { $snap['state_id']:",
        "      command => $snap['install_cmd'],",
        "      unless  => $snap['exists_cmd'],",
        "      path    => ['/usr/bin', '/bin'],",
        "    }",
        "  }",
        "",
        "  $container_images.each |Integer $idx, Hash $image| {",
        "    if $image['engine'] == 'docker' and $image['pull_ref'] {",
        '      exec { "enroll-docker-pull-${idx}":',
        "        command => $image['pull_cmd'],",
        "        unless  => $image['pull_unless'],",
        "        path    => ['/usr/bin', '/bin'],",
        "      }",
        "      $image['tag_aliases'].each |Integer $tag_idx, Hash $alias| {",
        '        exec { "enroll-docker-tag-${idx}-${tag_idx}":',
        "          command => $alias['tag_cmd'],",
        "          unless  => $alias['tag_unless'],",
        "          path    => ['/usr/bin', '/bin'],",
        '          require => Exec["enroll-docker-pull-${idx}"],',
        "        }",
        "      }",
        "    } elsif $image['engine'] == 'podman' and $image['pull_ref'] {",
        '      exec { "enroll-podman-pull-${idx}":',
        "        command => $image['pull_cmd'],",
        "        unless  => $image['pull_unless'],",
        "        path    => ['/usr/bin', '/bin'],",
        "      }",
        "      $image['tag_aliases'].each |Integer $tag_idx, Hash $alias| {",
        '        exec { "enroll-podman-tag-${idx}-${tag_idx}":',
        "          command => $alias['tag_cmd'],",
        "          unless  => $alias['tag_unless'],",
        "          path    => ['/usr/bin', '/bin'],",
        '          require => Exec["enroll-podman-pull-${idx}"],',
        "        }",
        "      }",
        "    }",
        "  }",
        "",
        "  if $firewall_runtime['ipset_restore_cmd'] {",
        "    exec { 'enroll-firewall-runtime-ipset-restore':",
        "      command     => $firewall_runtime['ipset_restore_cmd'],",
        "      path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],",
        "      refreshonly => true,",
        "      subscribe   => File[$firewall_runtime['ipset_save']],",
        "    }",
        "  }",
        "",
        "  if $firewall_runtime['iptables_v4_restore_cmd'] {",
        "    exec { 'enroll-firewall-runtime-iptables-v4-restore':",
        "      command     => $firewall_runtime['iptables_v4_restore_cmd'],",
        "      path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],",
        "      refreshonly => true,",
        "      subscribe   => File[$firewall_runtime['iptables_v4_save']],",
        "    }",
        "  }",
        "",
        "  if $firewall_runtime['iptables_v6_restore_cmd'] {",
        "    exec { 'enroll-firewall-runtime-iptables-v6-restore':",
        "      command     => $firewall_runtime['iptables_v6_restore_cmd'],",
        "      path        => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],",
        "      refreshonly => true,",
        "      subscribe   => File[$firewall_runtime['iptables_v6_save']],",
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


def _write_metadata(module_dir: Path, module_name: str, prole: PuppetRole) -> None:
    dependencies: List[Dict[str, str]] = []

    (module_dir / "metadata.json").write_text(
        json.dumps(
            {
                "name": f"enroll-{module_name}",
                "version": "0.1.0",
                "author": "Enroll",
                "summary": f"Generated Enroll Puppet module for {module_name}",
                "license": "UNLICENSED",
                "source": "",
                "dependencies": dependencies,
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
    role_lines = markdown_list(
        f"`{r.module_name}` from Enroll role `{r.role_name}`" for r in puppet_roles
    )
    node_lines = markdown_list(f"`{n}`" for n in (node_names or []))
    notes_text = markdown_list(
        f"`{r.module_name}`: {note}" for r in puppet_roles for note in r.notes
    )
    if hiera_mode:
        layout = f"""- `manifests/site.pp` declares node blocks and includes classes listed in Hiera key `enroll::classes`.
- `hiera.yaml` configures per-node lookup from `data/nodes/%{{trusted.certname}}.yaml` with a fallback to `data/common.yaml`.
- `data/nodes/{_node_data_filename(fqdn or '')}` contains this node's class list and class parameter data.
- `modules/<role>/manifests/init.pp` contains reusable, data-driven classes.
- `modules/<role>/files/nodes/<fqdn>/...` contains node-specific harvested file artifacts, avoiding clashes between hosts."""
        apply = f"""Run from this generated output directory, passing the node certname so Hiera selects the right node data:

```bash
sudo puppet apply --modulepath ./modules --hiera_config ./hiera.yaml --certname {fqdn} manifests/site.pp --noop --test
```

If you depend on other pre-installed Puppet modules, you may need to pass in other modulepaths as well, e.g:

```bash
sudo puppet apply --modulepath ./modules:/etc/puppet/code/modules --hiera_config ./hiera.yaml --certname {fqdn} manifests/site.pp --noop
```

For Puppet agent/control-repo use, place this output where `hiera.yaml`, `data/`, `manifests/`, and `modules/` form the environment root. Re-running Enroll with another `--fqdn` into the same output directory adds or replaces that node's YAML without deleting existing node data."""
    else:
        layout = """- `manifests/site.pp` declares a `node` block and includes the generated classes in manifest order.
- `modules/<role>/manifests/init.pp` contains resources for each generated Enroll role/snapshot or common package group.
- `modules/<role>/files/` contains harvested file artifacts for that role or group.
- Generated module names avoid Puppet reserved words such as `default`."""
        apply = """Run from this generated output directory so Puppet can find `./modules`, or pass an absolute module path:

```bash
sudo puppet apply --modulepath ./modules manifests/site.pp --noop --test
```

If you depend on other pre-installed Puppet modules, you may need to pass in other modulepaths as well, e.g:

```bash
sudo puppet apply --modulepath ./modules:/etc/puppet/code/modules manifests/site.pp --noop
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
- Docker and Podman images by digest using guarded `exec` resources (`pull`/`tag` commands with `unless` checks).
- Podman images by digest using guarded `podman pull` / `podman tag` exec resources.

## Current limitations

- JinjaTurtle templating is currently Ansible/Salt-oriented and is not applied to Puppet output - there are no erb templates, just raw files.
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
            _write_metadata(module_dir, prole.module_name, prole)

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
