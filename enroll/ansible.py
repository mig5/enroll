from __future__ import annotations

import os
import hashlib
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .cm import (
    CMModule,
    markdown_list,
    sanitize_markdown_text,
    snapshot_excluded_lines,
    snapshot_note_lines,
)
from .jinjaturtle import (
    jinjify_managed_files as _jinjify_managed_files,
    resolve_jinjaturtle_mode,
)
from .manifest_safety import (
    copy_safe_artifact_file,
    iter_safe_artifact_files,
    prepare_manifest_output_dir,
)
from .render_safety import (
    ansible_unsafe_data,
    assert_generated_yaml_safe,
    scaffold_token,
)
from .role_names import avoid_reserved_role_name
from .state import inventory_packages_from_state, roles_from_state
from .yamlutil import yaml_dump_mapping, yaml_load_mapping


@dataclass
class AnsibleManifestContext:
    bundle_dir: str
    out_dir: str
    roles_root: str
    jt_exe: Optional[str]
    jt_enabled: bool


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
        self.container_images: List[Dict[str, Any]] = []
        self.flatpak_remotes: List[Dict[str, Any]] = []
        self.flatpaks: List[Dict[str, Any]] = []
        self.snaps: List[Dict[str, Any]] = []
        self.users_groups: List[str] = []
        self.users_data: List[Dict[str, Any]] = []
        self.users_ssh_dirs: List[Dict[str, Any]] = []
        self.users_ssh_files: List[Dict[str, Any]] = []

    def has_resources(self) -> bool:
        return self.has_resources_or_attrs(
            "container_images",
            "flatpak_remotes",
            "flatpaks",
            "snaps",
            "users_data",
            "users_ssh_files",
        )

    def add_package_snapshot(self, snap: Dict[str, Any]) -> None:
        pkg = self.package_name_from_snapshot(snap)
        source_role = str(snap.get("role_name") or pkg or self.role_name)
        self.entries.append({"kind": "package", "snapshot": snap})
        super().add_package_snapshot(snap)
        if pkg:
            self.origin_lines.append(f"package `{pkg}` from role `{source_role}`")
        self.add_managed_content(snap)

    def add_service_snapshot(self, snap: Dict[str, Any]) -> None:
        unit = self.service_unit_from_snapshot(snap)
        source_role = str(snap.get("role_name") or unit or self.role_name)
        self.entries.append({"kind": "service", "snapshot": snap})
        self.add_service_packages_from_snapshot(snap)
        if unit:
            self.services.setdefault(
                unit,
                {
                    "name": unit,
                    "manage": True,
                    "enabled": self.service_enabled_from_snapshot(snap),
                    "state": self.service_state_from_snapshot(
                        snap, running="started", stopped="stopped"
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

    def add_firewall_runtime_snapshot(self, snap: Dict[str, Any]) -> None:
        self.add_service_packages_from_snapshot(snap)
        self.firewall_runtime.update(self.firewall_runtime_source_refs(snap))
        ipset_sets = self.firewall_runtime_ipset_sets(snap)
        if ipset_sets:
            self.firewall_runtime["ipset_sets"] = ipset_sets
        self.add_snapshot_notes(snap)

    def prepare_flatpak_remote(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return dict(item)

    def prepare_flatpak_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return dict(item)

    def prepare_snap_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return _normalise_snap_item(item)

    def add_container_images_snapshot(self, snap: Dict[str, Any]) -> None:
        self.container_images = [
            _normalise_container_image_item(img)
            for img in (snap.get("images", []) or [])
        ]
        self.add_snapshot_notes(snap)

    def add_users_snapshot(self, snap: Dict[str, Any]) -> None:
        users_data = self.user_records_from_snapshot(snap)
        for user in users_data:
            user["ssh_dir"] = str(user.get("home") or "").rstrip("/") + "/.ssh"

        ssh_files: List[Dict[str, Any]] = []
        for mf in snap.get("managed_files", []) or []:
            dest = mf.get("path") or ""
            src_rel = mf.get("src_rel") or ""
            if not dest or not src_rel:
                continue

            owner = "root"
            group = "root"
            for u in users_data:
                home_prefix = (u.get("home") or "").rstrip("/") + "/"
                if home_prefix and dest.startswith(home_prefix):
                    owner = str(u.get("name") or "root")
                    group = str(u.get("primary_group") or owner)
                    break

            mode = mf.get("mode") or "0644"
            if mf.get("reason") == "authorized_keys":
                mode = "0600"
            ssh_files.append(
                {
                    "dest": dest,
                    "src_rel": src_rel,
                    "owner": owner,
                    "group": group,
                    "mode": mode,
                }
            )

        ssh_dirs_by_dest: Dict[str, Dict[str, Any]] = {}
        for item in ssh_files:
            dest = str(item.get("dest") or "")
            if not dest:
                continue
            for user in users_data:
                ssh_dir = str(user.get("ssh_dir") or "").rstrip("/")
                if not ssh_dir or not dest.startswith(ssh_dir + "/"):
                    continue
                ssh_dirs_by_dest.setdefault(
                    ssh_dir,
                    {
                        "dest": ssh_dir,
                        "owner": str(user.get("name") or item.get("owner") or "root"),
                        "group": str(
                            user.get("primary_group") or item.get("group") or "root"
                        ),
                        "mode": "0700",
                    },
                )
                break

        self.users_groups = sorted(self.user_group_names_from_records(users_data))
        self.users_data = users_data
        self.users_ssh_files = ssh_files
        self.users_ssh_dirs = sorted(
            ssh_dirs_by_dest.values(), key=lambda item: str(item.get("dest") or "")
        )
        self.add_user_flatpaks_snapshot(snap)
        self.excluded.extend(snap.get("excluded", []) or [])
        self.add_snapshot_notes(snap)

    def render_firewall_runtime_tasks(self) -> str:
        var_prefix = scaffold_token(self.role_name, field="role var_prefix")
        return f"""- name: Ensure firewall runtime snapshot directory exists
  ansible.builtin.file:
    path: {self.firewall_runtime_dir}
    state: directory
    owner: root
    group: root
    mode: "0750"

- name: Deploy captured ipset snapshot
  vars:
    _enroll_ff:
      files:
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_ipset_save }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: {self.firewall_runtime_dest_path('ipset.save')}
    owner: root
    group: root
    mode: "0600"
  notify: Restore captured ipsets
  when: ({var_prefix}_ipset_save | default('') | length) > 0

- name: Deploy captured IPv4 iptables snapshot
  vars:
    _enroll_ff:
      files:
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_iptables_v4_save }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: {self.firewall_runtime_dest_path('iptables.v4')}
    owner: root
    group: root
    mode: "0600"
  notify: Restore captured IPv4 iptables rules
  when: ({var_prefix}_iptables_v4_save | default('') | length) > 0

- name: Deploy captured IPv6 iptables snapshot
  vars:
    _enroll_ff:
      files:
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_iptables_v6_save }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: {self.firewall_runtime_dest_path('iptables.v6')}
    owner: root
    group: root
    mode: "0600"
  notify: Restore captured IPv6 iptables rules
  when: ({var_prefix}_iptables_v6_save | default('') | length) > 0
"""

    def render_firewall_runtime_handlers(self) -> str:
        var_prefix = scaffold_token(self.role_name, field="role var_prefix")
        return f"""---
- name: Flush captured ipsets before restoring members
  ansible.builtin.command:
    cmd: "ipset flush {{{{ item }}}}"
  loop: "{{{{ {var_prefix}_ipset_sets | default([]) }}}}"
  listen: Restore captured ipsets
  register: _enroll_ipset_flush
  failed_when: false
  changed_when: false
  when: {var_prefix}_sync_ipsets_exact | default(true) | bool

- name: Restore captured ipsets
  ansible.builtin.shell: "ipset restore -exist < {self.firewall_runtime_dest_path('ipset.save')}"
  args:
    executable: /bin/sh
  listen: Restore captured ipsets
  when: ({var_prefix}_ipset_save | default('') | length) > 0

- name: Restore captured IPv4 iptables rules
  ansible.builtin.command:
    cmd: iptables-restore {self.firewall_runtime_dest_path('iptables.v4')}
  listen: Restore captured IPv4 iptables rules
  when:
    - ({var_prefix}_iptables_v4_save | default('') | length) > 0
    - {var_prefix}_restore_iptables | default(true) | bool

- name: Restore captured IPv6 iptables rules
  ansible.builtin.command:
    cmd: ip6tables-restore {self.firewall_runtime_dest_path('iptables.v6')}
  listen: Restore captured IPv6 iptables rules
  when:
    - ({var_prefix}_iptables_v6_save | default('') | length) > 0
    - {var_prefix}_restore_iptables | default(true) | bool
"""


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
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """Collect package/service role inputs from shared CMModule grouping logic."""

    services: List[Dict[str, Any]] = []
    packages: List[Dict[str, Any]] = []
    common_role_groups: Dict[str, List[Dict[str, Any]]] = {}
    for entry in CMModule.package_service_entries(
        roles, inventory_packages, use_common_roles=use_common_roles
    ):
        kind = str(entry.get("kind") or "package")
        snap = entry.get("snapshot") or {}
        if use_common_roles:
            common_role_groups.setdefault(
                str(entry.get("role_label") or "misc"), []
            ).append({"kind": kind, "snapshot": snap})
        elif kind == "service":
            services.append(snap)
        else:
            packages.append(snap)
    return services, packages, common_role_groups


def _add_role(roles: List[str], role: Optional[str]) -> None:
    if role and role not in roles:
        roles.append(role)


def _add_roles(roles: List[str], incoming: List[str]) -> None:
    for role in incoming:
        _add_role(roles, role)


def _ordered_playbook_roles(
    rendered_roles: List[str], tail_roles: List[str]
) -> List[str]:
    """Return generated role names in playbook order."""
    tail = {role for role in tail_roles if role in rendered_roles}
    ordered = [role for role in rendered_roles if role not in tail]
    ordered.extend(role for role in tail_roles if role in tail and role not in ordered)
    return ordered


def _prepare_ansible_context(
    bundle_dir: str,
    out_dir: str,
    *,
    jinjaturtle: Optional[bool],
) -> AnsibleManifestContext:
    jt_exe, jt_enabled = resolve_jinjaturtle_mode(jinjaturtle)

    out = prepare_manifest_output_dir(out_dir)
    out_dir = str(out)
    roles_root = os.path.join(out_dir, "roles")
    os.makedirs(roles_root, exist_ok=True)

    return AnsibleManifestContext(
        bundle_dir=bundle_dir,
        out_dir=out_dir,
        roles_root=roles_root,
        jt_exe=jt_exe,
        jt_enabled=jt_enabled,
    )


def _merge_mappings_overwrite(
    existing: Dict[str, Any], incoming: Dict[str, Any]
) -> Dict[str, Any]:
    """Merge incoming into existing with overwrite.

    NOTE: Unlike role defaults merging, host_vars should reflect the current
    harvest for a host. Therefore lists are replaced rather than unioned.
    """
    merged = dict(existing)
    merged.update(incoming)
    return merged


# --- Ansible layout helpers ---
def _copy2_replace(src: str, dst: str) -> None:
    dst_dir = os.path.dirname(dst)
    os.makedirs(dst_dir, exist_ok=True)

    # Copy to a temp file in the same directory, then atomically replace.
    fd, tmp = tempfile.mkstemp(prefix=".enroll-tmp-", dir=dst_dir)
    os.close(fd)
    try:
        copy_safe_artifact_file(src, tmp)

        # Ensure the working tree stays mergeable: make the file user-writable.
        st = os.stat(tmp, follow_symlinks=False)
        mode = stat.S_IMODE(st.st_mode)
        if not (mode & stat.S_IWUSR):
            os.chmod(tmp, mode | stat.S_IWUSR)

        os.replace(tmp, dst)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _copy_artifacts(
    bundle_dir: str,
    role: str,
    dst_files_dir: str,
    *,
    preserve_existing: bool = False,
    exclude_rels: Optional[Set[str]] = None,
) -> None:
    """Copy harvested artifacts for a role into a destination *files* directory.

    Artifacts are stored in <role_dir>/files.
    """
    for src, rel in iter_safe_artifact_files(bundle_dir, role):
        dst = os.path.join(dst_files_dir, rel)

        # If a file was successfully templatised by JinjaTurtle, do NOT
        # also materialise the raw copy in the destination files dir.
        if exclude_rels and rel in exclude_rels:
            try:
                if os.path.isfile(dst):
                    os.remove(dst)
            except Exception:
                pass  # nosec
            continue

        if preserve_existing and os.path.exists(dst):
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        _copy2_replace(str(src), dst)


def _write_role_scaffold(role_dir: str) -> None:
    os.makedirs(os.path.join(role_dir, "tasks"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "handlers"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "defaults"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "meta"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "files"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "templates"), exist_ok=True)


def _role_tag(role: str) -> str:
    """Return a stable Ansible tag name for a role.

    Lets operators run only selected roles via `--tags` when applying a manifest.
    """
    r = str(role or "").strip()
    # Ansible tag charset is fairly permissive, but keep it portable and consistent.
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", r).strip("_")
    if not safe:
        safe = "other"
    return f"role_{safe}"


def _write_generated_task_yaml(path: str, text: str, *, label: str) -> None:
    """Write generated task/handler/playbook YAML through one safety gate."""

    body = text.rstrip() + "\n"
    assert_generated_yaml_safe(body, label=label)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


def _write_playbook_all(path: str, roles: List[str]) -> None:
    pb_lines = [
        "---",
        "- name: Apply all roles on all hosts",
        "  gather_facts: true",
        "  hosts: all",
        "  become: true",
        "  roles:",
    ]
    for r in roles:
        safe = scaffold_token(r, field="role name")
        pb_lines.append(f"    - role: {safe}")
        pb_lines.append(f"      tags: [{_role_tag(safe)}]")
    text = "\n".join(pb_lines) + "\n"
    _write_generated_task_yaml(path, text, label="playbook.yml")


def _ensure_ansible_cfg(cfg_path: str) -> None:
    if not os.path.exists(cfg_path):
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("[defaults]\n")
            f.write("roles_path = roles\n")
            f.write("interpreter_python=auto_silent\n")
            f.write("# Supply inventory with ansible-playbook -i\n")
            f.write("stdout_callback = default\n")
            f.write("force_color = 1\n")
            f.write("vars_plugins_enabled = host_group_vars\n")
            f.write("fact_caching = jsonfile\n")
            f.write("fact_caching_connection = .enroll_cached_facts\n")
            f.write("forks = 30\n")
            f.write("remote_tmp = /tmp/ansible-${USER}\n")
            f.write("timeout = 12\n")
            f.write("[ssh_connection]\n")
            f.write("pipelining = True\n")
            f.write("scp_if_ssh = True\n")
        return


def _ensure_requirements_yaml(
    req_path: str,
    collections: Optional[List[Dict[str, str]]] = None,
) -> None:
    requested = collections or [{"name": "community.general", "version": ">=13.0.0"}]

    existing: Dict[str, Any] = {}
    if os.path.exists(req_path):
        try:
            existing = yaml_load_mapping(Path(req_path).read_text(encoding="utf-8"))
        except Exception:
            existing = {}

    current_items = existing.get("collections")
    if not isinstance(current_items, list):
        current_items = []

    by_name: Dict[str, Dict[str, str]] = {}
    ordered_names: List[str] = []
    for item in current_items:
        if isinstance(item, str):
            name = item.strip()
            if not name:
                continue
            entry: Dict[str, str] = {"name": name}
        elif isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            entry = {str(k): str(v) for k, v in item.items() if v is not None}
            entry["name"] = name
        else:
            continue
        if name not in by_name:
            ordered_names.append(name)
        by_name[name] = entry

    for item in requested:
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        entry = dict(item)
        entry["name"] = name
        if name not in by_name:
            ordered_names.append(name)
            by_name[name] = entry
        else:
            by_name[name].update(
                {k: v for k, v in entry.items() if v not in (None, "")}
            )

    out = {"collections": [by_name[name] for name in ordered_names]}
    Path(req_path).parent.mkdir(parents=True, exist_ok=True)
    Path(req_path).write_text(
        "---\n" + yaml_dump_mapping(out, sort_keys=False), encoding="utf-8"
    )


def _write_role_defaults(role_dir: str, mapping: Dict[str, Any]) -> None:
    """Overwrite role defaults/main.yml with the provided mapping."""
    defaults_path = os.path.join(role_dir, "defaults", "main.yml")
    os.makedirs(os.path.dirname(defaults_path), exist_ok=True)
    out = "---\n" + yaml_dump_mapping(ansible_unsafe_data(mapping), sort_keys=True)
    with open(defaults_path, "w", encoding="utf-8") as f:
        f.write(out)


def _write_role_meta(role_dir: str, collections: Optional[List[str]] = None) -> None:
    meta_path = os.path.join(role_dir, "meta", "main.yml")
    with open(meta_path, "w", encoding="utf-8") as f:
        f.write("---\n")
        f.write("dependencies: []\n")
        if collections:
            f.write("collections:\n")
            for collection in collections:
                f.write(f"  - {collection}\n")


def _write_ansible_role_vars(
    ctx: AnsibleManifestContext,
    role_dir: str,
    role: str,
    vars_map: Dict[str, Any],
) -> None:
    """Write overridable role defaults."""

    _write_role_defaults(role_dir, vars_map)


def _write_ansible_role(
    ctx: AnsibleManifestContext,
    role: str,
    *,
    vars_map: Optional[Dict[str, Any]] = None,
    tasks: str = "---\n",
    handlers: str = "---\n",
    collections: Optional[List[str]] = None,
) -> str:
    """Write an Ansible role through one common logistical path.

    The CM-specific rendering remains target-specific, but role directory layout,
    defaults and metadata writing are no longer repeated
    in every feature renderer.
    """

    role_dir = os.path.join(ctx.roles_root, role)
    _write_role_scaffold(role_dir)
    _write_ansible_role_vars(
        ctx,
        role_dir,
        role,
        vars_map or {},
    )

    tasks = _write_role_phases(role_dir, tasks)

    # Backstop guardrail: never write a tasks/handlers document whose *structure*
    # was altered by a harvested value. Enroll authors this YAML as scaffolding
    # and keeps all harvested data in variable files; if any harvested value ever
    # leaked into this text and changed its shape, fail closed here rather than
    # emit a poisoned playbook.
    _write_generated_task_yaml(
        os.path.join(role_dir, "tasks", "main.yml"),
        tasks,
        label=f"role '{role}' tasks/main.yml",
    )
    _write_generated_task_yaml(
        os.path.join(role_dir, "handlers", "main.yml"),
        handlers,
        label=f"role '{role}' handlers/main.yml",
    )

    _write_role_meta(role_dir, collections)

    return role


def _copy_role_artifacts(
    ctx: AnsibleManifestContext,
    role: str,
    artifact_role: str,
    *,
    exclude_rels: Optional[Set[str]] = None,
    preserve_existing: bool = False,
) -> None:
    role_dir = os.path.join(ctx.roles_root, role)
    dst_files_dir = os.path.join(role_dir, "files")
    _copy_artifacts(
        ctx.bundle_dir,
        artifact_role,
        dst_files_dir,
        preserve_existing=preserve_existing,
        exclude_rels=exclude_rels,
    )


def _render_readme(
    state: Dict[str, Any],
    rendered_roles: List[str],
) -> str:
    host = state.get("host", {}) if isinstance(state.get("host"), dict) else {}
    hostname = sanitize_markdown_text(host.get("hostname") or "unknown") or "unknown"
    roles = state.get("roles", {}) if isinstance(state.get("roles"), dict) else {}
    excluded = snapshot_excluded_lines(roles)
    notes = snapshot_note_lines(roles)
    role_lines = "\n".join(f"- `{role}`" for role in rendered_roles) or "- None."
    excluded_text = markdown_list(excluded)
    notes_text = markdown_list(notes)

    layout = """- `playbook.yml` applies the generated roles to the current inventory.
- `roles/<role>/tasks/main.yml` contains reusable Ansible tasks.
- `roles/<role>/defaults/main.yml` contains harvested/default role variables.
- `roles/<role>/files/...` and `roles/<role>/templates/...` contain harvested role artifacts where applicable.
- `roles/<role>/handlers/main.yml` contains any restore/restart/apply handlers."""
    apply = """```bash
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i localhost, -c local playbook.yml --check --diff
```"""

    return f"""# Enroll Ansible manifest

Generated from harvested state for `{hostname}`.

## Layout

{layout}

## Roles

{role_lines}

## Excluded captured paths

{excluded_text}

## Notes

{notes_text}

## Apply / dry-run

{apply}
"""


def _write_scaffold(ctx: AnsibleManifestContext) -> None:
    _ensure_ansible_cfg(os.path.join(ctx.out_dir, "ansible.cfg"))
    _ensure_requirements_yaml(os.path.join(ctx.out_dir, "requirements.yml"))


def _write_manifest_playbook(ctx: AnsibleManifestContext, roles: List[str]) -> None:
    path = Path(ctx.out_dir, "playbook.yml")
    _write_playbook_all(str(path), roles)
    text = path.read_text()
    pre = ["  vars:", "    enroll_defer_activation: true", "  pre_tasks:"]
    # Repository configuration must precede package installation.
    for role in roles:
        if role in {"apt_config", "dnf_config"}:
            pre.extend(_phase_import(role, "main"))
    for role in roles:
        if Path(ctx.roles_root, role, "tasks", "packages.yml").exists():
            pre.extend(_phase_import(role, "packages"))
    for role in roles:
        if Path(ctx.roles_root, role, "tasks", "accounts.yml").exists():
            pre.extend(_phase_import(role, "accounts"))
    # Keep an empty list valid when there are no prerequisite tasks.
    if pre[-1] == "  pre_tasks:":
        pre[-1] = "  pre_tasks: []"
    text = text.replace("  roles:\n", "\n".join(pre) + "\n  roles:\n")
    post = []
    for role in roles:
        if Path(ctx.roles_root, role, "tasks", "activate.yml").exists():
            post.extend(_phase_import(role, "activate"))
    if post:
        text += "  post_tasks:\n" + "\n".join(post) + "\n"
    _write_generated_task_yaml(str(path), text, label="playbook.yml")


def _phase_import(role: str, phase: str) -> List[str]:
    role = scaffold_token(role, field="role name")
    return [
        f"    - name: Apply {role} {phase}",
        "      ansible.builtin.import_role:",
        f"        name: {role}",
        f"        tasks_from: {phase}",
        f"      tags: [{_role_tag(role)}]",
    ]


def _write_role_phases(role_dir: str, tasks: str) -> str:
    """Expose prerequisite/activation entry points while keeping roles reusable."""
    chunks = re.split(r"(?m)(?=^- name:)", _task_body(tasks))
    phases = {"packages": [], "accounts": [], "activate": []}
    main = []
    for chunk in chunks:
        if "  ansible.builtin.package:" in chunk:
            phases["packages"].append(chunk)
        if any(f"  ansible.builtin.{module}:" in chunk for module in ("group", "user")):
            phases["accounts"].append(chunk)
        if "  ansible.builtin.systemd:" in chunk:
            # A failed probe must remain a failure, rather than being rewritten
            # as success and accidentally enabling a missing/unmanageable unit.
            chunk = chunk.replace("  failed_when: false\n", "")
            phases["activate"].append(chunk)
            chunk = chunk.replace(
                "  when:\n",
                "  when:\n    - not (enroll_defer_activation | default(false) | bool)\n",
            )
        main.append(chunk)
    for phase, parts in phases.items():
        if parts:
            _write_generated_task_yaml(
                str(Path(role_dir, "tasks", f"{phase}.yml")),
                "---\n" + "".join(parts),
                label=f"{phase} tasks",
            )
    return "---\n" + "".join(main)


# --- Ansible task snippets ---
def _render_generic_files_tasks(var_prefix: str) -> str:
    """Render generic tasks to deploy <var_prefix>_managed_files safely."""
    # Using first_found makes roles work in both modes:
    # - non-site: roles/<role>/files/...
    return f"""- name: Ensure managed directories exist (preserve owner/group/mode)
  ansible.builtin.file:
    path: "{{{{ item.dest }}}}"
    state: directory
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: "{{{{ {var_prefix}_managed_dirs | default([]) }}}}"

- name: Deploy any systemd unit files (templates)
  ansible.builtin.template:
    src: "{{{{ item.src_rel }}}}.j2"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', true)
      | selectattr('kind', 'equalto', 'template')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Deploy any systemd unit files (raw files)
  vars:
    _enroll_ff:
      files:
        - "{{{{ role_path }}}}/files/{{{{ item.src_rel }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', true)
      | selectattr('kind', 'equalto', 'copy')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Deploy any other managed files (templates)
  ansible.builtin.template:
    src: "{{{{ item.src_rel }}}}.j2"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', false)
      | selectattr('kind', 'equalto', 'template')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Deploy any other managed files (raw files)
  vars:
    _enroll_ff:
      files:
        - "{{{{ role_path }}}}/files/{{{{ item.src_rel }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', false)
      | selectattr('kind', 'equalto', 'copy')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Ensure managed symlinks exist
  ansible.builtin.file:
    src: "{{{{ item.src }}}}"
    dest: "{{{{ item.dest }}}}"
    state: link
    force: true
  loop: "{{{{ {var_prefix}_managed_links | default([]) }}}}"
  notify: "{{{{ item.notify | default([]) }}}}"
"""


def _render_install_packages_tasks(role: str, var_prefix: str) -> str:
    """Render package installation through Ansible's generic package provider."""

    role = scaffold_token(role, field="role name")
    var_prefix = scaffold_token(var_prefix, field="role var_prefix")
    return f"""- name: Install packages for {role}
  ansible.builtin.package:
    name: "{{{{ {var_prefix}_packages | default([]) }}}}"
    state: present
  when: ({var_prefix}_packages | default([])) | length > 0

"""


def _render_grouped_systemd_tasks(var_prefix: str) -> str:
    """Render tasks to manage multiple systemd units in a common role."""

    return f"""- name: Probe whether grouped systemd units exist and are manageable
  ansible.builtin.systemd:
    name: "{{{{ item.name }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  check_mode: true
  loop: "{{{{ {var_prefix}_systemd_units | default([]) }}}}"
  register: _enroll_unit_probes
  failed_when: false
  changed_when: false
  when:
    - enroll_manage_systemd_runtime | default(true) | bool
    - item.manage | default(false)

- name: Ensure grouped unit enablement matches harvest
  ansible.builtin.systemd:
    name: "{{{{ item.item.name }}}}"
    enabled: "{{{{ item.item.enabled | bool }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  loop: "{{{{ _enroll_unit_probes.results | default([]) }}}}"
  when:
    - enroll_manage_systemd_runtime | default(true) | bool
    - item.item.manage | default(false)
    - not (item.failed | default(false))

- name: Ensure grouped unit running state matches harvest
  ansible.builtin.systemd:
    name: "{{{{ item.item.name }}}}"
    state: "{{{{ item.item.state }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  loop: "{{{{ _enroll_unit_probes.results | default([]) }}}}"
  when:
    - enroll_manage_systemd_runtime | default(true) | bool
    - item.item.manage | default(false)
    - not (item.failed | default(false))
"""


def _render_sysctl_tasks(var_prefix: str) -> str:
    return f"""- name: Ensure sysctl.d exists
  ansible.builtin.file:
    path: /etc/sysctl.d
    state: directory
    owner: root
    group: root
    mode: "0755"

- name: Deploy captured sysctl configuration
  vars:
    _enroll_ff:
      files:
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_conf_src_rel }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: /etc/sysctl.d/99-enroll.conf
    owner: root
    group: root
    mode: "0644"
  when: ({var_prefix}_conf_src_rel | default('') | length) > 0
  notify: Apply captured sysctl configuration
"""


def _render_sysctl_handlers(var_prefix: str) -> str:
    return f"""---
- name: Apply captured sysctl configuration
  ansible.builtin.command:
    argv:
      - sysctl
      - -e
      - -p
      - /etc/sysctl.d/99-enroll.conf
  register: _enroll_sysctl_apply
  changed_when: false
  failed_when:
    - not ({var_prefix}_ignore_apply_errors | default(true) | bool)
    - _enroll_sysctl_apply.rc != 0
  when: {var_prefix}_apply | default(true) | bool
"""


def _task_body(tasks: str) -> str:
    return (tasks or "").strip().removeprefix("---").lstrip("\n")


def _render_single_systemd_tasks(var_prefix: str) -> str:
    return f"""- name: Probe whether systemd unit exists and is manageable
  ansible.builtin.systemd:
    name: "{{{{ {var_prefix}_unit_name }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  check_mode: true
  register: _unit_probe
  failed_when: false
  changed_when: false
  when:
    - enroll_manage_systemd_runtime | default(true) | bool
    - {var_prefix}_manage_unit | default(false)

- name: Ensure unit enablement matches harvest
  ansible.builtin.systemd:
    name: "{{{{ {var_prefix}_unit_name }}}}"
    enabled: "{{{{ {var_prefix}_systemd_enabled | bool }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  when:
    - enroll_manage_systemd_runtime | default(true) | bool
    - {var_prefix}_manage_unit | default(false)
    - _unit_probe is succeeded

- name: Ensure unit running state matches harvest
  ansible.builtin.systemd:
    name: "{{{{ {var_prefix}_unit_name }}}}"
    state: "{{{{ {var_prefix}_systemd_state }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  when:
    - enroll_manage_systemd_runtime | default(true) | bool
    - {var_prefix}_manage_unit | default(false)
    - _unit_probe is succeeded
"""


def _render_role_tasks(
    role: AnsibleRole,
    *,
    packages: bool = False,
    managed_content: bool = False,
    single_service: bool = False,
    grouped_services: bool = False,
    sysctl: bool = False,
    firewall_runtime: bool = False,
    extra_tasks: str = "",
) -> str:
    parts: List[str] = []
    if packages:
        parts.append(_render_install_packages_tasks(role.role_name, role.var_prefix))
    if managed_content:
        parts.append(_render_generic_files_tasks(role.var_prefix))
    if single_service:
        parts.append(_render_single_systemd_tasks(role.var_prefix))
    if grouped_services:
        parts.append(_render_grouped_systemd_tasks(role.var_prefix))
    if sysctl:
        parts.append(_render_sysctl_tasks(role.var_prefix))
    if firewall_runtime:
        parts.append(role.render_firewall_runtime_tasks())
    if extra_tasks:
        parts.append(extra_tasks)

    body = "\n\n".join(_task_body(part) for part in parts if _task_body(part))
    return "---\n" + (body.rstrip() + "\n" if body else "")


def _single_service_restart_handler_body(var_prefix: str) -> str:
    var_prefix = scaffold_token(var_prefix, field="role var_prefix")
    return f"""- name: Restart service for {var_prefix}
  ansible.builtin.systemd_service:
    name: "{{{{ {var_prefix}_unit_name }}}}"
    state: restarted
    daemon_reload: true
  when:
    - enroll_manage_systemd_runtime | default(true) | bool
    - {var_prefix}_manage_unit | default(false)
    - ({var_prefix}_systemd_state | default('stopped')) == 'started'
"""


def _service_restart_listen_topic(var_prefix: str, unit: str = "") -> str:
    """Use only scaffold-safe tokens, including for attacker-controlled units."""
    var_prefix = scaffold_token(var_prefix, field="role var_prefix")
    suffix = "_" + hashlib.sha256(unit.encode()).hexdigest()[:16] if unit else ""
    return f"enroll_restart_grouped_services_{var_prefix}{suffix}"


def _grouped_service_restart_handlers_body(role: AnsibleRole) -> str:
    parts = []
    prefix = scaffold_token(role.var_prefix, field="role var_prefix")
    for index, unit in enumerate(restart_units_for_role(role)):
        topic = _service_restart_listen_topic(prefix, unit)
        parts.append(
            f"""- name: Restart managed service {prefix} {index}
  ansible.builtin.systemd_service:
    name: "{{{{ {prefix}_restart_units[{index}] }}}}"
    state: restarted
    daemon_reload: true
  listen: {topic}
  when: enroll_manage_systemd_runtime | default(true) | bool
"""
        )
    return "\n".join(parts)


def restart_units_for_role(role: AnsibleRole) -> List[str]:
    """Return the harvested unit names a grouped role should restart, as data.

    These are emitted into the role's ``<var_prefix>_restart_units`` variable and
    consumed by the restart handler's loop. They are ordinary harvested values
    and are protected by ``ansible_unsafe_data`` when the variable file is
    written -- they never touch YAML scaffolding.
    """

    units: List[str] = []
    for unit, svc in sorted(role.services.items()):
        name = str(svc.get("name") or unit).strip()
        if not name or str(svc.get("state") or "stopped") != "started":
            continue
        units.append(name)
    return units


def _render_role_handlers(
    role: AnsibleRole,
    *,
    systemd_reload: bool = False,
    single_service: bool = False,
    grouped_services: bool = False,
    restart_grouped_services: bool = False,
    sysctl: bool = False,
    firewall_runtime: bool = False,
    extra_handlers: str = "",
) -> str:
    parts: List[str] = []
    if systemd_reload or single_service or grouped_services:
        parts.append(_SYSTEMD_DAEMON_RELOAD_HANDLER)
    if single_service:
        parts.append(_single_service_restart_handler_body(role.var_prefix))
    if grouped_services and restart_grouped_services:
        parts.append(_grouped_service_restart_handlers_body(role))
    if sysctl:
        parts.append(_render_sysctl_handlers(role.var_prefix))
    if firewall_runtime:
        parts.append(role.render_firewall_runtime_handlers())
    if extra_handlers:
        parts.append(extra_handlers)

    body = "\n\n".join(_task_body(part) for part in parts if _task_body(part))
    return "---\n" + (body.rstrip() + "\n" if body else "")


def _normalise_snap_item(item: Any) -> Dict[str, Any]:
    out = CMModule.normalise_snap_item(item)

    # The Ansible snap module's revision parameter pins/holds the snap. For
    # ordinary store snaps that track a channel, preserve the channel instead
    # of freezing every harvested host at today's revision.
    if out.get("revision") is not None and not out.get("channel"):
        out["install_revision"] = True
    else:
        out["install_revision"] = False
    return out


def _build_managed_dirs_var(
    managed_dirs: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Convert enroll managed_dirs into an Ansible-friendly list of dicts.

    Each dict drives a role task loop and is safe across hosts.
    """
    out: List[Dict[str, Any]] = []
    for d in managed_dirs:
        dest = d.get("path") or ""
        if not dest:
            continue
        out.append(
            {
                "dest": dest,
                "owner": d.get("owner") or "root",
                "group": d.get("group") or "root",
                "mode": d.get("mode") or "0755",
            }
        )
    return out


def _build_managed_files_var(
    managed_files: List[Dict[str, Any]],
    templated_src_rels: Set[str],
    *,
    notify_other: Optional[Any] = None,
    notify_systemd: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Convert enroll managed_files into an Ansible-friendly list of dicts.

    Each dict drives a role task loop and is safe across hosts.
    """
    out: List[Dict[str, Any]] = []
    for mf in managed_files:
        dest = mf.get("path") or ""
        src_rel = mf.get("src_rel") or ""
        if not dest or not src_rel:
            continue
        is_unit = str(dest).startswith("/etc/systemd/system/")
        kind = "template" if src_rel in templated_src_rels else "copy"
        notify: List[str] = []
        if is_unit and notify_systemd:
            notify.append(notify_systemd)
        if notify_other:
            if isinstance(notify_other, (list, tuple, set)):
                notify.extend(str(item) for item in notify_other if str(item))
            else:
                notify.append(str(notify_other))
        item = {
            "dest": dest,
            "src_rel": src_rel,
            "owner": mf.get("owner") or "root",
            "group": mf.get("group") or "root",
            "mode": mf.get("mode") or "0644",
            "kind": kind,
            "is_systemd_unit": bool(is_unit),
        }
        if notify:
            item["notify"] = notify
        out.append(item)

    return out


def _build_managed_links_var(
    managed_links: List[Dict[str, Any]],
    *,
    notify_other=None,
) -> List[Dict[str, Any]]:
    """Convert enroll managed_links into an Ansible-friendly list of dicts."""
    out: List[Dict[str, Any]] = []
    for ml in managed_links or []:
        dest = ml.get("path") or ""
        src = ml.get("target") or ""
        if not dest or not src:
            continue
        notifications = (
            list(notify_other)
            if isinstance(notify_other, (list, tuple))
            else ([notify_other] if notify_other else [])
        )
        if str(dest).startswith("/etc/systemd/system/"):
            notifications.insert(0, "Run systemd daemon-reload")
        out.append({"dest": dest, "src": src, "notify": notifications})
    return out


def _normalise_container_image_item(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        out = dict(item)
    else:
        out = {"pull_ref": str(item)}
    out.setdefault("engine", "docker")
    out.setdefault("scope", "system")
    out.setdefault("user", None)
    out.setdefault("home", None)
    out.setdefault("repo_tags", [])
    out.setdefault("repo_digests", [])
    out.setdefault("tag_aliases", [])
    out.setdefault("notes", [])
    return out


# --- Container image role renderer ---
_CONTAINER_COLLECTIONS = [
    {"name": "community.docker", "version": ">=4.0.0"},
    {"name": "containers.podman", "version": ">=1.20.0"},
]


def _render_container_images_role(
    ctx: AnsibleManifestContext,
    container_images_snapshot: Dict[str, Any],
) -> Optional[str]:
    raw_images = container_images_snapshot.get("images", []) or []
    if not container_images_snapshot and not raw_images:
        return

    arole = AnsibleRole(container_images_snapshot.get("role_name", "container_images"))
    arole.add_container_images_snapshot(container_images_snapshot)
    if not arole.container_images and not arole.notes:
        return

    _ensure_requirements_yaml(
        os.path.join(ctx.out_dir, "requirements.yml"), _CONTAINER_COLLECTIONS
    )

    vars_map = {"container_images": arole.container_images}
    tasks = """---

- name: Pull Docker images by immutable registry digest
  community.docker.docker_image_pull:
    name: "{{ item.pull_ref }}"
    pull: not_present
    platform: "{{ item.platform | default(omit, true) }}"
  loop: "{{ container_images | default([]) | selectattr('engine', 'equalto', 'docker') | selectattr('pull_ref') | list }}"
  when:
    - item.pull_ref | default('', true) | length > 0
  become: true

- name: Tag Docker images with harvested tag aliases
  community.docker.docker_image_tag:
    name: "{{ item.0.pull_ref }}"
    repository:
      - "{{ item.1.ref }}"
  loop: "{{ query('subelements', container_images | default([]) | selectattr('engine', 'equalto', 'docker') | selectattr('pull_ref') | list, 'tag_aliases', {'skip_missing': True}) }}"
  when:
    - item.0.pull_ref | default('', true) | length > 0
    - item.1.repository | default('', true) | length > 0
    - item.1.tag | default('', true) | length > 0
  become: true

- name: Pull system Podman images by immutable registry digest
  containers.podman.podman_image:
    name: "{{ item.pull_ref }}"
    state: present
    force: false
    platform: "{{ item.platform | default(omit, true) }}"
  loop: "{{ container_images | default([]) | selectattr('engine', 'equalto', 'podman') | rejectattr('scope', 'equalto', 'user') | selectattr('pull_ref') | list }}"
  when:
    - item.pull_ref | default('', true) | length > 0
  become: true

- name: Tag system Podman images with harvested tag aliases
  containers.podman.podman_tag:
    image: "{{ item.0.pull_ref }}"
    target_names:
      - "{{ item.1.ref }}"
  loop: "{{ query('subelements', container_images | default([]) | selectattr('engine', 'equalto', 'podman') | rejectattr('scope', 'equalto', 'user') | selectattr('pull_ref') | list, 'tag_aliases', {'skip_missing': True}) }}"
  when:
    - item.0.pull_ref | default('', true) | length > 0
    - item.1.ref | default('', true) | length > 0
  become: true

- name: Pull user Podman images by immutable registry digest
  containers.podman.podman_image:
    name: "{{ item.pull_ref }}"
    state: present
    force: false
    platform: "{{ item.platform | default(omit, true) }}"
  loop: "{{ container_images | default([]) | selectattr('engine', 'equalto', 'podman') | selectattr('scope', 'equalto', 'user') | selectattr('pull_ref') | list }}"
  when:
    - item.pull_ref | default('', true) | length > 0
    - item.user | default('', true) | length > 0
  become: true
  become_user: "{{ item.user }}"

- name: Tag user Podman images with harvested tag aliases
  containers.podman.podman_tag:
    image: "{{ item.0.pull_ref }}"
    target_names:
      - "{{ item.1.ref }}"
  loop: "{{ query('subelements', container_images | default([]) | selectattr('engine', 'equalto', 'podman') | selectattr('scope', 'equalto', 'user') | selectattr('pull_ref') | list, 'tag_aliases', {'skip_missing': True}) }}"
  when:
    - item.0.pull_ref | default('', true) | length > 0
    - item.0.user | default('', true) | length > 0
    - item.1.ref | default('', true) | length > 0
  become: true
  become_user: "{{ item.0.user }}"
"""
    return _write_ansible_role(
        ctx,
        arole.role_name,
        vars_map=vars_map,
        tasks=_render_role_tasks(arole, extra_tasks=tasks),
        collections=["community.docker", "containers.podman"],
    )


# --- Desktop package role renderers ---
def _render_flatpak_role(
    ctx: AnsibleManifestContext,
    flatpak_snapshot: Dict[str, Any],
) -> Optional[str]:
    if not flatpak_snapshot:
        return

    arole = AnsibleRole(flatpak_snapshot.get("role_name", "flatpak"))
    arole.add_flatpak_snapshot(flatpak_snapshot)

    _ensure_requirements_yaml(os.path.join(ctx.out_dir, "requirements.yml"))
    vars_map = {
        "flatpak_system_flatpaks": arole.flatpaks,
        "flatpak_remotes": arole.flatpak_remotes,
    }
    tasks = """---

- name: Ensure system Flatpak remotes exist
  ansible.builtin.command:
    argv:
      - flatpak
      - remote-add
      - --system
      - --if-not-exists
      - "{{ item.name }}"
      - "{{ item.url }}"
  loop: "{{ flatpak_remotes | default([]) }}"
  when:
    - item.name is defined
    - item.url is defined
    - item.url | length > 0
  become: true
  changed_when: false

- name: Install system-wide Flatpaks
  community.general.flatpak:
    name:
      - "{{ item.name }}"
    state: present
    method: system
    remote: "{{ item.remote | default(omit) }}"
    from_url: "{{ item.from_url | default(omit) }}"
  loop: "{{ flatpak_system_flatpaks | default([]) }}"
  when:
    - item.name is defined
    - item.name | length > 0
  become: true
"""
    return _write_ansible_role(
        ctx,
        arole.role_name,
        vars_map=vars_map,
        tasks=_render_role_tasks(arole, extra_tasks=tasks),
        collections=["community.general"],
    )


def _render_snap_role(
    ctx: AnsibleManifestContext,
    snap_snapshot: Dict[str, Any],
) -> Optional[str]:
    if not (
        snap_snapshot
        and (snap_snapshot.get("system_snaps") or snap_snapshot.get("notes"))
    ):
        return

    arole = AnsibleRole(snap_snapshot.get("role_name", "snap"))
    arole.add_snap_snapshot(snap_snapshot)
    if not (arole.snaps or arole.notes):
        return

    _ensure_requirements_yaml(os.path.join(ctx.out_dir, "requirements.yml"))
    vars_map = {"snap_system_snaps": arole.snaps}
    tasks = """---

- name: Install system-wide snaps with full detected attributes
  community.general.snap:
    name:
      - "{{ item.name }}"
    state: present
    channel: "{{ item.channel | default(omit) if not (item.install_revision | default(false)) else omit }}"
    revision: "{{ item.revision | default(omit) if (item.install_revision | default(false)) else omit }}"
    classic: "{{ item.classic | default(false) }}"
    devmode: "{{ item.devmode | default(false) }}"
    dangerous: "{{ item.dangerous | default(false) }}"
  loop: "{{ snap_system_snaps | default([]) }}"
  when:
    - item.name is defined
    - item.name | length > 0
  become: true
"""
    return _write_ansible_role(
        ctx,
        arole.role_name,
        vars_map=vars_map,
        tasks=_render_role_tasks(arole, extra_tasks=tasks),
        collections=["community.general"],
    )


# --- Managed-file role renderers ---
@dataclass(frozen=True)
class AnsibleManagedFileRoleSpec:
    """Declarative managed-file singleton role rendering spec."""

    key: str
    default_role: str
    category: str
    notify_systemd: Optional[str] = None
    handlers: str = "---\n"
    include_dirs_when_empty: bool = False


_SYSTEMD_DAEMON_RELOAD_HANDLER = """---
- name: Run systemd daemon-reload
  ansible.builtin.systemd:
    daemon_reload: true
  no_log: "{{ enroll_hide_systemd_status | default(true) | bool }}"
  when: enroll_manage_systemd_runtime | default(true) | bool
"""


MANAGED_FILE_ROLE_SPECS: Tuple[AnsibleManagedFileRoleSpec, ...] = (
    AnsibleManagedFileRoleSpec(
        key="apt_config",
        default_role="apt_config",
        category="apt_config",
    ),
    AnsibleManagedFileRoleSpec(
        key="dnf_config",
        default_role="dnf_config",
        category="dnf_config",
    ),
    AnsibleManagedFileRoleSpec(
        key="etc_custom",
        default_role="etc_custom",
        category="etc_custom",
        notify_systemd="Run systemd daemon-reload",
        handlers=_SYSTEMD_DAEMON_RELOAD_HANDLER,
    ),
    AnsibleManagedFileRoleSpec(
        key="usr_local_custom",
        default_role="usr_local_custom",
        category="usr_local_custom",
    ),
    AnsibleManagedFileRoleSpec(
        key="extra_paths",
        default_role="extra_paths",
        category="extra_paths",
        include_dirs_when_empty=True,
    ),
)


def _managed_file_role_has_resources(
    snapshot: Dict[str, Any], spec: AnsibleManagedFileRoleSpec
) -> bool:
    if not snapshot:
        return False
    if snapshot.get("managed_files"):
        return True
    return bool(spec.include_dirs_when_empty and snapshot.get("managed_dirs"))


def _write_managed_files_role_from_spec(
    ctx: AnsibleManifestContext,
    snapshot: Dict[str, Any],
    spec: AnsibleManagedFileRoleSpec,
) -> str:
    role = _write_managed_files_role(
        snapshot=snapshot,
        default_role=spec.default_role,
        bundle_dir=ctx.bundle_dir,
        roles_root=ctx.roles_root,
        out_dir=ctx.out_dir,
        jt_exe=ctx.jt_exe,
        jt_enabled=ctx.jt_enabled,
        notify_systemd=spec.notify_systemd,
        handlers=spec.handlers,
    )
    return role


def _write_managed_files_role(
    *,
    snapshot: Dict[str, Any],
    default_role: str,
    bundle_dir: str,
    roles_root: str,
    out_dir: str,
    jt_exe: Optional[str],
    jt_enabled: bool,
    notify_systemd: Optional[str],
    handlers: str,
) -> str:
    """Render an Ansible role whose main purpose is managed files/dirs.

    This covers apt_config, dnf_config, etc_custom, usr_local_custom, and
    extra_paths. Their harvested state shape is the same; only optional
    handlers differ.
    """

    role = snapshot.get("role_name", default_role)
    role_dir = os.path.join(roles_root, role)
    _write_role_scaffold(role_dir)

    var_prefix = role
    managed_files = snapshot.get("managed_files", []) or []
    managed_dirs = snapshot.get("managed_dirs", []) or []
    templated, jt_vars = _jinjify_managed_files(
        bundle_dir,
        role,
        os.path.join(role_dir, "templates"),
        managed_files,
        jt_exe=jt_exe,
        jt_enabled=jt_enabled,
        overwrite_templates=True,
    )

    _copy_artifacts(
        bundle_dir,
        role,
        os.path.join(role_dir, "files"),
        exclude_rels=templated,
    )

    files_var = _build_managed_files_var(
        managed_files,
        templated,
        notify_other=None,
        notify_systemd=notify_systemd,
    )
    dirs_var = _build_managed_dirs_var(managed_dirs)

    jt_map = yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
    vars_map: Dict[str, Any] = {
        f"{var_prefix}_managed_files": files_var,
        f"{var_prefix}_managed_dirs": dirs_var,
    }
    vars_map = _merge_mappings_overwrite(vars_map, jt_map)

    _write_role_defaults(role_dir, vars_map)

    tasks = _render_role_tasks(AnsibleRole(role), managed_content=True)
    _write_generated_task_yaml(
        os.path.join(role_dir, "tasks", "main.yml"),
        tasks,
        label=f"role '{role}' tasks/main.yml",
    )
    _write_generated_task_yaml(
        os.path.join(role_dir, "handlers", "main.yml"),
        handlers,
        label=f"role '{role}' handlers/main.yml",
    )

    with open(os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8") as f:
        f.write("---\ndependencies: []\n")

    return role


def _render_managed_file_roles(
    ctx: AnsibleManifestContext,
    roles: Dict[str, Any],
) -> Dict[str, str]:
    """Render file-centric singleton roles."""

    rendered_roles: Dict[str, str] = {}
    for spec in MANAGED_FILE_ROLE_SPECS:
        snapshot = roles.get(spec.key, {})
        if not isinstance(snapshot, dict):
            continue
        if not _managed_file_role_has_resources(snapshot, spec):
            continue
        rendered_roles[spec.category] = _write_managed_files_role_from_spec(
            ctx, snapshot, spec
        )
    return rendered_roles


# --- Package and service role renderers ---
def _role_managed_content_vars(
    ctx: AnsibleManifestContext,
    role: str,
    entries: List[Dict[str, Any]],
    *,
    notify_by_kind: Optional[Dict[str, Optional[str]]] = None,
    notify_service_handlers: bool = False,
    overwrite_templates: bool,
) -> Tuple[
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    Dict[str, Any],
]:
    role_dir = os.path.join(ctx.roles_root, role)
    files_var: List[Dict[str, Any]] = []
    dirs_var: List[Dict[str, Any]] = []
    links_var: List[Dict[str, Any]] = []
    jt_combined: Dict[str, Any] = {}
    seen_files: Set[Tuple[Any, Any, Any]] = set()
    seen_dirs: Set[Tuple[Any, Any, Any, Any]] = set()
    seen_links: Set[Tuple[Any, Any]] = set()
    service_units_by_package = CMModule.active_service_units_by_package(entries)

    for entry in entries:
        kind = str(entry.get("kind") or "package")
        snap = entry.get("snapshot") or {}
        source_role = str(snap.get("role_name") or "")
        managed_files = snap.get("managed_files", []) or []
        managed_dirs = snap.get("managed_dirs", []) or []
        managed_links = snap.get("managed_links", []) or []

        templated: Set[str] = set()
        jt_vars = ""
        if managed_files and source_role:
            templated, jt_vars = _jinjify_managed_files(
                ctx.bundle_dir,
                source_role,
                os.path.join(role_dir, "templates"),
                managed_files,
                jt_exe=ctx.jt_exe,
                jt_enabled=ctx.jt_enabled,
                overwrite_templates=overwrite_templates,
            )
            _copy_role_artifacts(ctx, role, source_role, exclude_rels=templated)

        notify_other = (notify_by_kind or {}).get(kind)
        if notify_service_handlers and kind == "service":
            unit = str(snap.get("unit") or "").strip()
            if unit and str(snap.get("active_state") or "") == "active":
                # Notify the role's fixed restart topic (scaffold-safe). The
                # specific unit travels as data in <var_prefix>_restart_units;
                # it is never spliced into the handler/notify YAML text.
                notify_other = [_service_restart_listen_topic(role, unit)]
            else:
                notify_other = None
        elif notify_service_handlers and kind == "package":
            units = CMModule.active_service_units_for_package_snapshot(
                snap, service_units_by_package
            )
            notify_other = [
                _service_restart_listen_topic(role, unit) for unit in sorted(units)
            ]

        for item in _build_managed_files_var(
            managed_files,
            templated,
            notify_other=notify_other,
            notify_systemd="Run systemd daemon-reload",
        ):
            key = (item.get("dest"), item.get("src_rel"), item.get("kind"))
            if key not in seen_files:
                seen_files.add(key)
                files_var.append(item)

        for item in _build_managed_dirs_var(managed_dirs):
            key = (
                item.get("dest"),
                item.get("owner"),
                item.get("group"),
                item.get("mode"),
            )
            if key not in seen_dirs:
                seen_dirs.add(key)
                dirs_var.append(item)

        for item in _build_managed_links_var(managed_links, notify_other=notify_other):
            key = (item.get("dest"), item.get("src"))
            if key not in seen_links:
                seen_links.add(key)
                links_var.append(item)

        jt_map = yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
        jt_combined = _merge_mappings_overwrite(jt_combined, jt_map)

    return (
        sorted(files_var, key=lambda item: str(item.get("dest") or "")),
        sorted(dirs_var, key=lambda item: str(item.get("dest") or "")),
        sorted(links_var, key=lambda item: str(item.get("dest") or "")),
        jt_combined,
    )


def _resource_role_vars(
    role: AnsibleRole,
    *,
    files_var: List[Dict[str, Any]],
    dirs_var: List[Dict[str, Any]],
    links_var: List[Dict[str, Any]],
    extra_vars: Optional[Dict[str, Any]] = None,
    jt_vars: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    var_prefix = role.var_prefix
    vars_map: Dict[str, Any] = {
        f"{var_prefix}_packages": role.sorted_packages,
        f"{var_prefix}_managed_files": files_var,
        f"{var_prefix}_managed_dirs": dirs_var,
        f"{var_prefix}_managed_links": links_var,
    }
    if extra_vars:
        vars_map.update(extra_vars)
    return _merge_mappings_overwrite(vars_map, jt_vars or {})


def _single_service_extra_vars(role: AnsibleRole) -> Dict[str, Any]:
    var_prefix = role.var_prefix
    unit = next(iter(role.services), "")
    unit_state = role.services.get(unit, {})
    return {
        f"{var_prefix}_unit_name": unit,
        f"{var_prefix}_manage_unit": bool(unit),
        f"{var_prefix}_systemd_enabled": bool(unit_state.get("enabled")),
        f"{var_prefix}_systemd_state": str(unit_state.get("state") or "stopped"),
    }


def _write_resource_ansible_role(
    ctx: AnsibleManifestContext,
    role: AnsibleRole,
    *,
    notify_by_kind: Dict[str, Optional[str]],
    overwrite_templates: bool,
    extra_vars: Optional[Dict[str, Any]] = None,
    single_service: bool = False,
    grouped_services: bool = False,
    restart_grouped_services: bool = False,
    notify_service_handlers: bool = False,
    systemd_reload: bool = False,
) -> str:
    files_var, dirs_var, links_var, jt_vars = _role_managed_content_vars(
        ctx,
        role.role_name,
        role.entries,
        notify_by_kind=notify_by_kind,
        notify_service_handlers=notify_service_handlers,
        overwrite_templates=overwrite_templates,
    )
    vars_map = _resource_role_vars(
        role,
        files_var=files_var,
        dirs_var=dirs_var,
        links_var=links_var,
        extra_vars=extra_vars,
        jt_vars=jt_vars,
    )
    return _write_ansible_role(
        ctx,
        role.role_name,
        vars_map=vars_map,
        tasks=_render_role_tasks(
            role,
            packages=True,
            managed_content=True,
            single_service=single_service,
            grouped_services=grouped_services,
        ),
        handlers=_render_role_handlers(
            role,
            systemd_reload=systemd_reload,
            single_service=single_service,
            grouped_services=grouped_services,
            restart_grouped_services=restart_grouped_services,
        ),
    )


def _render_service_roles(
    ctx: AnsibleManifestContext,
    services_to_manifest: List[Dict[str, Any]],
) -> List[str]:
    rendered_roles: List[str] = []
    for svc in services_to_manifest:
        source_role = str(svc.get("role_name") or svc.get("unit") or "service")
        role_name = avoid_reserved_role_name(source_role, prefix="service")
        role = AnsibleRole(role_name)
        role.add_service_snapshot(svc)
        _write_resource_ansible_role(
            ctx,
            role,
            notify_by_kind={"service": f"Restart service for {role.var_prefix}"},
            overwrite_templates=True,
            extra_vars=_single_service_extra_vars(role),
            single_service=True,
        )
        _add_role(rendered_roles, role.role_name)
    return rendered_roles


def _render_common_ansible_roles(
    ctx: AnsibleManifestContext,
    common_role_groups: Dict[str, List[Dict[str, Any]]],
    package_roles: List[Dict[str, Any]],
    occupied_role_names: Set[str],
) -> Tuple[List[str], List[str]]:
    rendered_roles: List[str] = []
    common_tail_roles: List[str] = []
    occupied_roles: Set[str] = set(occupied_role_names)
    for pr in package_roles:
        occupied_roles.add(
            avoid_reserved_role_name(str(pr.get("role_name") or ""), prefix="package")
        )

    for section_label, entries in sorted(common_role_groups.items()):
        role_name = _section_role_name(section_label, occupied_roles)
        role = AnsibleRole(
            role_name,
            var_prefix=role_name,
            section_label=section_label,
            grouped=True,
        )
        for entry in entries:
            snap = entry.get("snapshot") or {}
            if (entry.get("kind") or "package") == "service":
                role.add_service_snapshot(snap)
            else:
                role.add_package_snapshot(snap)

        systemd_units = role.systemd_units_var
        if {"cron", "logrotate"}.intersection(role.packages):
            common_tail_roles.append(role.role_name)

        _write_resource_ansible_role(
            ctx,
            role,
            notify_by_kind={"service": None},
            overwrite_templates=True,
            extra_vars={
                f"{role.var_prefix}_systemd_units": systemd_units,
                f"{role.var_prefix}_restart_units": restart_units_for_role(role),
            },
            grouped_services=True,
            restart_grouped_services=True,
            notify_service_handlers=True,
        )
        _add_role(rendered_roles, role.role_name)

    return rendered_roles, common_tail_roles


def _render_package_roles(
    ctx: AnsibleManifestContext,
    package_roles: List[Dict[str, Any]],
) -> List[str]:
    rendered_roles: List[str] = []
    for pr in package_roles:
        source_role = str(pr.get("role_name") or pr.get("package") or "package")
        role_name = avoid_reserved_role_name(source_role, prefix="package")
        role = AnsibleRole(role_name)
        role.add_package_snapshot(pr)
        _write_resource_ansible_role(
            ctx,
            role,
            notify_by_kind={"package": None},
            overwrite_templates=True,
            systemd_reload=True,
        )
        _add_role(rendered_roles, role.role_name)
    return rendered_roles


# --- Runtime state role renderers ---
def _render_sysctl_role(
    ctx: AnsibleManifestContext,
    sysctl_snapshot: Dict[str, Any],
) -> Optional[str]:
    if not (sysctl_snapshot and (sysctl_snapshot.get("managed_files") or [])):
        return

    role = sysctl_snapshot.get("role_name", "sysctl")
    managed_files = sysctl_snapshot.get("managed_files", []) or []
    conf_src_rel = ""
    for mf in managed_files:
        if mf.get("path") == "/etc/sysctl.d/99-enroll.conf":
            conf_src_rel = mf.get("src_rel") or ""
            break
    if not conf_src_rel and managed_files:
        conf_src_rel = managed_files[0].get("src_rel") or ""

    _write_role_scaffold(os.path.join(ctx.roles_root, role))
    _copy_role_artifacts(ctx, role, role)

    var_prefix = role
    vars_map: Dict[str, Any] = {
        f"{var_prefix}_conf_src_rel": conf_src_rel,
        f"{var_prefix}_apply": True,
        f"{var_prefix}_ignore_apply_errors": True,
    }
    return _write_ansible_role(
        ctx,
        role,
        vars_map=vars_map,
        tasks=_render_role_tasks(AnsibleRole(role), sysctl=True),
        handlers=_render_role_handlers(AnsibleRole(role), sysctl=True),
    )


def _render_enroll_runtime_role(ctx: AnsibleManifestContext) -> str:
    tasks = """---
- name: Ensure Enroll runtime directory exists
  ansible.builtin.file:
    path: /etc/enroll
    state: directory
    owner: root
    group: root
    mode: "0750"
"""
    return _write_ansible_role(
        ctx,
        "enroll_runtime",
        tasks=_render_role_tasks(AnsibleRole("enroll_runtime"), extra_tasks=tasks),
    )


def _render_firewall_runtime_role(
    ctx: AnsibleManifestContext,
    firewall_runtime_snapshot: Dict[str, Any],
) -> Optional[str]:
    role = firewall_runtime_snapshot.get("role_name", "firewall_runtime")
    arole = AnsibleRole(role)
    if not arole.firewall_runtime_snapshot_has_artifacts(firewall_runtime_snapshot):
        return
    arole.add_firewall_runtime_snapshot(firewall_runtime_snapshot)
    _write_role_scaffold(os.path.join(ctx.roles_root, role))
    _copy_role_artifacts(ctx, role, role)

    var_prefix = role
    packages = list(arole.package_names_from_snapshot(firewall_runtime_snapshot))
    refs = arole.firewall_runtime
    ipset_save = refs.get("ipset_save", "")
    ipset_sets = refs.get("ipset_sets", []) or []
    iptables_v4_save = refs.get("iptables_v4_save", "")
    iptables_v6_save = refs.get("iptables_v6_save", "")
    vars_map: Dict[str, Any] = {
        f"{var_prefix}_packages": packages,
        f"{var_prefix}_ipset_save": ipset_save,
        f"{var_prefix}_ipset_sets": ipset_sets,
        f"{var_prefix}_iptables_v4_save": iptables_v4_save,
        f"{var_prefix}_iptables_v6_save": iptables_v6_save,
        f"{var_prefix}_sync_ipsets_exact": True,
        f"{var_prefix}_restore_iptables": True,
    }
    return _write_ansible_role(
        ctx,
        role,
        vars_map=vars_map,
        tasks=_render_role_tasks(arole, packages=True, firewall_runtime=True),
        handlers=_render_role_handlers(arole, firewall_runtime=True),
    )


# --- User role renderer ---
def _render_users_role(
    ctx: AnsibleManifestContext,
    users_snapshot: Dict[str, Any],
) -> Optional[str]:
    if not users_snapshot:
        return

    role = users_snapshot.get("role_name", "users")
    arole = AnsibleRole(role)
    arole.add_users_snapshot(users_snapshot)

    _write_role_scaffold(os.path.join(ctx.roles_root, role))
    _copy_role_artifacts(ctx, role, role)

    users_needs_community = bool(arole.flatpak_remotes or arole.flatpaks)
    if users_needs_community:
        _ensure_requirements_yaml(os.path.join(ctx.out_dir, "requirements.yml"))

    vars_map = {
        "users_groups": arole.users_groups,
        "users_users": arole.users_data,
        "users_ssh_dirs": arole.users_ssh_dirs,
        "users_ssh_files": arole.users_ssh_files,
        "users_flatpaks": arole.flatpaks,
        "users_flatpak_remotes": arole.flatpak_remotes,
    }

    users_tasks = """---

- name: Ensure groups exist
  ansible.builtin.group:
    name: "{{ item }}"
    state: present
  loop: "{{ users_groups | default([]) }}"

- name: Ensure users exist
  ansible.builtin.user:
    name: "{{ item.name }}"
    uid: "{{ item.uid | default(omit) }}"
    group: "{{ item.primary_group }}"
    home: "{{ item.home }}"
    create_home: true
    shell: "{{ item.shell | default(omit) }}"
    comment: "{{ item.gecos | default(omit) }}"
    state: present
  loop: "{{ users_users | default([]) }}"

- name: Ensure users supplementary groups
  ansible.builtin.user:
    name: "{{ item.name }}"
    groups: "{{ item.supplementary_groups | default([]) | join(',') }}"
    append: true
  loop: "{{ users_users | default([]) }}"
  when: (item.supplementary_groups | default([])) | length > 0

- name: Ensure .ssh directories exist for managed SSH files
  ansible.builtin.file:
    path: "{{ item.dest }}"
    state: directory
    owner: "{{ item.owner }}"
    group: "{{ item.group }}"
    mode: "{{ item.mode }}"
  loop: "{{ users_ssh_dirs | default([]) }}"

- name: Deploy user-managed files
  vars:
    _enroll_ff:
      files:
        - "{{ role_path }}/files/{{ item.src_rel }}"
  ansible.builtin.copy:
    src: "{{ lookup('ansible.builtin.first_found', _enroll_ff) }}"
    dest: "{{ item.dest }}"
    owner: "{{ item.owner }}"
    group: "{{ item.group }}"
    mode: "{{ item.mode }}"
  loop: "{{ users_ssh_files | default([]) }}"
"""

    if users_needs_community:
        users_tasks += """
- name: Ensure user Flatpak remotes exist
  ansible.builtin.command:
    argv:
      - flatpak
      - remote-add
      - --user
      - --if-not-exists
      - "{{ item.name }}"
      - "{{ item.url }}"
  loop: "{{ users_flatpak_remotes | default([]) | selectattr('method', 'equalto', 'user') | list }}"
  when:
    - item.name is defined
    - item.url is defined
    - item.url | length > 0
    - item.user is defined
  become: true
  become_user: "{{ item.user }}"
  environment:
    HOME: "{{ item.home | default('/home/' ~ item.user, true) }}"
    XDG_DATA_HOME: "{{ (item.home | default('/home/' ~ item.user, true)) ~ '/.local/share' }}"
  changed_when: false

- name: Install user Flatpaks
  community.general.flatpak:
    name:
      - "{{ item.name }}"
    state: present
    method: user
    remote: "{{ item.remote | default(omit) }}"
    from_url: "{{ item.from_url | default(omit) }}"
  loop: "{{ users_flatpaks | default([]) }}"
  when:
    - item.name is defined
    - item.name | length > 0
    - item.user is defined
  become: true
  become_user: "{{ item.user }}"
  environment:
    HOME: "{{ item.home | default('/home/' ~ item.user, true) }}"
    XDG_DATA_HOME: "{{ (item.home | default('/home/' ~ item.user, true)) ~ '/.local/share' }}"
"""

    return _write_ansible_role(
        ctx,
        role,
        vars_map=vars_map,
        tasks=_render_role_tasks(arole, extra_tasks=users_tasks),
        collections=["community.general"] if users_needs_community else None,
    )


class AnsibleManifestRenderer:
    """Render Ansible roles and playbook from a harvest bundle."""

    def __init__(
        self,
        bundle_dir: str,
        out_dir: str,
        *,
        jinjaturtle: Optional[bool] = None,
        no_common_roles: bool = False,
    ) -> None:
        self.bundle_dir = bundle_dir
        self.out_dir = out_dir
        self.jinjaturtle = jinjaturtle
        self.no_common_roles = no_common_roles

    def render(self) -> None:
        state = AnsibleRole.load_state(self.bundle_dir)
        roles = roles_from_state(state)
        inventory_packages = inventory_packages_from_state(state)

        ctx = _prepare_ansible_context(
            self.bundle_dir,
            self.out_dir,
            jinjaturtle=self.jinjaturtle,
        )
        _write_scaffold(ctx)

        use_common_roles = not self.no_common_roles
        services_to_manifest, package_roles, common_role_groups = (
            _collect_ansible_roles(
                roles,
                inventory_packages,
                use_common_roles=use_common_roles,
            )
        )

        # Render the concrete roles, then derive playbook order from the role
        # names actually written.
        managed_roles = _render_managed_file_roles(ctx, roles)
        users_role = _render_users_role(ctx, roles.get("users", {}))
        flatpak_role = _render_flatpak_role(ctx, roles.get("flatpak", {}))
        snap_role = _render_snap_role(ctx, roles.get("snap", {}))
        container_role = _render_container_images_role(
            ctx, roles.get("container_images", {})
        )
        sysctl_role = _render_sysctl_role(ctx, roles.get("sysctl", {}))
        firewall_role = _render_firewall_runtime_role(
            ctx, roles.get("firewall_runtime", {})
        )
        enroll_runtime_role = (
            _render_enroll_runtime_role(ctx) if firewall_role else None
        )
        service_roles = _render_service_roles(ctx, services_to_manifest)

        occupied_role_names = set(managed_roles.values())
        for role in (
            users_role,
            flatpak_role,
            snap_role,
            container_role,
            sysctl_role,
            firewall_role,
            enroll_runtime_role,
        ):
            if role:
                occupied_role_names.add(role)
        occupied_role_names.update(service_roles)

        common_roles, common_tail_roles = _render_common_ansible_roles(
            ctx, common_role_groups, package_roles, occupied_role_names
        )
        standalone_package_roles = _render_package_roles(ctx, package_roles)

        rendered_roles: List[str] = []
        for category in ("apt_config", "dnf_config"):
            _add_role(rendered_roles, managed_roles.get(category))
        _add_roles(rendered_roles, common_roles)
        _add_roles(rendered_roles, standalone_package_roles)
        _add_roles(rendered_roles, service_roles)
        for category in ("etc_custom", "usr_local_custom", "extra_paths"):
            _add_role(rendered_roles, managed_roles.get(category))
        for role in (flatpak_role, snap_role, container_role, users_role):
            _add_role(rendered_roles, role)

        # Keep the old safety rule without a plan class: packages that restore
        # per-user cron/logrotate state should run after the users role.
        ordered_roles = _ordered_playbook_roles(
            rendered_roles, ["cron", "logrotate"] + common_tail_roles
        )
        for role in (enroll_runtime_role, sysctl_role, firewall_role):
            _add_role(ordered_roles, role)

        _write_manifest_playbook(ctx, ordered_roles)
        Path(ctx.out_dir, "README.md").write_text(
            _render_readme(state, ordered_roles),
            encoding="utf-8",
        )


def manifest_from_bundle_dir(
    bundle_dir: str,
    out_dir: str,
    *,
    jinjaturtle: Optional[bool] = None,
    no_common_roles: bool = False,
) -> None:
    AnsibleManifestRenderer(
        bundle_dir,
        out_dir,
        jinjaturtle=jinjaturtle,
        no_common_roles=no_common_roles,
    ).render()
