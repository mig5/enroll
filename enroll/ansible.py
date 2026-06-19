from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .cm import CMModule, package_section_label, section_label_for_packages
from .jinjaturtle import (
    jinjify_managed_files as _jinjify_managed_files,
    resolve_jinjaturtle_mode,
)
from .role_names import avoid_reserved_role_name
from .state import inventory_packages_from_state, roles_from_state
from .yamlutil import yaml_dump_mapping, yaml_load_mapping


@dataclass
class AnsibleManifestContext:
    bundle_dir: str
    out_dir: str
    roles_root: str
    fqdn: Optional[str]
    site_mode: bool
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
    """Collect the raw Ansible role inputs from harvest state."""
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
        return [], [], common_role_groups

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
    fqdn: Optional[str],
    jinjaturtle: str,
) -> AnsibleManifestContext:
    site_mode = fqdn is not None and fqdn != ""
    jt_exe, jt_enabled = resolve_jinjaturtle_mode(jinjaturtle)

    os.makedirs(out_dir, exist_ok=True)
    roles_root = os.path.join(out_dir, "roles")
    os.makedirs(roles_root, exist_ok=True)

    return AnsibleManifestContext(
        bundle_dir=bundle_dir,
        out_dir=out_dir,
        roles_root=roles_root,
        fqdn=fqdn,
        site_mode=site_mode,
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
        shutil.copy2(src, tmp)

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

    In non --fqdn mode, this is usually <role_dir>/files.
    In --fqdn site mode, this is usually:
      inventory/host_vars/<fqdn>/<role>/.files
    """
    artifacts_dir = os.path.join(bundle_dir, "artifacts", role)
    if not os.path.isdir(artifacts_dir):
        return
    for root, _, files in os.walk(artifacts_dir):
        for fn in files:
            src = os.path.join(root, fn)
            rel = os.path.relpath(src, artifacts_dir)
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
            _copy2_replace(src, dst)


def _write_role_scaffold(role_dir: str) -> None:
    os.makedirs(os.path.join(role_dir, "tasks"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "handlers"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "defaults"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "meta"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "files"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "templates"), exist_ok=True)


def _role_tag(role: str) -> str:
    """Return a stable Ansible tag name for a role.

    Used by `enroll diff --enforce` to run only the roles needed to repair drift.
    """
    r = str(role or "").strip()
    # Ansible tag charset is fairly permissive, but keep it portable and consistent.
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", r).strip("_")
    if not safe:
        safe = "other"
    return f"role_{safe}"


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
        pb_lines.append(f"    - role: {r}")
        pb_lines.append(f"      tags: [{_role_tag(r)}]")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(pb_lines) + "\n")


def _write_playbook_host(path: str, fqdn: str, roles: List[str]) -> None:
    pb_lines = [
        "---",
        f"- name: Apply all roles on {fqdn}",
        f"  hosts: {fqdn}",
        "  gather_facts: true",
        "  become: true",
        "  roles:",
    ]
    for r in roles:
        pb_lines.append(f"    - role: {r}")
        pb_lines.append(f"      tags: [{_role_tag(r)}]")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(pb_lines) + "\n")


def _ensure_ansible_cfg(cfg_path: str) -> None:
    if not os.path.exists(cfg_path):
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("[defaults]\n")
            f.write("roles_path = roles\n")
            f.write("interpreter_python=/usr/bin/python3\n")
            f.write("inventory = inventory\n")
            f.write("stdout_callback = unixy\n")
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


def _ensure_inventory_host(inv_path: str, fqdn: str) -> None:
    os.makedirs(os.path.dirname(inv_path), exist_ok=True)
    if not os.path.exists(inv_path):
        with open(inv_path, "w", encoding="utf-8") as f:
            f.write("[all]\n")
            f.write(fqdn + "\n")
        return

    with open(inv_path, "r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f.readlines()]

    # ensure there is an [all] group; if not, create it at top
    if not any(ln.strip() == "[all]" for ln in lines):
        lines = ["[all]"] + lines

    # check if fqdn already present (exact match, ignoring whitespace)
    if any(ln.strip() == fqdn for ln in lines):
        return

    # append at end
    lines.append(fqdn)
    with open(inv_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _hostvars_path(site_root: str, fqdn: str, role: str) -> str:
    return os.path.join(site_root, "inventory", "host_vars", fqdn, f"{role}.yml")


def _host_role_files_dir(site_root: str, fqdn: str, role: str) -> str:
    """Host-specific files dir for a given role.

    Layout:
      inventory/host_vars/<fqdn>/<role>/.files/
    """
    return os.path.join(site_root, "inventory", "host_vars", fqdn, role, ".files")


def _write_hostvars(site_root: str, fqdn: str, role: str, data: Dict[str, Any]) -> None:
    """Write host_vars YAML for a role for a specific host.

    This is host-specific state and should track the current harvest output.
    Existing keys not mentioned in `data` are preserved, but keys in `data`
    are overwritten (including list values).
    """
    path = _hostvars_path(site_root, fqdn, role)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    existing_map: Dict[str, Any] = {}
    if os.path.exists(path):
        try:
            existing_text = Path(path).read_text(encoding="utf-8")
            existing_map = yaml_load_mapping(existing_text)
        except Exception:
            existing_map = {}

    merged = _merge_mappings_overwrite(existing_map, data)

    out = "---\n" + yaml_dump_mapping(merged, sort_keys=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)


def _write_role_defaults(role_dir: str, mapping: Dict[str, Any]) -> None:
    """Overwrite role defaults/main.yml with the provided mapping."""
    defaults_path = os.path.join(role_dir, "defaults", "main.yml")
    os.makedirs(os.path.dirname(defaults_path), exist_ok=True)
    out = "---\n" + yaml_dump_mapping(mapping, sort_keys=True)
    with open(defaults_path, "w", encoding="utf-8") as f:
        f.write(out)


def _write_site_scaffold(ctx: AnsibleManifestContext) -> None:
    if not ctx.site_mode:
        return
    os.makedirs(os.path.join(ctx.out_dir, "inventory"), exist_ok=True)
    os.makedirs(os.path.join(ctx.out_dir, "inventory", "host_vars"), exist_ok=True)
    os.makedirs(os.path.join(ctx.out_dir, "playbooks"), exist_ok=True)
    _ensure_inventory_host(
        os.path.join(ctx.out_dir, "inventory", "hosts.ini"), ctx.fqdn or ""
    )
    _ensure_ansible_cfg(os.path.join(ctx.out_dir, "ansible.cfg"))
    _ensure_requirements_yaml(os.path.join(ctx.out_dir, "requirements.yml"))


def _write_manifest_playbook(ctx: AnsibleManifestContext, roles: List[str]) -> None:
    if ctx.site_mode:
        _write_playbook_host(
            os.path.join(ctx.out_dir, "playbooks", f"{ctx.fqdn}.yml"),
            ctx.fqdn or "",
            roles,
        )
    else:
        _write_playbook_all(os.path.join(ctx.out_dir, "playbook.yml"), roles)


# --- Ansible task snippets ---
def _render_generic_files_tasks(var_prefix: str) -> str:
    """Render generic tasks to deploy <var_prefix>_managed_files safely."""
    # Using first_found makes roles work in both modes:
    # - site-mode: inventory/host_vars/<host>/<role>/.files/...
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
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ item.src_rel }}}}"
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

- name: Reload systemd to pick up unit changes
  ansible.builtin.meta: flush_handlers
  when: >-
    ({var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', true)
      | list
      | length) > 0

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
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ item.src_rel }}}}"
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
"""


def _render_install_packages_tasks(role: str, var_prefix: str) -> str:
    """Render package installation through Ansible's generic package provider."""

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
  when: item.manage | default(false)

- name: Ensure grouped unit enablement matches harvest
  ansible.builtin.systemd:
    name: "{{{{ item.item.name }}}}"
    enabled: "{{{{ item.item.enabled | bool }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  loop: "{{{{ _enroll_unit_probes.results | default([]) }}}}"
  when:
    - item.item.manage | default(false)
    - not (item.failed | default(false))

- name: Ensure grouped unit running state matches harvest
  ansible.builtin.systemd:
    name: "{{{{ item.item.name }}}}"
    state: "{{{{ item.item.state }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  loop: "{{{{ _enroll_unit_probes.results | default([]) }}}}"
  when:
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
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ {var_prefix}_conf_src_rel }}}}"
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


def _render_firewall_runtime_tasks(var_prefix: str) -> str:
    """Render tasks for live ipset/iptables snapshots."""
    return f"""- name: Ensure firewall runtime snapshot directory exists
  ansible.builtin.file:
    path: /etc/enroll/firewall
    state: directory
    owner: root
    group: root
    mode: "0750"

- name: Deploy captured ipset snapshot
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ {var_prefix}_ipset_save }}}}"
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_ipset_save }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: /etc/enroll/firewall/ipset.save
    owner: root
    group: root
    mode: "0600"
  notify: Restore captured ipsets
  when: ({var_prefix}_ipset_save | default('') | length) > 0

- name: Deploy captured IPv4 iptables snapshot
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ {var_prefix}_iptables_v4_save }}}}"
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_iptables_v4_save }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: /etc/enroll/firewall/iptables.v4
    owner: root
    group: root
    mode: "0600"
  notify: Restore captured IPv4 iptables rules
  when: ({var_prefix}_iptables_v4_save | default('') | length) > 0

- name: Deploy captured IPv6 iptables snapshot
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ {var_prefix}_iptables_v6_save }}}}"
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_iptables_v6_save }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: /etc/enroll/firewall/iptables.v6
    owner: root
    group: root
    mode: "0600"
  notify: Restore captured IPv6 iptables rules
  when: ({var_prefix}_iptables_v6_save | default('') | length) > 0
"""


def _render_firewall_runtime_handlers(var_prefix: str) -> str:
    """Render handlers for live ipset/iptables snapshots.

    Runtime firewall snapshots are intentionally applied only when Enroll's
    staged snapshot file changes. Live iptables/ipset state is volatile, and
    daemons such as Docker may mutate counters/chains between configuration
    management runs. Treating restore as a file-change handler keeps repeated
    Ansible runs idempotent while still applying a new harvested snapshot.
    """
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
  ansible.builtin.shell: "ipset restore -exist < /etc/enroll/firewall/ipset.save"
  args:
    executable: /bin/sh
  listen: Restore captured ipsets
  when: ({var_prefix}_ipset_save | default('') | length) > 0

- name: Restore captured IPv4 iptables rules
  ansible.builtin.command:
    cmd: iptables-restore /etc/enroll/firewall/iptables.v4
  listen: Restore captured IPv4 iptables rules
  when:
    - ({var_prefix}_iptables_v4_save | default('') | length) > 0
    - {var_prefix}_restore_iptables | default(true) | bool

- name: Restore captured IPv6 iptables rules
  ansible.builtin.command:
    cmd: ip6tables-restore /etc/enroll/firewall/iptables.v6
  listen: Restore captured IPv6 iptables rules
  when:
    - ({var_prefix}_iptables_v6_save | default('') | length) > 0
    - {var_prefix}_restore_iptables | default(true) | bool
"""


# --- Ansible variable builders ---
def _normalise_flatpak_item(
    item: Any,
    *,
    method: str,
    user: Optional[str] = None,
    home: Optional[str] = None,
) -> Dict[str, Any]:
    if isinstance(item, str):
        out: Dict[str, Any] = {"name": item, "method": method}
    elif isinstance(item, dict):
        out = dict(item)
        out.setdefault("method", method)
    else:
        out = {"name": str(item), "method": method}
    if user:
        out.setdefault("user", user)
    if home:
        out.setdefault("home", home)
    return out


def _normalise_flatpak_remote(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        out = dict(item)
    else:
        out = {"name": str(item)}
    out.setdefault("method", "system")
    return out


def _normalise_snap_item(item: Any) -> Dict[str, Any]:
    if isinstance(item, str):
        out: Dict[str, Any] = {"name": item}
    elif isinstance(item, dict):
        out = dict(item)
    else:
        out = {"name": str(item)}

    notes = out.get("notes") or []
    if isinstance(notes, str):
        notes = [notes]
    notes_l = {str(n).lower() for n in notes}
    out["classic"] = bool(out.get("classic") or "classic" in notes_l)
    out["devmode"] = bool(out.get("devmode") or "devmode" in notes_l)
    out["dangerous"] = bool(out.get("dangerous") or "dangerous" in notes_l)

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
    notify_other: Optional[str] = None,
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
        if (not is_unit) and notify_other:
            notify.append(notify_other)
        out.append(
            {
                "dest": dest,
                "src_rel": src_rel,
                "owner": mf.get("owner") or "root",
                "group": mf.get("group") or "root",
                "mode": mf.get("mode") or "0644",
                "kind": kind,
                "is_systemd_unit": bool(is_unit),
                "notify": notify,
            }
        )
    return out


def _build_managed_links_var(
    managed_links: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Convert enroll managed_links into an Ansible-friendly list of dicts."""
    out: List[Dict[str, Any]] = []
    for ml in managed_links or []:
        dest = ml.get("path") or ""
        src = ml.get("target") or ""
        if not dest or not src:
            continue
        out.append({"dest": dest, "src": src})
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


# --- Ansible README builders ---
def _markdown_list(items: List[str]) -> str:
    values = [str(item) for item in items if str(item)]
    return "\n".join(f"- {item}" for item in values) or "- (none)"


def _managed_file_lines(
    managed_files: List[Dict[str, Any]], *, include_reason: bool
) -> List[str]:
    out: List[str] = []
    for mf in managed_files:
        path = str(mf.get("path") or "")
        if not path:
            continue
        if include_reason:
            out.append(f"{path} ({mf.get('reason')})")
        else:
            out.append(path)
    return out


def _excluded_lines(excluded: List[Dict[str, Any]]) -> List[str]:
    return [f"{e.get('path')} ({e.get('reason')})" for e in excluded if e.get("path")]


def _read_artifact_lines(bundle_dir: str, role: str, src_rel: str) -> List[str]:
    art_path = os.path.join(bundle_dir, "artifacts", role, src_rel)
    try:
        with open(art_path, "r", encoding="utf-8", errors="replace") as f:
            return [line.rstrip("\n") for line in f]
    except OSError:
        return []


def _apt_config_readme(
    *,
    bundle_dir: str,
    role: str,
    snapshot: Dict[str, Any],
    managed_files: List[Dict[str, Any]],
    managed_dirs: List[Dict[str, Any]],
    excluded: List[Dict[str, Any]],
    notes: List[Any],
) -> str:
    source_paths: List[str] = []
    keyring_paths: List[str] = []
    repo_hosts: Set[str] = set()
    url_re = re.compile(r"(?:https?|ftp)://([^/\s]+)", re.IGNORECASE)

    for mf in managed_files:
        path = str(mf.get("path") or "")
        src_rel = str(mf.get("src_rel") or "")
        if not path or not src_rel:
            continue
        if path == "/etc/apt/sources.list" or path.startswith(
            "/etc/apt/sources.list.d/"
        ):
            source_paths.append(path)
            for line in _read_artifact_lines(bundle_dir, role, src_rel):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                for match in url_re.finditer(s):
                    repo_hosts.add(match.group(1))
        if (
            path.startswith("/etc/apt/trusted.gpg")
            or path.startswith("/etc/apt/keyrings/")
            or path.startswith("/usr/share/keyrings/")
        ):
            keyring_paths.append(path)

    return f"""# apt_config

APT configuration harvested from the system (sources, pinning, and keyrings).

## Repository hosts
{_markdown_list(sorted(repo_hosts))}

## Source files
{_markdown_list(sorted(set(source_paths)))}

## Keyrings
{_markdown_list(sorted(set(keyring_paths)))}

## Managed files
{_markdown_list(_managed_file_lines(managed_files, include_reason=True))}

## Excluded
{_markdown_list(_excluded_lines(excluded))}

## Notes
{_markdown_list([str(n) for n in notes])}
"""


def _dnf_config_readme(
    *,
    bundle_dir: str,
    role: str,
    snapshot: Dict[str, Any],
    managed_files: List[Dict[str, Any]],
    managed_dirs: List[Dict[str, Any]],
    excluded: List[Dict[str, Any]],
    notes: List[Any],
) -> str:
    repo_paths: List[str] = []
    key_paths: List[str] = []
    repo_hosts: Set[str] = set()
    url_re = re.compile(r"(?:https?|ftp)://([^/\s]+)", re.IGNORECASE)
    file_url_re = re.compile(r"file://(/[^\s]+)")

    for mf in managed_files:
        path = str(mf.get("path") or "")
        src_rel = str(mf.get("src_rel") or "")
        if not path or not src_rel:
            continue
        if path.startswith("/etc/yum.repos.d/") and path.endswith(".repo"):
            repo_paths.append(path)
            for line in _read_artifact_lines(bundle_dir, role, src_rel):
                s = line.strip()
                if not s or s.startswith("#") or s.startswith(";"):
                    continue
                for match in url_re.finditer(s):
                    repo_hosts.add(match.group(1))
                for match in file_url_re.finditer(s):
                    key_paths.append(match.group(1))
        if path.startswith("/etc/pki/rpm-gpg/"):
            key_paths.append(path)

    return f"""# dnf_config

DNF/YUM configuration harvested from the system (repos, config files, and RPM GPG keys).

## Repository hosts
{_markdown_list(sorted(repo_hosts))}

## Repo files
{_markdown_list(sorted(set(repo_paths)))}

## GPG keys
{_markdown_list(sorted(set(key_paths)))}

## Managed files
{_markdown_list(_managed_file_lines(managed_files, include_reason=True))}

## Excluded
{_markdown_list(_excluded_lines(excluded))}

## Notes
{_markdown_list([str(n) for n in notes])}
"""


def _simple_managed_files_readme(
    title: str,
    description: str,
    *,
    include_reason: bool,
) -> Callable[..., str]:
    def _builder(
        *,
        bundle_dir: str,
        role: str,
        snapshot: Dict[str, Any],
        managed_files: List[Dict[str, Any]],
        managed_dirs: List[Dict[str, Any]],
        excluded: List[Dict[str, Any]],
        notes: List[Any],
    ) -> str:
        return f"""# {title}

{description}

## Managed files
{_markdown_list(_managed_file_lines(managed_files, include_reason=include_reason))}

## Excluded
{_markdown_list(_excluded_lines(excluded))}

## Notes
{_markdown_list([str(n) for n in notes])}
"""

    return _builder


def _extra_paths_readme(
    *,
    bundle_dir: str,
    role: str,
    snapshot: Dict[str, Any],
    managed_files: List[Dict[str, Any]],
    managed_dirs: List[Dict[str, Any]],
    excluded: List[Dict[str, Any]],
    notes: List[Any],
) -> str:
    include_pats = snapshot.get("include_patterns", []) or []
    exclude_pats = snapshot.get("exclude_patterns", []) or []
    return f"""# {role}

User-requested extra file harvesting.

## Include patterns
{_markdown_list([str(p) for p in include_pats])}

## Exclude patterns
{_markdown_list([str(p) for p in exclude_pats])}

## Managed directories
{_markdown_list([str(d.get('path') or '') for d in managed_dirs])}

## Managed files
{_markdown_list(_managed_file_lines(managed_files, include_reason=False))}

## Excluded
{_markdown_list(_excluded_lines(excluded))}

## Notes
{_markdown_list([str(n) for n in notes])}
"""


# --- Container image role renderer ---
_CONTAINER_COLLECTIONS = [
    {"name": "community.docker", "version": ">=4.0.0"},
    {"name": "containers.podman", "version": ">=1.0.0"},
]


def _render_container_images_role(
    ctx: AnsibleManifestContext,
    container_images_snapshot: Dict[str, Any],
) -> Optional[str]:
    raw_images = container_images_snapshot.get("images", []) or []
    if not container_images_snapshot and not raw_images:
        return

    images = [_normalise_container_image_item(img) for img in raw_images]
    if not images and not (container_images_snapshot.get("notes") or []):
        return

    role = container_images_snapshot.get("role_name", "container_images")
    role_dir = os.path.join(ctx.roles_root, role)
    _write_role_scaffold(role_dir)
    _ensure_requirements_yaml(
        os.path.join(ctx.out_dir, "requirements.yml"), _CONTAINER_COLLECTIONS
    )

    vars_map = {"container_images": images}
    if ctx.site_mode:
        _write_role_defaults(role_dir, {"container_images": []})
        _write_hostvars(ctx.out_dir, ctx.fqdn or "", role, vars_map)
    else:
        _write_role_defaults(role_dir, vars_map)

    with open(os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8") as f:
        f.write(
            "---\n"
            "dependencies: []\n"
            "collections:\n"
            "  - community.docker\n"
            "  - containers.podman\n"
        )

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
    with open(os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8") as f:
        f.write(tasks)

    with open(
        os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
    ) as f:
        f.write("---\n")

    def _fmt_image(img: Dict[str, Any]) -> str:
        pull_ref = (
            img.get("pull_ref") or "(no registry digest; not rendered as an exact pull)"
        )
        tags = img.get("repo_tags") or []
        tag_part = f" tags={', '.join(tags)}" if tags else ""
        platform = img.get("platform")
        platform_part = f" platform={platform}" if platform else ""
        return f"- {img.get('engine', 'unknown')}: {pull_ref}{tag_part}{platform_part}"

    notes = list(container_images_snapshot.get("notes", []) or [])
    unpinned_notes: List[str] = []
    for img in images:
        if img.get("pull_ref"):
            continue
        label = (
            ", ".join(img.get("repo_tags") or [])
            or img.get("image_id")
            or "unknown image"
        )
        unpinned_notes.append(
            f"{label}: no RepoDigest was available, so no exact pull task is emitted."
        )

    readme = (
        """# container_images

Generated Docker and Podman image-cache restoration role.

Images are pulled by immutable registry digest, such as
`registry.example.net/app@sha256:...`, when the harvest found a usable
`RepoDigest`. Local image IDs are recorded in `state.json` for evidence but are
not registry pull references.

**Note:** This role requires the `community.docker` and `containers.podman`
Ansible collections. Install them with:
`ansible-galaxy collection install -r requirements.yml`.

Registry credentials are not harvested. Private-registry authentication must be
managed separately before this role runs.

## Container images
"""
        + "\n".join(_fmt_image(img) for img in images)
        + """

## Notes
"""
        + ("\n".join([f"- {n}" for n in notes + unpinned_notes]) or "- (none)")
        + "\n"
    )
    with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)

    return role


# --- Desktop package role renderers ---
def _render_flatpak_role(
    ctx: AnsibleManifestContext,
    flatpak_snapshot: Dict[str, Any],
) -> Optional[str]:
    out_dir = ctx.out_dir
    roles_root = ctx.roles_root
    fqdn = ctx.fqdn
    site_mode = ctx.site_mode

    # -------------------------
    # Flatpak role (system-wide Flatpak remotes and applications)
    # -------------------------
    raw_flatpak_apps = flatpak_snapshot.get("system_flatpaks", []) or []
    raw_flatpak_remotes = flatpak_snapshot.get("remotes", []) or []

    if flatpak_snapshot:
        role = flatpak_snapshot.get("role_name", "flatpak")
        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)
        _ensure_requirements_yaml(os.path.join(out_dir, "requirements.yml"))

        flatpak_system_flatpaks = [
            _normalise_flatpak_item(fp, method="system") for fp in raw_flatpak_apps
        ]
        flatpak_remotes = [_normalise_flatpak_remote(r) for r in raw_flatpak_remotes]

        vars_map = {
            "flatpak_system_flatpaks": flatpak_system_flatpaks,
            "flatpak_remotes": flatpak_remotes,
        }
        if site_mode:
            _write_role_defaults(
                role_dir,
                {"flatpak_system_flatpaks": [], "flatpak_remotes": []},
            )
            _write_hostvars(out_dir, fqdn or "", role, vars_map)
        else:
            _write_role_defaults(role_dir, vars_map)

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(
                "---\n" "dependencies: []\n" "collections:\n" "  - community.general\n"
            )

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
        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(tasks)

        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\n")

        def _fmt_flatpak_apps(items: List[Dict[str, Any]]) -> str:
            lines = []
            for item in items:
                name = item.get("name")
                if not name:
                    continue
                detail_parts = []
                for key in ("remote", "branch", "arch"):
                    value = item.get(key)
                    if value not in (None, "", []):
                        detail_parts.append(f"{key}={value}")
                details = f" ({', '.join(detail_parts)})" if detail_parts else ""
                lines.append(f"- {name}{details}")
            return "\n".join(lines) or "- (none)"

        def _fmt_flatpak_remotes(items: List[Dict[str, Any]]) -> str:
            lines = []
            for item in items:
                name = item.get("name")
                url = item.get("url")
                if not name or not url:
                    continue
                lines.append(f"- {name}: {url}")
            return "\n".join(lines) or "- (none)"

        notes = flatpak_snapshot.get("notes", []) or []
        readme = (
            """# flatpak

Generated system-wide Flatpak remotes and applications.

**Note:** This role requires the `community.general` Ansible collection.
Install it with: `ansible-galaxy collection install -r requirements.yml`.

Flatpak `remote` is harvested from the installed deployment where detectable.
The original `.flatpakref` URL is generally not preserved by Flatpak after
installation, so `from_url` is only emitted if a future/hand-edited state file
contains it.

## System Flatpak remotes
"""
            + _fmt_flatpak_remotes(flatpak_remotes)
            + """\n
## System-wide Flatpaks
"""
            + _fmt_flatpak_apps(flatpak_system_flatpaks)
            + """\n
## Notes
"""
            + ("\n".join([f"- {n}" for n in notes]) or "- (none)")
            + """\n"""
        )
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        return role


def _render_snap_role(
    ctx: AnsibleManifestContext,
    snap_snapshot: Dict[str, Any],
) -> Optional[str]:
    out_dir = ctx.out_dir
    roles_root = ctx.roles_root
    fqdn = ctx.fqdn
    site_mode = ctx.site_mode

    # -------------------------
    # Snap role (system-wide snap packages)
    # -------------------------
    raw_system_snaps = snap_snapshot.get("system_snaps", []) or []

    if raw_system_snaps:
        role = snap_snapshot.get("role_name", "snap") if snap_snapshot else "snap"
        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)
        _ensure_requirements_yaml(os.path.join(out_dir, "requirements.yml"))

        snap_system_snaps = [_normalise_snap_item(s) for s in raw_system_snaps]

        vars_map = {"snap_system_snaps": snap_system_snaps}
        if site_mode:
            _write_role_defaults(role_dir, {"snap_system_snaps": []})
            _write_hostvars(out_dir, fqdn or "", role, vars_map)
        else:
            _write_role_defaults(role_dir, vars_map)

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(
                "---\n" "dependencies: []\n" "collections:\n" "  - community.general\n"
            )

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
  register: _enroll_snap_full_results
  ignore_errors: true

- name: Install system-wide snaps with compatibility options
  community.general.snap:
    name:
      - "{{ item.item.name }}"
    state: present
    channel: "{{ item.item.channel | default(omit) if not (item.item.install_revision | default(false)) else omit }}"
    classic: "{{ item.item.classic | default(false) }}"
  loop: "{{ (_enroll_snap_full_results | default({})).results | default([]) }}"
  when:
    - item.failed | default(false)
    - item.item.name is defined
    - item.item.name | length > 0
  become: true
  register: _enroll_snap_compat_results
  ignore_errors: true

- name: Install system-wide snaps with minimal options
  community.general.snap:
    name:
      - "{{ item.item.item.name }}"
    state: present
  loop: "{{ (_enroll_snap_compat_results | default({})).results | default([]) }}"
  when:
    - item.failed | default(false)
    - item.item.item.name is defined
    - item.item.item.name | length > 0
  become: true
  ignore_errors: true
"""
        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(tasks)

        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\n")

        def _fmt_snap_apps(items: List[Dict[str, Any]]) -> str:
            lines = []
            for item in items:
                name = item.get("name")
                if not name:
                    continue
                detail_parts = []
                for key in ("channel", "revision"):
                    value = item.get(key)
                    if value not in (None, "", []):
                        detail_parts.append(f"{key}={value}")
                for key in ("classic", "devmode", "dangerous"):
                    if item.get(key):
                        detail_parts.append(key)
                details = f" ({', '.join(detail_parts)})" if detail_parts else ""
                lines.append(f"- {name}{details}")
            return "\n".join(lines) or "- (none)"

        notes = snap_snapshot.get("notes", []) or []
        readme = (
            """# snap

Generated system-wide snap packages.

**Note:** This role requires the `community.general` Ansible collection.
Install it with: `ansible-galaxy collection install -r requirements.yml`.

The first install task uses all harvested attributes. If the installed
`community.general.snap` module is too old for some parameters, the generated
role falls back to reduced then minimal install tasks on a best-effort basis.

## System-wide snaps
"""
            + _fmt_snap_apps(snap_system_snaps)
            + """\n
## Notes
"""
            + ("\n".join([f"- {n}" for n in notes]) or "- (none)")
            + """\n"""
        )
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        return role


# --- Managed-file role renderers ---
@dataclass(frozen=True)
class AnsibleManagedFileRoleSpec:
    """Declarative managed-file singleton role rendering spec."""

    key: str
    default_role: str
    category: str
    readme_builder: Callable[..., str]
    notify_systemd: Optional[str] = None
    handlers: str = "---\n"
    include_dirs_when_empty: bool = False


_SYSTEMD_DAEMON_RELOAD_HANDLER = """---
- name: Run systemd daemon-reload
  ansible.builtin.systemd:
    daemon_reload: true
  no_log: "{{ enroll_hide_systemd_status | default(true) | bool }}"
"""


MANAGED_FILE_ROLE_SPECS: Tuple[AnsibleManagedFileRoleSpec, ...] = (
    AnsibleManagedFileRoleSpec(
        key="apt_config",
        default_role="apt_config",
        category="apt_config",
        readme_builder=_apt_config_readme,
    ),
    AnsibleManagedFileRoleSpec(
        key="dnf_config",
        default_role="dnf_config",
        category="dnf_config",
        readme_builder=_dnf_config_readme,
    ),
    AnsibleManagedFileRoleSpec(
        key="etc_custom",
        default_role="etc_custom",
        category="etc_custom",
        notify_systemd="Run systemd daemon-reload",
        handlers=_SYSTEMD_DAEMON_RELOAD_HANDLER,
        readme_builder=_simple_managed_files_readme(
            "etc_custom",
            "Unowned /etc config files not attributed to packages or services.",
            include_reason=False,
        ),
    ),
    AnsibleManagedFileRoleSpec(
        key="usr_local_custom",
        default_role="usr_local_custom",
        category="usr_local_custom",
        readme_builder=_simple_managed_files_readme(
            "usr_local_custom",
            "Unowned /usr/local files (scripts in /usr/local/bin and config under /usr/local/etc).",
            include_reason=False,
        ),
    ),
    AnsibleManagedFileRoleSpec(
        key="extra_paths",
        default_role="extra_paths",
        category="extra_paths",
        readme_builder=_extra_paths_readme,
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
        fqdn=ctx.fqdn,
        site_mode=ctx.site_mode,
        jt_exe=ctx.jt_exe,
        jt_enabled=ctx.jt_enabled,
        notify_systemd=spec.notify_systemd,
        handlers=spec.handlers,
        readme_builder=spec.readme_builder,
    )
    return role


def _write_managed_files_role(
    *,
    snapshot: Dict[str, Any],
    default_role: str,
    bundle_dir: str,
    roles_root: str,
    out_dir: str,
    fqdn: Optional[str],
    site_mode: bool,
    jt_exe: Optional[str],
    jt_enabled: bool,
    notify_systemd: Optional[str],
    handlers: str,
    readme_builder: Callable[..., str],
) -> str:
    """Render an Ansible role whose main purpose is managed files/dirs.

    This covers apt_config, dnf_config, etc_custom, usr_local_custom, and
    extra_paths. Their harvested state shape is the same; only their README
    and optional handler differ.
    """

    role = snapshot.get("role_name", default_role)
    role_dir = os.path.join(roles_root, role)
    _write_role_scaffold(role_dir)

    var_prefix = role
    managed_files = snapshot.get("managed_files", []) or []
    managed_dirs = snapshot.get("managed_dirs", []) or []
    excluded = snapshot.get("excluded", []) or []
    notes = snapshot.get("notes", []) or []

    templated, jt_vars = _jinjify_managed_files(
        bundle_dir,
        role,
        os.path.join(role_dir, "templates"),
        managed_files,
        jt_exe=jt_exe,
        jt_enabled=jt_enabled,
        overwrite_templates=not site_mode,
    )

    if site_mode:
        _copy_artifacts(
            bundle_dir,
            role,
            _host_role_files_dir(out_dir, fqdn or "", role),
            exclude_rels=templated,
        )
    else:
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

    if site_mode:
        _write_role_defaults(
            role_dir,
            {f"{var_prefix}_managed_files": [], f"{var_prefix}_managed_dirs": []},
        )
        _write_hostvars(out_dir, fqdn or "", role, vars_map)
    else:
        _write_role_defaults(role_dir, vars_map)

    tasks = "---\n" + _render_generic_files_tasks(var_prefix)
    with open(os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8") as f:
        f.write(tasks.rstrip() + "\n")

    with open(
        os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
    ) as f:
        f.write(handlers.rstrip() + "\n")

    with open(os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8") as f:
        f.write("---\ndependencies: []\n")

    readme = readme_builder(
        bundle_dir=bundle_dir,
        role=role,
        snapshot=snapshot,
        managed_files=managed_files,
        managed_dirs=managed_dirs,
        excluded=excluded,
        notes=notes,
    )
    with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)

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
def _render_service_roles(
    ctx: AnsibleManifestContext,
    services_to_manifest: List[Dict[str, Any]],
) -> List[str]:
    bundle_dir = ctx.bundle_dir
    out_dir = ctx.out_dir
    roles_root = ctx.roles_root
    fqdn = ctx.fqdn
    site_mode = ctx.site_mode
    jt_exe = ctx.jt_exe
    jt_enabled = ctx.jt_enabled
    rendered_roles: List[str] = []

    # -------------------------
    # Service roles
    # -------------------------
    for svc in services_to_manifest:
        source_role = svc["role_name"]
        role = avoid_reserved_role_name(source_role, prefix="service")
        unit = svc["unit"]
        pkgs = svc.get("packages", []) or []
        managed_files = svc.get("managed_files", []) or []
        managed_dirs = svc.get("managed_dirs", []) or []
        managed_links = svc.get("managed_links", []) or []

        ansible_role = AnsibleRole(role)
        ansible_role.add_service_snapshot(svc)

        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)

        var_prefix = role

        unit_state = ansible_role.services.get(unit, {})
        enabled_at_harvest = bool(unit_state.get("enabled"))
        desired_state = str(unit_state.get("state") or "stopped")

        templated, jt_vars = _jinjify_managed_files(
            bundle_dir,
            source_role,
            os.path.join(role_dir, "templates"),
            managed_files,
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=not site_mode,
        )

        # Copy only the non-templated artifacts.
        if site_mode:
            _copy_artifacts(
                bundle_dir,
                source_role,
                _host_role_files_dir(out_dir, fqdn or "", role),
                exclude_rels=templated,
            )
        else:
            _copy_artifacts(
                bundle_dir,
                source_role,
                os.path.join(role_dir, "files"),
                exclude_rels=templated,
            )

        files_var = _build_managed_files_var(
            managed_files,
            templated,
            notify_other="Restart service",
            notify_systemd="Run systemd daemon-reload",
        )

        links_var = _build_managed_links_var(managed_links)

        dirs_var = _build_managed_dirs_var(managed_dirs)

        jt_map = yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
        base_vars: Dict[str, Any] = {
            f"{var_prefix}_unit_name": unit,
            f"{var_prefix}_packages": pkgs,
            f"{var_prefix}_managed_files": files_var,
            f"{var_prefix}_managed_dirs": dirs_var,
            f"{var_prefix}_managed_links": links_var,
            f"{var_prefix}_manage_unit": True,
            f"{var_prefix}_systemd_enabled": bool(enabled_at_harvest),
            f"{var_prefix}_systemd_state": desired_state,
        }
        base_vars = _merge_mappings_overwrite(base_vars, jt_map)

        if site_mode:
            # Role defaults are host-agnostic/safe; all harvested state is in host_vars.
            _write_role_defaults(
                role_dir,
                {
                    f"{var_prefix}_unit_name": unit,
                    f"{var_prefix}_packages": [],
                    f"{var_prefix}_managed_files": [],
                    f"{var_prefix}_managed_dirs": [],
                    f"{var_prefix}_managed_links": [],
                    f"{var_prefix}_manage_unit": False,
                    f"{var_prefix}_systemd_enabled": False,
                    f"{var_prefix}_systemd_state": "stopped",
                },
            )
            _write_hostvars(out_dir, fqdn or "", role, base_vars)
        else:
            _write_role_defaults(role_dir, base_vars)

        handlers = f"""---
- name: Run systemd daemon-reload
  ansible.builtin.systemd:
    daemon_reload: true
  no_log: "{{ enroll_hide_systemd_status | default(true) | bool }}"

- name: Restart service
  ansible.builtin.service:
    name: "{{{{ {var_prefix}_unit_name }}}}"
    state: restarted
  when:
    - {var_prefix}_manage_unit | default(false)
    - ({var_prefix}_systemd_state | default('stopped')) == 'started'
"""
        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(handlers)

        task_parts: List[str] = []
        task_parts.append("---\n" + _render_install_packages_tasks(role, var_prefix))

        task_parts.append(_render_generic_files_tasks(var_prefix))

        task_parts.append(
            f"""- name: Probe whether systemd unit exists and is manageable
  ansible.builtin.systemd:
    name: "{{{{ {var_prefix}_unit_name }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  check_mode: true
  register: _unit_probe
  failed_when: false
  changed_when: false
  when: {var_prefix}_manage_unit | default(false)

- name: Ensure unit enablement matches harvest
  ansible.builtin.systemd:
    name: "{{{{ {var_prefix}_unit_name }}}}"
    enabled: "{{{{ {var_prefix}_systemd_enabled | bool }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  when:
    - {var_prefix}_manage_unit | default(false)
    - _unit_probe is succeeded

- name: Ensure unit running state matches harvest
  ansible.builtin.systemd:
    name: "{{{{ {var_prefix}_unit_name }}}}"
    state: "{{{{ {var_prefix}_systemd_state }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  when:
    - {var_prefix}_manage_unit | default(false)
    - _unit_probe is succeeded
"""
        )

        tasks = "\n".join(task_parts).rstrip() + "\n"
        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(tasks)

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\ndependencies: []\n")

        excluded = svc.get("excluded", [])
        notes = svc.get("notes", [])
        readme = f"""# {role}

Generated from `{unit}`.

## Packages
{os.linesep.join("- " + p for p in pkgs) or "- (none detected)"}

## Managed files
{os.linesep.join("- " + mf["path"] + " (" + mf["reason"] + ")" for mf in managed_files) or "- (none)"}

## Managed symlinks
{os.linesep.join("- " + ml["path"] + " -> " + ml["target"] + " (" + ml.get("reason", "") + ")" for ml in managed_links) or "- (none)"}

## Excluded (possible secrets / unsafe)
{os.linesep.join("- " + e["path"] + " (" + e["reason"] + ")" for e in excluded) or "- (none)"}

## Notes
{os.linesep.join("- " + n for n in notes) or "- (none)"}
"""
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        _add_role(rendered_roles, role)
    return rendered_roles


def _render_common_ansible_roles(
    ctx: AnsibleManifestContext,
    common_role_groups: Dict[str, List[Dict[str, Any]]],
    package_roles: List[Dict[str, Any]],
    occupied_role_names: Set[str],
) -> Tuple[List[str], List[str]]:
    bundle_dir = ctx.bundle_dir
    roles_root = ctx.roles_root
    jt_exe = ctx.jt_exe
    jt_enabled = ctx.jt_enabled

    rendered_roles: List[str] = []
    common_tail_roles: List[str] = []

    # -------------------------
    # Common package section/group roles
    #
    # Outside --fqdn/site mode, package and systemd-unit roles are grouped by
    # Debian Section or RPM Group by default.  Managed config and unit state can
    # live in those section roles too; --no-common-roles preserves the historic
    # one-role-per-package/unit output, and --fqdn implies that mode because
    # grouped role contents would be unsafe across multiple harvested hosts.
    # -------------------------
    # -------------------------
    # Manually installed package roles
    # -------------------------
    occupied_roles: Set[str] = set(occupied_role_names)
    for pr in package_roles:
        occupied_roles.add(
            avoid_reserved_role_name(str(pr.get("role_name") or ""), prefix="package")
        )

    for section_label, entries in sorted(common_role_groups.items()):
        role = _section_role_name(section_label, occupied_roles)
        ansible_role = AnsibleRole(
            role,
            var_prefix=role,
            section_label=section_label,
            grouped=True,
        )
        for entry in entries:
            kind = entry.get("kind") or "package"
            snap = entry.get("snapshot") or {}
            if kind == "service":
                ansible_role.add_service_snapshot(snap)
            else:
                ansible_role.add_package_snapshot(snap)

        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)

        var_prefix = ansible_role.var_prefix
        files_var: List[Dict[str, Any]] = []
        dirs_var: List[Dict[str, Any]] = []
        links_var: List[Dict[str, Any]] = []
        jt_combined: Dict[str, Any] = {}

        seen_files: Set[tuple] = set()
        seen_dirs: Set[tuple] = set()
        seen_links: Set[tuple] = set()

        for entry in ansible_role.entries:
            kind = entry.get("kind") or "package"
            snap = entry.get("snapshot") or {}
            source_role = str(snap.get("role_name") or "")
            managed_files = snap.get("managed_files", []) or []
            managed_dirs = snap.get("managed_dirs", []) or []
            managed_links = snap.get("managed_links", []) or []

            templated: Set[str] = set()
            jt_vars = ""
            if managed_files and source_role:
                templated, jt_vars = _jinjify_managed_files(
                    bundle_dir,
                    source_role,
                    os.path.join(role_dir, "templates"),
                    managed_files,
                    jt_exe=jt_exe,
                    jt_enabled=jt_enabled,
                    overwrite_templates=True,
                )

                _copy_artifacts(
                    bundle_dir,
                    source_role,
                    os.path.join(role_dir, "files"),
                    exclude_rels=templated,
                )

            notify_other = "Restart managed services" if kind == "service" else None
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

            for item in _build_managed_links_var(managed_links):
                key = (item.get("dest"), item.get("src"))
                if key not in seen_links:
                    seen_links.add(key)
                    links_var.append(item)

            jt_map = yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
            jt_combined = _merge_mappings_overwrite(jt_combined, jt_map)

        packages = ansible_role.sorted_packages
        files_var = sorted(files_var, key=lambda x: str(x.get("dest") or ""))
        dirs_var = sorted(dirs_var, key=lambda x: str(x.get("dest") or ""))
        links_var = sorted(links_var, key=lambda x: str(x.get("dest") or ""))
        systemd_units = ansible_role.systemd_units_var

        base_vars: Dict[str, Any] = {
            f"{var_prefix}_packages": packages,
            f"{var_prefix}_managed_files": files_var,
            f"{var_prefix}_managed_dirs": dirs_var,
            f"{var_prefix}_managed_links": links_var,
            f"{var_prefix}_systemd_units": systemd_units,
        }
        base_vars = _merge_mappings_overwrite(base_vars, jt_combined)

        _write_role_defaults(role_dir, base_vars)

        if {"cron", "logrotate"}.intersection(ansible_role.packages):
            common_tail_roles.append(role)

        handlers = (
            """---
- name: Run systemd daemon-reload
  ansible.builtin.systemd:
    daemon_reload: true
  no_log: "{{ enroll_hide_systemd_status | default(true) | bool }}"

- name: Restart managed services
  ansible.builtin.service:
    name: "{{ item.name }}"
    state: restarted
  loop: "{{ """
            + f"{var_prefix}_systemd_units"
            + """ | default([]) }}"
  when:
    - item.manage | default(false)
    - (item.state | default('stopped')) == 'started'
"""
        )
        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(handlers)

        task_parts: List[str] = []
        task_parts.append("---\n" + _render_install_packages_tasks(role, var_prefix))
        task_parts.append(_render_generic_files_tasks(var_prefix))
        task_parts.append(_render_grouped_systemd_tasks(var_prefix))

        tasks = "\n".join(task_parts).rstrip() + "\n"
        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(tasks)

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\ndependencies: []\n")

        readme = f"""# {role}

Common role for package section/group `{section_label}`.

## Origin roles
{os.linesep.join("- " + line for line in sorted(ansible_role.origin_lines)) or "- (none)"}

## Packages
{os.linesep.join("- " + p for p in packages) or "- (none)"}

## Managed files
{os.linesep.join("- " + mf["dest"] for mf in files_var) or "- (none)"}

## Managed symlinks
{os.linesep.join("- " + ml["dest"] + " -> " + ml["src"] for ml in links_var) or "- (none)"}

## Systemd units
{os.linesep.join("- " + u["name"] + " (enabled=" + str(u["enabled"]).lower() + ", state=" + u["state"] + ")" for u in systemd_units) or "- (none)"}

## Excluded (possible secrets / unsafe)
{os.linesep.join("- " + e.get("path", "") + " (" + e.get("reason", "") + ")" for e in ansible_role.excluded) or "- (none)"}

## Notes
{os.linesep.join("- " + n for n in ansible_role.notes) or "- (none)"}
"""
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        _add_role(rendered_roles, role)

    return rendered_roles, common_tail_roles


def _render_package_roles(
    ctx: AnsibleManifestContext,
    package_roles: List[Dict[str, Any]],
) -> List[str]:
    bundle_dir = ctx.bundle_dir
    out_dir = ctx.out_dir
    roles_root = ctx.roles_root
    fqdn = ctx.fqdn
    site_mode = ctx.site_mode
    jt_exe = ctx.jt_exe
    jt_enabled = ctx.jt_enabled
    rendered_roles: List[str] = []

    # Process package roles (those with configuration files)
    for pr in package_roles:
        source_role = pr["role_name"]
        role = avoid_reserved_role_name(source_role, prefix="package")
        pkg = pr.get("package") or ""
        managed_files = pr.get("managed_files", []) or []
        managed_dirs = pr.get("managed_dirs", []) or []
        managed_links = pr.get("managed_links", []) or []

        ansible_role = AnsibleRole(role)
        ansible_role.add_package_snapshot(pr)

        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)

        var_prefix = role

        templated, jt_vars = _jinjify_managed_files(
            bundle_dir,
            source_role,
            os.path.join(role_dir, "templates"),
            managed_files,
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=not site_mode,
        )

        # Copy only the non-templated artifacts.
        if site_mode:
            _copy_artifacts(
                bundle_dir,
                source_role,
                _host_role_files_dir(out_dir, fqdn or "", role),
                exclude_rels=templated,
            )
        else:
            _copy_artifacts(
                bundle_dir,
                source_role,
                os.path.join(role_dir, "files"),
                exclude_rels=templated,
            )

        pkgs = ansible_role.sorted_packages

        files_var = _build_managed_files_var(
            managed_files,
            templated,
            notify_other=None,
            notify_systemd="Run systemd daemon-reload",
        )

        links_var = _build_managed_links_var(managed_links)

        dirs_var = _build_managed_dirs_var(managed_dirs)

        jt_map = yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
        base_vars: Dict[str, Any] = {
            f"{var_prefix}_packages": pkgs,
            f"{var_prefix}_managed_files": files_var,
            f"{var_prefix}_managed_dirs": dirs_var,
            f"{var_prefix}_managed_links": links_var,
        }
        base_vars = _merge_mappings_overwrite(base_vars, jt_map)

        if site_mode:
            _write_role_defaults(
                role_dir,
                {
                    f"{var_prefix}_packages": [],
                    f"{var_prefix}_managed_files": [],
                    f"{var_prefix}_managed_dirs": [],
                    f"{var_prefix}_managed_links": [],
                },
            )
            _write_hostvars(out_dir, fqdn or "", role, base_vars)
        else:
            _write_role_defaults(role_dir, base_vars)

        handlers = """---
- name: Run systemd daemon-reload
  ansible.builtin.systemd:
    daemon_reload: true
  no_log: "{{ enroll_hide_systemd_status | default(true) | bool }}"
"""
        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(handlers)

        task_parts: List[str] = []
        task_parts.append("---\n" + _render_install_packages_tasks(role, var_prefix))
        task_parts.append(_render_generic_files_tasks(var_prefix))

        tasks = "\n".join(task_parts).rstrip() + "\n"
        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(tasks)

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\ndependencies: []\n")

        excluded = pr.get("excluded", [])
        notes = pr.get("notes", [])
        readme = f"""# {role}

Generated for package `{pkg}`.

## Managed files
{os.linesep.join("- " + mf["path"] + " (" + mf["reason"] + ")" for mf in managed_files) or "- (none)"}

## Managed symlinks
{os.linesep.join("- " + ml["path"] + " -> " + ml["target"] + " (" + ml.get("reason", "") + ")" for ml in managed_links) or "- (none)"}

## Excluded (possible secrets / unsafe)
{os.linesep.join("- " + e["path"] + " (" + e["reason"] + ")" for e in excluded) or "- (none)"}

## Notes
{os.linesep.join("- " + n for n in notes) or "- (none)"}

> Note: package roles (those not discovered via a systemd service) do not attempt to restart or enable services automatically.
"""
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        _add_role(rendered_roles, role)
    return rendered_roles


# --- Runtime state role renderers ---
def _render_sysctl_role(
    ctx: AnsibleManifestContext,
    sysctl_snapshot: Dict[str, Any],
) -> Optional[str]:
    if not (sysctl_snapshot and (sysctl_snapshot.get("managed_files") or [])):
        return

    role = sysctl_snapshot.get("role_name", "sysctl")
    role_dir = os.path.join(ctx.roles_root, role)
    _write_role_scaffold(role_dir)

    var_prefix = role
    managed_files = sysctl_snapshot.get("managed_files", []) or []
    conf_src_rel = ""
    for mf in managed_files:
        if mf.get("path") == "/etc/sysctl.d/99-enroll.conf":
            conf_src_rel = mf.get("src_rel") or ""
            break
    if not conf_src_rel and managed_files:
        conf_src_rel = managed_files[0].get("src_rel") or ""

    parameters = sysctl_snapshot.get("parameters", {}) or {}
    notes = sysctl_snapshot.get("notes", []) or []

    if ctx.site_mode:
        _copy_artifacts(
            ctx.bundle_dir,
            role,
            _host_role_files_dir(ctx.out_dir, ctx.fqdn or "", role),
        )
    else:
        _copy_artifacts(ctx.bundle_dir, role, os.path.join(role_dir, "files"))

    vars_map: Dict[str, Any] = {
        f"{var_prefix}_conf_src_rel": conf_src_rel,
        f"{var_prefix}_apply": True,
        f"{var_prefix}_ignore_apply_errors": True,
    }

    if ctx.site_mode:
        _write_role_defaults(
            role_dir,
            {
                f"{var_prefix}_conf_src_rel": "",
                f"{var_prefix}_apply": True,
                f"{var_prefix}_ignore_apply_errors": True,
            },
        )
        _write_hostvars(ctx.out_dir, ctx.fqdn or "", role, vars_map)
    else:
        _write_role_defaults(role_dir, vars_map)

    tasks = "---\n" + _render_sysctl_tasks(var_prefix)
    with open(os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8") as f:
        f.write(tasks.rstrip() + "\n")

    handlers_dir = os.path.join(role_dir, "handlers")
    os.makedirs(handlers_dir, exist_ok=True)
    with open(os.path.join(handlers_dir, "main.yml"), "w", encoding="utf-8") as f:
        f.write(_render_sysctl_handlers(var_prefix))

    with open(os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8") as f:
        f.write("---\ndependencies: []\n")

    param_count = len(parameters) if isinstance(parameters, dict) else 0
    sample_params = []
    if isinstance(parameters, dict):
        sample_params = sorted(parameters.keys())[:25]

    readme = f"""# {role}

Generated from live writable sysctl state captured during harvest.

This role deploys the captured values to `/etc/sysctl.d/99-enroll.conf`. The generated file intentionally contains writable, single-line sysctl values only; read-only, multiline, action-like, and host-identity keys are skipped to avoid creating a noisy or brittle boot-time configuration.

## Captured parameters

Captured parameter count: {param_count}

{os.linesep.join("- " + x for x in sample_params) or "- (none)"}

{"- ..." if param_count > len(sample_params) else ""}

## Notes
{os.linesep.join("- " + n for n in notes) or "- (none)"}

## Safety notes
- `sysctl_apply` defaults to `true` and applies `/etc/sysctl.d/99-enroll.conf` when the file changes.
- `sysctl_ignore_apply_errors` defaults to `true`, because sysctl availability and writability can vary across kernels, containers, and hardware.
- Review this role before applying it broadly across unlike hosts.
"""
    with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)

    return role


def _render_enroll_runtime_role(ctx: AnsibleManifestContext) -> str:
    role = "enroll_runtime"
    role_dir = os.path.join(ctx.roles_root, role)
    _write_role_scaffold(role_dir)
    tasks = """---
- name: Ensure Enroll runtime directory exists
  ansible.builtin.file:
    path: /etc/enroll
    state: directory
    owner: root
    group: root
    mode: "0750"
"""
    with open(os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8") as f:
        f.write(tasks.rstrip() + "\n")
    with open(os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8") as f:
        f.write("---\ndependencies: []\n")
    with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(
            "# enroll_runtime\n\n"
            "Generated by Enroll to hold common runtime scaffolding used by other generated roles.\n"
        )
    return role


def _render_firewall_runtime_role(
    ctx: AnsibleManifestContext,
    firewall_runtime_snapshot: Dict[str, Any],
) -> Optional[str]:
    if not (
        firewall_runtime_snapshot
        and (
            firewall_runtime_snapshot.get("ipset_save")
            or firewall_runtime_snapshot.get("iptables_v4_save")
            or firewall_runtime_snapshot.get("iptables_v6_save")
        )
    ):
        return

    role = firewall_runtime_snapshot.get("role_name", "firewall_runtime")
    role_dir = os.path.join(ctx.roles_root, role)
    _write_role_scaffold(role_dir)

    var_prefix = role
    packages = firewall_runtime_snapshot.get("packages", []) or []
    ipset_save = firewall_runtime_snapshot.get("ipset_save") or ""
    ipset_sets = firewall_runtime_snapshot.get("ipset_sets", []) or []
    iptables_v4_save = firewall_runtime_snapshot.get("iptables_v4_save") or ""
    iptables_v6_save = firewall_runtime_snapshot.get("iptables_v6_save") or ""
    notes = firewall_runtime_snapshot.get("notes", []) or []

    if ctx.site_mode:
        _copy_artifacts(
            ctx.bundle_dir,
            role,
            _host_role_files_dir(ctx.out_dir, ctx.fqdn or "", role),
        )
    else:
        _copy_artifacts(ctx.bundle_dir, role, os.path.join(role_dir, "files"))

    vars_map: Dict[str, Any] = {
        f"{var_prefix}_packages": packages,
        f"{var_prefix}_ipset_save": ipset_save,
        f"{var_prefix}_ipset_sets": ipset_sets,
        f"{var_prefix}_iptables_v4_save": iptables_v4_save,
        f"{var_prefix}_iptables_v6_save": iptables_v6_save,
        f"{var_prefix}_sync_ipsets_exact": True,
        f"{var_prefix}_restore_iptables": True,
    }

    if ctx.site_mode:
        _write_role_defaults(
            role_dir,
            {
                f"{var_prefix}_packages": [],
                f"{var_prefix}_ipset_save": "",
                f"{var_prefix}_ipset_sets": [],
                f"{var_prefix}_iptables_v4_save": "",
                f"{var_prefix}_iptables_v6_save": "",
                f"{var_prefix}_sync_ipsets_exact": True,
                f"{var_prefix}_restore_iptables": True,
            },
        )
        _write_hostvars(ctx.out_dir, ctx.fqdn or "", role, vars_map)
    else:
        _write_role_defaults(role_dir, vars_map)

    tasks = (
        "---\n"
        + _render_install_packages_tasks(role, var_prefix)
        + _render_firewall_runtime_tasks(var_prefix)
    )
    with open(os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8") as f:
        f.write(tasks.rstrip() + "\n")

    with open(
        os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
    ) as f:
        f.write(_render_firewall_runtime_handlers(var_prefix).rstrip() + "\n")

    with open(os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8") as f:
        f.write("---\ndependencies: []\n")

    readme = f"""# {role}

Generated from live firewall runtime state captured during harvest.

This role restores live ipset and iptables state only for firewall families where Enroll did not find corresponding persistent configuration on the source host. Static firewall configuration files, such as `/etc/iptables/rules.v4`, `/etc/iptables/rules.v6`, UFW, nftables, firewalld, or `/etc/ipset*`, are harvested separately as managed files and treated as authoritative for their respective family.

## Captured snapshots
- ipset: {ipset_save or "(none)"}
- iptables IPv4: {iptables_v4_save or "(none)"}
- iptables IPv6: {iptables_v6_save or "(none)"}

## Captured ipsets
{os.linesep.join("- " + x for x in ipset_sets) or "- (none)"}

## Notes
{os.linesep.join("- " + n for n in notes) or "- (none)"}

## Safety notes
- `firewall_runtime_sync_ipsets_exact` defaults to `true`; it flushes captured set members before replaying the saved members so stale entries are removed. This applies only when no persistent ipset config was found.
- `firewall_runtime_restore_iptables` defaults to `true`; `iptables-restore`/`ip6tables-restore` replace only captured families. A family is captured only when no corresponding persistent iptables config was found.
"""
    with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)

    return role


# --- User role renderer ---
def _render_users_role(
    ctx: AnsibleManifestContext,
    users_snapshot: Dict[str, Any],
) -> Optional[str]:
    bundle_dir = ctx.bundle_dir
    out_dir = ctx.out_dir
    roles_root = ctx.roles_root
    fqdn = ctx.fqdn
    site_mode = ctx.site_mode

    # -------------------------
    # Users role (non-system users)
    # -------------------------
    if users_snapshot:
        role = users_snapshot.get("role_name", "users")
        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)

        # Users role includes harvested SSH-related files; in site mode keep them
        # host-specific to avoid cross-host clobber.
        if site_mode:
            _copy_artifacts(
                bundle_dir, role, _host_role_files_dir(out_dir, fqdn or "", role)
            )
        else:
            _copy_artifacts(bundle_dir, role, os.path.join(role_dir, "files"))

        users = users_snapshot.get("users", [])
        managed_files = users_snapshot.get("managed_files", [])
        excluded = users_snapshot.get("excluded", [])
        notes = users_snapshot.get("notes", [])

        # Build groups list and a simplified user dict list suitable for loops
        group_names: List[str] = []
        group_set = set()
        users_data: List[Dict[str, Any]] = []
        for u in users:
            name = u.get("name")
            if not name:
                continue
            pg = u.get("primary_group") or name
            home = u.get("home") or f"/home/{name}"
            sshdir = home.rstrip("/") + "/.ssh"
            supp = u.get("supplementary_groups") or []
            if pg:
                group_set.add(pg)
            for g in supp:
                if g:
                    group_set.add(g)

            users_data.append(
                {
                    "name": name,
                    "uid": u.get("uid"),
                    "primary_group": pg,
                    "home": home,
                    "ssh_dir": sshdir,
                    "shell": u.get("shell"),
                    "gecos": u.get("gecos"),
                    "supplementary_groups": sorted(set(supp)),
                }
            )

        group_names = sorted(group_set)

        # User-managed files (authorized_keys plus dangerous-mode shell dotfiles).
        # Keep the variable name for compatibility with existing generated data.
        ssh_files: List[Dict[str, Any]] = []
        for mf in managed_files:
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

            # Prefer the harvested file mode so we preserve any deliberate
            # permissions (e.g. 0600 for certain dotfiles). For authorized_keys,
            # enforce 0600 regardless.
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

        # Only create .ssh directories for users that actually have harvested
        # files under .ssh.
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
        ssh_dirs = sorted(
            ssh_dirs_by_dest.values(), key=lambda item: str(item.get("dest") or "")
        )

        # Build Flatpak and Snap lists. Flatpak can be installed system-wide or
        # per-user. Snap packages are system-wide; per-user ~/snap/* directories
        # are runtime/user data and are not treated as install sources.
        users_flatpaks: List[Dict[str, Any]] = []
        user_flatpak_map = users_snapshot.get("user_flatpaks", {}) or {}
        home_by_user = {
            str(u.get("name")): str(u.get("home") or "") for u in users_data
        }
        for uname, flatpaks in user_flatpak_map.items():
            for fp in flatpaks or []:
                users_flatpaks.append(
                    _normalise_flatpak_item(
                        fp,
                        method="user",
                        user=str(uname),
                        home=home_by_user.get(str(uname)) or None,
                    )
                )

        flatpak_remotes = [
            _normalise_flatpak_remote(r)
            for r in (users_snapshot.get("user_flatpak_remotes", []) or [])
        ]
        users_needs_community = bool(flatpak_remotes or users_flatpaks)
        if users_needs_community:
            _ensure_requirements_yaml(os.path.join(out_dir, "requirements.yml"))

        # Variables are host-specific in site mode; in non-site mode they live in role defaults.
        if site_mode:
            _write_role_defaults(
                role_dir,
                {
                    "users_groups": [],
                    "users_users": [],
                    "users_ssh_dirs": [],
                    "users_ssh_files": [],
                    "users_flatpaks": [],
                    "users_flatpak_remotes": [],
                },
            )
            _write_hostvars(
                out_dir,
                fqdn or "",
                role,
                {
                    "users_groups": group_names,
                    "users_users": users_data,
                    "users_ssh_dirs": ssh_dirs,
                    "users_ssh_files": ssh_files,
                    "users_flatpaks": users_flatpaks,
                    "users_flatpak_remotes": flatpak_remotes,
                },
            )
        else:
            _write_role_defaults(
                role_dir,
                {
                    "users_groups": group_names,
                    "users_users": users_data,
                    "users_ssh_dirs": ssh_dirs,
                    "users_ssh_files": ssh_files,
                    "users_flatpaks": users_flatpaks,
                    "users_flatpak_remotes": flatpak_remotes,
                },
            )

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            if users_needs_community:
                f.write(
                    "---\n"
                    "dependencies: []\n"
                    "collections:\n"
                    "  - community.general\n"
                )
            else:
                f.write("---\ndependencies: []\n")

        # tasks (data-driven)
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
        - "{{ inventory_dir }}/host_vars/{{ inventory_hostname }}/{{ role_name }}/.files/{{ item.src_rel }}"
        - "{{ role_path }}/files/{{ item.src_rel }}"
  ansible.builtin.copy:
    src: "{{ lookup('ansible.builtin.first_found', _enroll_ff) }}"
    dest: "{{ item.dest }}"
    owner: "{{ item.owner }}"
    group: "{{ item.group }}"
    mode: "{{ item.mode }}"
  loop: "{{ users_ssh_files | default([]) }}"
"""

        if flatpak_remotes or users_flatpaks:
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

        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(users_tasks)

        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\n")

        def _fmt_user_flatpaks(items: List[Dict[str, Any]]) -> str:
            lines = []
            for item in items:
                name = item.get("name")
                user = item.get("user")
                if not name or not user:
                    continue
                detail_parts = []
                for key in ("remote", "branch", "arch"):
                    value = item.get(key)
                    if value not in (None, "", []):
                        detail_parts.append(f"{key}={value}")
                details = f" ({', '.join(detail_parts)})" if detail_parts else ""
                lines.append(f"- {user}: {name}{details}")
            return "\n".join(lines) or "- (none)"

        def _fmt_remotes(items: List[Dict[str, Any]]) -> str:
            lines = []
            for item in items:
                name = item.get("name")
                url = item.get("url")
                method = item.get("method") or "system"
                user = item.get("user")
                if not name or not url:
                    continue
                owner = f"user={user}" if user else "system"
                lines.append(f"- {name} ({method}, {owner}): {url}")
            return "\n".join(lines) or "- (none)"

        readme = (
            """# users

Generated non-system user accounts, SSH public material, and per-user Flatpak
applications/remotes.

**Note:** User Flatpak tasks require the `community.general` Ansible collection.
Install it with: `ansible-galaxy collection install -r requirements.yml`.

Flatpak `remote` is harvested from the installed deployment where detectable.
The original `.flatpakref` URL is generally not preserved by Flatpak after
installation, so `from_url` is only emitted if a future/hand-edited state file
contains it.


## Users
"""
            + (
                "\n".join([f"- {u.get('name')} (uid {u.get('uid')})" for u in users])
                or "- (none)"
            )
            + """\n
## Included SSH files
"""
            + (
                "\n".join(
                    [f"- {mf.get('path')} ({mf.get('reason')})" for mf in managed_files]
                )
                or "- (none)"
            )
            + """\n
## Flatpak remotes
"""
            + _fmt_remotes(flatpak_remotes)
            + """\n
## User Flatpaks
"""
            + _fmt_user_flatpaks(users_flatpaks)
            + """\n
## Excluded
"""
            + (
                "\n".join([f"- {e.get('path')} ({e.get('reason')})" for e in excluded])
                or "- (none)"
            )
            + """\n
## Notes
"""
            + ("\n".join([f"- {n}" for n in notes]) or "- (none)")
            + """\n"""
        )
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        return role


class AnsibleManifestRenderer:
    """Render Ansible roles and playbook from a harvest bundle."""

    def __init__(
        self,
        bundle_dir: str,
        out_dir: str,
        *,
        fqdn: Optional[str] = None,
        jinjaturtle: str = "auto",
        no_common_roles: bool = False,
    ) -> None:
        self.bundle_dir = bundle_dir
        self.out_dir = out_dir
        self.fqdn = fqdn
        self.jinjaturtle = jinjaturtle
        self.no_common_roles = no_common_roles

    def render(self) -> None:
        state = AnsibleRole.load_state(self.bundle_dir)
        roles = roles_from_state(state)
        inventory_packages = inventory_packages_from_state(state)

        ctx = _prepare_ansible_context(
            self.bundle_dir,
            self.out_dir,
            fqdn=self.fqdn,
            jinjaturtle=self.jinjaturtle,
        )
        _write_site_scaffold(ctx)

        use_common_roles = (not ctx.site_mode) and (not self.no_common_roles)
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


def manifest_from_bundle_dir(
    bundle_dir: str,
    out_dir: str,
    *,
    fqdn: Optional[str] = None,
    jinjaturtle: str = "auto",
    no_common_roles: bool = False,
) -> None:
    AnsibleManifestRenderer(
        bundle_dir,
        out_dir,
        fqdn=fqdn,
        jinjaturtle=jinjaturtle,
        no_common_roles=no_common_roles,
    ).render()
