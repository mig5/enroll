from __future__ import annotations

import os
from typing import Any, Dict, List, Set

from ..context import AnsibleManifestContext
from ..jinjaturtle import _jinjify_managed_files
from ..layout import (
    _copy_artifacts,
    _host_role_files_dir,
    _write_hostvars,
    _write_role_defaults,
    _write_role_scaffold,
)
from ..model import AnsibleManifestPlan, AnsibleRole, _section_role_name
from ..tasks import (
    _render_generic_files_tasks,
    _render_grouped_systemd_tasks,
    _render_install_packages_tasks,
)
from ..vars import (
    _build_managed_dirs_var,
    _build_managed_files_var,
    _build_managed_links_var,
)
from ..yamlutil import _merge_mappings_overwrite, _yaml_load_mapping
from ...role_names import avoid_reserved_role_name


def _render_service_roles(
    ctx: AnsibleManifestContext,
    manifest_plan: AnsibleManifestPlan,
    services_to_manifest: List[Dict[str, Any]],
) -> None:
    bundle_dir = ctx.bundle_dir
    out_dir = ctx.out_dir
    roles_root = ctx.roles_root
    fqdn = ctx.fqdn
    site_mode = ctx.site_mode
    jt_exe = ctx.jt_exe
    jt_enabled = ctx.jt_enabled

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
            role_dir,
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

        jt_map = _yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
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

        task_parts.append(
            _render_generic_files_tasks(var_prefix, include_restart_notify=True)
        )

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

        manifest_plan.add("service", role)


def _render_common_ansible_roles(
    ctx: AnsibleManifestContext,
    manifest_plan: AnsibleManifestPlan,
    common_role_groups: Dict[str, List[Dict[str, Any]]],
    package_roles: List[Dict[str, Any]],
) -> List[str]:
    bundle_dir = ctx.bundle_dir
    roles_root = ctx.roles_root
    jt_exe = ctx.jt_exe
    jt_enabled = ctx.jt_enabled

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
    occupied_roles: Set[str] = set(
        manifest_plan.roles("apt_config")
        + manifest_plan.roles("dnf_config")
        + manifest_plan.roles("users")
        + manifest_plan.roles("flatpak")
        + manifest_plan.roles("snap")
        + manifest_plan.roles("service")
        + manifest_plan.roles("firewall_runtime")
        + manifest_plan.roles("sysctl")
        + manifest_plan.roles("etc_custom")
        + manifest_plan.roles("usr_local_custom")
        + manifest_plan.roles("extra_paths")
    )
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
                    role_dir,
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

            jt_map = _yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
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
        task_parts.append(
            _render_generic_files_tasks(var_prefix, include_restart_notify=True)
        )
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

        manifest_plan.add("package", role)

    return common_tail_roles


def _render_package_roles(
    ctx: AnsibleManifestContext,
    manifest_plan: AnsibleManifestPlan,
    package_roles: List[Dict[str, Any]],
) -> None:
    bundle_dir = ctx.bundle_dir
    out_dir = ctx.out_dir
    roles_root = ctx.roles_root
    fqdn = ctx.fqdn
    site_mode = ctx.site_mode
    jt_exe = ctx.jt_exe
    jt_enabled = ctx.jt_enabled

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
            role_dir,
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

        jt_map = _yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
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
        task_parts.append(
            _render_generic_files_tasks(var_prefix, include_restart_notify=False)
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

        manifest_plan.add("package", role)
