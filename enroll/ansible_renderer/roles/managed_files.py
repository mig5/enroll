from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from ..context import AnsibleManifestContext
from ..jinjaturtle import _jinjify_managed_files
from ..layout import (
    _copy_artifacts,
    _host_role_files_dir,
    _write_hostvars,
    _write_role_defaults,
    _write_role_scaffold,
)
from ..model import AnsibleManifestPlan
from ..readme import (
    _apt_config_readme,
    _dnf_config_readme,
    _extra_paths_readme,
    _simple_managed_files_readme,
)
from ..tasks import _render_generic_files_tasks
from ..vars import _build_managed_dirs_var, _build_managed_files_var
from ..yamlutil import _merge_mappings_overwrite, _yaml_load_mapping


@dataclass(frozen=True)
class AnsibleManagedFileRoleSpec:
    """Declarative managed-file singleton role rendering spec.

    Puppet and Salt collect these singleton snapshots in a simple loop and feed
    each one through the same managed-content renderer.  Ansible has more
    layout concerns (defaults vs host_vars, optional JinjaTurtle templates,
    handlers), but the resource intent is the same, so keep the per-role
    differences in data rather than spelling out one branch per role.
    """

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
    manifest_plan: AnsibleManifestPlan,
    snapshot: Dict[str, Any],
    spec: AnsibleManagedFileRoleSpec,
) -> None:
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
    manifest_plan.add(spec.category, role)


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
        role_dir,
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

    jt_map = _yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
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

    tasks = "---\n" + _render_generic_files_tasks(
        var_prefix, include_restart_notify=False
    )
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
    manifest_plan: AnsibleManifestPlan,
    roles: Dict[str, Any],
) -> None:
    """Render file-centric singleton roles in the same loop style as Puppet/Salt."""

    for spec in MANAGED_FILE_ROLE_SPECS:
        snapshot = roles.get(spec.key, {})
        if not isinstance(snapshot, dict):
            continue
        if not _managed_file_role_has_resources(snapshot, spec):
            continue
        _write_managed_files_role_from_spec(ctx, manifest_plan, snapshot, spec)
