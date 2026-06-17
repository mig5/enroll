from __future__ import annotations

import os
from typing import Any, Dict

from ..context import AnsibleManifestContext
from ..layout import (
    _copy_artifacts,
    _host_role_files_dir,
    _write_hostvars,
    _write_role_defaults,
    _write_role_scaffold,
)
from ..model import AnsibleManifestPlan
from ..tasks import (
    _render_firewall_runtime_tasks,
    _render_install_packages_tasks,
    _render_sysctl_handlers,
    _render_sysctl_tasks,
)


def _render_sysctl_role(
    ctx: AnsibleManifestContext,
    manifest_plan: AnsibleManifestPlan,
    sysctl_snapshot: Dict[str, Any],
) -> None:
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

    manifest_plan.add("sysctl", role)


def _render_firewall_runtime_role(
    ctx: AnsibleManifestContext,
    manifest_plan: AnsibleManifestPlan,
    firewall_runtime_snapshot: Dict[str, Any],
) -> None:
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

    manifest_plan.add("firewall_runtime", role)
