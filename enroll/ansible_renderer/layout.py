from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .context import AnsibleManifestContext
from .yamlutil import _merge_mappings_overwrite, _yaml_dump_mapping, _yaml_load_mapping


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


def _ensure_requirements_yaml(req_path: str) -> None:
    if not os.path.exists(req_path):
        with open(req_path, "w", encoding="utf-8") as f:
            f.write("---\n")
            f.write("collections:\n")
            f.write("  - name: community.general\n")
            f.write('    version: ">=13.0.0"\n')
        return


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
            existing_map = _yaml_load_mapping(existing_text)
        except Exception:
            existing_map = {}

    merged = _merge_mappings_overwrite(existing_map, data)

    out = "---\n" + _yaml_dump_mapping(merged, sort_keys=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)


def _write_role_defaults(role_dir: str, mapping: Dict[str, Any]) -> None:
    """Overwrite role defaults/main.yml with the provided mapping."""
    defaults_path = os.path.join(role_dir, "defaults", "main.yml")
    os.makedirs(os.path.dirname(defaults_path), exist_ok=True)
    out = "---\n" + _yaml_dump_mapping(mapping, sort_keys=True)
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
