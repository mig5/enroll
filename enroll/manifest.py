from __future__ import annotations

import json
import os
import shutil
from typing import Any, Dict, List


def _yaml_list(items: List[str], indent: int = 2) -> str:
    pad = " " * indent
    if not items:
        return f"{pad}[]"
    return "\n".join(f"{pad}- {x}" for x in items)


def _copy_artifacts(bundle_dir: str, role: str, role_dir: str) -> None:
    artifacts_dir = os.path.join(bundle_dir, "artifacts", role)
    if not os.path.isdir(artifacts_dir):
        return
    for root, _, files in os.walk(artifacts_dir):
        for fn in files:
            src = os.path.join(root, fn)
            rel = os.path.relpath(src, artifacts_dir)
            dst = os.path.join(role_dir, "files", rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)


def _write_role_scaffold(role_dir: str) -> None:
    os.makedirs(os.path.join(role_dir, "tasks"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "handlers"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "defaults"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "meta"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "files"), exist_ok=True)


def _write_playbook(path: str, roles: List[str]) -> None:
    pb_lines = ["---", "- hosts: all", "  become: true", "  roles:"]
    for r in roles:
        pb_lines.append(f"    - {r}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(pb_lines) + "\n")


def manifest(bundle_dir: str, out_dir: str) -> None:
    state_path = os.path.join(bundle_dir, "state.json")
    with open(state_path, "r", encoding="utf-8") as f:
        state = json.load(f)

    services: List[Dict[str, Any]] = state.get("services", [])
    package_roles: List[Dict[str, Any]] = state.get("package_roles", [])
    users_snapshot: Dict[str, Any] = state.get("users", {})

    os.makedirs(out_dir, exist_ok=True)
    roles_root = os.path.join(out_dir, "roles")
    os.makedirs(roles_root, exist_ok=True)

    manifested_users_roles: List[str] = []
    manifested_service_roles: List[str] = []
    manifested_pkg_roles: List[str] = []

    # -------------------------
    # Users role (non-system users)
    # -------------------------
    if users_snapshot and users_snapshot.get("users"):
        role = users_snapshot.get("role_name", "users")
        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)
        _copy_artifacts(bundle_dir, role, role_dir)

        users = users_snapshot.get("users", [])
        managed_files = users_snapshot.get("managed_files", [])
        excluded = users_snapshot.get("excluded", [])
        notes = users_snapshot.get("notes", [])

        # Build group set from users
        group_names = set()
        for u in users:
            pg = u.get("primary_group")
            if pg:
                group_names.add(pg)
            for g in u.get("supplementary_groups", []) or []:
                group_names.add(g)
        group_names = sorted(group_names)

        # defaults: store users list (handy for later), but tasks are explicit for readability
        defaults = """---
users_accounts:
""" + ("\n".join([f"  - name: {u.get('name')}" for u in users]) + "\n")
        with open(os.path.join(role_dir, "defaults", "main.yml"), "w", encoding="utf-8") as f:
            f.write(defaults)

        with open(os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8") as f:
            f.write("---\ndependencies: []\n")

        # tasks
        lines: List[str] = ["---"]
        # groups first (idempotent; safe even if already present)
        for g in group_names:
            lines.append(f"- name: Ensure group {g} exists")
            lines.append("  ansible.builtin.group:")
            lines.append(f"    name: {g}")
            lines.append("    state: present")

        # users
        for u in users:
            name = u["name"]
            lines.append(f"- name: Ensure user {name} exists")
            lines.append("  ansible.builtin.user:")
            lines.append(f"    name: {name}")
            lines.append(f"    uid: {u.get('uid')}")
            lines.append(f"    group: {u.get('primary_group')}")
            supp = u.get("supplementary_groups") or []
            if supp:
                lines.append("    groups: " + ",".join(supp))
                lines.append("    append: true")
            lines.append(f"    home: {u.get('home')}")
            lines.append("    create_home: true")
            if u.get("shell"):
                lines.append(f"    shell: {u.get('shell')}")
            if u.get("gecos"):
                # quote to avoid YAML surprises
                gec = u.get("gecos").replace('"', '\"')
                lines.append(f'    comment: "{gec}"')
            lines.append("    password_lock: true")
            lines.append("    state: present")

            # Ensure ~/.ssh
            home = u.get("home") or f"/home/{name}"
            sshdir = home.rstrip("/") + "/.ssh"
            lines.append(f"- name: Ensure {name} .ssh directory exists")
            lines.append("  ansible.builtin.file:")
            lines.append(f"    path: {sshdir}")
            lines.append("    state: directory")
            lines.append(f"    owner: {name}")
            lines.append(f"    group: {u.get('primary_group')}")
            lines.append("    mode: '0700'")

        # Copy harvested SSH public material (authorized_keys + *.pub)
        for mf in managed_files:
            dest = mf["path"]
            src = mf["src_rel"]
            # Determine file owner from dest path: /home/<user>/...
            owner = None
            for u in users:
                if dest.startswith((u.get("home") or "").rstrip("/") + "/"):
                    owner = u["name"]
                    group = u.get("primary_group")
                    break
            if owner is None:
                # fallback: try /home/<user>/
                parts = dest.split("/")
                owner = parts[2] if len(parts) > 2 and parts[1] == "home" else "root"
                group = owner

            mode = "0600" if mf.get("reason") == "authorized_keys" else "0644"
            lines.append(f"- name: Deploy {dest}")
            lines.append("  ansible.builtin.copy:")
            lines.append(f"    src: {src}")
            lines.append(f"    dest: {dest}")
            lines.append(f"    owner: {owner}")
            lines.append(f"    group: {group}")
            lines.append(f"    mode: '{mode}'")

        tasks = "\n".join(lines).rstrip() + "\n"
        with open(os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8") as f:
            f.write(tasks)

        # handlers (none needed)
        with open(os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8") as f:
            f.write("---\n")

        readme = """# users

Generated non-system user accounts and SSH public material.

## Users
""" + ("\n".join([f"- {u.get('name')} (uid {u.get('uid')})" for u in users]) or "- (none)") + """\n
## Included SSH files
""" + ("\n".join([f"- {mf.get('path')} ({mf.get('reason')})" for mf in managed_files]) or "- (none)") + """\n
## Excluded
""" + ("\n".join([f"- {e.get('path')} ({e.get('reason')})" for e in excluded]) or "- (none)") + """\n
## Notes
""" + ("\n".join([f"- {n}" for n in notes]) or "- (none)") + """\n"""
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        manifested_users_roles.append(role)

    # -------------------------
    # Service roles
    # -------------------------
    for svc in services:
        role = svc["role_name"]
        unit = svc["unit"]
        pkgs = svc["packages"]
        managed_files = svc["managed_files"]

        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)
        _copy_artifacts(bundle_dir, role, role_dir)

        var_prefix = role

        defaults = f"""---
{var_prefix}_packages:
{_yaml_list(pkgs, indent=2)}
"""
        with open(os.path.join(role_dir, "defaults", "main.yml"), "w", encoding="utf-8") as f:
            f.write(defaults)

        handlers = """---
- name: systemd daemon-reload
  ansible.builtin.systemd:
    daemon_reload: true

- name: Restart service
  ansible.builtin.service:
    name: "{{ unit_name }}"
    state: restarted
"""
        with open(os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8") as f:
            f.write(handlers)

        systemd_files = [mf for mf in managed_files if mf["path"].startswith("/etc/systemd/system/")]
        other_files = [mf for mf in managed_files if mf not in systemd_files]

        def copy_task(mf: Dict[str, Any], notify: str | None) -> str:
            notify_line = f"  notify: {notify}\n" if notify else ""
            return f"""- name: Deploy {mf["path"]}
  ansible.builtin.copy:
    src: "{mf["src_rel"]}"
    dest: "{mf["path"]}"
    owner: "{mf["owner"]}"
    group: "{mf["group"]}"
    mode: "{mf["mode"]}"
{notify_line}"""

        task_parts: List[str] = []
        task_parts.append(f"""---
- name: Set unit name
  ansible.builtin.set_fact:
    unit_name: "{unit}"

- name: Install packages for {role}
  ansible.builtin.apt:
    name: "{{{{ {var_prefix}_packages }}}}"
    state: present
    update_cache: true
  when: {var_prefix}_packages | length > 0
""")

        if systemd_files:
            for mf in systemd_files:
                task_parts.append(copy_task(mf, "[systemd daemon-reload]"))
            task_parts.append("""- name: Reload systemd to pick up unit changes
  ansible.builtin.meta: flush_handlers
""")

        for mf in other_files:
            task_parts.append(copy_task(mf, "[Restart service]"))

        task_parts.append(f"""- name: Ensure {unit} is enabled and running
  ansible.builtin.service:
    name: "{{{{ unit_name }}}}"
    enabled: true
    state: started
""")

        tasks = "\n".join(task_parts).rstrip() + "\n"
        with open(os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8") as f:
            f.write(tasks)

        with open(os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8") as f:
            f.write("---\ndependencies: []\n")

        excluded = svc.get("excluded", [])
        notes = svc.get("notes", [])
        readme = f"""# {role}

Generated from `{unit}`.

## Packages
{os.linesep.join("- " + p for p in pkgs) or "- (none detected)"}

## Managed files
{os.linesep.join("- " + mf["path"] + " (" + mf["reason"] + ")" for mf in managed_files) or "- (none)"}

## Excluded (possible secrets / unsafe)
{os.linesep.join("- " + e["path"] + " (" + e["reason"] + ")" for e in excluded) or "- (none)"}

## Notes
{os.linesep.join("- " + n for n in notes) or "- (none)"}
"""
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        manifested_service_roles.append(role)

    # -------------------------
    # Manual package roles
    # -------------------------
    for pr in package_roles:
        role = pr["role_name"]
        pkg = pr["package"]
        managed_files = pr["managed_files"]

        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)
        _copy_artifacts(bundle_dir, role, role_dir)

        var_prefix = role

        defaults = f"""---
{var_prefix}_packages:
  - {pkg}
"""
        with open(os.path.join(role_dir, "defaults", "main.yml"), "w", encoding="utf-8") as f:
            f.write(defaults)

        handlers = """---
- name: systemd daemon-reload
  ansible.builtin.systemd:
    daemon_reload: true
"""
        with open(os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8") as f:
            f.write(handlers)

        systemd_files = [mf for mf in managed_files if mf["path"].startswith("/etc/systemd/system/")]
        other_files = [mf for mf in managed_files if mf not in systemd_files]

        def copy_task(mf: Dict[str, Any], notify: str | None) -> str:
            notify_line = f"  notify: {notify}\n" if notify else ""
            return f"""- name: Deploy {mf["path"]}
  ansible.builtin.copy:
    src: "{mf["src_rel"]}"
    dest: "{mf["path"]}"
    owner: "{mf["owner"]}"
    group: "{mf["group"]}"
    mode: "{mf["mode"]}"
{notify_line}"""

        task_parts: List[str] = []
        task_parts.append(f"""---
- name: Install manual package {pkg}
  ansible.builtin.apt:
    name: "{{{{ {var_prefix}_packages }}}}"
    state: present
    update_cache: true
""")

        if systemd_files:
            for mf in systemd_files:
                task_parts.append(copy_task(mf, "[systemd daemon-reload]"))
            task_parts.append("""- name: Reload systemd to pick up unit changes
  ansible.builtin.meta: flush_handlers
""")

        for mf in other_files:
            task_parts.append(copy_task(mf, None))

        tasks = "\n".join(task_parts).rstrip() + "\n"
        with open(os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8") as f:
            f.write(tasks)

        with open(os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8") as f:
            f.write("---\ndependencies: []\n")

        excluded = pr.get("excluded", [])
        notes = pr.get("notes", [])
        readme = f"""# {role}

Generated for manual package `{pkg}`.

## Managed files
{os.linesep.join("- " + mf["path"] + " (" + mf["reason"] + ")" for mf in managed_files) or "- (none)"}

## Excluded (possible secrets / unsafe)
{os.linesep.join("- " + e["path"] + " (" + e["reason"] + ")" for e in excluded) or "- (none)"}

## Notes
{os.linesep.join("- " + n for n in notes) or "- (none)"}

> Note: package roles do not attempt to restart or enable services automatically.
"""
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        manifested_pkg_roles.append(role)

    # Playbooks
    _write_playbook(os.path.join(out_dir, "playbook.yml"), manifested_users_roles + manifested_pkg_roles + manifested_service_roles)
