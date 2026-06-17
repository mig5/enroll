from __future__ import annotations

import os
from typing import Any, Dict, List

from ..context import AnsibleManifestContext
from ..layout import (
    _copy_artifacts,
    _ensure_requirements_yaml,
    _host_role_files_dir,
    _write_hostvars,
    _write_role_defaults,
    _write_role_scaffold,
)
from ..model import AnsibleManifestPlan
from ..vars import _normalise_flatpak_item, _normalise_flatpak_remote


def _render_users_role(
    ctx: AnsibleManifestContext,
    manifest_plan: AnsibleManifestPlan,
    users_snapshot: Dict[str, Any],
) -> None:
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
        # files under .ssh. This mirrors Puppet's behaviour and avoids creating
        # empty SSH directories merely because a user account exists.
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

        def _fmt_app_list(items: List[Dict[str, Any]]) -> str:
            lines = []
            for item in items:
                name = item.get("name")
                if not name:
                    continue
                detail_parts = []
                for key in ("remote", "channel", "revision", "branch", "arch"):
                    value = item.get(key)
                    if value not in (None, "", []):
                        detail_parts.append(f"{key}={value}")
                for key in ("classic", "devmode", "dangerous"):
                    if item.get(key):
                        detail_parts.append(key)
                details = f" ({', '.join(detail_parts)})" if detail_parts else ""
                lines.append(f"- {name}{details}")
            return "\n".join(lines) or "- (none)"

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

        manifest_plan.add("users", role)
