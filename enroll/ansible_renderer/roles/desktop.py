from __future__ import annotations

import os
from typing import Any, Dict, List

from ..context import AnsibleManifestContext
from ..layout import (
    _ensure_requirements_yaml,
    _write_hostvars,
    _write_role_defaults,
    _write_role_scaffold,
)
from ..model import AnsibleManifestPlan
from ..vars import (
    _normalise_flatpak_item,
    _normalise_flatpak_remote,
    _normalise_snap_item,
)


def _render_flatpak_role(
    ctx: AnsibleManifestContext,
    manifest_plan: AnsibleManifestPlan,
    flatpak_snapshot: Dict[str, Any],
) -> None:
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

        manifest_plan.add("flatpak", role)


def _render_snap_role(
    ctx: AnsibleManifestContext,
    manifest_plan: AnsibleManifestPlan,
    snap_snapshot: Dict[str, Any],
) -> None:
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

        manifest_plan.add("snap", role)
