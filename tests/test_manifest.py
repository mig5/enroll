import json
from pathlib import Path

from enroll.manifest import manifest


def test_manifest_writes_roles_and_playbook_with_clean_when(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
    (bundle / "artifacts" / "foo" / "etc").mkdir(parents=True, exist_ok=True)
    (bundle / "artifacts" / "foo" / "etc" / "foo.conf").write_text(
        "x", encoding="utf-8"
    )

    state = {
        "host": {"hostname": "test", "os": "debian"},
        "users": {
            "role_name": "users",
            "users": [
                {
                    "name": "alice",
                    "uid": 1000,
                    "gid": 1000,
                    "gecos": "Alice",
                    "home": "/home/alice",
                    "shell": "/bin/bash",
                    "primary_group": "alice",
                    "supplementary_groups": ["docker", "qubes"],
                }
            ],
            "managed_files": [],
            "excluded": [],
            "notes": [],
        },
        "etc_custom": {
            "role_name": "etc_custom",
            "managed_files": [
                {
                    "path": "/etc/default/keyboard",
                    "src_rel": "etc/default/keyboard",
                    "owner": "root",
                    "group": "root",
                    "mode": "0644",
                    "reason": "custom_unowned",
                }
            ],
            "excluded": [],
            "notes": [],
        },
        "services": [
            {
                "unit": "foo.service",
                "role_name": "foo",
                "packages": ["foo"],
                "active_state": "inactive",
                "sub_state": "dead",
                "unit_file_state": "enabled",
                "condition_result": "no",
                "managed_files": [
                    {
                        "path": "/etc/foo.conf",
                        "src_rel": "etc/foo.conf",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "modified_conffile",
                    }
                ],
                "excluded": [],
                "notes": [],
            }
        ],
        "package_roles": [
            {
                "package": "curl",
                "role_name": "curl",
                "managed_files": [],
                "excluded": [],
                "notes": [],
            }
        ],
    }

    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    # Create artifact for etc_custom file so copy works
    (bundle / "artifacts" / "etc_custom" / "etc" / "default").mkdir(
        parents=True, exist_ok=True
    )
    (bundle / "artifacts" / "etc_custom" / "etc" / "default" / "keyboard").write_text(
        "kbd", encoding="utf-8"
    )

    manifest(str(bundle), str(out))

    # Service role: systemd management should be gated on foo_manage_unit and a probe.
    tasks = (out / "roles" / "foo" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "- name: Probe whether systemd unit exists and is manageable" in tasks
    assert "when: foo_manage_unit | default(false)" in tasks
    assert (
        "when:\n    - foo_manage_unit | default(false)\n    - _unit_probe is succeeded\n"
        in tasks
    )

    # Ensure we didn't emit deprecated/broken '{{ }}' delimiters in when: lines.
    for line in tasks.splitlines():
        if line.lstrip().startswith("when:"):
            assert "{{" not in line and "}}" not in line

    defaults = (out / "roles" / "foo" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "foo_manage_unit: true" in defaults
    assert "foo_systemd_enabled: true" in defaults
    assert "foo_systemd_state: stopped" in defaults

    # Playbook should include users, etc_custom, packages, and services
    pb = (out / "playbook.yml").read_text(encoding="utf-8")
    assert "- users" in pb
    assert "- etc_custom" in pb
    assert "- curl" in pb
    assert "- foo" in pb


def test_manifest_site_mode_creates_host_inventory_and_raw_files(tmp_path: Path):
    """In --fqdn mode, host-specific state goes into inventory/host_vars."""

    fqdn = "host1.example.test"
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"

    # Artifacts for a service-managed file.
    (bundle / "artifacts" / "foo" / "etc").mkdir(parents=True, exist_ok=True)
    (bundle / "artifacts" / "foo" / "etc" / "foo.conf").write_text(
        "x", encoding="utf-8"
    )

    # Artifacts for etc_custom file so copy works.
    (bundle / "artifacts" / "etc_custom" / "etc" / "default").mkdir(
        parents=True, exist_ok=True
    )
    (bundle / "artifacts" / "etc_custom" / "etc" / "default" / "keyboard").write_text(
        "kbd", encoding="utf-8"
    )

    state = {
        "host": {"hostname": "test", "os": "debian"},
        "users": {
            "role_name": "users",
            "users": [],
            "managed_files": [],
            "excluded": [],
            "notes": [],
        },
        "etc_custom": {
            "role_name": "etc_custom",
            "managed_files": [
                {
                    "path": "/etc/default/keyboard",
                    "src_rel": "etc/default/keyboard",
                    "owner": "root",
                    "group": "root",
                    "mode": "0644",
                    "reason": "custom_unowned",
                }
            ],
            "excluded": [],
            "notes": [],
        },
        "services": [
            {
                "unit": "foo.service",
                "role_name": "foo",
                "packages": ["foo"],
                "active_state": "active",
                "sub_state": "running",
                "unit_file_state": "enabled",
                "condition_result": "yes",
                "managed_files": [
                    {
                        "path": "/etc/foo.conf",
                        "src_rel": "etc/foo.conf",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "modified_conffile",
                    }
                ],
                "excluded": [],
                "notes": [],
            }
        ],
        "package_roles": [],
    }

    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    manifest(str(bundle), str(out), fqdn=fqdn)

    # Host playbook exists.
    assert (out / "playbooks" / f"{fqdn}.yml").exists()

    # Role defaults are safe/host-agnostic in site mode.
    foo_defaults = (out / "roles" / "foo" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "foo_packages: []" in foo_defaults
    assert "foo_managed_files: []" in foo_defaults
    assert "foo_manage_unit: false" in foo_defaults

    # Host vars contain host-specific state.
    foo_hostvars = (out / "inventory" / "host_vars" / fqdn / "foo.yml").read_text(
        encoding="utf-8"
    )
    assert "foo_packages" in foo_hostvars
    assert "foo_managed_files" in foo_hostvars
    assert "foo_manage_unit: true" in foo_hostvars
    assert "foo_systemd_state: started" in foo_hostvars

    # Non-templated raw config is stored per-host under .files.
    assert (
        out / "inventory" / "host_vars" / fqdn / "foo" / ".files" / "etc" / "foo.conf"
    ).exists()


def test_copy2_replace_overwrites_readonly_destination(tmp_path: Path):
    """Merging into an existing manifest should tolerate read-only files.

    Some harvested artifacts (e.g. private keys) may be mode 0400. If a previous
    run copied them into the destination tree, a subsequent run must still be
    able to update/replace them.
    """

    import os
    import stat

    from enroll.manifest import _copy2_replace

    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.write_text("new", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")
    os.chmod(dst, 0o400)

    _copy2_replace(str(src), str(dst))

    assert dst.read_text(encoding="utf-8") == "new"
    mode = stat.S_IMODE(dst.stat().st_mode)
    assert mode & stat.S_IWUSR  # destination should remain mergeable
