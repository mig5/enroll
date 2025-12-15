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

    # Service role: conditional start must be a clean Ansible expression
    tasks = (out / "roles" / "foo" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "when:\n    - _unit_probe is succeeded\n    - foo_start | bool\n" in tasks
    # Ensure we didn't emit deprecated/broken '{{ }}' delimiters in when:
    for line in tasks.splitlines():
        if line.lstrip().startswith("when:"):
            assert "{{" not in line and "}}" not in line

    defaults = (out / "roles" / "foo" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "foo_start: false" in defaults

    # Playbook should include users, etc_custom, packages, and services
    pb = (out / "playbook.yml").read_text(encoding="utf-8")
    assert "- users" in pb
    assert "- etc_custom" in pb
    assert "- curl" in pb
    assert "- foo" in pb
