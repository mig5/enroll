import json
from pathlib import Path

import enroll.manifest as manifest


def test_manifest_emits_symlink_tasks_and_vars(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"

    state = {
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {"packages": {}},
        "roles": {
            "users": {
                "role_name": "users",
                "users": [],
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "services": [
                {
                    "unit": "nginx.service",
                    "role_name": "nginx",
                    "packages": ["nginx"],
                    "active_state": "active",
                    "sub_state": "running",
                    "unit_file_state": "enabled",
                    "condition_result": None,
                    "managed_files": [],
                    "managed_links": [
                        {
                            "path": "/etc/nginx/sites-enabled/default",
                            "target": "../sites-available/default",
                            "reason": "enabled_symlink",
                        }
                    ],
                    "excluded": [],
                    "notes": [],
                }
            ],
            "packages": [],
            "apt_config": {
                "role_name": "apt_config",
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "dnf_config": {
                "role_name": "dnf_config",
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "etc_custom": {
                "role_name": "etc_custom",
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "usr_local_custom": {
                "role_name": "usr_local_custom",
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "extra_paths": {
                "role_name": "extra_paths",
                "include_patterns": [],
                "exclude_patterns": [],
                "managed_files": [],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            },
        },
    }

    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "artifacts").mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state), encoding="utf-8")

    manifest.manifest(str(bundle), str(out))

    tasks = (out / "roles" / "nginx" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "- name: Ensure managed symlinks exist" in tasks
    assert 'loop: "{{ nginx_managed_links | default([]) }}"' in tasks

    defaults = (out / "roles" / "nginx" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    # The role defaults should include the converted link mapping.
    assert "nginx_managed_links:" in defaults
    assert "dest: /etc/nginx/sites-enabled/default" in defaults
    assert "src: ../sites-available/default" in defaults
