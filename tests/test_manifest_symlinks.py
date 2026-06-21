from pathlib import Path

from tests.state_helpers import write_schema_state

import enroll.manifest as manifest


def test_manifest_emits_symlink_tasks_and_vars(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"

    state = {
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {
            "packages": {
                "nginx": {
                    "version": "1.0",
                    "arches": ["amd64"],
                    "installations": [
                        {"version": "1.0", "arch": "amd64", "section": "httpd"}
                    ],
                    "section": "httpd",
                    "observed_via": [{"kind": "systemd_unit", "ref": "nginx.service"}],
                    "roles": ["nginx"],
                }
            }
        },
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
    write_schema_state(bundle, state)

    manifest.manifest(str(bundle), str(out))

    role_dir = out / "roles" / "httpd"
    tasks = (role_dir / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "- name: Ensure managed symlinks exist" in tasks
    assert 'loop: "{{ httpd_managed_links | default([]) }}"' in tasks

    defaults = (role_dir / "defaults" / "main.yml").read_text(encoding="utf-8")
    # The grouped role defaults should include the converted link mapping.
    assert "httpd_managed_links:" in defaults
    assert "dest: /etc/nginx/sites-enabled/default" in defaults
    assert "src: ../sites-available/default" in defaults
