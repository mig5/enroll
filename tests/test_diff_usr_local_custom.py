import json
from pathlib import Path

from enroll.diff import compare_harvests


def _write_bundle(root: Path, state: dict, artifacts: dict[str, bytes]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    for rel, data in artifacts.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def test_diff_includes_usr_local_custom_files(tmp_path: Path):
    old = tmp_path / "old"
    new = tmp_path / "new"

    old_state = {
        "schema_version": 3,
        "host": {"hostname": "h1", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {
            "packages": {
                "curl": {
                    "version": "1.0",
                    "arches": [],
                    "installations": [{"version": "1.0", "arch": "amd64"}],
                    "observed_via": [{"kind": "user_installed"}],
                    "roles": [],
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
            "services": [],
            "packages": [],
            "apt_config": {
                "role_name": "apt_config",
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
                "managed_files": [
                    {
                        "path": "/usr/local/etc/myapp.conf",
                        "src_rel": "usr/local/etc/myapp.conf",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "usr_local_etc_custom",
                    }
                ],
                "excluded": [],
                "notes": [],
            },
            "extra_paths": {
                "role_name": "extra_paths",
                "include_patterns": [],
                "exclude_patterns": [],
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
        },
    }

    new_state = {
        **old_state,
        "inventory": {
            "packages": {
                **old_state["inventory"]["packages"],
                "htop": {
                    "version": "3.0",
                    "arches": [],
                    "installations": [{"version": "3.0", "arch": "amd64"}],
                    "observed_via": [{"kind": "user_installed"}],
                    "roles": [],
                },
            }
        },
        "roles": {
            **old_state["roles"],
            "usr_local_custom": {
                "role_name": "usr_local_custom",
                "managed_files": [
                    {
                        "path": "/usr/local/etc/myapp.conf",
                        "src_rel": "usr/local/etc/myapp.conf",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "usr_local_etc_custom",
                    },
                    {
                        "path": "/usr/local/bin/myscript",
                        "src_rel": "usr/local/bin/myscript",
                        "owner": "root",
                        "group": "root",
                        "mode": "0755",
                        "reason": "usr_local_bin_script",
                    },
                ],
                "excluded": [],
                "notes": [],
            },
        },
    }

    _write_bundle(
        old,
        old_state,
        {
            "artifacts/usr_local_custom/usr/local/etc/myapp.conf": b"myapp=1\n",
        },
    )
    _write_bundle(
        new,
        new_state,
        {
            "artifacts/usr_local_custom/usr/local/etc/myapp.conf": b"myapp=2\n",
            "artifacts/usr_local_custom/usr/local/bin/myscript": b"#!/bin/sh\necho hi\n",
        },
    )

    report, has_changes = compare_harvests(str(old), str(new))
    assert has_changes is True

    # Packages: htop was added.
    assert report["packages"]["added"] == ["htop"]

    # Files: /usr/local/etc/myapp.conf should be detected as changed (content sha differs).
    changed_paths = {c["path"] for c in report["files"]["changed"]}
    assert "/usr/local/etc/myapp.conf" in changed_paths

    # Files: new script was added.
    added_paths = {a["path"] for a in report["files"]["added"]}
    assert "/usr/local/bin/myscript" in added_paths
