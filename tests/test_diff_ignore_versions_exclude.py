from __future__ import annotations

import json
from pathlib import Path


def _write_bundle(
    root: Path, state: dict, artifacts: dict[str, bytes] | None = None
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    artifacts = artifacts or {}
    for rel, data in artifacts.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def _minimal_roles() -> dict:
    """A small roles structure that's sufficient for enroll.diff file indexing."""
    return {
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
            "managed_files": [],
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
    }


def test_diff_ignore_package_versions_suppresses_version_drift(tmp_path: Path):
    from enroll.diff import compare_harvests

    old = tmp_path / "old"
    new = tmp_path / "new"

    old_state = {
        "schema_version": 3,
        "host": {"hostname": "h1"},
        "inventory": {
            "packages": {
                "curl": {
                    "version": "1.0",
                    "installations": [{"version": "1.0", "arch": "amd64"}],
                }
            }
        },
        "roles": _minimal_roles(),
    }
    new_state = {
        **old_state,
        "inventory": {
            "packages": {
                "curl": {
                    "version": "1.1",
                    "installations": [{"version": "1.1", "arch": "amd64"}],
                }
            }
        },
    }

    _write_bundle(old, old_state)
    _write_bundle(new, new_state)

    # Without ignore flag, version drift is reported and counts as changes.
    report, has_changes = compare_harvests(str(old), str(new))
    assert has_changes is True
    assert report["packages"]["version_changed"]

    # With ignore flag, version drift is suppressed and does not count as changes.
    report2, has_changes2 = compare_harvests(
        str(old), str(new), ignore_package_versions=True
    )
    assert has_changes2 is False
    assert report2["packages"]["version_changed"] == []
    assert report2["packages"]["version_changed_ignored_count"] == 1
    assert report2["filters"]["ignore_package_versions"] is True


def test_diff_exclude_path_filters_file_drift_and_affects_has_changes(tmp_path: Path):
    from enroll.diff import compare_harvests

    old = tmp_path / "old"
    new = tmp_path / "new"

    # Only file drift is under /var/anacron, which is excluded.
    old_state = {
        "schema_version": 3,
        "host": {"hostname": "h1"},
        "inventory": {"packages": {}},
        "roles": {
            **_minimal_roles(),
            "extra_paths": {
                **_minimal_roles()["extra_paths"],
                "managed_files": [
                    {
                        "path": "/var/anacron/daily.stamp",
                        "src_rel": "var/anacron/daily.stamp",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "extra_path",
                    }
                ],
            },
        },
    }
    new_state = json.loads(json.dumps(old_state))

    _write_bundle(
        old,
        old_state,
        {"artifacts/extra_paths/var/anacron/daily.stamp": b"yesterday\n"},
    )
    _write_bundle(
        new,
        new_state,
        {"artifacts/extra_paths/var/anacron/daily.stamp": b"today\n"},
    )

    report, has_changes = compare_harvests(
        str(old), str(new), exclude_paths=["/var/anacron"]
    )
    assert has_changes is False
    assert report["files"]["changed"] == []
    assert report["filters"]["exclude_paths"] == ["/var/anacron"]


def test_diff_exclude_path_only_filters_files_not_packages(tmp_path: Path):
    from enroll.diff import compare_harvests

    old = tmp_path / "old"
    new = tmp_path / "new"

    old_state = {
        "schema_version": 3,
        "host": {"hostname": "h1"},
        "inventory": {"packages": {"curl": {"version": "1.0"}}},
        "roles": {
            **_minimal_roles(),
            "extra_paths": {
                **_minimal_roles()["extra_paths"],
                "managed_files": [
                    {
                        "path": "/var/anacron/daily.stamp",
                        "src_rel": "var/anacron/daily.stamp",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "extra_path",
                    }
                ],
            },
        },
    }
    new_state = {
        **old_state,
        "inventory": {
            "packages": {
                "curl": {"version": "1.0"},
                "htop": {"version": "3.0"},
            }
        },
    }

    _write_bundle(
        old,
        old_state,
        {"artifacts/extra_paths/var/anacron/daily.stamp": b"yesterday\n"},
    )
    _write_bundle(
        new,
        new_state,
        {
            "artifacts/extra_paths/var/anacron/daily.stamp": b"today\n",
        },
    )

    report, has_changes = compare_harvests(
        str(old), str(new), exclude_paths=["/var/anacron"]
    )
    assert has_changes is True
    # File drift is filtered, but package drift remains.
    assert report["files"]["changed"] == []
    assert report["packages"]["added"] == ["htop"]
