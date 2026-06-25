from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest


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


def test_enforce_old_harvest_runs_ansible_with_tags_from_file_drift(
    monkeypatch, tmp_path: Path
):
    import enroll.diff as d
    import enroll.manifest as mf

    # Pretend ansible-playbook is installed.
    monkeypatch.setattr(d.shutil, "which", lambda name: "/usr/bin/ansible-playbook")

    calls: dict[str, object] = {}

    # Stub manifest generation to only create playbook.yml (fast, no real roles needed).
    def fake_manifest(_harvest_dir: str, out_dir: str, **_kwargs):
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=False)
        (out / "playbook.yml").write_text(
            "---\n- hosts: all\n  gather_facts: false\n  roles: []\n",
            encoding="utf-8",
        )

    monkeypatch.setattr(mf, "manifest", fake_manifest)

    def fake_run(
        argv, cwd=None, env=None, capture_output=False, text=False, check=False
    ):
        calls["argv"] = list(argv)
        calls["cwd"] = cwd
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(d.subprocess, "run", fake_run)

    old = tmp_path / "old"
    old_state = {
        "schema_version": 3,
        "host": {"hostname": "h1"},
        "inventory": {"packages": {}},
        "roles": {
            **_minimal_roles(),
            "usr_local_custom": {
                **_minimal_roles()["usr_local_custom"],
                "managed_files": [
                    {
                        "path": "/etc/myapp.conf",
                        "src_rel": "etc/myapp.conf",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "custom",
                    }
                ],
            },
        },
    }
    _write_bundle(old, old_state)

    # Minimal report containing enforceable drift: a baseline file is "removed".
    report = {
        "packages": {"added": [], "removed": [], "version_changed": []},
        "services": {"enabled_added": [], "enabled_removed": [], "changed": []},
        "users": {"added": [], "removed": [], "changed": []},
        "files": {
            "added": [],
            "removed": [{"path": "/etc/myapp.conf", "role": "usr_local_custom"}],
            "changed": [],
        },
    }

    info = d.enforce_old_harvest(str(old), report=report)
    assert info["status"] == "applied"
    assert "--tags" in info["command"]
    assert "role_usr_local_custom" in ",".join(info.get("tags") or [])

    argv = calls.get("argv")
    assert argv and argv[0].endswith("ansible-playbook")
    assert "--tags" in argv
    # Ensure we pass the computed tag.
    i = argv.index("--tags")
    assert "role_usr_local_custom" in str(argv[i + 1])


def test_cli_diff_enforce_forwards_target(monkeypatch):
    import enroll.cli as cli

    report = {
        "packages": {"added": [], "removed": ["curl"], "version_changed": []},
        "services": {"enabled_added": [], "enabled_removed": [], "changed": []},
        "users": {"added": [], "removed": [], "changed": []},
        "files": {"added": [], "removed": [], "changed": []},
    }

    monkeypatch.setattr(cli, "compare_harvests", lambda *a, **k: (report, True))
    monkeypatch.setattr(cli, "has_enforceable_drift", lambda r: True)

    calls: dict[str, object] = {}

    def fake_enforce(old, **kwargs):
        calls["old"] = old
        calls.update(kwargs)
        return {"status": "applied", "target": kwargs.get("target"), "returncode": 0}

    monkeypatch.setattr(cli, "enforce_old_harvest", fake_enforce)
    monkeypatch.setattr(cli, "format_report", lambda report, fmt="text": "R\n")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "diff",
            "--old",
            "/tmp/old",
            "--new",
            "/tmp/new",
            "--enforce",
        ],
    )

    cli.main()
    assert calls["old"] == "/tmp/old"
    assert calls["report"] is report


def test_cli_diff_enforce_rejects_non_ansible_target(monkeypatch):
    """Salt and Puppet targets have been removed from --enforce."""
    import enroll.cli as cli

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "diff",
            "--old",
            "/tmp/old",
            "--new",
            "/tmp/new",
            "--enforce",
            "--target",
            "puppet",
        ],
    )

    with pytest.raises(SystemExit):
        cli.main()


def test_cli_diff_forwards_exclude_and_ignore_flags(monkeypatch, capsys):
    import enroll.cli as cli

    calls: dict[str, object] = {}

    def fake_compare(
        old, new, *, sops_mode=False, exclude_paths=None, ignore_package_versions=False
    ):
        calls["compare"] = {
            "old": old,
            "new": new,
            "sops_mode": sops_mode,
            "exclude_paths": exclude_paths,
            "ignore_package_versions": ignore_package_versions,
        }
        # No changes -> should not try to enforce.
        return {"packages": {}, "services": {}, "users": {}, "files": {}}, False

    monkeypatch.setattr(cli, "compare_harvests", fake_compare)
    monkeypatch.setattr(cli, "format_report", lambda report, fmt="text": "R\n")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "diff",
            "--old",
            "/tmp/old",
            "--new",
            "/tmp/new",
            "--exclude-path",
            "/var/anacron",
            "--ignore-package-versions",
        ],
    )

    cli.main()
    _ = capsys.readouterr()
    assert calls["compare"]["exclude_paths"] == ["/var/anacron"]
    assert calls["compare"]["ignore_package_versions"] is True


def test_cli_diff_enforce_skips_when_no_enforceable_drift(monkeypatch):
    import enroll.cli as cli

    # Drift exists, but is not enforceable (only additions / version changes).
    report = {
        "packages": {"added": ["htop"], "removed": [], "version_changed": []},
        "services": {
            "enabled_added": ["x.service"],
            "enabled_removed": [],
            "changed": [],
        },
        "users": {"added": ["bob"], "removed": [], "changed": []},
        "files": {"added": [{"path": "/tmp/new"}], "removed": [], "changed": []},
    }

    monkeypatch.setattr(cli, "compare_harvests", lambda *a, **k: (report, True))
    monkeypatch.setattr(cli, "has_enforceable_drift", lambda r: False)
    called = {"enforce": False}
    monkeypatch.setattr(
        cli, "enforce_old_harvest", lambda *a, **k: called.update({"enforce": True})
    )

    captured = {}

    def fake_format(rep, fmt="text"):
        captured["report"] = rep
        return "R\n"

    monkeypatch.setattr(cli, "format_report", fake_format)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "diff",
            "--old",
            "/tmp/old",
            "--new",
            "/tmp/new",
            "--enforce",
        ],
    )

    cli.main()
    assert called["enforce"] is False
    assert captured["report"]["enforcement"]["status"] == "skipped"
