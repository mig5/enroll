from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import enroll.cli as cli
from enroll.validate import validate_harvest


def _base_state() -> dict:
    return {
        "enroll": {"version": "0.0.test", "harvest_time": 0},
        "host": {
            "hostname": "testhost",
            "os": "unknown",
            "pkg_backend": "dpkg",
            "os_release": {},
        },
        "inventory": {"packages": {}},
        "roles": {
            "users": {
                "role_name": "users",
                "users": [],
                "managed_dirs": [],
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "services": [],
            "packages": [],
            "apt_config": {
                "role_name": "apt_config",
                "managed_dirs": [],
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "dnf_config": {
                "role_name": "dnf_config",
                "managed_dirs": [],
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "etc_custom": {
                "role_name": "etc_custom",
                "managed_dirs": [],
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "usr_local_custom": {
                "role_name": "usr_local_custom",
                "managed_dirs": [],
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "extra_paths": {
                "role_name": "extra_paths",
                "include_patterns": [],
                "exclude_patterns": [],
                "managed_dirs": [],
                "managed_files": [],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            },
        },
    }


def _write_bundle(tmp_path: Path, state: dict) -> Path:
    bundle = tmp_path / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "artifacts").mkdir()
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    return bundle


def test_validate_ok_bundle(tmp_path: Path):
    state = _base_state()
    state["roles"]["etc_custom"]["managed_files"].append(
        {
            "path": "/etc/hosts",
            "src_rel": "etc/hosts",
            "owner": "root",
            "group": "root",
            "mode": "0644",
            "reason": "custom_specific_path",
        }
    )

    bundle = _write_bundle(tmp_path, state)
    art = bundle / "artifacts" / "etc_custom" / "etc" / "hosts"
    art.parent.mkdir(parents=True, exist_ok=True)
    art.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    res = validate_harvest(str(bundle))
    assert res.ok
    assert res.errors == []


def test_validate_missing_artifact_is_error(tmp_path: Path):
    state = _base_state()
    state["roles"]["etc_custom"]["managed_files"].append(
        {
            "path": "/etc/hosts",
            "src_rel": "etc/hosts",
            "owner": "root",
            "group": "root",
            "mode": "0644",
            "reason": "custom_specific_path",
        }
    )
    bundle = _write_bundle(tmp_path, state)
    res = validate_harvest(str(bundle))
    assert not res.ok
    assert any("missing artifact" in e for e in res.errors)


def test_validate_schema_error_is_reported(tmp_path: Path):
    state = _base_state()
    state["host"]["os"] = "not_a_real_os"
    bundle = _write_bundle(tmp_path, state)
    res = validate_harvest(str(bundle))
    assert not res.ok
    assert any(e.startswith("schema /host/os") for e in res.errors)


def test_cli_validate_exits_2_on_validation_error(monkeypatch, tmp_path: Path):
    state = _base_state()
    state["roles"]["etc_custom"]["managed_files"].append(
        {
            "path": "/etc/hosts",
            "src_rel": "etc/hosts",
            "owner": "root",
            "group": "root",
            "mode": "0644",
            "reason": "custom_specific_path",
        }
    )
    bundle = _write_bundle(tmp_path, state)

    monkeypatch.setattr(sys, "argv", ["enroll", "validate", str(bundle)])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2
