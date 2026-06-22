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


def test_cli_validate_exits_1_on_validation_error(monkeypatch, tmp_path: Path):
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
    assert e.value.code == 1


def test_cli_validate_exits_1_on_validation_warning_with_flag(
    monkeypatch, tmp_path: Path
):
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

    art2 = bundle / "artifacts" / "etc_custom" / "etc" / "hosts2"
    art2.write_text("hello\n", encoding="utf-8")

    monkeypatch.setattr(
        sys, "argv", ["enroll", "validate", str(bundle), "--fail-on-warnings"]
    )
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 1


def test_validation_result_ok():
    from enroll.validate import ValidationResult

    result = ValidationResult(errors=[], warnings=[])
    assert result.ok is True
    assert result.to_text() == "OK: harvest bundle validated\n"


def test_validation_result_with_errors():
    from enroll.validate import ValidationResult

    result = ValidationResult(errors=["error1", "error2"], warnings=[])
    assert result.ok is False
    text = result.to_text()
    assert "ERROR: 2 validation error(s)" in text
    assert "error1" in text
    assert "error2" in text


def test_validation_result_with_warnings():
    from enroll.validate import ValidationResult

    result = ValidationResult(errors=[], warnings=["warn1"])
    assert result.ok is True
    text = result.to_text()
    assert "WARN: 1 warning(s)" in text
    assert "warn1" in text


def test_validation_result_to_dict():
    from enroll.validate import ValidationResult

    result = ValidationResult(errors=["e1"], warnings=["w1"])
    d = result.to_dict()
    assert d["ok"] is False
    assert d["errors"] == ["e1"]
    assert d["warnings"] == ["w1"]


def test_iter_managed_files_singleton_roles():
    from enroll.validate import _iter_managed_files

    state = {
        "roles": {
            "users": {"managed_files": [{"path": "/etc/passwd", "src_rel": "passwd"}]},
            "packages": [
                {
                    "role_name": "vim",
                    "managed_files": [{"path": "/usr/bin/vim", "src_rel": "vim"}],
                }
            ],
        }
    }
    files = _iter_managed_files(state)
    assert len(files) == 2
    assert ("users", {"path": "/etc/passwd", "src_rel": "passwd"}) in files


def test_iter_managed_files_services_role():
    from enroll.validate import _iter_managed_files

    state = {
        "roles": {
            "services": [
                {
                    "role_name": "nginx",
                    "managed_files": [
                        {"path": "/etc/nginx/nginx.conf", "src_rel": "nginx.conf"}
                    ],
                }
            ]
        }
    }
    files = _iter_managed_files(state)
    assert len(files) == 1
    assert files[0][0] == "nginx"


def test_iter_managed_files_handles_non_dict_items():
    from enroll.validate import _iter_managed_files

    state = {
        "roles": {
            "users": {
                "managed_files": [
                    "not_a_dict",
                    {"path": "/etc/passwd", "src_rel": "passwd"},
                ]
            },
            "services": ["not_a_dict", {"role_name": "nginx", "managed_files": []}],
            "packages": ["not_a_dict"],
        }
    }
    files = _iter_managed_files(state)
    assert len(files) == 1


def test_iter_managed_files_empty_state():
    from enroll.validate import _iter_managed_files

    state = {"roles": {}}
    files = _iter_managed_files(state)
    assert files == []


def test_validate_harvest_missing_state_json(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    result = validate_harvest(str(bundle_dir))
    assert result.ok is False
    assert any("missing state.json" in e for e in result.errors)


def test_validate_harvest_invalid_json(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    state_file = bundle_dir / "state.json"
    state_file.write_text("not valid json", encoding="utf-8")
    result = validate_harvest(str(bundle_dir))
    assert result.ok is False
    assert any("failed to parse" in e for e in result.errors)


def test_validate_harvest_schema_error(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    state_file = bundle_dir / "state.json"
    state_file.write_text("{}", encoding="utf-8")
    result = validate_harvest(
        str(bundle_dir), schema="https://invalid.invalid/schema.json"
    )
    assert result.ok is False
    assert any("failed to load/validate schema" in e for e in result.errors)


def test_validate_harvest_missing_artifact(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    artifacts_dir = bundle_dir / "artifacts"
    artifacts_dir.mkdir()
    state = {
        "roles": {
            "users": {"managed_files": [{"path": "/etc/passwd", "src_rel": "passwd"}]}
        }
    }
    state_file = bundle_dir / "state.json"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    result = validate_harvest(str(bundle_dir))
    assert result.ok is False
    assert any("missing artifact" in e for e in result.errors)


def test_validate_harvest_suspicious_src_rel(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    state = {
        "roles": {
            "users": {
                "managed_files": [
                    {"path": "/etc/passwd", "src_rel": "../../../etc/passwd"}
                ]
            }
        }
    }
    state_file = bundle_dir / "state.json"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    result = validate_harvest(str(bundle_dir))
    assert result.ok is False
    assert any("suspicious src_rel" in e for e in result.errors)


def test_validate_harvest_missing_src_rel(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    state = {"roles": {"users": {"managed_files": [{"path": "/etc/passwd"}]}}}
    state_file = bundle_dir / "state.json"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    result = validate_harvest(str(bundle_dir))
    assert result.ok is False
    assert any("missing src_rel" in e for e in result.errors)


def test_validate_harvest_firewall_runtime_missing(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    artifacts_dir = bundle_dir / "artifacts"
    fw_dir = artifacts_dir / "firewall_runtime"
    fw_dir.mkdir(parents=True)
    state = {
        "roles": {
            "firewall_runtime": {
                "role_name": "firewall_runtime",
                "iptables_v4_save": "iptables.save",
            }
        }
    }
    state_file = bundle_dir / "state.json"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    result = validate_harvest(str(bundle_dir))
    assert result.ok is False
    assert any("missing firewall runtime artifact" in e for e in result.errors)


def test_validate_harvest_firewall_runtime_suspicious(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    state = {
        "roles": {
            "firewall_runtime": {
                "role_name": "firewall_runtime",
                "iptables_v4_save": "../../../etc/passwd",
            }
        }
    }
    state_file = bundle_dir / "state.json"
    state_file.write_text(json.dumps(state), encoding="utf-8")
    result = validate_harvest(str(bundle_dir))
    assert result.ok is False
    assert any("suspicious src_rel" in e for e in result.errors)


def test_validate_harvest_no_schema_option(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    state_file = bundle_dir / "state.json"
    state_file.write_text("invalid json", encoding="utf-8")
    result = validate_harvest(str(bundle_dir), no_schema=True)
    assert result.ok is False
    assert any("failed to parse" in e for e in result.errors)


def test_validate_harvest_rejects_artifact_symlink(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    artifact = bundle_dir / "artifacts" / "users" / "etc" / "shadow"
    artifact.parent.mkdir(parents=True)
    artifact.symlink_to("/etc/shadow")
    (bundle_dir / "state.json").write_text(
        json.dumps(
            {
                "roles": {
                    "users": {
                        "managed_files": [
                            {"path": "/etc/shadow", "src_rel": "etc/shadow"}
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    result = validate_harvest(str(bundle_dir), no_schema=True)

    assert result.ok is False
    assert any("symlink" in e for e in result.errors)


def test_validate_harvest_rejects_unreferenced_artifact_symlink(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    artifact = bundle_dir / "artifacts" / "users" / "etc" / "shadow"
    artifact.parent.mkdir(parents=True)
    artifact.symlink_to("/etc/shadow")
    (bundle_dir / "state.json").write_text(
        json.dumps({"roles": {"users": {"managed_files": []}}}),
        encoding="utf-8",
    )

    result = validate_harvest(str(bundle_dir), no_schema=True)

    assert result.ok is False
    assert any("symlink" in e for e in result.errors)


def test_validate_harvest_rejects_top_level_artifacts_symlink(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    target = tmp_path / "artifact-target"
    target.mkdir()
    (bundle_dir / "artifacts").symlink_to(target, target_is_directory=True)
    (bundle_dir / "state.json").write_text(
        json.dumps({"roles": {"users": {"managed_files": []}}}),
        encoding="utf-8",
    )

    result = validate_harvest(str(bundle_dir), no_schema=True)

    assert result.ok is False
    assert any("artifacts directory is a symlink" in e for e in result.errors)


def test_validate_harvest_rejects_top_level_artifacts_file(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    (bundle_dir / "artifacts").write_text("not a directory", encoding="utf-8")
    (bundle_dir / "state.json").write_text(
        json.dumps({"roles": {"users": {"managed_files": []}}}),
        encoding="utf-8",
    )

    result = validate_harvest(str(bundle_dir), no_schema=True)

    assert result.ok is False
    assert any("artifacts path is not a directory" in e for e in result.errors)
