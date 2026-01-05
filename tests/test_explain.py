from __future__ import annotations

import json
from pathlib import Path

import enroll.explain as ex


def _write_state(bundle: Path, state: dict) -> Path:
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    return bundle / "state.json"


def test_explain_state_text_renders_roles_inventory_and_reasons(tmp_path: Path):
    bundle = tmp_path / "bundle"
    state = {
        "schema_version": 3,
        "host": {"hostname": "h1", "os": "debian", "pkg_backend": "dpkg"},
        "enroll": {"version": "0.0.0"},
        "inventory": {
            "packages": {
                "foo": {
                    "installations": [{"version": "1.0", "arch": "amd64"}],
                    "observed_via": [
                        {"kind": "systemd_unit", "ref": "foo.service"},
                        {"kind": "package_role", "ref": "foo"},
                    ],
                    "roles": ["foo"],
                },
                "bar": {
                    "installations": [{"version": "2.0", "arch": "amd64"}],
                    "observed_via": [{"kind": "user_installed", "ref": "manual"}],
                    "roles": ["bar"],
                },
            }
        },
        "roles": {
            "users": {
                "role_name": "users",
                "users": [{"name": "alice"}],
                "managed_files": [
                    {
                        "path": "/home/alice/.ssh/authorized_keys",
                        "src_rel": "home/alice/.ssh/authorized_keys",
                        "owner": "alice",
                        "group": "alice",
                        "mode": "0600",
                        "reason": "authorized_keys",
                    }
                ],
                "managed_dirs": [
                    {
                        "path": "/home/alice/.ssh",
                        "owner": "alice",
                        "group": "alice",
                        "mode": "0700",
                        "reason": "parent_of_managed_file",
                    }
                ],
                "excluded": [{"path": "/etc/shadow", "reason": "sensitive_content"}],
                "notes": ["n1", "n2"],
            },
            "services": [
                {
                    "unit": "foo.service",
                    "role_name": "foo",
                    "packages": ["foo"],
                    "managed_files": [
                        {
                            "path": "/etc/foo.conf",
                            "src_rel": "etc/foo.conf",
                            "owner": "root",
                            "group": "root",
                            "mode": "0644",
                            "reason": "modified_conffile",
                        },
                        # Unknown reason should fall back to generic text.
                        {
                            "path": "/etc/odd.conf",
                            "src_rel": "etc/odd.conf",
                            "owner": "root",
                            "group": "root",
                            "mode": "0644",
                            "reason": "mystery_reason",
                        },
                    ],
                    "excluded": [],
                    "notes": [],
                }
            ],
            "packages": [
                {
                    "package": "bar",
                    "role_name": "bar",
                    "managed_files": [],
                    "excluded": [],
                    "notes": [],
                }
            ],
            "extra_paths": {
                "role_name": "extra_paths",
                "include_patterns": ["/etc/a", "/etc/b"],
                "exclude_patterns": ["/etc/x", "/etc/y"],
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
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
        },
    }

    state_path = _write_state(bundle, state)

    out = ex.explain_state(str(state_path), fmt="text", max_examples=1)

    assert "Enroll explained:" in out
    assert "Host: h1" in out
    assert "Inventory" in out
    # observed_via summary should include both kinds (order not strictly guaranteed)
    assert "observed_via" in out
    assert "systemd_unit" in out
    assert "user_installed" in out

    # extra_paths include/exclude patterns should be rendered with max_examples truncation.
    assert "include_patterns:" in out
    assert "/etc/a" in out
    assert "exclude_patterns:" in out

    # Reasons section should mention known and unknown reasons.
    assert "modified_conffile" in out
    assert "mystery_reason" in out
    assert "Captured with reason 'mystery_reason'" in out

    # Excluded paths section.
    assert "Why paths were excluded" in out
    assert "sensitive_content" in out


def test_explain_state_json_contains_structured_report(tmp_path: Path):
    bundle = tmp_path / "bundle"
    state = {
        "schema_version": 3,
        "host": {"hostname": "h2", "os": "rhel", "pkg_backend": "rpm"},
        "enroll": {"version": "1.2.3"},
        "inventory": {"packages": {}},
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
                "excluded": [],
                "notes": [],
            },
        },
    }
    state_path = _write_state(bundle, state)

    raw = ex.explain_state(str(state_path), fmt="json", max_examples=2)
    rep = json.loads(raw)
    assert rep["host"]["hostname"] == "h2"
    assert rep["enroll"]["version"] == "1.2.3"
    assert rep["inventory"]["package_count"] == 0
    assert isinstance(rep["roles"], list)
    assert "reasons" in rep
