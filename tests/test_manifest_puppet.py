from __future__ import annotations

import json
from pathlib import Path

from enroll import manifest


def _write_state(bundle: Path, state: dict) -> None:
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")


def test_manifest_puppet_writes_control_repo_style_output(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "puppet"
    artifact = bundle / "artifacts" / "foo" / "etc" / "foo.conf"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("setting = true\n", encoding="utf-8")
    sysctl_artifact = bundle / "artifacts" / "sysctl" / "sysctl" / "99-enroll.conf"
    sysctl_artifact.parent.mkdir(parents=True, exist_ok=True)
    sysctl_artifact.write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")

    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {"packages": {}},
        "roles": {
            "users": {
                "role_name": "users",
                "users": [
                    {
                        "name": "alice",
                        "uid": 1000,
                        "gid": 1000,
                        "gecos": "Alice Example",
                        "home": "/home/alice",
                        "shell": "/bin/bash",
                        "primary_group": "alice",
                        "supplementary_groups": ["docker"],
                    }
                ],
                "managed_dirs": [],
                "managed_files": [],
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
                    "managed_dirs": [
                        {
                            "path": "/etc/foo",
                            "owner": "root",
                            "group": "root",
                            "mode": "0755",
                            "reason": "parent_dir",
                        }
                    ],
                    "managed_files": [
                        {
                            "path": "/etc/foo/foo.conf",
                            "src_rel": "etc/foo.conf",
                            "owner": "root",
                            "group": "root",
                            "mode": "0644",
                            "reason": "modified_conffile",
                        }
                    ],
                    "managed_links": [],
                    "excluded": [],
                    "notes": [],
                }
            ],
            "packages": [
                {
                    "package": "curl",
                    "role_name": "curl",
                    "section": "net",
                    "managed_dirs": [],
                    "managed_files": [],
                    "managed_links": [],
                    "excluded": [],
                    "notes": [],
                }
            ],
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
            "sysctl": {
                "role_name": "sysctl",
                "managed_dirs": [],
                "managed_files": [
                    {
                        "path": "/etc/sysctl.d/99-enroll.conf",
                        "src_rel": "sysctl/99-enroll.conf",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "system_sysctl",
                    }
                ],
                "parameters": {"net.ipv4.ip_forward": "1"},
                "notes": [],
            },
            "firewall_runtime": {
                "role_name": "firewall_runtime",
                "packages": [],
                "ipset_save": None,
                "ipset_sets": [],
                "iptables_v4_save": None,
                "iptables_v6_save": None,
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
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="puppet", fqdn="test.example")

    site_pp = (out / "manifests" / "site.pp").read_text(encoding="utf-8")
    assert site_pp == (
        "node 'test.example' {\n"
        "  include curl\n"
        "  include foo\n"
        "  include users\n"
        "  include sysctl\n"
        "}\n"
    )

    curl_pp = (out / "modules" / "curl" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "class curl" in curl_pp
    assert "package { 'curl':" in curl_pp

    foo_pp = (out / "modules" / "foo" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "class foo" in foo_pp
    assert "package { 'foo':" in foo_pp
    assert "file { '/etc/foo/foo.conf':" in foo_pp
    assert "source => 'puppet:///modules/foo/etc/foo.conf'" in foo_pp
    assert "service { 'foo.service':" in foo_pp

    users_pp = (out / "modules" / "users" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "class users" in users_pp
    assert "group { 'docker':" in users_pp
    assert "user { 'alice':" in users_pp

    sysctl_pp = (out / "modules" / "sysctl" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "class sysctl" in sysctl_pp
    assert "Boolean $sysctl_apply = true" in sysctl_pp
    assert "Boolean $sysctl_ignore_apply_errors = true" in sysctl_pp
    assert "exec { 'enroll-apply-sysctl':" in sysctl_pp
    assert "command     => $sysctl_ignore_apply_errors ? {" in sysctl_pp
    assert "sysctl -e -p /etc/sysctl.d/99-enroll.conf || true" in sysctl_pp

    assert (out / "modules" / "foo" / "files" / "etc" / "foo.conf").exists()
    assert (out / "modules" / "sysctl" / "files" / "sysctl" / "99-enroll.conf").exists()


def test_manifest_puppet_uses_default_node_and_common_package_modules(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "puppet"
    artifact = bundle / "artifacts" / "foo" / "etc" / "foo.conf"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("setting = true\n", encoding="utf-8")

    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {
            "packages": {
                "curl": {"section": "net"},
                "foo": {"installations": [{"section": "net"}]},
            }
        },
        "roles": {
            "services": [
                {
                    "unit": "foo.service",
                    "role_name": "foo",
                    "packages": ["foo"],
                    "active_state": "active",
                    "unit_file_state": "enabled",
                    "managed_dirs": [],
                    "managed_files": [
                        {
                            "path": "/etc/foo/foo.conf",
                            "src_rel": "etc/foo.conf",
                            "owner": "root",
                            "group": "root",
                            "mode": "0644",
                        }
                    ],
                    "managed_links": [],
                }
            ],
            "packages": [
                {
                    "package": "curl",
                    "role_name": "curl",
                    "section": "net",
                    "managed_dirs": [],
                    "managed_files": [],
                    "managed_links": [],
                }
            ],
            "users": {
                "role_name": "users",
                "users": [],
                "managed_dirs": [],
                "managed_files": [],
            },
            "apt_config": {
                "role_name": "apt_config",
                "managed_dirs": [],
                "managed_files": [],
            },
            "dnf_config": {
                "role_name": "dnf_config",
                "managed_dirs": [],
                "managed_files": [],
            },
            "sysctl": {"role_name": "sysctl", "managed_dirs": [], "managed_files": []},
            "firewall_runtime": {"role_name": "firewall_runtime", "packages": []},
            "etc_custom": {
                "role_name": "etc_custom",
                "managed_dirs": [],
                "managed_files": [],
            },
            "usr_local_custom": {
                "role_name": "usr_local_custom",
                "managed_dirs": [],
                "managed_files": [],
            },
            "extra_paths": {
                "role_name": "extra_paths",
                "managed_dirs": [],
                "managed_files": [],
                "managed_links": [],
            },
        },
    }
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="puppet")

    site_pp = (out / "manifests" / "site.pp").read_text(encoding="utf-8")
    assert site_pp == "node default {\n  include net\n}\n"

    net_pp = (out / "modules" / "net" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "class net" in net_pp
    assert "package { 'curl':" in net_pp
    assert "package { 'foo':" in net_pp
    assert "file { '/etc/foo/foo.conf':" in net_pp
    assert "source => 'puppet:///modules/net/etc/foo.conf'" in net_pp
    assert "service { 'foo.service':" in net_pp
    assert (out / "modules" / "net" / "files" / "etc" / "foo.conf").exists()
    assert not (out / "modules" / "curl").exists()
    assert not (out / "modules" / "foo").exists()


def test_manifest_puppet_avoids_reserved_module_names_and_duplicate_resources(
    tmp_path: Path,
):
    bundle = tmp_path / "bundle"
    out = tmp_path / "puppet"
    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {
            "packages": {
                "alpha": {"section": "admin"},
                "beta": {"section": "misc"},
                "gamma": {"section": "default"},
            }
        },
        "roles": {
            "packages": [
                {
                    "package": "alpha",
                    "role_name": "alpha",
                    "section": "admin",
                    "managed_dirs": [
                        {
                            "path": "/etc/default",
                            "owner": "root",
                            "group": "root",
                            "mode": "0755",
                        }
                    ],
                    "managed_files": [],
                    "managed_links": [],
                },
                {
                    "package": "beta",
                    "role_name": "beta",
                    "section": "misc",
                    "managed_dirs": [
                        {
                            "path": "/etc/default",
                            "owner": "root",
                            "group": "root",
                            "mode": "0755",
                        }
                    ],
                    "managed_files": [],
                    "managed_links": [],
                },
                {
                    "package": "gamma",
                    "role_name": "gamma",
                    "section": "default",
                    "managed_dirs": [],
                    "managed_files": [],
                    "managed_links": [],
                },
            ],
            "users": {
                "role_name": "users",
                "users": [],
                "managed_dirs": [],
                "managed_files": [],
            },
            "apt_config": {
                "role_name": "apt_config",
                "managed_dirs": [],
                "managed_files": [],
            },
            "dnf_config": {
                "role_name": "dnf_config",
                "managed_dirs": [],
                "managed_files": [],
            },
            "sysctl": {"role_name": "sysctl", "managed_dirs": [], "managed_files": []},
            "firewall_runtime": {"role_name": "firewall_runtime", "packages": []},
            "etc_custom": {
                "role_name": "etc_custom",
                "managed_dirs": [],
                "managed_files": [],
            },
            "usr_local_custom": {
                "role_name": "usr_local_custom",
                "managed_dirs": [],
                "managed_files": [],
            },
            "extra_paths": {
                "role_name": "extra_paths",
                "managed_dirs": [],
                "managed_files": [],
                "managed_links": [],
            },
        },
    }
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="puppet")

    site_pp = (out / "manifests" / "site.pp").read_text(encoding="utf-8")
    assert "include default\n" not in site_pp
    assert "include package_group_default" in site_pp
    assert (
        out / "modules" / "package_group_default" / "manifests" / "init.pp"
    ).exists()

    init_pps = "\n".join(
        p.read_text(encoding="utf-8")
        for p in sorted((out / "modules").glob("*/manifests/init.pp"))
    )
    assert init_pps.count("file { '/etc/default':") == 1


def test_manifest_rejects_unknown_target(tmp_path: Path):
    bundle = tmp_path / "bundle"
    _write_state(bundle, {"roles": {}})

    try:
        manifest.manifest(str(bundle), str(tmp_path / "out"), target="chef")
    except ValueError as e:
        assert "unsupported manifest target" in str(e)
    else:
        raise AssertionError("expected ValueError")
