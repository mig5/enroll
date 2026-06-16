import json
from pathlib import Path

import os
import stat
import tarfile
import pytest

import enroll.manifest as manifest


def _minimal_package_state(packages):
    return {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {
            "packages": {
                p["package"]: {
                    "version": "1.0",
                    "arches": ["amd64"],
                    "installations": [
                        {
                            "version": "1.0",
                            "arch": "amd64",
                            "section": p.get("section") or "misc",
                        }
                    ],
                    "section": p.get("section") or "misc",
                    "observed_via": [{"kind": "package_role", "ref": p["role_name"]}],
                    "roles": [p["role_name"]],
                }
                for p in packages
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
            "packages": packages,
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


def _write_state(bundle: Path, state: dict) -> None:
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")


def test_manifest_writes_roles_and_playbook_with_clean_when(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
    (bundle / "artifacts" / "foo" / "etc").mkdir(parents=True, exist_ok=True)
    (bundle / "artifacts" / "foo" / "etc" / "foo.conf").write_text(
        "x", encoding="utf-8"
    )

    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {
            "packages": {
                "foo": {
                    "version": "1.0",
                    "arches": [],
                    "installations": [{"version": "1.0", "arch": "amd64"}],
                    "observed_via": [{"kind": "systemd_unit", "ref": "foo.service"}],
                    "roles": ["foo"],
                },
                "curl": {
                    "version": "8.0",
                    "arches": [],
                    "installations": [{"version": "8.0", "arch": "amd64"}],
                    "observed_via": [{"kind": "package_role", "ref": "curl"}],
                    "roles": ["curl"],
                },
            }
        },
        "roles": {
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
            "packages": [
                {
                    "package": "curl",
                    "role_name": "curl",
                    "managed_files": [],
                    "excluded": [],
                    "notes": [],
                }
            ],
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

    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    # Create artifact for etc_custom file so copy works
    (bundle / "artifacts" / "etc_custom" / "etc" / "default").mkdir(
        parents=True, exist_ok=True
    )
    (bundle / "artifacts" / "etc_custom" / "etc" / "default" / "keyboard").write_text(
        "kbd", encoding="utf-8"
    )

    # Create artifacts for usr_local_custom files so copy works
    (bundle / "artifacts" / "usr_local_custom" / "usr" / "local" / "etc").mkdir(
        parents=True, exist_ok=True
    )
    (
        bundle
        / "artifacts"
        / "usr_local_custom"
        / "usr"
        / "local"
        / "etc"
        / "myapp.conf"
    ).write_text("myapp=1\n", encoding="utf-8")
    (bundle / "artifacts" / "usr_local_custom" / "usr" / "local" / "bin").mkdir(
        parents=True, exist_ok=True
    )
    (
        bundle / "artifacts" / "usr_local_custom" / "usr" / "local" / "bin" / "myscript"
    ).write_text("#!/bin/sh\necho hi\n", encoding="utf-8")

    manifest.manifest(str(bundle), str(out), no_common_roles=True)

    # Service role: systemd management should be gated on foo_manage_unit and a probe.
    tasks = (out / "roles" / "foo" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "- name: Probe whether systemd unit exists and is manageable" in tasks
    assert 'no_log: "{{ enroll_hide_systemd_status | default(true) | bool }}"' in tasks
    assert "when: foo_manage_unit | default(false)" in tasks
    assert (
        "when:\n    - foo_manage_unit | default(false)\n    - _unit_probe is succeeded\n"
        in tasks
    )

    # Ensure we didn't emit deprecated/broken '{{ }}' delimiters in when: lines.
    for line in tasks.splitlines():
        if line.lstrip().startswith("when:"):
            assert "{{" not in line and "}}" not in line

    defaults = (out / "roles" / "foo" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "foo_manage_unit: true" in defaults
    assert "foo_systemd_enabled: true" in defaults
    assert "foo_systemd_state: stopped" in defaults

    # Playbook should include users, etc_custom, packages, and services
    pb = (out / "playbook.yml").read_text(encoding="utf-8")
    assert "role: users" in pb
    assert "role: etc_custom" in pb
    assert "role: usr_local_custom" in pb
    assert "role: curl" in pb
    assert "role: foo" in pb


def test_manifest_groups_simple_packages_by_section_by_default(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
    state = _minimal_package_state(
        [
            {
                "package": "curl",
                "role_name": "curl",
                "section": "net",
                "has_config": False,
                "managed_files": [],
                "managed_dirs": [],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            },
            {
                "package": "rsync",
                "role_name": "rsync",
                "section": "net",
                "has_config": False,
                "managed_files": [],
                "managed_dirs": [],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            },
            {
                "package": "vim",
                "role_name": "vim",
                "section": "editors",
                "has_config": False,
                "managed_files": [],
                "managed_dirs": [],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            },
            {
                "package": "nginx",
                "role_name": "nginx",
                "section": "httpd",
                "has_config": True,
                "managed_files": [],
                "managed_dirs": [],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            },
        ]
    )
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out))

    assert (out / "roles" / "net").exists()
    assert (out / "roles" / "editors").exists()
    assert (out / "roles" / "httpd").exists()
    assert not (out / "roles" / "curl").exists()
    assert not (out / "roles" / "rsync").exists()
    assert not (out / "roles" / "vim").exists()
    assert not (out / "roles" / "nginx").exists()

    net_defaults = (out / "roles" / "net" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "- curl" in net_defaults
    assert "- rsync" in net_defaults

    pb = (out / "playbook.yml").read_text(encoding="utf-8")
    assert "role: net" in pb
    assert "role: editors" in pb
    assert "role: httpd" in pb


def test_manifest_no_common_roles_preserves_package_roles(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
    state = _minimal_package_state(
        [
            {
                "package": "curl",
                "role_name": "curl",
                "section": "net",
                "has_config": False,
                "managed_files": [],
                "managed_dirs": [],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            },
            {
                "package": "vim",
                "role_name": "vim",
                "section": "editors",
                "has_config": False,
                "managed_files": [],
                "managed_dirs": [],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            },
        ]
    )
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), no_common_roles=True)

    assert (out / "roles" / "curl").exists()
    assert (out / "roles" / "vim").exists()
    assert not (out / "roles" / "net").exists()
    assert not (out / "roles" / "editors").exists()


def test_manifest_groups_excluded_package_paths_into_common_roles(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
    state = _minimal_package_state(
        [
            {
                "package": "secret-agent",
                "role_name": "secret_agent",
                "section": "net",
                "has_config": False,
                "managed_files": [],
                "managed_dirs": [],
                "managed_links": [],
                "excluded": [
                    {"path": "/etc/secret-agent/key", "reason": "possible_secret"}
                ],
                "notes": [],
            }
        ]
    )
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out))

    assert (out / "roles" / "net").exists()
    assert not (out / "roles" / "secret_agent").exists()
    readme = (out / "roles" / "net" / "README.md").read_text(encoding="utf-8")
    assert "/etc/secret-agent/key" in readme


def test_manifest_groups_managed_package_config_into_common_role(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
    (bundle / "artifacts" / "nginx" / "etc" / "nginx").mkdir(
        parents=True, exist_ok=True
    )
    (bundle / "artifacts" / "nginx" / "etc" / "nginx" / "nginx.conf").write_text(
        "worker_processes auto;\n", encoding="utf-8"
    )
    state = _minimal_package_state(
        [
            {
                "package": "nginx",
                "role_name": "nginx",
                "section": "httpd",
                "has_config": True,
                "managed_files": [
                    {
                        "path": "/etc/nginx/nginx.conf",
                        "src_rel": "etc/nginx/nginx.conf",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "modified_conffile",
                    }
                ],
                "managed_dirs": [
                    {
                        "path": "/etc/nginx",
                        "owner": "root",
                        "group": "root",
                        "mode": "0755",
                        "reason": "parent_of_managed_file",
                    }
                ],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            }
        ]
    )
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out))

    assert (out / "roles" / "httpd").exists()
    assert not (out / "roles" / "nginx").exists()
    defaults = (out / "roles" / "httpd" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "- nginx" in defaults
    assert "dest: /etc/nginx/nginx.conf" in defaults
    assert (out / "roles" / "httpd" / "files" / "etc" / "nginx" / "nginx.conf").exists()


def test_manifest_groups_systemd_units_into_common_role(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
    (bundle / "artifacts" / "network_manager" / "etc" / "NetworkManager").mkdir(
        parents=True, exist_ok=True
    )
    (
        bundle
        / "artifacts"
        / "network_manager"
        / "etc"
        / "NetworkManager"
        / "NetworkManager.conf"
    ).write_text("[main]\n", encoding="utf-8")

    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {
            "packages": {
                "network-manager": {
                    "version": "1.0",
                    "arches": ["amd64"],
                    "installations": [
                        {"version": "1.0", "arch": "amd64", "section": "net"}
                    ],
                    "section": "net",
                    "observed_via": [
                        {"kind": "systemd_unit", "ref": "NetworkManager.service"}
                    ],
                    "roles": ["network_manager", "network_manager_dispatcher"],
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
                    "unit": "NetworkManager.service",
                    "role_name": "network_manager",
                    "packages": ["network-manager"],
                    "active_state": "active",
                    "sub_state": "running",
                    "unit_file_state": "enabled",
                    "condition_result": "yes",
                    "managed_files": [
                        {
                            "path": "/etc/NetworkManager/NetworkManager.conf",
                            "src_rel": "etc/NetworkManager/NetworkManager.conf",
                            "owner": "root",
                            "group": "root",
                            "mode": "0644",
                            "reason": "modified_conffile",
                        }
                    ],
                    "managed_dirs": [],
                    "managed_links": [],
                    "excluded": [],
                    "notes": [],
                },
                {
                    "unit": "NetworkManager-dispatcher.service",
                    "role_name": "network_manager_dispatcher",
                    "packages": ["network-manager"],
                    "active_state": "inactive",
                    "sub_state": "dead",
                    "unit_file_state": "enabled",
                    "condition_result": "no",
                    "managed_files": [],
                    "managed_dirs": [],
                    "managed_links": [],
                    "excluded": [],
                    "notes": [],
                },
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
                "excluded": [],
                "notes": [],
            },
        },
    }
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out))

    assert (out / "roles" / "net").exists()
    assert not (out / "roles" / "network_manager").exists()
    assert not (out / "roles" / "network_manager_dispatcher").exists()
    defaults = (out / "roles" / "net" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "- network-manager" in defaults
    assert "name: NetworkManager.service" in defaults
    assert "name: NetworkManager-dispatcher.service" in defaults
    assert "dest: /etc/NetworkManager/NetworkManager.conf" in defaults
    tasks = (out / "roles" / "net" / "tasks" / "main.yml").read_text(encoding="utf-8")
    assert "Ensure grouped unit enablement matches harvest" in tasks
    assert 'no_log: "{{ enroll_hide_systemd_status | default(true) | bool }}"' in tasks


def test_manifest_fqdn_implies_no_common_roles(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
    state = _minimal_package_state(
        [
            {
                "package": "curl",
                "role_name": "curl",
                "section": "net",
                "has_config": False,
                "managed_files": [],
                "managed_dirs": [],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            }
        ]
    )
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), fqdn="host1.example.test")

    assert (out / "roles" / "curl").exists()
    assert not (out / "roles" / "net").exists()


def test_manifest_site_mode_creates_host_inventory_and_raw_files(tmp_path: Path):
    """In --fqdn mode, host-specific state goes into inventory/host_vars."""

    fqdn = "host1.example.test"
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"

    # Artifacts for a service-managed file.
    (bundle / "artifacts" / "foo" / "etc").mkdir(parents=True, exist_ok=True)
    (bundle / "artifacts" / "foo" / "etc" / "foo.conf").write_text(
        "x", encoding="utf-8"
    )

    # Artifacts for etc_custom file so copy works.
    (bundle / "artifacts" / "etc_custom" / "etc" / "default").mkdir(
        parents=True, exist_ok=True
    )
    (bundle / "artifacts" / "etc_custom" / "etc" / "default" / "keyboard").write_text(
        "kbd", encoding="utf-8"
    )

    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {
            "packages": {
                "foo": {
                    "version": "1.0",
                    "arches": [],
                    "installations": [{"version": "1.0", "arch": "amd64"}],
                    "observed_via": [{"kind": "systemd_unit", "ref": "foo.service"}],
                    "roles": ["foo"],
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
                    "unit": "foo.service",
                    "role_name": "foo",
                    "packages": ["foo"],
                    "active_state": "active",
                    "sub_state": "running",
                    "unit_file_state": "enabled",
                    "condition_result": "yes",
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

    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    # Artifacts for usr_local_custom file so copy works.
    (bundle / "artifacts" / "usr_local_custom" / "usr" / "local" / "etc").mkdir(
        parents=True, exist_ok=True
    )
    (
        bundle
        / "artifacts"
        / "usr_local_custom"
        / "usr"
        / "local"
        / "etc"
        / "myapp.conf"
    ).write_text("myapp=1\n", encoding="utf-8")

    manifest.manifest(str(bundle), str(out), fqdn=fqdn)

    # Host playbook exists.
    assert (out / "playbooks" / f"{fqdn}.yml").exists()

    # Role defaults are safe/host-agnostic in site mode.
    foo_defaults = (out / "roles" / "foo" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "foo_packages: []" in foo_defaults
    assert "foo_managed_files: []" in foo_defaults
    assert "foo_manage_unit: false" in foo_defaults

    # Host vars contain host-specific state.
    foo_hostvars = (out / "inventory" / "host_vars" / fqdn / "foo.yml").read_text(
        encoding="utf-8"
    )
    assert "foo_packages" in foo_hostvars
    assert "foo_managed_files" in foo_hostvars
    assert "foo_manage_unit: true" in foo_hostvars
    assert "foo_systemd_state: started" in foo_hostvars

    # Non-templated raw config is stored per-host under .files.
    assert (
        out / "inventory" / "host_vars" / fqdn / "foo" / ".files" / "etc" / "foo.conf"
    ).exists()


def test_copy2_replace_overwrites_readonly_destination(tmp_path: Path):
    """Merging into an existing manifest should tolerate read-only files.

    Some harvested artifacts (e.g. private keys) may be mode 0400. If a previous
    run copied them into the destination tree, a subsequent run must still be
    able to update/replace them.
    """

    import os
    import stat

    from enroll.manifest import _copy2_replace

    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.write_text("new", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")
    os.chmod(dst, 0o400)

    _copy2_replace(str(src), str(dst))

    assert dst.read_text(encoding="utf-8") == "new"
    mode = stat.S_IMODE(dst.stat().st_mode)
    assert mode & stat.S_IWUSR  # destination should remain mergeable


def test_manifest_includes_dnf_config_role_when_present(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"

    # Create a dnf_config artifact.
    (bundle / "artifacts" / "dnf_config" / "etc" / "dnf").mkdir(
        parents=True, exist_ok=True
    )
    (bundle / "artifacts" / "dnf_config" / "etc" / "dnf" / "dnf.conf").write_text(
        "[main]\n", encoding="utf-8"
    )

    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "redhat", "pkg_backend": "rpm"},
        "inventory": {
            "packages": {
                "dnf": {
                    "version": "4.0",
                    "arches": [],
                    "installations": [{"version": "4.0", "arch": "x86_64"}],
                    "observed_via": [{"kind": "dnf_config"}],
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
            "dnf_config": {
                "role_name": "dnf_config",
                "managed_files": [
                    {
                        "path": "/etc/dnf/dnf.conf",
                        "src_rel": "etc/dnf/dnf.conf",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "dnf_config",
                    }
                ],
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

    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    manifest.manifest(str(bundle), str(out))

    pb = (out / "playbook.yml").read_text(encoding="utf-8")
    assert "role: dnf_config" in pb

    tasks = (out / "roles" / "dnf_config" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    # Ensure the role exists and contains some file deployment logic.
    assert "Deploy any other managed files" in tasks


def test_render_install_packages_tasks_contains_dnf_branch():
    from enroll.manifest import _render_install_packages_tasks

    txt = _render_install_packages_tasks("role", "role")
    assert "ansible.builtin.apt" in txt
    assert "ansible.builtin.dnf" in txt
    assert "ansible.builtin.package" in txt
    assert "pkg_mgr" in txt


def test_manifest_orders_cron_and_logrotate_at_playbook_tail(tmp_path: Path):
    """Cron/logrotate roles should appear at the end.

    The cron role may restore per-user crontabs under /var/spool, so it should
    run after users have been created.
    """

    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"

    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {"packages": {}},
        "roles": {
            "users": {
                "role_name": "users",
                "users": [{"name": "alice"}],
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "services": [],
            "packages": [
                {
                    "package": "curl",
                    "role_name": "curl",
                    "managed_files": [],
                    "excluded": [],
                    "notes": [],
                },
                {
                    "package": "cron",
                    "role_name": "cron",
                    "managed_files": [
                        {
                            "path": "/var/spool/cron/crontabs/alice",
                            "src_rel": "var/spool/cron/crontabs/alice",
                            "owner": "alice",
                            "group": "root",
                            "mode": "0600",
                            "reason": "system_cron",
                        }
                    ],
                    "excluded": [],
                    "notes": [],
                },
                {
                    "package": "logrotate",
                    "role_name": "logrotate",
                    "managed_files": [
                        {
                            "path": "/etc/logrotate.conf",
                            "src_rel": "etc/logrotate.conf",
                            "owner": "root",
                            "group": "root",
                            "mode": "0644",
                            "reason": "system_logrotate",
                        }
                    ],
                    "excluded": [],
                    "notes": [],
                },
            ],
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

    # Minimal artifacts for managed files.
    (bundle / "artifacts" / "cron" / "var" / "spool" / "cron" / "crontabs").mkdir(
        parents=True, exist_ok=True
    )
    (
        bundle / "artifacts" / "cron" / "var" / "spool" / "cron" / "crontabs" / "alice"
    ).write_text("@daily echo hi\n", encoding="utf-8")
    (bundle / "artifacts" / "logrotate" / "etc").mkdir(parents=True, exist_ok=True)
    (bundle / "artifacts" / "logrotate" / "etc" / "logrotate.conf").write_text(
        "weekly\n", encoding="utf-8"
    )

    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    manifest.manifest(str(bundle), str(out))

    pb = (out / "playbook.yml").read_text(encoding="utf-8").splitlines()
    # Roles are emitted as indented list items under the `roles:` key.
    roles = [
        ln.strip().removeprefix("- ").strip() for ln in pb if ln.startswith("    - ")
    ]

    # Ensure the grouped role containing cron/logrotate is still ordered after users.
    assert roles[-1] == "role: misc"
    assert roles.index("role: users") < roles.index("role: misc")
    assert "role: users" in roles


def test_yaml_helpers_fallback_when_yaml_unavailable(monkeypatch):
    monkeypatch.setattr(manifest, "_try_yaml", lambda: None)
    assert manifest._yaml_load_mapping("foo: 1\n") == {}
    out = manifest._yaml_dump_mapping({"b": 2, "a": 1})
    # Best-effort fallback is key: repr(value)
    assert out.splitlines()[0].startswith("a: ")
    assert out.endswith("\n")


def test_copy2_replace_makes_readonly_sources_user_writable(
    monkeypatch, tmp_path: Path
):
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("hello", encoding="utf-8")
    # Make source read-only; copy2 preserves mode, so tmp will be read-only too.
    os.chmod(src, 0o444)

    manifest._copy2_replace(str(src), str(dst))

    st = os.stat(dst, follow_symlinks=False)
    assert stat.S_IMODE(st.st_mode) & stat.S_IWUSR


def test_prepare_bundle_dir_sops_decrypts_and_extracts(monkeypatch, tmp_path: Path):
    enc = tmp_path / "harvest.tar.gz.sops"
    enc.write_text("ignored", encoding="utf-8")

    def fake_require():
        return None

    def fake_decrypt(src: str, dst: str, *, mode: int = 0o600):
        # Create a minimal tar.gz with a state.json file.
        with tarfile.open(dst, "w:gz") as tf:
            p = tmp_path / "state.json"
            p.write_text("{}", encoding="utf-8")
            tf.add(p, arcname="state.json")

    monkeypatch.setattr(manifest, "require_sops_cmd", fake_require)
    monkeypatch.setattr(manifest, "decrypt_file_binary_to", fake_decrypt)

    bundle_dir, td = manifest._prepare_bundle_dir(str(enc), sops_mode=True)
    try:
        assert (Path(bundle_dir) / "state.json").exists()
    finally:
        td.cleanup()


def test_prepare_bundle_dir_rejects_non_dir_without_sops(tmp_path: Path):
    fp = tmp_path / "bundle.tar.gz"
    fp.write_text("x", encoding="utf-8")
    with pytest.raises(RuntimeError):
        manifest._prepare_bundle_dir(str(fp), sops_mode=False)


def test_tar_dir_to_with_progress_writes_progress_when_tty(monkeypatch, tmp_path: Path):
    src = tmp_path / "dir"
    src.mkdir()
    (src / "a.txt").write_text("a", encoding="utf-8")
    (src / "b.txt").write_text("b", encoding="utf-8")

    out = tmp_path / "out.tar.gz"
    writes: list[bytes] = []

    monkeypatch.setattr(manifest.os, "isatty", lambda fd: True)
    monkeypatch.setattr(manifest.os, "write", lambda fd, b: writes.append(b) or len(b))

    manifest._tar_dir_to_with_progress(str(src), str(out), desc="tarring")
    assert out.exists()
    assert writes  # progress was written
    assert writes[-1].endswith(b"\n")


def test_encrypt_manifest_out_dir_to_sops_handles_missing_tmp_cleanup(
    monkeypatch, tmp_path: Path
):
    src_dir = tmp_path / "manifest"
    src_dir.mkdir()
    (src_dir / "x.txt").write_text("x", encoding="utf-8")

    out = tmp_path / "manifest.tar.gz.sops"

    monkeypatch.setattr(manifest, "require_sops_cmd", lambda: None)

    def fake_encrypt(in_fp, out_fp, *args, **kwargs):
        Path(out_fp).write_text("enc", encoding="utf-8")

    monkeypatch.setattr(manifest, "encrypt_file_binary", fake_encrypt)
    # Simulate race where tmp tar is already removed.
    monkeypatch.setattr(
        manifest.os, "unlink", lambda p: (_ for _ in ()).throw(FileNotFoundError())
    )

    res = manifest._encrypt_manifest_out_dir_to_sops(str(src_dir), str(out), ["ABC"])  # type: ignore[arg-type]
    assert str(res).endswith(".sops")
    assert out.exists()


def test_manifest_applies_jinjaturtle_to_jinjifyable_managed_file(
    monkeypatch, tmp_path: Path
):
    # Create a minimal bundle with just an apt_config snapshot.
    bundle = tmp_path / "bundle"
    (bundle / "artifacts" / "apt_config" / "etc" / "apt").mkdir(parents=True)
    (bundle / "artifacts" / "apt_config" / "etc" / "apt" / "foo.ini").write_text(
        "key=VALUE\n", encoding="utf-8"
    )

    state = {
        "schema_version": 1,
        "inventory": {"packages": {}},
        "roles": {
            "services": [],
            "packages": [],
            "apt_config": {
                "role_name": "apt_config",
                "managed_files": [
                    {
                        "path": "/etc/apt/foo.ini",
                        "src_rel": "etc/apt/foo.ini",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "apt_config",
                    }
                ],
                "managed_dirs": [],
                "excluded": [],
                "notes": [],
            },
        },
    }
    (bundle / "state.json").write_text(
        __import__("json").dumps(state), encoding="utf-8"
    )

    monkeypatch.setattr(manifest, "find_jinjaturtle_cmd", lambda: "jinjaturtle")

    class _Res:
        template_text = "key={{ foo }}\n"
        vars_text = "foo: 123\n"

    monkeypatch.setattr(manifest, "run_jinjaturtle", lambda *a, **k: _Res())

    out_dir = tmp_path / "out"
    manifest.manifest(str(bundle), str(out_dir), jinjaturtle="on")

    tmpl = out_dir / "roles" / "apt_config" / "templates" / "etc" / "apt" / "foo.ini.j2"
    assert tmpl.exists()
    assert "{{ foo }}" in tmpl.read_text(encoding="utf-8")

    defaults = out_dir / "roles" / "apt_config" / "defaults" / "main.yml"
    txt = defaults.read_text(encoding="utf-8")
    assert "foo: 123" in txt
    # Non-templated file should not exist under files/.
    assert not (
        out_dir / "roles" / "apt_config" / "files" / "etc" / "apt" / "foo.ini"
    ).exists()


def test_manifest_writes_firewall_runtime_role(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
    (bundle / "artifacts" / "firewall_runtime" / "firewall").mkdir(
        parents=True, exist_ok=True
    )
    (bundle / "artifacts" / "firewall_runtime" / "firewall" / "ipset.save").write_text(
        "create blocklist hash:ip family inet\nadd blocklist 203.0.113.10\n",
        encoding="utf-8",
    )
    (bundle / "artifacts" / "firewall_runtime" / "firewall" / "iptables.v4").write_text(
        "*filter\n:INPUT DROP [0:0]\n-A INPUT -m set --match-set blocklist src -j DROP\nCOMMIT\n",
        encoding="utf-8",
    )

    state = {
        "schema_version": 3,
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
            "firewall_runtime": {
                "role_name": "firewall_runtime",
                "packages": ["ipset", "iptables"],
                "ipset_save": "firewall/ipset.save",
                "ipset_sets": ["blocklist"],
                "iptables_v4_save": "firewall/iptables.v4",
                "iptables_v6_save": None,
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
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    manifest.manifest(str(bundle), str(out))

    tasks = (out / "roles" / "firewall_runtime" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "ipset restore -exist" in tasks
    assert "iptables-restore /etc/enroll/firewall/iptables.v4" in tasks
    assert "ipset flush {{ item }}" in tasks

    defaults = (out / "roles" / "firewall_runtime" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "firewall_runtime_ipset_sets:" in defaults
    assert "- blocklist" in defaults
    assert "firewall_runtime_restore_iptables: true" in defaults

    pb = (out / "playbook.yml").read_text(encoding="utf-8")
    assert "role: firewall_runtime" in pb
    assert (
        out / "roles" / "firewall_runtime" / "files" / "firewall" / "ipset.save"
    ).exists()


def test_try_yaml_with_yaml_installed():
    result = manifest._try_yaml()
    # PyYAML should be installed for tests
    if result is None:
        pytest.skip("PyYAML not installed")
    assert hasattr(result, "safe_load")
    assert hasattr(result, "dump")


def test_yaml_load_mapping_with_yaml(tmp_path: Path):
    text = """
key1: value1
key2:
  nested: value
list:
  - item1
  - item2
"""
    result = manifest._yaml_load_mapping(text)
    assert result["key1"] == "value1"
    assert result["key2"]["nested"] == "value"
    assert result["list"] == ["item1", "item2"]


def test_yaml_load_mapping_empty():
    result = manifest._yaml_load_mapping("")
    assert result == {}


def test_yaml_load_mapping_invalid():
    result = manifest._yaml_load_mapping("invalid: yaml: :")
    assert result == {}


def test_yaml_load_mapping_not_dict():
    result = manifest._yaml_load_mapping("- item1\n- item2")
    assert result == {}


def test_yaml_load_mapping_none():
    result = manifest._yaml_load_mapping("~")
    assert result == {}


def test_yaml_dump_mapping_with_yaml(tmp_path: Path):
    obj = {"key1": "value1", "key2": 123}
    result = manifest._yaml_dump_mapping(obj)
    assert "key1: value1" in result
    assert "key2:" in result


def test_yaml_dump_mapping_empty():
    result = manifest._yaml_dump_mapping({})
    # Empty dict produces '{}'
    assert result.strip() == "{}"


def test_yaml_dump_mapping_with_nested(tmp_path: Path):
    obj = {"key1": {"nested": "value"}}
    result = manifest._yaml_dump_mapping(obj)
    assert "nested:" in result


def test_merge_mappings_overwrite_simple():
    existing = {"key1": "old", "key2": "keep"}
    incoming = {"key1": "new", "key3": "added"}
    result = manifest._merge_mappings_overwrite(existing, incoming)
    assert result["key1"] == "new"
    assert result["key2"] == "keep"
    assert result["key3"] == "added"


def test_merge_mappings_overwrite_nested():
    existing = {"key1": {"a": 1}}
    incoming = {"key1": {"b": 2}}
    result = manifest._merge_mappings_overwrite(existing, incoming)
    # Nested dicts are replaced, not merged
    assert result["key1"] == {"b": 2}


def test_merge_mappings_overwrite_empty():
    result = manifest._merge_mappings_overwrite({}, {"key": "value"})
    assert result == {"key": "value"}

    result = manifest._merge_mappings_overwrite({"key": "value"}, {})
    assert result == {"key": "value"}


def test_copy2_replace(tmp_path: Path):
    src = tmp_path / "src.txt"
    src.write_text("content", encoding="utf-8")
    dst = tmp_path / "dst" / "subdir" / "dst.txt"

    manifest._copy2_replace(str(src), str(dst))

    assert dst.exists()
    assert dst.read_text(encoding="utf-8") == "content"


def test_copy2_replace_preserves_metadata(tmp_path: Path):
    src = tmp_path / "src.txt"
    src.write_text("content", encoding="utf-8")
    os.chmod(str(src), 0o644)
    dst = tmp_path / "dst.txt"

    manifest._copy2_replace(str(src), str(dst))

    assert dst.exists()
    st = dst.stat()
    assert stat.S_IMODE(st.st_mode) == 0o644


def test_copy2_replace_atomic(tmp_path: Path):
    src = tmp_path / "src.txt"
    src.write_text("content", encoding="utf-8")
    dst = tmp_path / "dst.txt"

    # Write initial content
    dst.write_text("old", encoding="utf-8")

    manifest._copy2_replace(str(src), str(dst))

    assert dst.read_text(encoding="utf-8") == "content"


def test_render_firewall_runtime_tasks_empty():
    state = {"roles": {}}
    result = manifest._render_firewall_runtime_tasks(state)
    # Function always returns at least a basic playbook structure
    assert isinstance(result, str)
    assert len(result) > 0


def test_render_firewall_runtime_tasks_with_iptables():
    state = {
        "roles": {
            "firewall_runtime": {
                "role_name": "firewall_runtime",
                "iptables_v4_save": "artifacts/firewall_runtime/iptables.save",
            }
        }
    }
    result = manifest._render_firewall_runtime_tasks(state)
    assert len(result) >= 1


def test_render_firewall_runtime_tasks_with_ipset():
    state = {
        "roles": {
            "firewall_runtime": {
                "role_name": "firewall_runtime",
                "ipset_save": "artifacts/firewall_runtime/ipset.save",
            }
        }
    }
    result = manifest._render_firewall_runtime_tasks(state)
    assert len(result) >= 1


def test_render_firewall_runtime_tasks_with_ipv6():
    state = {
        "roles": {
            "firewall_runtime": {
                "role_name": "firewall_runtime",
                "iptables_v6_save": "artifacts/firewall_runtime/ip6tables.save",
            }
        }
    }
    result = manifest._render_firewall_runtime_tasks(state)
    assert len(result) >= 1


def test_manifest_renders_flatpak_and_snap_details(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
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
                        "gecos": "Alice",
                        "home": "/home/alice",
                        "shell": "/bin/bash",
                        "primary_group": "alice",
                        "supplementary_groups": [],
                    }
                ],
                "managed_files": [],
                "excluded": [],
                "notes": [],
                "user_flatpak_remotes": [
                    {
                        "name": "acme-user",
                        "method": "user",
                        "url": "https://flatpak.example/user-repo/",
                        "user": "alice",
                        "home": "/home/alice",
                    },
                ],
                "user_flatpaks": {
                    "alice": [
                        {
                            "name": "org.example.UserApp",
                            "method": "user",
                            "remote": "acme-user",
                            "branch": "stable",
                            "arch": "x86_64",
                        }
                    ]
                },
            },
            "flatpak": {
                "role_name": "flatpak",
                "remotes": [
                    {
                        "name": "acme",
                        "method": "system",
                        "url": "https://flatpak.example/repo/",
                    },
                ],
                "system_flatpaks": [
                    {
                        "name": "com.example.App",
                        "method": "system",
                        "remote": "acme",
                        "branch": "stable",
                        "arch": "x86_64",
                    }
                ],
                "notes": [],
            },
            "snap": {
                "role_name": "snap",
                "system_snaps": [
                    {
                        "name": "code",
                        "channel": "latest/stable",
                        "revision": 123,
                        "classic": True,
                        "notes": ["classic"],
                    }
                ],
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
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    manifest.manifest(str(bundle), str(out))

    users_defaults = (out / "roles" / "users" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    users_tasks = (out / "roles" / "users" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    users_readme = (out / "roles" / "users" / "README.md").read_text(encoding="utf-8")
    flatpak_defaults = (out / "roles" / "flatpak" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    flatpak_tasks = (out / "roles" / "flatpak" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    snap_defaults = (out / "roles" / "snap" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    snap_tasks = (out / "roles" / "snap" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )

    assert "users_flatpak_remotes:" in users_defaults
    assert "remote: acme-user" in users_defaults
    assert "community.general.snap" not in users_tasks
    assert "Install system-wide snaps" not in users_tasks
    assert "Install system-wide Flatpaks" not in users_tasks
    assert "ansible-galaxy collection install -r requirements.yml" in users_readme

    assert "snap_system_snaps:" in snap_defaults
    assert "channel: latest/stable" in snap_defaults
    assert "classic: true" in snap_defaults
    assert "community.general.snap" in snap_tasks
    assert "Install system-wide snaps with full detected attributes" in snap_tasks
    assert "Install system-wide snaps with compatibility options" in snap_tasks
    assert "Install system-wide snaps with minimal options" in snap_tasks
    assert "ignore_errors: true" in snap_tasks

    assert "flatpak_system_flatpaks:" in flatpak_defaults
    assert "remote: acme" in flatpak_defaults
    assert "community.general.flatpak" in flatpak_tasks
    assert "Install system-wide Flatpaks" in flatpak_tasks
    assert (out / "requirements.yml").exists()


def test_users_role_without_portable_apps_omits_community_general_tasks(tmp_path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "out"
    state = {
        "roles": {
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
                        "supplementary_groups": [],
                    }
                ],
                "managed_files": [],
                "excluded": [],
                "notes": [],
            },
            "services": [],
            "packages": [],
        },
    }
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    manifest.manifest(str(bundle), str(out))

    users_tasks = (out / "roles" / "users" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    users_meta = (out / "roles" / "users" / "meta" / "main.yml").read_text(
        encoding="utf-8"
    )

    assert "community.general.flatpak" not in users_tasks
    assert "community.general.snap" not in users_tasks
    assert "collections:" not in users_meta


def test_manifest_emits_flatpak_role_even_when_no_flatpaks(tmp_path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "out"
    state = {
        "roles": {
            "users": {
                "role_name": "users",
                "users": [],
                "managed_files": [],
                "excluded": [],
                "notes": [],
                "user_flatpaks": {},
                "user_flatpak_remotes": [],
            },
            "flatpak": {
                "role_name": "flatpak",
                "system_flatpaks": [],
                "remotes": [],
                "notes": [],
            },
            "services": [],
            "packages": [],
        }
    }
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    manifest.manifest(str(bundle), str(out))

    flatpak_tasks = (out / "roles" / "flatpak" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    flatpak_defaults = (out / "roles" / "flatpak" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )

    assert "flatpak_system_flatpaks: []" in flatpak_defaults
    assert "flatpak_remotes: []" in flatpak_defaults
    assert "Install system-wide Flatpaks" in flatpak_tasks
    assert "Ensure system Flatpak remotes exist" in flatpak_tasks


def test_manifest_avoids_package_role_collision_with_flatpak_singleton(tmp_path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "out"
    state = {
        "roles": {
            "users": {
                "role_name": "users",
                "users": [],
                "managed_files": [],
                "excluded": [],
                "notes": [],
                "user_flatpaks": {},
                "user_flatpak_remotes": [],
            },
            "flatpak": {
                "role_name": "flatpak",
                "remotes": [
                    {
                        "name": "flathub",
                        "method": "system",
                        "url": "https://dl.flathub.org/repo/",
                    }
                ],
                "system_flatpaks": [
                    {
                        "name": "org.onionshare.OnionShare",
                        "method": "system",
                        "remote": "flathub",
                        "branch": "stable",
                        "arch": "x86_64",
                    }
                ],
                "notes": [],
            },
            "services": [],
            "packages": [
                {
                    "package": "flatpak",
                    "role_name": "flatpak",
                    "managed_files": [],
                    "managed_dirs": [],
                    "managed_links": [],
                    "excluded": [],
                    "notes": [],
                    "has_config": True,
                }
            ],
        }
    }
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    manifest.manifest(str(bundle), str(out), no_common_roles=True)

    flatpak_defaults = (out / "roles" / "flatpak" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    playbook = (out / "playbook.yml").read_text(encoding="utf-8")

    assert "org.onionshare.OnionShare" in flatpak_defaults
    assert (out / "roles" / "package_flatpak" / "tasks" / "main.yml").exists()
    assert "role: flatpak" in playbook
    assert "role: package_flatpak" in playbook


def test_manifest_writes_sysctl_role(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"
    (bundle / "artifacts" / "sysctl" / "sysctl").mkdir(parents=True, exist_ok=True)
    (bundle / "artifacts" / "sysctl" / "sysctl" / "99-enroll.conf").write_text(
        "net.ipv4.ip_forward = 1\n",
        encoding="utf-8",
    )

    state = {
        "schema_version": 3,
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
            "sysctl": {
                "role_name": "sysctl",
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
                "notes": ["Captured 1 live writable sysctl parameter(s)."],
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
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    manifest.manifest(str(bundle), str(out))

    tasks = (out / "roles" / "sysctl" / "tasks" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "dest: /etc/sysctl.d/99-enroll.conf" in tasks
    assert "notify: Apply captured sysctl configuration" in tasks

    handlers = (out / "roles" / "sysctl" / "handlers" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "- -p" in handlers
    assert "- /etc/sysctl.d/99-enroll.conf" in handlers

    defaults = (out / "roles" / "sysctl" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "sysctl_conf_src_rel: sysctl/99-enroll.conf" in defaults
    assert "sysctl_ignore_apply_errors: true" in defaults

    pb = (out / "playbook.yml").read_text(encoding="utf-8")
    assert "role: sysctl" in pb
    assert (out / "roles" / "sysctl" / "files" / "sysctl" / "99-enroll.conf").exists()
