from __future__ import annotations

import json
from pathlib import Path

import yaml

from state_helpers import write_schema_state

from enroll import manifest
from enroll.puppet import (
    PuppetRole,
    _puppet_name,
    _render_role_class,
    _role_hiera_values,
)


def _write_state(bundle: Path, state: dict) -> None:
    write_schema_state(bundle, state)


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
    assert "node 'test.example' {" in site_pp
    assert "lookup('enroll::classes'" in site_pp
    assert "$enroll_classes.each" in site_pp
    assert "include $enroll_class" in site_pp
    assert "node default {" in site_pp

    assert (out / "hiera.yaml").exists()
    node_data = yaml.safe_load(
        (out / "data" / "nodes" / "test.example.yaml").read_text(encoding="utf-8")
    )
    assert node_data["enroll::classes"] == ["curl", "foo", "users", "sysctl"]
    assert node_data["curl::packages"] == ["curl"]
    assert node_data["foo::packages"] == ["foo"]
    assert node_data["foo::files"]["/etc/foo/foo.conf"]["source"] == (
        "puppet:///modules/foo/nodes/test.example/etc/foo.conf"
    )
    assert node_data["foo::files"]["/etc/foo/foo.conf"]["notify_services"] == [
        "foo.service"
    ]
    assert node_data["foo::services"]["foo.service"] == {
        "ensure": "running",
        "enable": True,
    }
    assert node_data["users::users"]["alice"]["comment"] == "Alice Example"
    assert node_data["users::users"]["alice"]["groups"] == ["docker"]
    assert node_data["sysctl::files"]["/etc/sysctl.d/99-enroll.conf"]["source"] == (
        "puppet:///modules/sysctl/nodes/test.example/sysctl/99-enroll.conf"
    )

    curl_pp = (out / "modules" / "curl" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "class curl" in curl_pp
    assert "Array[String] $packages = []" in curl_pp
    assert "package { $package_name:" in curl_pp
    assert "package { 'curl':" not in curl_pp

    foo_pp = (out / "modules" / "foo" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "class foo" in foo_pp
    assert "Hash[String, Hash] $files = {}" in foo_pp
    assert "* => $attrs" in foo_pp
    assert "package { 'foo':" not in foo_pp
    assert "file { '/etc/foo/foo.conf':" not in foo_pp

    users_pp = (out / "modules" / "users" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "class users" in users_pp
    assert "Hash[String, Hash] $users = {}" in users_pp
    assert "user { 'alice':" not in users_pp

    sysctl_pp = (out / "modules" / "sysctl" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "class sysctl" in sysctl_pp
    assert "Boolean $sysctl_apply = true" in sysctl_pp
    assert "Boolean $sysctl_ignore_apply_errors = true" in sysctl_pp
    assert "exec { 'enroll-apply-sysctl':" in sysctl_pp
    assert (
        "if $sysctl_apply and '/etc/sysctl.d/99-enroll.conf' in $files {" in sysctl_pp
    )

    assert (
        out
        / "modules"
        / "foo"
        / "files"
        / "nodes"
        / "test.example"
        / "etc"
        / "foo.conf"
    ).exists()
    assert (
        out
        / "modules"
        / "sysctl"
        / "files"
        / "nodes"
        / "test.example"
        / "sysctl"
        / "99-enroll.conf"
    ).exists()


def test_manifest_puppet_fqdn_package_notify_service_declared_in_same_role(
    tmp_path: Path,
):
    bundle = tmp_path / "bundle"
    out = tmp_path / "puppet"
    artifact = bundle / "artifacts" / "apparmor" / "etc" / "apparmor" / "parser.conf"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("cache-loc /var/cache/apparmor\n", encoding="utf-8")

    state = {
        "schema_version": 3,
        "host": {"hostname": "vpn-ssh", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {"packages": {"apparmor": {"section": "admin"}}},
        "roles": {
            "services": [
                {
                    "unit": "apparmor.service",
                    "role_name": "apparmor_service",
                    "packages": ["apparmor"],
                    "active_state": "active",
                    "unit_file_state": "enabled",
                    "managed_dirs": [],
                    "managed_files": [],
                    "managed_links": [],
                }
            ],
            "packages": [
                {
                    "package": "apparmor",
                    "role_name": "apparmor",
                    "section": "admin",
                    "managed_dirs": [],
                    "managed_files": [
                        {
                            "path": "/etc/apparmor/parser.conf",
                            "src_rel": "etc/apparmor/parser.conf",
                            "owner": "root",
                            "group": "root",
                            "mode": "0644",
                        }
                    ],
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

    manifest.manifest(str(bundle), str(out), target="puppet", fqdn="vpn-ssh")

    node_data = yaml.safe_load(
        (out / "data" / "nodes" / "vpn-ssh.yaml").read_text(encoding="utf-8")
    )
    assert node_data["apparmor::files"]["/etc/apparmor/parser.conf"][
        "notify_services"
    ] == ["apparmor.service"]
    assert node_data["apparmor::services"]["apparmor.service"] == {
        "ensure": "running",
        "enable": True,
    }

    apparmor_pp = (out / "modules" / "apparmor" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "Hash[String, Hash] $services = {}" in apparmor_pp
    assert "service { $resource_title:" in apparmor_pp
    assert apparmor_pp.index("$services.each") < apparmor_pp.index("$files.each")
    assert "$attrs['notify_services'].map" in apparmor_pp
    assert "notify  => $notify_targets" in apparmor_pp


def test_manifest_puppet_fqdn_mode_can_accumulate_separate_node_data(
    tmp_path: Path,
):
    out = tmp_path / "puppet"

    def write_bundle(name: str, content: str) -> Path:
        bundle = tmp_path / name
        artifact = bundle / "artifacts" / "foo" / "etc" / "foo.conf"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(content, encoding="utf-8")
        _write_state(
            bundle,
            {
                "schema_version": 3,
                "host": {"hostname": name, "os": "debian", "pkg_backend": "dpkg"},
                "inventory": {"packages": {}},
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
                    "packages": [],
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
                    "sysctl": {
                        "role_name": "sysctl",
                        "managed_dirs": [],
                        "managed_files": [],
                    },
                    "firewall_runtime": {
                        "role_name": "firewall_runtime",
                        "packages": [],
                    },
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
            },
        )
        return bundle

    first = write_bundle("first", "first = true\n")
    second = write_bundle("second", "second = true\n")

    manifest.manifest(str(first), str(out), target="puppet", fqdn="first.example")
    manifest.manifest(str(second), str(out), target="puppet", fqdn="second.example")

    assert (out / "data" / "nodes" / "first.example.yaml").exists()
    assert (out / "data" / "nodes" / "second.example.yaml").exists()

    site_pp = (out / "manifests" / "site.pp").read_text(encoding="utf-8")
    assert "node 'first.example' {" in site_pp
    assert "node 'second.example' {" in site_pp

    first_artifact = (
        out
        / "modules"
        / "foo"
        / "files"
        / "nodes"
        / "first.example"
        / "etc"
        / "foo.conf"
    )
    second_artifact = (
        out
        / "modules"
        / "foo"
        / "files"
        / "nodes"
        / "second.example"
        / "etc"
        / "foo.conf"
    )
    assert first_artifact.read_text(encoding="utf-8") == "first = true\n"
    assert second_artifact.read_text(encoding="utf-8") == "second = true\n"

    first_data = yaml.safe_load(
        (out / "data" / "nodes" / "first.example.yaml").read_text(encoding="utf-8")
    )
    second_data = yaml.safe_load(
        (out / "data" / "nodes" / "second.example.yaml").read_text(encoding="utf-8")
    )
    assert first_data["foo::files"]["/etc/foo/foo.conf"]["source"] == (
        "puppet:///modules/foo/nodes/first.example/etc/foo.conf"
    )
    assert second_data["foo::files"]["/etc/foo/foo.conf"]["source"] == (
        "puppet:///modules/foo/nodes/second.example/etc/foo.conf"
    )


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
    assert "notify => Service['foo.service']" in net_pp
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


def test_manifest_puppet_renders_container_images_static_and_hiera(tmp_path: Path):
    digest = "docker.io/library/nginx@sha256:" + "a" * 64
    podman_digest = "quay.io/example/app@sha256:" + "b" * 64
    state = {
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
            "container_images": {
                "role_name": "container_images",
                "images": [
                    {
                        "engine": "docker",
                        "scope": "system",
                        "user": None,
                        "home": None,
                        "image_id": "sha256:" + "c" * 64,
                        "repo_tags": ["docker.io/library/nginx:1.27"],
                        "repo_digests": [digest],
                        "pull_ref": digest,
                        "tag_aliases": [
                            {
                                "ref": "docker.io/library/nginx:1.27",
                                "repository": "docker.io/library/nginx",
                                "tag": "1.27",
                            }
                        ],
                        "os": "linux",
                        "architecture": "amd64",
                        "variant": None,
                        "platform": "linux/amd64",
                        "size": 123,
                        "created": "2026-01-01T00:00:00Z",
                        "source": "docker image inspect",
                        "notes": [],
                    },
                    {
                        "engine": "podman",
                        "scope": "system",
                        "user": None,
                        "home": None,
                        "image_id": "sha256:" + "d" * 64,
                        "repo_tags": ["quay.io/example/app:prod"],
                        "repo_digests": [podman_digest],
                        "pull_ref": podman_digest,
                        "tag_aliases": [],
                        "os": "linux",
                        "architecture": "amd64",
                        "variant": None,
                        "platform": "linux/amd64",
                        "size": 456,
                        "created": "2026-01-01T00:00:00Z",
                        "source": "podman image inspect",
                        "notes": [],
                    },
                ],
                "notes": [],
            },
        }
    }
    bundle = tmp_path / "bundle"
    out = tmp_path / "puppet"
    _write_state(bundle, state)
    manifest.manifest(str(bundle), str(out), target="puppet")

    site_pp = (out / "manifests" / "site.pp").read_text(encoding="utf-8")
    assert "include container_images" in site_pp
    pp = (out / "modules" / "container_images" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "docker::image" not in pp
    assert "docker pull" in pp
    assert "Docker::Image" not in pp
    assert digest in pp
    assert "docker tag" in pp
    assert "podman pull" in pp
    metadata = json.loads(
        (out / "modules" / "container_images" / "metadata.json").read_text(
            encoding="utf-8"
        )
    )
    assert metadata["dependencies"] == []

    fqdn_out = tmp_path / "puppet-fqdn"
    manifest.manifest(str(bundle), str(fqdn_out), target="puppet", fqdn="node.example")
    node_data = yaml.safe_load(
        (fqdn_out / "data" / "nodes" / "node.example.yaml").read_text(encoding="utf-8")
    )
    assert node_data["container_images::container_images"][0]["pull_ref"] == digest
    fqdn_pp = (
        fqdn_out / "modules" / "container_images" / "manifests" / "init.pp"
    ).read_text(encoding="utf-8")
    assert "Array[Hash] $container_images = []" in fqdn_pp
    assert "docker::image" not in fqdn_pp
    assert "enroll-docker-pull-${idx}" in fqdn_pp
    assert "enroll-podman-pull-${idx}" in fqdn_pp
    assert "$image['pull_cmd']" in fqdn_pp
    assert "podman pull" in (
        fqdn_out / "data" / "nodes" / "node.example.yaml"
    ).read_text(encoding="utf-8")


def test_manifest_puppet_renders_firewall_runtime_resources(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "puppet"
    fw_dir = bundle / "artifacts" / "firewall_runtime" / "firewall"
    fw_dir.mkdir(parents=True, exist_ok=True)
    (fw_dir / "ipset.save").write_text(
        "create blocklist hash:ip family inet\nadd blocklist 203.0.113.10\n",
        encoding="utf-8",
    )
    (fw_dir / "iptables.v4").write_text(
        "*filter\n:INPUT DROP [0:0]\n-A INPUT -m set --match-set blocklist src -j DROP\nCOMMIT\n",
        encoding="utf-8",
    )
    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {"packages": {}},
        "roles": {
            "firewall_runtime": {
                "role_name": "firewall_runtime",
                "packages": ["ipset", "iptables"],
                "ipset_save": "firewall/ipset.save",
                "ipset_sets": ["blocklist"],
                "iptables_v4_save": "firewall/iptables.v4",
                "iptables_v6_save": None,
                "notes": [],
            }
        },
    }
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="puppet")

    pp = (out / "modules" / "firewall_runtime" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    runtime_pp = (
        out / "modules" / "enroll_runtime" / "manifests" / "init.pp"
    ).read_text(encoding="utf-8")
    assert "file { '/etc/enroll':" in runtime_pp
    assert "file { '/etc/enroll':" not in pp
    assert "file { '/etc/enroll/firewall':" in pp
    assert "require => File['/etc/enroll']," in pp
    assert "file { '/etc/enroll/firewall/ipset.save':" in pp
    assert "ipset restore -exist" in pp
    assert "ipset flush blocklist" in pp
    assert "iptables-restore /etc/enroll/firewall/iptables.v4" in pp
    assert "refreshonly => true" in pp
    assert "subscribe => File['/etc/enroll/firewall/iptables.v4']" in pp
    assert "iptables-save >" not in pp
    assert "Live firewall runtime snapshots were detected" not in pp
    assert (
        out / "modules" / "firewall_runtime" / "files" / "firewall" / "ipset.save"
    ).exists()

    fqdn_out = tmp_path / "puppet-fqdn"
    manifest.manifest(str(bundle), str(fqdn_out), target="puppet", fqdn="node.example")
    node_data = yaml.safe_load(
        (fqdn_out / "data" / "nodes" / "node.example.yaml").read_text(encoding="utf-8")
    )
    assert "enroll_runtime" in node_data["enroll::classes"]
    assert "firewall_runtime" in node_data["enroll::classes"]
    assert node_data["enroll::classes"].index("enroll_runtime") < node_data[
        "enroll::classes"
    ].index("firewall_runtime")
    assert node_data["enroll_runtime::dirs"]["/etc/enroll"]["ensure"] == "directory"
    assert node_data["firewall_runtime::firewall_runtime"]["ipset_sets"] == [
        "blocklist"
    ]
    assert (
        "ipset restore -exist"
        in node_data["firewall_runtime::firewall_runtime"]["ipset_restore_cmd"]
    )
    assert (
        node_data["firewall_runtime::files"]["/etc/enroll/firewall/ipset.save"][
            "source"
        ]
        == "puppet:///modules/firewall_runtime/nodes/node.example/firewall/ipset.save"
    )
    fqdn_pp = (
        fqdn_out / "modules" / "firewall_runtime" / "manifests" / "init.pp"
    ).read_text(encoding="utf-8")
    assert "Hash $firewall_runtime = {}" in fqdn_pp
    assert "$firewall_runtime['ipset_restore_cmd']" in fqdn_pp


def test_manifest_puppet_omits_firewall_runtime_when_no_rules_were_sampled(
    tmp_path: Path,
):
    bundle = tmp_path / "bundle"
    out = tmp_path / "puppet"
    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {"packages": {}},
        "roles": {
            "firewall_runtime": {
                "role_name": "firewall_runtime",
                "packages": [],
                "ipset_save": None,
                "ipset_sets": [],
                "iptables_v4_save": None,
                "iptables_v6_save": None,
                "notes": [
                    "not running as root; live firewall runtime was not captured"
                ],
            }
        },
    }
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="puppet")

    site_pp = (out / "manifests" / "site.pp").read_text(encoding="utf-8")
    assert "include enroll_runtime" not in site_pp
    assert "include firewall_runtime" not in site_pp
    assert not (out / "modules" / "enroll_runtime").exists()
    assert not (out / "modules" / "firewall_runtime").exists()


def _puppet_flatpak_snap_users_snapshot() -> dict:
    return {
        "users": [
            {
                "name": "alice",
                "uid": 1000,
                "primary_group": "alice",
                "supplementary_groups": ["docker"],
                "home": "/home/alice",
                "shell": "/bin/bash",
                "gecos": "Alice,,,Other",
            }
        ],
        "user_flatpak_remotes": [
            {
                "method": "user",
                "user": "alice",
                "name": "flathub",
                "url": "https://dl.flathub.org/repo/flathub.flatpakrepo",
            }
        ],
        "user_flatpaks": {
            "alice": [
                {
                    "ref": "app/org.foo.App/x86_64/stable",
                    "remote": "flathub",
                }
            ]
        },
    }


def _puppet_system_flatpak_snapshot() -> dict:
    return {
        "remotes": [
            {
                "name": "systemrepo",
                "url": "https://example.invalid/repo.flatpakrepo",
            }
        ],
        "system_flatpaks": [
            {
                "name": "org.system.App",
                "remote": "systemrepo",
            }
        ],
    }


def _puppet_snap_snapshot() -> dict:
    return {
        "system_snaps": [
            {
                "name": "hello-world",
                "tracking": "latest/stable",
                "confinement": "classic",
            },
            {
                "name": "danger-snap",
                "revision": "42",
                "notes": ["installed with --dangerous"],
            },
        ],
    }


def test_puppet_role_renders_flatpaks_snaps_and_user_flatpaks() -> None:
    role = PuppetRole("apps")
    role.add_users_snapshot(_puppet_flatpak_snap_users_snapshot())
    role.add_flatpak_snapshot(_puppet_system_flatpak_snapshot())
    role.add_snap_snapshot(_puppet_snap_snapshot())

    rendered = _render_role_class(role)
    assert "group { 'alice':" in rendered
    assert "user { 'alice':" in rendered
    assert "flatpak --user remote-add --if-not-exists flathub" in rendered
    assert "HOME=/home/alice" in rendered
    assert "require => User['alice']" in rendered
    assert "flatpak --user install -y flathub app/org.foo.App/x86_64/stable" in rendered
    assert "flatpak --system install -y systemrepo org.system.App" in rendered
    assert "snap install hello-world --channel=latest/stable --classic" in rendered
    assert "snap install danger-snap --revision=42 --dangerous" in rendered

    hiera = _role_hiera_values(role)
    assert hiera["apps::flatpak_remotes"][0]["environment"] == [
        "HOME=/home/alice",
        "XDG_DATA_HOME=/home/alice/.local/share",
    ]
    assert hiera["apps::flatpaks"][0]["user"] == "alice"
    assert hiera["apps::snaps"][0]["classic"] is True
    assert hiera["apps::snaps"][1]["dangerous"] is True


def test_puppet_role_records_container_image_limitations() -> None:
    role = PuppetRole("container_images")
    role.add_container_images_snapshot(
        {
            "images": [
                "not-a-dict",
                {"engine": "containerd", "pull_ref": "example.invalid/app@sha256:abc"},
                {
                    "engine": "docker",
                    "repo_tags": ["example.invalid/app:latest"],
                    "pull_ref": "",
                },
            ],
            "notes": ["image capture note"],
        }
    )

    assert role.container_images == []
    assert any("has no RepoDigest" in note for note in role.notes)
    assert role.notes[-1] == "image capture note"


def test_puppet_managed_content_notes_missing_artifacts_and_links(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    module_files = tmp_path / "puppet" / "modules" / "demo" / "files"
    role = PuppetRole("demo")
    role.add_managed_content(
        {
            "managed_dirs": [
                {
                    "path": "/etc/demo",
                    "owner": "root",
                    "group": "root",
                    "mode": "0750",
                }
            ],
            "managed_files": [
                {"path": "", "src_rel": "etc/ignored.conf"},
                {"path": "/etc/missing.conf", "src_rel": "etc/missing.conf"},
            ],
            "managed_links": [
                {"path": "", "target": "/nowhere"},
                {"path": "/etc/demo/current", "target": "/opt/demo/current"},
            ],
        },
        bundle_dir=str(bundle),
        artifact_role="demo",
        module_files_dir=module_files,
    )

    assert role.dirs["/etc/demo"]["mode"] == "0750"
    assert role.links["/etc/demo/current"]["target"] == "/opt/demo/current"
    assert any("Skipped /etc/missing.conf" in note for note in role.notes)


def test_puppet_names_are_sanitised_for_target_reserved_words() -> None:
    assert _puppet_name("") == "role"
    assert _puppet_name("123") == "role_123"
    assert _puppet_name("node") == "role_node"
    assert _puppet_name("web-app") == "web_app"


def test_manifest_puppet_uses_jinjaturtle_erb_templates(monkeypatch, tmp_path: Path):
    import enroll.jinjaturtle as jinjaturtle_mod
    from enroll.jinjaturtle import JinjifyResult

    bundle = tmp_path / "bundle"
    out = tmp_path / "puppet"
    artifact = bundle / "artifacts" / "foo" / "etc" / "foo.ini"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("[main]\nkey = 1\n", encoding="utf-8")

    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {"packages": {}},
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
                            "path": "/etc/foo.ini",
                            "src_rel": "etc/foo.ini",
                            "owner": "root",
                            "group": "root",
                            "mode": "0644",
                        }
                    ],
                    "managed_links": [],
                }
            ],
            "packages": [],
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

    monkeypatch.setattr(
        jinjaturtle_mod, "find_jinjaturtle_cmd", lambda: "/usr/bin/jinjaturtle"
    )
    monkeypatch.setattr(jinjaturtle_mod, "can_jinjify_path", lambda _path: True)

    calls = []

    def fake_run_jinjaturtle(
        jt_exe: str,
        src_path: str,
        *,
        role_name: str,
        force_format=None,
        template_engine: str = "jinja2",
        puppet_class=None,
    ):
        calls.append((role_name, template_engine, puppet_class))
        assert template_engine == "erb"
        assert puppet_class == "foo"
        return JinjifyResult(
            template_text="[main]\nkey = <%= @main_key %>\n",
            vars_text="foo::main_key: 1\n",
        )

    monkeypatch.setattr(jinjaturtle_mod, "run_jinjaturtle", fake_run_jinjaturtle)

    manifest.manifest(
        str(bundle),
        str(out),
        target="puppet",
        jinjaturtle="on",
        no_common_roles=True,
    )

    assert calls == [("foo", "erb", "foo")]
    assert (out / "modules" / "foo" / "templates" / "etc" / "foo.ini.erb").read_text(
        encoding="utf-8"
    ) == "[main]\nkey = <%= @main_key %>\n"
    assert not (out / "modules" / "foo" / "files" / "etc" / "foo.ini").exists()

    init_pp = (out / "modules" / "foo" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "Any $main_key = 1," in init_pp
    assert "content => template('foo/etc/foo.ini.erb')" in init_pp
    assert "source =>" not in init_pp


def test_manifest_puppet_fqdn_writes_erb_template_values_to_node_hiera(
    monkeypatch, tmp_path: Path
):
    import enroll.jinjaturtle as jinjaturtle_mod
    from enroll.jinjaturtle import JinjifyResult

    bundle = tmp_path / "bundle"
    out = tmp_path / "puppet"
    artifact = bundle / "artifacts" / "foo" / "etc" / "foo.ini"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("[main]\nkey = 1\n", encoding="utf-8")
    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {"packages": {}},
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
                        {"path": "/etc/foo.ini", "src_rel": "etc/foo.ini"}
                    ],
                    "managed_links": [],
                }
            ],
            "packages": [],
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

    monkeypatch.setattr(
        jinjaturtle_mod, "find_jinjaturtle_cmd", lambda: "/usr/bin/jinjaturtle"
    )
    monkeypatch.setattr(jinjaturtle_mod, "can_jinjify_path", lambda _path: True)
    monkeypatch.setattr(
        jinjaturtle_mod,
        "run_jinjaturtle",
        lambda *a, **k: JinjifyResult(
            template_text="[main]\nkey = <%= @main_key %>\n",
            vars_text="foo::main_key: 1\n",
        ),
    )

    manifest.manifest(
        str(bundle), str(out), target="puppet", fqdn="test.example", jinjaturtle="on"
    )

    node_data = yaml.safe_load(
        (out / "data" / "nodes" / "test.example.yaml").read_text(encoding="utf-8")
    )
    assert node_data["foo::main_key"] == 1
    assert node_data["foo::files"]["/etc/foo.ini"]["template"] == "foo/etc/foo.ini.erb"
    assert "source" not in node_data["foo::files"]["/etc/foo.ini"]
    init_pp = (out / "modules" / "foo" / "manifests" / "init.pp").read_text(
        encoding="utf-8"
    )
    assert "Any $main_key = undef," in init_pp
    assert "content => template($attrs['template'])" in init_pp
