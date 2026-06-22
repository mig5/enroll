from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

import yaml

from state_helpers import write_schema_state

from enroll import manifest
from enroll.salt import (
    SaltRole,
    _render_pillar_role,
    _render_static_role,
    _role_pillar_values,
    _salt_name,
    _state_id,
)


def _write_state(bundle: Path, state: dict) -> None:
    write_schema_state(bundle, state)


def _sample_state() -> dict:
    return {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {
            "packages": {"foo": {"section": "net"}, "curl": {"section": "net"}}
        },
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
                "managed_links": [],
                "excluded": [],
                "notes": [],
            },
            "services": [
                {
                    "unit": "foo.service",
                    "role_name": "foo",
                    "packages": ["foo"],
                    "active_state": "active",
                    "unit_file_state": "enabled",
                    "managed_dirs": [
                        {
                            "path": "/etc/foo",
                            "owner": "root",
                            "group": "root",
                            "mode": "0755",
                        }
                    ],
                    "managed_files": [
                        {
                            "path": "/etc/foo/foo.conf",
                            "src_rel": "etc/foo.conf",
                            "owner": "root",
                            "group": "root",
                            "mode": "0644",
                        }
                    ],
                    "managed_links": [
                        {"path": "/etc/foo/enabled.conf", "target": "/etc/foo/foo.conf"}
                    ],
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
                "managed_links": [],
            },
            "dnf_config": {
                "role_name": "dnf_config",
                "managed_dirs": [],
                "managed_files": [],
                "managed_links": [],
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
                    }
                ],
                "managed_links": [],
                "parameters": {"net.ipv4.ip_forward": "1"},
                "notes": [],
            },
            "firewall_runtime": {"role_name": "firewall_runtime", "packages": []},
            "etc_custom": {
                "role_name": "etc_custom",
                "managed_dirs": [],
                "managed_files": [],
                "managed_links": [],
            },
            "usr_local_custom": {
                "role_name": "usr_local_custom",
                "managed_dirs": [],
                "managed_files": [],
                "managed_links": [],
            },
            "extra_paths": {
                "role_name": "extra_paths",
                "managed_dirs": [],
                "managed_files": [],
                "managed_links": [],
            },
        },
    }


def _write_sample_artifacts(bundle: Path) -> None:
    artifact = bundle / "artifacts" / "foo" / "etc" / "foo.conf"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("setting = true\n", encoding="utf-8")
    sysctl_artifact = bundle / "artifacts" / "sysctl" / "sysctl" / "99-enroll.conf"
    sysctl_artifact.parent.mkdir(parents=True, exist_ok=True)
    sysctl_artifact.write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")


def test_manifest_salt_writes_single_site_state_tree(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
    _write_sample_artifacts(bundle)
    _write_state(bundle, _sample_state())

    manifest.manifest(str(bundle), str(out), target="salt")

    top = yaml.safe_load((out / "states" / "top.sls").read_text(encoding="utf-8"))
    assert top["base"]["*"] == ["roles.net", "roles.users", "roles.sysctl"]

    net_sls = (out / "states" / "roles" / "net" / "init.sls").read_text(
        encoding="utf-8"
    )
    assert "pkg.installed:" in net_sls
    assert '- name: "curl"' in net_sls
    assert '- name: "foo"' in net_sls
    assert '"/etc/foo/foo.conf":' in net_sls
    assert 'source: "salt://roles/net/files/etc/foo.conf"' in net_sls
    assert "watch_in:" in net_sls
    assert 'service: "enroll_service_net_foo_service_20435514"' in net_sls
    assert "file.symlink:" in net_sls
    assert "service.running:" in net_sls
    assert (out / "states" / "roles" / "net" / "files" / "etc" / "foo.conf").exists()

    users_sls = (out / "states" / "roles" / "users" / "init.sls").read_text(
        encoding="utf-8"
    )
    assert "group.present:" in users_sls
    assert "user.present:" in users_sls
    assert "Alice Example" in users_sls
    assert "optional_groups" not in users_sls
    assert "- remove_groups: false" in users_sls

    sysctl_sls = (out / "states" / "roles" / "sysctl" / "init.sls").read_text(
        encoding="utf-8"
    )
    assert "cmd.run:" in sysctl_sls
    assert "sysctl -e -p /etc/sysctl.d/99-enroll.conf || true" in sysctl_sls
    assert (out / "README.md").exists()
    assert (out / "config" / "master.d" / "enroll.conf").exists()


def test_manifest_salt_fqdn_package_watch_targets_declared_service_role(
    tmp_path: Path,
):
    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
    artifact = bundle / "artifacts" / "apparmor" / "etc" / "apparmor" / "parser.conf"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("cache-loc /var/cache/apparmor\n", encoding="utf-8")

    state = _sample_state()
    state["inventory"] = {"packages": {"apparmor": {"section": "admin"}}}
    state["roles"]["services"] = [
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
    ]
    state["roles"]["packages"] = [
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
    ]
    state["roles"]["sysctl"] = {
        "role_name": "sysctl",
        "managed_dirs": [],
        "managed_files": [],
        "managed_links": [],
    }
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="salt", fqdn="vpn-ssh")

    pillar_top = yaml.safe_load(
        (out / "pillar" / "top.sls").read_text(encoding="utf-8")
    )
    node_sls = pillar_top["base"]["vpn-ssh"][0]
    pillar_path = out / "pillar" / Path(*node_sls.split("."))
    pillar = yaml.safe_load(pillar_path.with_suffix(".sls").read_text(encoding="utf-8"))
    roles = pillar["enroll"]["roles"]
    expected_service_state = _state_id(
        "service", "apparmor.service", role="apparmor_service"
    )

    assert roles["apparmor"]["files"]["/etc/apparmor/parser.conf"]["watch_in"] == [
        {"service": expected_service_state}
    ]
    assert roles["apparmor_service"]["services"]["apparmor.service"]["state_id"] == (
        expected_service_state
    )


def test_manifest_salt_fqdn_mode_uses_pillar_and_accumulates_nodes(tmp_path: Path):
    out = tmp_path / "salt"

    def write_bundle(name: str, content: str) -> Path:
        bundle = tmp_path / name
        _write_sample_artifacts(bundle)
        (bundle / "artifacts" / "foo" / "etc" / "foo.conf").write_text(
            content, encoding="utf-8"
        )
        state = _sample_state()
        state["host"]["hostname"] = name
        _write_state(bundle, state)
        return bundle

    first = write_bundle("first", "first=true\n")
    second = write_bundle("second", "second=true\n")

    manifest.manifest(str(first), str(out), target="salt", fqdn="first.example")
    manifest.manifest(str(second), str(out), target="salt", fqdn="second.example")

    state_top = yaml.safe_load((out / "states" / "top.sls").read_text(encoding="utf-8"))
    assert state_top["base"]["first.example"] == [
        "roles.curl",
        "roles.foo",
        "roles.users",
        "roles.sysctl",
    ]
    assert state_top["base"]["second.example"] == [
        "roles.curl",
        "roles.foo",
        "roles.users",
        "roles.sysctl",
    ]

    pillar_top = yaml.safe_load(
        (out / "pillar" / "top.sls").read_text(encoding="utf-8")
    )
    assert set(pillar_top["base"]) == {"first.example", "second.example"}
    first_pillar_sls = pillar_top["base"]["first.example"][0]
    first_node = out / "pillar" / Path(*first_pillar_sls.split("."))
    first_data = yaml.safe_load(
        first_node.with_suffix(".sls").read_text(encoding="utf-8")
    )
    assert first_data["enroll"]["classes"] == [
        "roles.curl",
        "roles.foo",
        "roles.users",
        "roles.sysctl",
    ]
    assert first_data["enroll"]["roles"]["foo"]["packages"] == ["foo"]
    assert first_data["enroll"]["roles"]["foo"]["files"]["/etc/foo/foo.conf"][
        "source"
    ] == ("salt://roles/foo/files/nodes/first.example/etc/foo.conf")

    foo_sls = (out / "states" / "roles" / "foo" / "init.sls").read_text(
        encoding="utf-8"
    )
    assert "salt['pillar.get']('enroll:roles:foo'" in foo_sls
    assert "pkg.installed:" in foo_sls
    assert "file.managed:" in foo_sls
    assert (
        out
        / "states"
        / "roles"
        / "foo"
        / "files"
        / "nodes"
        / "first.example"
        / "etc"
        / "foo.conf"
    ).exists()
    assert (
        out
        / "states"
        / "roles"
        / "foo"
        / "files"
        / "nodes"
        / "second.example"
        / "etc"
        / "foo.conf"
    ).exists()


def test_manifest_salt_user_gecos_and_groups_are_salt_safe(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
    state = _sample_state()
    state["roles"]["users"]["users"][0]["name"] = "node"
    state["roles"]["users"]["users"][0]["primary_group"] = "node"
    state["roles"]["users"]["users"][0]["gid"] = 1000
    state["roles"]["users"]["users"][0]["gecos"] = "Node,,,"
    _write_sample_artifacts(bundle)
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="salt")

    users_sls = (out / "states" / "roles" / "users" / "init.sls").read_text(
        encoding="utf-8"
    )
    assert '- fullname: "Node"' in users_sls
    assert "Node,,," not in users_sls
    assert "optional_groups" not in users_sls
    assert "- remove_groups: false" in users_sls


def test_manifest_salt_fqdn_user_pillar_gecos_and_groups_are_salt_safe(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
    state = _sample_state()
    state["roles"]["users"]["users"][0]["gecos"] = "Node,,,"
    _write_sample_artifacts(bundle)
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="salt", fqdn="node.example")

    pillar_top = yaml.safe_load(
        (out / "pillar" / "top.sls").read_text(encoding="utf-8")
    )
    node_sls = pillar_top["base"]["node.example"][0]
    pillar_path = out / "pillar" / Path(*node_sls.split("."))
    data = yaml.safe_load(pillar_path.with_suffix(".sls").read_text(encoding="utf-8"))
    alice = data["enroll"]["roles"]["users"]["users"]["alice"]
    assert alice["fullname"] == "Node"
    assert "Node,,," not in pillar_path.with_suffix(".sls").read_text(encoding="utf-8")
    assert alice["remove_groups"] is False
    assert "optional_groups" not in pillar_path.with_suffix(".sls").read_text(
        encoding="utf-8"
    )

    users_sls = (out / "states" / "roles" / "users" / "init.sls").read_text(
        encoding="utf-8"
    )
    assert "optional_groups" not in users_sls
    assert "remove_groups" in users_sls


def test_cli_manifest_target_salt_is_forwarded(monkeypatch, tmp_path):
    import sys

    import enroll.cli as cli

    called = {}

    def fake_manifest(harvest_dir: str, out_dir: str, **kwargs):
        called["harvest"] = harvest_dir
        called["out"] = out_dir
        called["target"] = kwargs.get("target")

    monkeypatch.setattr(cli, "manifest", fake_manifest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "manifest",
            "--harvest",
            str(tmp_path / "bundle"),
            "--out",
            str(tmp_path / "salt"),
            "--target",
            "salt",
        ],
    )

    cli.main()
    assert called["harvest"] == str(tmp_path / "bundle")
    assert called["out"] == str(tmp_path / "salt")
    assert called["target"] == "salt"


def test_manifest_salt_renders_container_images_in_single_and_fqdn_modes(
    tmp_path: Path,
):
    digest = "docker.io/library/nginx@sha256:" + "a" * 64
    podman_digest = "quay.io/example/app@sha256:" + "b" * 64
    state = _sample_state()
    state["roles"]["container_images"] = {
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
                "tag_aliases": [
                    {
                        "ref": "quay.io/example/app:prod",
                        "repository": "quay.io/example/app",
                        "tag": "prod",
                    }
                ],
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
    }
    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
    _write_sample_artifacts(bundle)
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="salt")

    top = yaml.safe_load((out / "states" / "top.sls").read_text(encoding="utf-8"))
    assert "roles.container_images" in top["base"]["*"]
    sls = (out / "states" / "roles" / "container_images" / "init.sls").read_text(
        encoding="utf-8"
    )
    assert "docker_image.present:" not in sls
    assert "docker pull" in sls
    assert digest in sls
    assert "docker image inspect" in sls
    assert "{{.Id}}" not in sls
    assert "sed -n" in sls
    assert "docker tag" in sls
    assert "- cmd: enroll_docker_pull_container_images" in sls
    assert "podman pull" in sls
    assert "podman tag" in sls

    fqdn_out = tmp_path / "salt-fqdn"
    manifest.manifest(str(bundle), str(fqdn_out), target="salt", fqdn="node.example")
    pillar_top = yaml.safe_load(
        (fqdn_out / "pillar" / "top.sls").read_text(encoding="utf-8")
    )
    node_sls = pillar_top["base"]["node.example"][0]
    pillar_path = fqdn_out / "pillar" / Path(*node_sls.split("."))
    pillar = yaml.safe_load(pillar_path.with_suffix(".sls").read_text(encoding="utf-8"))
    assert (
        pillar["enroll"]["roles"]["container_images"]["container_images"][0]["pull_ref"]
        == digest
    )
    fqdn_sls = (
        fqdn_out / "states" / "roles" / "container_images" / "init.sls"
    ).read_text(encoding="utf-8")
    assert "docker_image.present:" not in fqdn_sls
    assert "enroll_docker_pull_container_images" in fqdn_sls
    assert "enroll_podman_pull_container_images" in fqdn_sls
    assert "image.get('pull_cmd')" in fqdn_sls
    pillar_text = pillar_path.with_suffix(".sls").read_text(encoding="utf-8")
    assert "docker pull" in pillar_text
    assert "docker image inspect" in pillar_text
    assert "{{.Id}}" not in pillar_text
    assert "sed -n" in pillar_text
    assert "podman pull" in pillar_text


def test_manifest_salt_uses_jinjaturtle_templates(monkeypatch, tmp_path: Path):
    import enroll.jinjaturtle as jinjaturtle_mod
    from enroll.jinjaturtle import JinjifyResult

    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
    state = _sample_state()
    _write_sample_artifacts(bundle)
    _write_state(bundle, state)

    monkeypatch.setattr(
        jinjaturtle_mod, "find_jinjaturtle_cmd", lambda: "/usr/bin/jinjaturtle"
    )
    monkeypatch.setattr(jinjaturtle_mod, "can_jinjify_path", lambda _path: True)

    def fake_run_jinjaturtle(
        jt_exe: str, src_path: str, *, role_name: str, force_format=None
    ):
        assert jt_exe == "/usr/bin/jinjaturtle"
        assert role_name == "foo"
        assert src_path.endswith("artifacts/foo/etc/foo.conf")
        return JinjifyResult(
            template_text="setting = {{ foo_setting }}\n",
            vars_text="foo_setting: true\n",
        )

    monkeypatch.setattr(jinjaturtle_mod, "run_jinjaturtle", fake_run_jinjaturtle)

    manifest.manifest(str(bundle), str(out), target="salt", jinjaturtle="on")

    role_dir = out / "states" / "roles" / "net"
    assert (role_dir / "templates" / "etc" / "foo.conf.j2").read_text(
        encoding="utf-8"
    ) == "setting = {{ foo_setting }}\n"
    assert not (role_dir / "files" / "etc" / "foo.conf").exists()
    sls = (role_dir / "init.sls").read_text(encoding="utf-8")
    assert 'source: "salt://roles/net/templates/etc/foo.conf.j2"' in sls
    assert 'template: "jinja"' in sls
    assert "foo_setting: true" in sls

    fqdn_out = tmp_path / "salt-fqdn"
    manifest.manifest(
        str(bundle),
        str(fqdn_out),
        target="salt",
        fqdn="node.example",
        jinjaturtle="on",
    )

    fqdn_role_dir = fqdn_out / "states" / "roles" / "foo"
    assert (fqdn_role_dir / "templates" / "etc" / "foo.conf.j2").exists()
    assert not (
        fqdn_role_dir / "files" / "nodes" / "node.example" / "etc" / "foo.conf"
    ).exists()
    pillar_top = yaml.safe_load(
        (fqdn_out / "pillar" / "top.sls").read_text(encoding="utf-8")
    )
    node_sls = pillar_top["base"]["node.example"][0]
    pillar_path = fqdn_out / "pillar" / Path(*node_sls.split("."))
    pillar = yaml.safe_load(pillar_path.with_suffix(".sls").read_text(encoding="utf-8"))
    file_data = pillar["enroll"]["roles"]["foo"]["files"]["/etc/foo/foo.conf"]
    assert file_data["source"] == "salt://roles/foo/templates/etc/foo.conf.j2"
    assert file_data["watch_in"] == [
        {"service": "enroll_service_foo_foo_service_20435514"}
    ]
    assert file_data["template"] == "jinja"
    assert file_data["context"] == {"foo_setting": True}


def test_manifest_salt_rewrites_jinjaturtle_json_filters(monkeypatch, tmp_path: Path):
    import enroll.jinjaturtle as jinjaturtle_mod
    from enroll.jinjaturtle import JinjifyResult

    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
    state = _sample_state()
    _write_sample_artifacts(bundle)
    _write_state(bundle, state)

    monkeypatch.setattr(
        jinjaturtle_mod, "find_jinjaturtle_cmd", lambda: "/usr/bin/jinjaturtle"
    )
    monkeypatch.setattr(jinjaturtle_mod, "can_jinjify_path", lambda _path: True)

    def fake_run_jinjaturtle(
        jt_exe: str, src_path: str, *, role_name: str, force_format=None
    ):
        return JinjifyResult(
            template_text='{ "setting": {{ foo_setting | to_json(ensure_ascii=False) }} }\n',
            vars_text='foo_setting: "alpha"\n',
        )

    monkeypatch.setattr(jinjaturtle_mod, "run_jinjaturtle", fake_run_jinjaturtle)

    manifest.manifest(str(bundle), str(out), target="salt", jinjaturtle="on")

    template_text = (
        out / "states" / "roles" / "net" / "templates" / "etc" / "foo.conf.j2"
    ).read_text(encoding="utf-8")
    assert "to_json" not in template_text
    assert "foo_setting__enroll_json" in template_text
    sls = (out / "states" / "roles" / "net" / "init.sls").read_text(encoding="utf-8")
    assert "foo_setting__enroll_json:" in sls
    assert '"alpha"' in sls


def test_manifest_salt_pillar_role_uses_json_for_template_context() -> None:
    role = SaltRole("foo")
    role.add_managed_file(
        "/etc/foo.json",
        source="salt://roles/foo/templates/etc/foo.json.j2",
        user="root",
        group="root",
        mode="0644",
        makedirs=True,
        template="jinja",
        context=OrderedDict(
            [("foo_name", "alpha"), ("foo_nested", OrderedDict([("x", 1)]))]
        ),
    )

    pillar = _role_pillar_values(role)
    assert type(pillar["files"]["/etc/foo.json"]["context"]) is dict
    assert type(pillar["files"]["/etc/foo.json"]["context"]["foo_nested"]) is dict

    rendered = _render_static_role(role)
    assert "foo_nested:" in rendered
    context_block = (
        _render_pillar_role(role).split("context:", 1)[1].split("{% endif %}", 1)[0]
    )
    assert "|yaml_encode" not in context_block
    assert "|tojson" in _render_pillar_role(role)


def test_manifest_salt_renders_firewall_runtime_states(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
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

    manifest.manifest(str(bundle), str(out), target="salt")

    top = yaml.safe_load((out / "states" / "top.sls").read_text(encoding="utf-8"))
    assert "roles.enroll_runtime" in top["base"]["*"]
    assert top["base"]["*"].index("roles.enroll_runtime") < top["base"]["*"].index(
        "roles.firewall_runtime"
    )
    runtime_sls = (out / "states" / "roles" / "enroll_runtime" / "init.sls").read_text(
        encoding="utf-8"
    )
    assert '"/etc/enroll":' in runtime_sls
    sls = (out / "states" / "roles" / "firewall_runtime" / "init.sls").read_text(
        encoding="utf-8"
    )
    assert '"/etc/enroll":' not in sls
    assert '"/etc/enroll/firewall":' in sls
    assert '- file: "/etc/enroll"' in sls
    assert '"/etc/enroll/firewall/ipset.save":' in sls
    assert "ipset restore -exist" in sls
    assert "ipset flush blocklist" in sls
    assert "iptables-restore /etc/enroll/firewall/iptables.v4" in sls
    assert "    - onchanges:" in sls
    assert '      - file: "/etc/enroll/firewall/iptables.v4"' in sls
    assert "iptables-save >" not in sls
    assert "Live firewall runtime snapshots were detected" not in sls
    assert (
        out
        / "states"
        / "roles"
        / "firewall_runtime"
        / "files"
        / "firewall"
        / "ipset.save"
    ).exists()

    fqdn_out = tmp_path / "salt-fqdn"
    manifest.manifest(str(bundle), str(fqdn_out), target="salt", fqdn="node.example")
    pillar_top = yaml.safe_load(
        (fqdn_out / "pillar" / "top.sls").read_text(encoding="utf-8")
    )
    node_sls = pillar_top["base"]["node.example"][0]
    pillar_path = fqdn_out / "pillar" / Path(*node_sls.split("."))
    pillar = yaml.safe_load(pillar_path.with_suffix(".sls").read_text(encoding="utf-8"))
    assert "roles.enroll_runtime" in pillar["enroll"]["classes"]
    assert "firewall_runtime" in pillar["enroll"]["roles"]
    assert (
        pillar["enroll"]["roles"]["enroll_runtime"]["dirs"]["/etc/enroll"]["mode"]
        == "0750"
    )
    role_data = pillar["enroll"]["roles"]["firewall_runtime"]
    assert role_data["firewall_runtime"]["ipset_sets"] == ["blocklist"]
    assert "ipset restore -exist" in role_data["firewall_runtime"]["ipset_restore_cmd"]
    assert role_data["files"]["/etc/enroll/firewall/ipset.save"]["source"] == (
        "salt://roles/firewall_runtime/files/nodes/node.example/firewall/ipset.save"
    )
    fqdn_sls = (
        fqdn_out / "states" / "roles" / "firewall_runtime" / "init.sls"
    ).read_text(encoding="utf-8")
    assert "firewall_runtime.get('ipset_restore_cmd')" in fqdn_sls


def test_manifest_salt_omits_firewall_runtime_when_no_rules_were_sampled(
    tmp_path: Path,
):
    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
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

    manifest.manifest(str(bundle), str(out), target="salt")

    top = yaml.safe_load((out / "states" / "top.sls").read_text(encoding="utf-8"))
    assert "roles.enroll_runtime" not in top["base"]["*"]
    assert "roles.firewall_runtime" not in top["base"]["*"]
    assert not (out / "states" / "roles" / "enroll_runtime").exists()
    assert not (out / "states" / "roles" / "firewall_runtime").exists()


def _salt_flatpak_snap_users_snapshot() -> dict:
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


def _salt_system_flatpak_snapshot() -> dict:
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


def _salt_snap_snapshot() -> dict:
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


def test_salt_role_renders_flatpaks_snaps_and_user_flatpaks() -> None:
    role = SaltRole("apps")
    role.add_users_snapshot(_salt_flatpak_snap_users_snapshot())
    role.add_flatpak_snapshot(_salt_system_flatpak_snapshot())
    role.add_snap_snapshot(_salt_snap_snapshot())

    rendered = _render_static_role(role)
    assert "group.present:" in rendered
    assert "user.present:" in rendered
    assert "flatpak --user remote-add --if-not-exists flathub" in rendered
    assert '      - HOME: "/home/alice"' in rendered
    assert "      - user: enroll_user_apps_alice_522b276a" in rendered
    assert "flatpak --user install -y flathub app/org.foo.App/x86_64/stable" in rendered
    assert "flatpak --system install -y systemrepo org.system.App" in rendered
    assert "snap install hello-world --channel=latest/stable --classic" in rendered
    assert "snap install danger-snap --revision=42 --dangerous" in rendered

    pillar = _role_pillar_values(role)
    assert pillar["flatpak_remotes"][0]["env"] == {
        "HOME": "/home/alice",
        "XDG_DATA_HOME": "/home/alice/.local/share",
    }
    assert pillar["flatpaks"][0]["user"] == "alice"
    assert pillar["snaps"][0]["classic"] is True
    assert pillar["snaps"][1]["dangerous"] is True


def test_salt_role_records_container_image_limitations() -> None:
    role = SaltRole("container_images")
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


def test_salt_managed_content_notes_missing_artifacts_and_links(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    role_files = tmp_path / "salt" / "states" / "roles" / "demo" / "files"
    role = SaltRole("demo")
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
        role_files_dir=role_files,
    )

    assert role.dirs["/etc/demo"]["mode"] == "0750"
    assert role.links["/etc/demo/current"]["target"] == "/opt/demo/current"
    assert any("Skipped /etc/missing.conf" in note for note in role.notes)


def test_salt_names_are_sanitised_for_target_reserved_words() -> None:
    assert _salt_name("") == "role"
    assert _salt_name("123") == "role_123"
    assert _salt_name("top") == "role_top"
    assert _salt_name("web-app") == "web_app"


def test_manifest_salt_static_escapes_harvested_jinja_delimiters(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
    state = _sample_state()
    payload = "{{ salt['cmd.run']('touch /tmp/PWNED_BY_ENROLL_SALT') }}"
    state["roles"]["users"]["users"][0]["gecos"] = payload
    _write_sample_artifacts(bundle)
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="salt")

    users_sls = (out / "states" / "roles" / "users" / "init.sls").read_text(
        encoding="utf-8"
    )
    assert payload not in users_sls
    assert "\\u007b\\u007b salt['cmd.run']" in users_sls

    calls = []

    class FakeCmd:
        def run(self, command):
            calls.append(command)
            return "EXECUTED"

    from jinja2 import Template

    rendered = Template(users_sls).render(salt={"cmd.run": FakeCmd().run})
    rendered_data = yaml.safe_load(rendered)
    assert calls == []
    user_state = next(
        state
        for state in rendered_data.values()
        if isinstance(state, dict) and "user.present" in state
    )
    attrs = user_state["user.present"]
    fullname = next(item["fullname"] for item in attrs if "fullname" in item)
    assert fullname == payload


def test_manifest_salt_fqdn_escapes_harvested_jinja_delimiters_in_pillar(
    tmp_path: Path,
):
    bundle = tmp_path / "bundle"
    out = tmp_path / "salt"
    state = _sample_state()
    payload = "{{ salt['cmd.run']('touch /tmp/PWNED_BY_ENROLL_SALT') }}"
    state["roles"]["users"]["users"][0]["gecos"] = payload
    _write_sample_artifacts(bundle)
    _write_state(bundle, state)

    manifest.manifest(str(bundle), str(out), target="salt", fqdn="node.example")

    pillar_top = yaml.safe_load(
        (out / "pillar" / "top.sls").read_text(encoding="utf-8")
    )
    node_sls = pillar_top["base"]["node.example"][0]
    pillar_path = out / "pillar" / Path(*node_sls.split("."))
    text = pillar_path.with_suffix(".sls").read_text(encoding="utf-8")
    assert payload not in text
    assert "\\u007b\\u007b salt['cmd.run']" in text

    calls = []

    class FakeCmd:
        def run(self, command):
            calls.append(command)
            return "EXECUTED"

    from jinja2 import Template

    rendered = Template(text).render(salt={"cmd.run": FakeCmd().run})
    rendered_data = yaml.safe_load(rendered)
    assert calls == []
    assert (
        rendered_data["enroll"]["roles"]["users"]["users"]["alice"]["fullname"]
        == payload
    )
