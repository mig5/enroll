import shutil

import pytest
import yaml

from enroll.manifest import manifest
from enroll.manifest_safety import ManifestOutputError
from enroll.multihost import host_role_alias, read_metadata, role_index, tree_index
from state_helpers import write_schema_state


def bundle(
    root, *, content="same\n", package="one", destination="/etc/example", role="app"
):
    artifact = root / "artifacts" / role / "config"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(content)
    write_schema_state(
        root,
        {
            "roles": {
                "packages": [
                    {
                        "role_name": role,
                        "package": package,
                        "managed_files": [
                            {
                                "path": destination,
                                "src_rel": "config",
                                "owner": "root",
                                "group": "root",
                                "mode": "0644",
                                "reason": "custom_unowned",
                            }
                        ],
                    }
                ]
            }
        },
    )
    return root


def apt_bundle(root, content):
    artifact = root / "artifacts/apt_config/etc/apt/sources.list"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(content)
    write_schema_state(
        root,
        {
            "roles": {
                "apt_config": {
                    "role_name": "apt_config",
                    "managed_files": [
                        {
                            "path": "/etc/apt/sources.list",
                            "src_rel": "etc/apt/sources.list",
                            "owner": "root",
                            "group": "root",
                            "mode": "0644",
                            "reason": "apt_config",
                        }
                    ],
                }
            }
        },
    )
    return root


def generate(src, out, host, **kwargs):
    manifest(
        str(src), str(out), host=host, no_common_roles=True, jinjaturtle=False, **kwargs
    )


def test_host_role_alias_is_readable_and_distinct():
    assert host_role_alias("httpd", "ashpool.mig5.net") == (
        "httpd__host_ashpool_mig5_net_34f62c26a93d"
    )
    assert host_role_alias("httpd", "ashpool-mig5-net") != host_role_alias(
        "httpd", "ashpool.mig5.net"
    )
    assert len(host_role_alias("a" * 200, "host" * 60)) <= 255


def test_extend_without_original_harvest_preserves_host_edits(tmp_path):
    first = bundle(tmp_path / "first")
    out = tmp_path / "project"
    generate(first, out, "web1")
    shutil.rmtree(first)
    variables = out / "inventory/host_vars/web1/main.yml"
    variables.write_text(
        variables.read_text() + "ansible_host: 192.0.2.1\ncustom_setting: keep\n"
    )
    before = variables.read_bytes()
    role_before = tree_index(out / "roles/app")
    second = bundle(tmp_path / "second", package="two", destination="/etc/other")
    generate(second, out, "web2", extend=True)
    assert variables.read_bytes() == before
    assert tree_index(out / "roles/app") == role_before
    new = yaml.safe_load((out / "inventory/host_vars/web2/main.yml").read_text())
    assert new["app_packages"] == ["two"]
    assert new["app_managed_files"][0]["dest"] == "/etc/other"
    assert yaml.safe_load((out / "roles/app/defaults/main.yml").read_text()) == {}
    assert set(read_metadata(out)["hosts"]) == {"web1", "web2"}
    for host in ("web1", "web2"):
        assert (
            yaml.safe_load((out / "playbooks" / f"{host}.yml").read_text())[0]["hosts"]
            == host
        )


@pytest.mark.parametrize(
    "change",
    [
        "role_edit",
        "artifact_edit",
        "duplicate",
        "control",
        "symlink",
        "hardlink",
        "deleted_role",
    ],
)
def test_refused_extension_leaves_project_unchanged(tmp_path, change):
    first = bundle(tmp_path / "first")
    second = bundle(
        tmp_path / "second", content="different\n" if change == "file" else "same\n"
    )
    out = tmp_path / "project"
    generate(first, out, "web1")
    if change == "role_edit":
        (out / "roles/app/tasks/main.yml").write_text("---\n[]\n")
    elif change == "artifact_edit":
        (out / "roles/app/files/config").write_text("operator edit\n")
    elif change == "control":
        (out / "playbook.yml").write_text("---\n[]\n")
    elif change == "deleted_role":
        shutil.rmtree(out / "roles/app")
    elif change == "symlink":
        (out / "link").symlink_to(first)
    elif change == "hardlink":
        (out / "linked").hardlink_to(out / "README.md")
    # Raw bytes snapshot also works for deliberately unsafe project entries.
    before = {
        str(p.relative_to(out)): p.read_bytes() for p in out.rglob("*") if p.is_file()
    }
    with pytest.raises((ManifestOutputError, RuntimeError)):
        generate(second, out, "web1" if change == "duplicate" else "web2", extend=True)
    after = {
        str(p.relative_to(out)): p.read_bytes() for p in out.rglob("*") if p.is_file()
    }
    assert after == before


def test_new_role_added_existing_role_edit_preserved(tmp_path):
    out = tmp_path / "project"
    generate(bundle(tmp_path / "first"), out, "web1")
    edited = out / "roles/app/tasks/main.yml"
    edited.write_text("---\n[]\n")
    generate(bundle(tmp_path / "second", role="other"), out, "web2", extend=True)
    assert edited.read_text() == "---\n[]\n"
    assert (out / "roles/other/tasks/main.yml").exists()


def test_different_role_artifacts_remain_host_specific(tmp_path):
    out = tmp_path / "project"
    generate(bundle(tmp_path / "first", content="first\n"), out, "web1")
    generate(bundle(tmp_path / "second", content="second\n"), out, "web2", extend=True)
    metadata = read_metadata(out)
    roles = {host: metadata["hosts"][host]["roles"][0] for host in ("web1", "web2")}
    assert roles["web1"] == "app"
    assert roles["web2"] == "app"
    assert (out / "inventory/host_files/web1/app/files/config").read_text() == "first\n"
    assert (
        out / "inventory/host_files/web2/app/files/config"
    ).read_text() == "second\n"
    assert not (out / "roles/app/files/config").exists()
    for host, role in roles.items():
        play = yaml.safe_load((out / "playbooks" / f"{host}.yml").read_text())
        assert play[0]["roles"][0]["role"] == role
    assert metadata["roles"][roles["web2"]] == role_index(out / "roles" / roles["web2"])
    generate(bundle(tmp_path / "third", content="first\n"), out, "web3", extend=True)
    assert "app" in read_metadata(out)["hosts"]["web3"]["roles"]
    assert (out / "inventory/host_files/web3/app/files/config").read_text() == "first\n"


def test_identical_artifacts_stay_in_shared_role(tmp_path):
    out = tmp_path / "project"
    for host in ("web1", "web2", "web3"):
        generate(
            bundle(tmp_path / host, content="shared\n"),
            out,
            host,
            extend=host != "web1",
        )
    assert (out / "roles/app/files/config").read_text() == "shared\n"
    assert not (out / "inventory/host_files").exists()
    assert {
        read_metadata(out)["hosts"][host]["roles"][0]
        for host in ("web1", "web2", "web3")
    } == {"app"}


def test_different_apt_role_updates_early_phase_import(tmp_path):
    out = tmp_path / "project"
    generate(apt_bundle(tmp_path / "first", "deb first\n"), out, "web1")
    generate(apt_bundle(tmp_path / "second", "deb second\n"), out, "web2", extend=True)
    role = next(
        r
        for r in read_metadata(out)["hosts"]["web2"]["roles"]
        if r.startswith("apt_config")
    )
    assert role == "apt_config"
    play = yaml.safe_load((out / "playbooks/web2.yml").read_text())[0]
    assert any(
        task.get("ansible.builtin.import_role", {}).get("name") == role
        for task in play["pre_tasks"]
    )
    assert not (out / "roles/apt_config/files/etc/apt/sources.list").exists()
    assert (
        out / "inventory/host_files/web1/apt_config/files/etc/apt/sources.list"
    ).read_text() == "deb first\n"
    assert (
        out / "inventory/host_files/web2/apt_config/files/etc/apt/sources.list"
    ).read_text() == "deb second\n"


def test_only_differing_artifact_is_promoted_for_all_later_hosts(tmp_path):
    def source(root, content):
        role = root / "artifacts/apt_config/etc/apt"
        role.mkdir(parents=True)
        (role / "sources.list").write_text(content)
        (role / "common.conf").write_text("shared\n")
        write_schema_state(
            root,
            {
                "roles": {
                    "apt_config": {
                        "role_name": "apt_config",
                        "managed_files": [
                            {
                                "path": "/etc/apt/" + name,
                                "src_rel": "etc/apt/" + name,
                                "owner": "root",
                                "group": "root",
                                "mode": "0644",
                                "reason": "apt_config",
                            }
                            for name in ("sources.list", "common.conf")
                        ],
                    }
                }
            },
        )
        return root

    out = tmp_path / "project"
    for host, content in (
        ("web1", "first\n"),
        ("web2", "second\n"),
        ("web3", "first\n"),
    ):
        generate(source(tmp_path / host, content), out, host, extend=host != "web1")
        assert "apt_config" in read_metadata(out)["hosts"][host]["roles"]
    assert (
        out / "roles/apt_config/files/etc/apt/common.conf"
    ).read_text() == "shared\n"
    assert not (out / "roles/apt_config/files/etc/apt/sources.list").exists()
    for host, content in (
        ("web1", "first\n"),
        ("web2", "second\n"),
        ("web3", "first\n"),
    ):
        assert (
            out / f"inventory/host_files/{host}/apt_config/files/etc/apt/sources.list"
        ).read_text() == content


def test_extension_rejects_missing_artifact_in_existing_host_role(tmp_path):
    out = tmp_path / "project"
    generate(bundle(tmp_path / "first"), out, "web1")
    variables = out / "inventory/host_vars/web1/main.yml"
    values = yaml.safe_load(variables.read_text())
    values["app_managed_files"][0]["src_rel"] = "missing-file"
    variables.write_text(yaml.safe_dump(values))
    before = tree_index(out)
    with pytest.raises(ManifestOutputError, match="Missing generated role artifact"):
        generate(bundle(tmp_path / "second", role="other"), out, "web2", extend=True)
    assert tree_index(out) == before


@pytest.mark.parametrize(
    "host",
    ["../bad", "all", "ungrouped", "web:other", "web\nother", "-bad", "{{ bad }}"],
)
def test_unsafe_host_names_refused(tmp_path, host):
    with pytest.raises(ManifestOutputError):
        generate(bundle(tmp_path / "bundle"), tmp_path / "project", host)
    assert not (tmp_path / "project").exists()


def test_extension_requires_host_and_plain_project(tmp_path):
    with pytest.raises(ValueError, match="requires"):
        manifest("unused", "unused", extend=True)
    with pytest.raises(ValueError, match="no --sops"):
        manifest(
            "unused", "unused", extend=True, host="host", sops_fingerprints=["key"]
        )


def test_failed_atomic_publication_preserves_project(tmp_path, monkeypatch):
    from enroll import multihost

    out = tmp_path / "project"
    generate(bundle(tmp_path / "first"), out, "web1")
    before = tree_index(out)

    def fail(*args):
        raise ManifestOutputError("filesystem lacks atomic exchange")

    monkeypatch.setattr(multihost, "atomic_exchange", fail)
    with pytest.raises(ManifestOutputError, match="atomic"):
        generate(bundle(tmp_path / "second"), out, "web2", extend=True)
    assert tree_index(out) == before


def test_two_host_project_executes_shared_roles_with_isolated_settings(tmp_path):
    import os
    import subprocess
    import sys
    from enroll.yamlutil import yaml_dump_mapping

    ansible_path = os.environ.get("ENROLL_TEST_ANSIBLE_PYTHONPATH")
    if not ansible_path:
        pytest.skip("set ENROLL_TEST_ANSIBLE_PYTHONPATH for Ansible execution")
    out = tmp_path / "project"
    for host in ("web1", "web2"):
        source = tmp_path / host
        artifact = source / "artifacts/etc_custom/config"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("shared content\n")
        write_schema_state(
            source,
            {
                "roles": {
                    "etc_custom": {
                        "managed_files": [
                            {
                                "path": str(tmp_path / f"{host}.conf"),
                                "src_rel": "config",
                                "owner": str(os.getuid()),
                                "group": str(os.getgid()),
                                "mode": "0644",
                                "reason": "custom_unowned",
                            }
                        ]
                    }
                }
            },
        )
        generate(source, out, host, extend=host == "web2")
        variables = out / "inventory/host_vars" / host / "main.yml"
        values = yaml.safe_load(variables.read_text())
        values.update(
            ansible_connection="local", ansible_python_interpreter=sys.executable
        )
        variables.write_text(yaml_dump_mapping(values))
    command = [
        sys.executable,
        "-m",
        "ansible.cli.playbook",
        "-i",
        "inventory/hosts.yml",
        "playbook.yml",
    ]
    env = dict(
        os.environ,
        PYTHONPATH=ansible_path,
        ANSIBLE_NOCOLOR="1",
        ANSIBLE_FORCE_COLOR="0",
    )
    run = subprocess.run(
        command + ["--limit", "web1"],
        cwd=out,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert (tmp_path / "web1.conf").read_text() == "shared content\n"
    assert not (tmp_path / "web2.conf").exists()
    run = subprocess.run(
        command, cwd=out, env=env, capture_output=True, text=True, timeout=60
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert (tmp_path / "web2.conf").read_text() == "shared content\n"


def test_concurrent_project_edit_aborts_publication(tmp_path, monkeypatch):
    from enroll import multihost

    out = tmp_path / "project"
    generate(bundle(tmp_path / "first"), out, "web1")
    original = multihost.merge_project

    def edit_during_merge(*args):
        original(*args)
        (out / "operator-note.txt").write_text("keep this edit")

    monkeypatch.setattr(multihost, "merge_project", edit_during_merge)
    with pytest.raises(ManifestOutputError, match="changed during"):
        generate(bundle(tmp_path / "second"), out, "web2", extend=True)
    assert (out / "operator-note.txt").read_text() == "keep this edit"
    assert set(read_metadata(out)["hosts"]) == {"web1"}


def test_added_control_file_and_options_mismatch_refused(tmp_path):
    out = tmp_path / "project"
    first, second = bundle(tmp_path / "first"), bundle(tmp_path / "second")
    generate(first, out, "web1")
    with pytest.raises(ManifestOutputError, match="options differ"):
        manifest(str(second), str(out), host="web2", extend=True, jinjaturtle=False)
    (out / "playbooks/extra.yml").write_text("[]\n")
    before = tree_index(out)
    with pytest.raises(ManifestOutputError, match="control was edited"):
        generate(second, out, "web2", extend=True)
    assert tree_index(out) == before


def test_extension_from_inside_project_refused(tmp_path, monkeypatch):
    out = tmp_path / "project"
    first, second = bundle(tmp_path / "first"), bundle(tmp_path / "second")
    generate(first, out, "web1")
    before = tree_index(out)
    monkeypatch.chdir(out)
    with pytest.raises(ManifestOutputError, match="outside"):
        generate(second, out, "web2", extend=True)
    assert tree_index(out) == before


def test_host_input_order_does_not_change_effective_project(tmp_path):
    sources = {
        "web1": bundle(tmp_path / "first", package="one"),
        "web2": bundle(tmp_path / "second", package="two"),
    }
    for name, order in (("forward", ["web1", "web2"]), ("reverse", ["web2", "web1"])):
        for index, host in enumerate(order):
            generate(sources[host], tmp_path / name, host, extend=bool(index))
    assert tree_index(tmp_path / "forward") == tree_index(tmp_path / "reverse")
