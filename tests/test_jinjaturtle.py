from pathlib import Path

from tests.state_helpers import write_schema_state

import enroll.manifest as manifest_mod
import enroll.jinjaturtle as jinjaturtle_mod
from enroll.jinjaturtle import JinjifyResult


def test_manifest_uses_jinjaturtle_templates_and_does_not_copy_raw(
    monkeypatch, tmp_path: Path
):
    """If jinjaturtle can templatisize a file, we should store a template in the role
    and avoid keeping the raw file copy in the destination files area.

    This test stubs out jinjaturtle execution so it doesn't depend on the external tool.
    """

    bundle = tmp_path / "bundle"
    out = tmp_path / "ansible"

    # A jinjaturtle-compatible config file.
    (bundle / "artifacts" / "foo" / "etc").mkdir(parents=True, exist_ok=True)
    (bundle / "artifacts" / "foo" / "etc" / "foo.ini").write_text(
        "[main]\nkey = 1\n", encoding="utf-8"
    )

    state = {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {
            "packages": {
                "foo": {
                    "version": "1.0",
                    "arches": [],
                    "installations": [
                        {"version": "1.0", "arch": "amd64", "section": "utils"}
                    ],
                    "section": "utils",
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
                    "active_state": "inactive",
                    "sub_state": "dead",
                    "unit_file_state": "disabled",
                    "condition_result": "no",
                    "managed_files": [
                        {
                            "path": "/etc/foo.ini",
                            "src_rel": "etc/foo.ini",
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
    write_schema_state(bundle, state)

    # Pretend jinjaturtle exists.
    monkeypatch.setattr(
        jinjaturtle_mod, "find_jinjaturtle_cmd", lambda: "/usr/bin/jinjaturtle"
    )

    # Stub jinjaturtle output.
    def fake_run_jinjaturtle(
        jt_exe: str, src_path: str, *, role_name: str, force_format=None
    ):
        assert role_name == "foo"
        return JinjifyResult(
            template_text="[main]\nkey = {{ foo_key }}\n",
            vars_text="foo_key: 1\n",
        )

    monkeypatch.setattr(jinjaturtle_mod, "run_jinjaturtle", fake_run_jinjaturtle)

    manifest_mod.manifest(str(bundle), str(out), jinjaturtle="on")

    role_dir = out / "roles" / "utils"

    # Template should exist in the grouped section role.
    assert (role_dir / "templates" / "etc" / "foo.ini.j2").exists()

    # Raw file should NOT be copied into role files/ because it was templatised.
    assert not (role_dir / "files" / "etc" / "foo.ini").exists()

    # Defaults should include jinjaturtle vars.
    defaults = (role_dir / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert "foo_key: 1" in defaults


def test_openssh_paths_are_jinjaturtle_supported_and_forced_to_ssh() -> None:
    from enroll.jinjaturtle import can_jinjify_path, infer_other_formats

    assert infer_other_formats("/etc/ssh/sshd_config") == "ssh"
    assert infer_other_formats("/etc/ssh/ssh_config") == "ssh"
    assert infer_other_formats("/etc/ssh/sshd_config.d/50-hardening.conf") == "ssh"
    assert infer_other_formats("/etc/ssh/ssh_config.d/99-proxy.conf") == "ssh"

    assert can_jinjify_path("/etc/ssh/sshd_config")
    assert can_jinjify_path("/etc/ssh/ssh_config")


def test_jinjify_managed_files_namespaces_multiple_templates(
    monkeypatch, tmp_path: Path
):
    from enroll.jinjaturtle import jinjify_managed_files

    bundle = tmp_path / "bundle"
    template_root = tmp_path / "templates"
    for rel in ("etc/foo/a.yaml", "etc/foo/b.yaml"):
        path = bundle / "artifacts" / "foo" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ignore: []\n", encoding="utf-8")

    calls = []

    def fake_run_jinjaturtle(jt_exe, src_path, *, role_name, force_format=None):
        calls.append((Path(src_path).name, role_name))
        return JinjifyResult(
            template_text=f"ignore: {{{{ {role_name}_ignore }}}}\n",
            vars_text=f"{role_name}_ignore: []\n",
        )

    monkeypatch.setattr(jinjaturtle_mod, "run_jinjaturtle", fake_run_jinjaturtle)

    templated, vars_text = jinjify_managed_files(
        bundle,
        "foo",
        template_root,
        [
            {"path": "/etc/foo/a.yaml", "src_rel": "etc/foo/a.yaml"},
            {"path": "/etc/foo/b.yaml", "src_rel": "etc/foo/b.yaml"},
        ],
        jt_exe="jinjaturtle",
        jt_enabled=True,
        overwrite_templates=True,
        role_name="foo",
    )

    assert templated == {"etc/foo/a.yaml", "etc/foo/b.yaml"}
    assert calls == [
        ("a.yaml", "foo_etc_foo_a_yaml"),
        ("b.yaml", "foo_etc_foo_b_yaml"),
    ]
    assert "foo_etc_foo_a_yaml_ignore: []" in vars_text
    assert "foo_etc_foo_b_yaml_ignore: []" in vars_text
    assert (template_root / "etc" / "foo" / "a.yaml.j2").read_text(
        encoding="utf-8"
    ) == "ignore: {{ foo_etc_foo_a_yaml_ignore }}\n"


def test_jinjify_managed_files_rejects_templates_with_missing_defaults(
    monkeypatch, tmp_path: Path
):
    from enroll.jinjaturtle import jinjify_managed_files

    bundle = tmp_path / "bundle"
    template_root = tmp_path / "templates"
    artifact = bundle / "artifacts" / "foo" / "etc" / "foo" / "pdk.yaml"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("ignore: []\n", encoding="utf-8")

    def fake_run_jinjaturtle(jt_exe, src_path, *, role_name, force_format=None):
        return JinjifyResult(
            template_text=f"ignore: {{{{ {role_name}_ignore }}}}\n",
            vars_text="--- {}\n",
        )

    monkeypatch.setattr(jinjaturtle_mod, "run_jinjaturtle", fake_run_jinjaturtle)

    templated, vars_text = jinjify_managed_files(
        bundle,
        "foo",
        template_root,
        [{"path": "/etc/foo/pdk.yaml", "src_rel": "etc/foo/pdk.yaml"}],
        jt_exe="jinjaturtle",
        jt_enabled=True,
        overwrite_templates=True,
        role_name="foo",
    )

    assert templated == set()
    assert vars_text == ""
    assert not (template_root / "etc" / "foo" / "pdk.yaml.j2").exists()
