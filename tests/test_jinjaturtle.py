from pathlib import Path

from state_helpers import write_schema_state
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

    # Pin the per-run var-prefix salt so generated variable names are
    # deterministic for this test.
    monkeypatch.setattr(jinjaturtle_mod, "_VAR_PREFIX_SALT", "t")
    expected_prefix = jinjaturtle_mod.managed_file_var_prefix("foo", "etc/foo.ini")

    # Stub jinjaturtle output.
    def fake_run_jinjaturtle(
        jt_exe: str, src_path: str, *, role_name: str, force_format=None
    ):
        assert role_name == expected_prefix
        return JinjifyResult(
            template_text=f"[main]\nkey = {{{{ {role_name}_key }}}}\n",
            vars_text=f"{role_name}_key: 1\n",
        )

    monkeypatch.setattr(jinjaturtle_mod, "run_jinjaturtle", fake_run_jinjaturtle)

    manifest_mod.manifest(str(bundle), str(out), jinjaturtle=True)

    role_dir = out / "roles" / "utils"

    # Template should exist in the grouped section role.
    assert (role_dir / "templates" / "etc" / "foo.ini.j2").exists()

    # Raw file should NOT be copied into role files/ because it was templatised.
    assert not (role_dir / "files" / "etc" / "foo.ini").exists()

    # Defaults should include jinjaturtle vars.
    defaults = (role_dir / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert f"{expected_prefix}_key: 1" in defaults


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
    monkeypatch.setattr(jinjaturtle_mod, "_VAR_PREFIX_SALT", "t")

    pa = jinjaturtle_mod.managed_file_var_prefix("foo", "etc/foo/a.yaml")
    pb = jinjaturtle_mod.managed_file_var_prefix("foo", "etc/foo/b.yaml")

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
        ("a.yaml", pa),
        ("b.yaml", pb),
    ]
    assert f"{pa}_ignore: []" in vars_text
    assert f"{pb}_ignore: []" in vars_text
    assert (template_root / "etc" / "foo" / "a.yaml.j2").read_text(
        encoding="utf-8"
    ) == f"ignore: {{{{ {pa}_ignore }}}}\n"


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


def test_jinjify_managed_files_always_namespaces_single_template(
    monkeypatch, tmp_path: Path
):
    from enroll.jinjaturtle import jinjify_managed_files

    bundle = tmp_path / "bundle"
    template_root = tmp_path / "templates"
    artifact = bundle / "artifacts" / "foo" / "etc" / "foo.yaml"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("managed_files: []\n", encoding="utf-8")

    calls = []

    def fake_run_jinjaturtle(jt_exe, src_path, *, role_name, force_format=None):
        calls.append(role_name)
        return JinjifyResult(
            template_text=f"managed_files: {{{{ {role_name}_managed_files }}}}\n",
            vars_text=f"{role_name}_managed_files: []\n",
        )

    monkeypatch.setattr(jinjaturtle_mod, "run_jinjaturtle", fake_run_jinjaturtle)
    monkeypatch.setattr(jinjaturtle_mod, "_VAR_PREFIX_SALT", "t")
    prefix = jinjaturtle_mod.managed_file_var_prefix("foo", "etc/foo.yaml")

    templated, vars_text = jinjify_managed_files(
        bundle,
        "foo",
        template_root,
        [{"path": "/etc/foo.yaml", "src_rel": "etc/foo.yaml"}],
        jt_exe="jinjaturtle",
        jt_enabled=True,
        overwrite_templates=True,
        role_name="foo",
    )

    assert templated == {"etc/foo.yaml"}
    assert calls == [prefix]
    assert f"{prefix}_managed_files: []" in vars_text
    assert "foo_managed_files:" not in vars_text


def test_jinjify_managed_files_rejects_reserved_role_variable_collision(
    monkeypatch, tmp_path: Path
):
    from enroll.jinjaturtle import jinjify_managed_files

    bundle = tmp_path / "bundle"
    template_root = tmp_path / "templates"
    artifact = bundle / "artifacts" / "foo" / "etc" / "foo.yaml"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("managed_files: []\n", encoding="utf-8")

    def fake_run_jinjaturtle(jt_exe, src_path, *, role_name, force_format=None):
        return JinjifyResult(
            template_text="managed_files: {{ foo_managed_files }}\n",
            vars_text="foo_managed_files: []\n",
        )

    monkeypatch.setattr(jinjaturtle_mod, "run_jinjaturtle", fake_run_jinjaturtle)

    templated, vars_text = jinjify_managed_files(
        bundle,
        "foo",
        template_root,
        [{"path": "/etc/foo.yaml", "src_rel": "etc/foo.yaml"}],
        jt_exe="jinjaturtle",
        jt_enabled=True,
        overwrite_templates=True,
        role_name="foo",
    )

    assert templated == set()
    assert vars_text == ""
    assert not (template_root / "etc" / "foo.yaml.j2").exists()


def test_malicious_json_key_falls_back_to_raw_copy(monkeypatch, tmp_path: Path):
    """A harvested JSON config that injects a Jinja construct in an object key
    must not produce a template. The real JinjaTurtle output-safety gate refuses
    it (exit 2), so Enroll falls back to copying the raw file verbatim.

    Uses the real jinjaturtle binary when present; skipped otherwise.
    """
    import shutil as _shutil

    import pytest

    from enroll.jinjaturtle import jinjify_managed_files

    jt_exe = _shutil.which("jinjaturtle")
    if not jt_exe:
        pytest.skip("jinjaturtle binary not on PATH")

    bundle = tmp_path / "bundle"
    template_root = tmp_path / "templates"
    artifact = bundle / "artifacts" / "foo" / "etc" / "app.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    # Injected key references a (predictable) Enroll-declared variable name; the
    # JSON-key gate must still refuse it regardless of the salt.
    artifact.write_text(
        '{ "{{ ansible_hostname }}": "x", "port": 8080 }', encoding="utf-8"
    )

    templated, vars_text = jinjify_managed_files(
        bundle,
        "foo",
        template_root,
        [{"path": "/etc/app.json", "src_rel": "etc/app.json"}],
        jt_exe=jt_exe,
        jt_enabled=True,
        overwrite_templates=True,
        role_name="foo",
    )

    # No template emitted; the raw file is left to be copied verbatim downstream.
    assert templated == set()
    assert vars_text == ""
    assert not (template_root / "etc" / "app.json.j2").exists()


def test_jinjify_artifact_rejects_unsafe_src_rel(monkeypatch, tmp_path: Path):
    from enroll.jinjaturtle import jinjify_artifact

    bundle = tmp_path / "bundle"
    template_root = tmp_path / "templates"
    outside = tmp_path / "outside.yaml"
    outside.write_text("key: value\n", encoding="utf-8")

    called = False

    def fake_run_jinjaturtle(*_args, **_kwargs):
        nonlocal called
        called = True
        return JinjifyResult(template_text="key: {{ key }}\n", vars_text="key: value\n")

    monkeypatch.setattr(jinjaturtle_mod, "run_jinjaturtle", fake_run_jinjaturtle)

    result = jinjify_artifact(
        bundle,
        "foo",
        "../outside.yaml",
        "/etc/foo.yaml",
        template_root,
        jt_exe="jinjaturtle",
        jt_enabled=True,
    )

    assert result is None
    assert called is False


def test_retained_template_cannot_use_incompatible_new_context(monkeypatch, tmp_path):
    artifact = tmp_path / "bundle" / "artifacts" / "app" / "app.ini"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("port=80\n")
    root = tmp_path / "templates"
    root.mkdir()
    retained = root / "app.ini.j2"
    retained.write_text("port={{ port }}\n")
    monkeypatch.setattr(
        jinjaturtle_mod,
        "run_jinjaturtle",
        lambda *a, **kw: JinjifyResult(
            template_text="listen={{ listen }}\n", vars_text="listen: 8080\n"
        ),
    )
    result = jinjaturtle_mod.jinjify_artifact(
        tmp_path / "bundle",
        "app",
        "app.ini",
        "/etc/app.ini",
        root,
        jt_exe="jinjaturtle",
        jt_enabled=True,
        overwrite_templates=False,
    )
    assert result is None
    assert retained.read_text() == "port={{ port }}\n"
