import json
from pathlib import Path

import enroll.manifest as manifest_mod
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
        "host": {"hostname": "test", "os": "debian"},
        "users": {
            "role_name": "users",
            "users": [],
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
        "package_roles": [],
    }

    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    # Pretend jinjaturtle exists.
    monkeypatch.setattr(
        manifest_mod, "find_jinjaturtle_cmd", lambda: "/usr/bin/jinjaturtle"
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

    monkeypatch.setattr(manifest_mod, "run_jinjaturtle", fake_run_jinjaturtle)

    manifest_mod.manifest(str(bundle), str(out), jinjaturtle="on")

    # Template should exist in the role.
    assert (out / "roles" / "foo" / "templates" / "etc" / "foo.ini.j2").exists()

    # Raw file should NOT be copied into role files/ because it was templatised.
    assert not (out / "roles" / "foo" / "files" / "etc" / "foo.ini").exists()

    # Defaults should include jinjaturtle vars.
    defaults = (out / "roles" / "foo" / "defaults" / "main.yml").read_text(
        encoding="utf-8"
    )
    assert "foo_key: 1" in defaults
