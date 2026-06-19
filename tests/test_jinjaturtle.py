import json
from pathlib import Path

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
    (bundle / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

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
