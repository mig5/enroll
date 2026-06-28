from __future__ import annotations

import os
import tarfile
from pathlib import Path

import pytest

from enroll.ansible import _role_tag
from enroll.manifest_safety import freeze_directory_bundle
from enroll.diff import (
    _Spinner,
    _utc_now_iso,
    _report_markdown,
)


def _make_bundle_dir(tmp_path: Path) -> Path:
    b = tmp_path / "bundle"
    (b / "artifacts").mkdir(parents=True)
    (b / "state.json").write_text("{}\n", encoding="utf-8")
    return b


def _tar_gz_of_dir(src: Path, out: Path) -> None:
    with tarfile.open(out, mode="w:gz") as tf:
        # tar -C src . semantics
        for p in src.rglob("*"):
            rel = p.relative_to(src)
            tf.add(p, arcname=str(rel))


def test_bundle_from_directory_and_statejson_path(tmp_path: Path):
    import enroll.diff as d

    b = _make_bundle_dir(tmp_path)

    # Plain resolution (no freeze) returns the directory in place. Freezing is
    # opt-in and exercised by the consumer-level tests below.
    br1 = d._bundle_from_input(str(b), sops_mode=False)
    assert br1.dir == b
    assert br1.state_path.exists()

    br2 = d._bundle_from_input(str(b / "state.json"), sops_mode=False)
    assert br2.dir == b


def test_bundle_from_input_directory_freeze_copies_and_protects(tmp_path: Path):
    import enroll.diff as d

    b = _make_bundle_dir(tmp_path)
    art = b / "artifacts" / "app"
    art.mkdir(parents=True)
    (art / "f.conf").write_text("orig\n", encoding="utf-8")

    # With freeze=True the bundle is copied into a private temp dir, and mutating
    # the source afterwards does not change the frozen copy.
    result = d._bundle_from_input(str(b), sops_mode=False, freeze=True)
    try:
        assert result.dir != b
        assert result.tempdir is not None
        frozen_f = result.dir / "artifacts" / "app" / "f.conf"
        assert frozen_f.read_text(encoding="utf-8") == "orig\n"

        # Attacker rewrites the source after the freeze; frozen copy is unaffected.
        (art / "f.conf").write_text("tampered\n", encoding="utf-8")
        assert frozen_f.read_text(encoding="utf-8") == "orig\n"
    finally:
        if result.tempdir:
            result.tempdir.cleanup()


def test_bundle_from_tarball_extracts(tmp_path: Path):
    import enroll.diff as d

    b = _make_bundle_dir(tmp_path)
    tgz = tmp_path / "bundle.tgz"
    _tar_gz_of_dir(b, tgz)

    br = d._bundle_from_input(str(tgz), sops_mode=False)
    try:
        assert br.dir.is_dir()
        assert (br.dir / "state.json").exists()
    finally:
        if br.tempdir:
            br.tempdir.cleanup()


def test_bundle_from_sops_like_file(monkeypatch, tmp_path: Path):
    import enroll.diff as d

    b = _make_bundle_dir(tmp_path)
    tgz = tmp_path / "bundle.tar.gz"
    _tar_gz_of_dir(b, tgz)

    # Pretend the tarball is an encrypted bundle by giving it a .sops name.
    sops_path = tmp_path / "bundle.tar.gz.sops"
    sops_path.write_bytes(tgz.read_bytes())

    # Stub out sops machinery: "decrypt" just copies through.
    monkeypatch.setattr(d, "require_sops_cmd", lambda: "sops")

    def fake_decrypt(src: Path, dest: Path, mode: int):
        dest.write_bytes(Path(src).read_bytes())
        try:
            os.chmod(dest, mode)
        except OSError:
            pass

    monkeypatch.setattr(d, "decrypt_file_binary_to", fake_decrypt)

    br = d._bundle_from_input(str(sops_path), sops_mode=False)
    try:
        assert (br.dir / "state.json").exists()
    finally:
        if br.tempdir:
            br.tempdir.cleanup()


def test_bundle_from_input_missing_path(tmp_path: Path):
    import enroll.diff as d

    with pytest.raises(RuntimeError, match="not found"):
        d._bundle_from_input(str(tmp_path / "nope"), sops_mode=False)


import json
import sys


from enroll.diff import (
    _bundle_from_input,
    _file_index,
    _iter_managed_files,
    _load_state,
    _pkg_version_display,
    _pkg_version_key,
    _progress_enabled,
    _roles,
    _service_units,
    _sha256,
    _users_by_name,
    compare_harvests,
)
from enroll.sopsutil import SopsError


def test_progress_enabled_when_tty(monkeypatch):
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    monkeypatch.delenv("ENROLL_NO_PROGRESS", raising=False)
    assert _progress_enabled() is True


def test_progress_enabled_when_not_tty(monkeypatch):
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    monkeypatch.delenv("ENROLL_NO_PROGRESS", raising=False)
    assert _progress_enabled() is False


def test_progress_enabled_with_env_var(monkeypatch):
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    monkeypatch.setenv("ENROLL_NO_PROGRESS", "1")
    assert _progress_enabled() is False

    monkeypatch.setenv("ENROLL_NO_PROGRESS", "true")
    assert _progress_enabled() is False

    monkeypatch.setenv("ENROLL_NO_PROGRESS", "yes")
    assert _progress_enabled() is False


def test_sha256(tmp_path: Path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world", encoding="utf-8")
    hash_result = _sha256(test_file)
    assert len(hash_result) == 64


def test_sha256_empty_file(tmp_path: Path):
    test_file = tmp_path / "empty.txt"
    test_file.write_bytes(b"")
    hash_result = _sha256(test_file)
    assert (
        hash_result
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_bundle_from_input_directory(tmp_path: Path):
    result = _bundle_from_input(str(tmp_path), sops_mode=False)
    assert result.dir == tmp_path
    assert result.tempdir is None


def test_bundle_from_input_state_json_path(tmp_path: Path):
    state_file = tmp_path / "state.json"
    state_file.write_text("{}", encoding="utf-8")
    result = _bundle_from_input(str(state_file), sops_mode=False)
    assert result.dir == tmp_path
    assert result.tempdir is None


def test_bundle_from_input_not_found():
    with pytest.raises(RuntimeError) as exc_info:
        _bundle_from_input("/nonexistent/path", sops_mode=False)
    assert "not found" in str(exc_info.value).lower()


def test_bundle_from_input_tarball(tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    state_file = bundle_dir / "state.json"
    state_file.write_text("{}", encoding="utf-8")

    tar_path = tmp_path / "bundle.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(bundle_dir, arcname="bundle")

    result = _bundle_from_input(str(tar_path), sops_mode=False)
    assert result.dir.exists()
    assert result.tempdir is not None
    result.tempdir.cleanup()


def test_bundle_from_input_invalid_type(tmp_path: Path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("not a bundle", encoding="utf-8")

    with pytest.raises(RuntimeError) as exc_info:
        _bundle_from_input(str(test_file), sops_mode=False)
    assert "not a directory" in str(exc_info.value).lower()


def test_load_state(tmp_path: Path):
    state_file = tmp_path / "state.json"
    state_file.write_text('{"host": {"hostname": "test"}}', encoding="utf-8")
    result = _load_state(tmp_path)
    assert result["host"]["hostname"] == "test"


def test_roles_with_roles():
    state = {"roles": {"users": {}, "services": []}}
    result = _roles(state)
    assert "users" in result


def test_service_units_empty():
    assert _service_units({}) == {}


def test_service_units_with_services():
    state = {
        "roles": {
            "services": [
                {"unit": "nginx.service", "active_state": "active"},
                {"unit": "ssh.service", "active_state": "inactive"},
            ]
        }
    }
    result = _service_units(state)
    assert "nginx.service" in result
    assert "ssh.service" in result
    assert result["nginx.service"]["active_state"] == "active"


def test_users_by_name_empty():
    assert _users_by_name({}) == {}


def test_users_by_name_with_users():
    state = {
        "roles": {
            "users": {
                "users": [
                    {"name": "alice", "uid": 1000},
                    {"name": "bob", "uid": 1001},
                ]
            }
        }
    }
    result = _users_by_name(state)
    assert "alice" in result
    assert "bob" in result
    assert result["alice"]["uid"] == 1000


def test_pkg_version_key_with_version():
    entry = {"version": "1.2.3"}
    assert _pkg_version_key(entry) == "1.2.3"


def test_pkg_version_key_with_installations():
    entry = {
        "installations": [
            {"arch": "x86_64", "version": "1.2.3"},
            {"arch": "aarch64", "version": "1.2.3"},
        ]
    }
    result = _pkg_version_key(entry)
    assert "x86_64:1.2.3" in result
    assert "aarch64:1.2.3" in result


def test_pkg_version_key_with_empty_version():
    entry = {"version": None}
    assert _pkg_version_key(entry) is None


def test_pkg_version_key_with_invalid_installations():
    entry = {"installations": ["not_a_dict", {"arch": "x86_64", "version": "1.0"}]}
    result = _pkg_version_key(entry)
    assert "x86_64:1.0" in result


def test_pkg_version_display_with_version():
    entry = {"version": "1.2.3"}
    assert _pkg_version_display(entry) == "1.2.3"


def test_pkg_version_display_with_installations():
    entry = {
        "installations": [
            {"arch": "x86_64", "version": "1.2.3"},
        ]
    }
    assert _pkg_version_display(entry) == "1.2.3 (x86_64)"


def test_pkg_version_display_empty():
    assert _pkg_version_display({}) is None


def test_iter_managed_files_empty():
    state = {"roles": {}}
    files = list(_iter_managed_files(state))
    assert files == []


def test_iter_managed_files_services():
    state = {
        "roles": {
            "services": [
                {
                    "role_name": "nginx",
                    "managed_files": [
                        {"path": "/etc/nginx/nginx.conf", "src_rel": "nginx.conf"}
                    ],
                }
            ]
        }
    }
    files = list(_iter_managed_files(state))
    assert len(files) == 1
    assert files[0] == (
        "nginx",
        {"path": "/etc/nginx/nginx.conf", "src_rel": "nginx.conf"},
    )


def test_iter_managed_files_packages():
    state = {
        "roles": {
            "packages": [
                {
                    "role_name": "vim",
                    "managed_files": [{"path": "/usr/bin/vim", "src_rel": "bin/vim"}],
                }
            ]
        }
    }
    files = list(_iter_managed_files(state))
    assert len(files) == 1
    assert files[0][0] == "vim"


def test_iter_managed_files_users():
    state = {
        "roles": {
            "users": {
                "role_name": "users",
                "managed_files": [{"path": "/etc/passwd", "src_rel": "passwd"}],
            }
        }
    }
    files = list(_iter_managed_files(state))
    assert len(files) == 1
    assert files[0][0] == "users"


def test_iter_managed_files_apt_config():
    state = {
        "roles": {
            "apt_config": {
                "role_name": "apt_config",
                "managed_files": [
                    {"path": "/etc/apt/sources.list", "src_rel": "sources.list"}
                ],
            }
        }
    }
    files = list(_iter_managed_files(state))
    assert len(files) == 1
    assert files[0][0] == "apt_config"


def test_iter_managed_files_etc_custom():
    state = {
        "roles": {
            "etc_custom": {
                "role_name": "etc_custom",
                "managed_files": [
                    {"path": "/etc/custom.conf", "src_rel": "custom.conf"}
                ],
            }
        }
    }
    files = list(_iter_managed_files(state))
    assert len(files) == 1
    assert files[0][0] == "etc_custom"


def test_iter_managed_files_usr_local_custom():
    state = {
        "roles": {
            "usr_local_custom": {
                "role_name": "usr_local_custom",
                "managed_files": [
                    {"path": "/usr/local/bin/script", "src_rel": "bin/script"}
                ],
            }
        }
    }
    files = list(_iter_managed_files(state))
    assert len(files) == 1
    assert files[0][0] == "usr_local_custom"


def test_iter_managed_files_extra_paths():
    state = {
        "roles": {
            "extra_paths": {
                "role_name": "extra_paths",
                "managed_files": [{"path": "/opt/app/config", "src_rel": "config"}],
            }
        }
    }
    files = list(_iter_managed_files(state))
    assert len(files) == 1
    assert files[0][0] == "extra_paths"


def test_file_index_empty():
    state = {"roles": {}}
    index = _file_index(Path("/tmp"), state)
    assert index == {}


def test_file_index_with_files(tmp_path: Path):
    state = {
        "roles": {
            "users": {
                "managed_files": [
                    {"path": "/etc/passwd", "src_rel": "passwd", "owner": "root"},
                ]
            }
        }
    }
    index = _file_index(tmp_path, state)
    assert "/etc/passwd" in index
    assert index["/etc/passwd"].role == "users"
    assert index["/etc/passwd"].owner == "root"


def test_file_index_duplicates_first_wins(tmp_path: Path):
    state = {
        "roles": {
            "users": {
                "managed_files": [
                    {"path": "/etc/passwd", "src_rel": "passwd"},
                ]
            },
            "etc_custom": {
                "managed_files": [
                    {"path": "/etc/passwd", "src_rel": "custom_passwd"},
                ]
            },
        }
    }
    index = _file_index(tmp_path, state)
    assert "/etc/passwd" in index
    assert index["/etc/passwd"].src_rel == "passwd"


def test_file_index_skips_missing_path_or_src_rel(tmp_path: Path):
    state = {
        "roles": {
            "users": {
                "managed_files": [
                    {"path": "/etc/passwd"},  # missing src_rel
                    {"src_rel": "passwd"},  # missing path
                ]
            }
        }
    }
    index = _file_index(tmp_path, state)
    assert index == {}


def test_compare_harvests_no_changes(tmp_path: Path):
    old_bundle = tmp_path / "old"
    old_bundle.mkdir()
    (old_bundle / "state.json").write_text(
        json.dumps(
            {
                "inventory": {"packages": {"vim": {"version": "1.0"}}},
                "roles": {},
            }
        ),
        encoding="utf-8",
    )

    new_bundle = tmp_path / "new"
    new_bundle.mkdir()
    (new_bundle / "state.json").write_text(
        json.dumps(
            {
                "inventory": {"packages": {"vim": {"version": "1.0"}}},
                "roles": {},
            }
        ),
        encoding="utf-8",
    )

    report, has_changes = compare_harvests(str(old_bundle), str(new_bundle))
    assert has_changes is False
    assert report["packages"]["added"] == []
    assert report["packages"]["removed"] == []


def test_compare_harvests_package_added(tmp_path: Path):
    old_bundle = tmp_path / "old"
    old_bundle.mkdir()
    (old_bundle / "state.json").write_text(
        json.dumps({"inventory": {"packages": {}}, "roles": {}}),
        encoding="utf-8",
    )

    new_bundle = tmp_path / "new"
    new_bundle.mkdir()
    (new_bundle / "state.json").write_text(
        json.dumps(
            {"inventory": {"packages": {"vim": {"version": "1.0"}}}, "roles": {}}
        ),
        encoding="utf-8",
    )

    report, has_changes = compare_harvests(str(old_bundle), str(new_bundle))
    assert has_changes is True
    assert "vim" in report["packages"]["added"]


def test_compare_harvests_package_removed(tmp_path: Path):
    old_bundle = tmp_path / "old"
    old_bundle.mkdir()
    (old_bundle / "state.json").write_text(
        json.dumps(
            {"inventory": {"packages": {"vim": {"version": "1.0"}}}, "roles": {}}
        ),
        encoding="utf-8",
    )

    new_bundle = tmp_path / "new"
    new_bundle.mkdir()
    (new_bundle / "state.json").write_text(
        json.dumps({"inventory": {"packages": {}}, "roles": {}}),
        encoding="utf-8",
    )

    report, has_changes = compare_harvests(str(old_bundle), str(new_bundle))
    assert has_changes is True
    assert "vim" in report["packages"]["removed"]


def test_compare_harvests_package_version_changed(tmp_path: Path):
    old_bundle = tmp_path / "old"
    old_bundle.mkdir()
    (old_bundle / "state.json").write_text(
        json.dumps(
            {"inventory": {"packages": {"vim": {"version": "1.0"}}}, "roles": {}}
        ),
        encoding="utf-8",
    )

    new_bundle = tmp_path / "new"
    new_bundle.mkdir()
    (new_bundle / "state.json").write_text(
        json.dumps(
            {"inventory": {"packages": {"vim": {"version": "2.0"}}}, "roles": {}}
        ),
        encoding="utf-8",
    )

    report, has_changes = compare_harvests(str(old_bundle), str(new_bundle))
    assert has_changes is True
    assert len(report["packages"]["version_changed"]) == 1


def test_compare_harvests_ignore_package_versions(tmp_path: Path):
    old_bundle = tmp_path / "old"
    old_bundle.mkdir()
    (old_bundle / "state.json").write_text(
        json.dumps(
            {"inventory": {"packages": {"vim": {"version": "1.0"}}}, "roles": {}}
        ),
        encoding="utf-8",
    )

    new_bundle = tmp_path / "new"
    new_bundle.mkdir()
    (new_bundle / "state.json").write_text(
        json.dumps(
            {"inventory": {"packages": {"vim": {"version": "2.0"}}}, "roles": {}}
        ),
        encoding="utf-8",
    )

    report, has_changes = compare_harvests(
        str(old_bundle), str(new_bundle), ignore_package_versions=True
    )
    assert report["packages"]["version_changed_ignored_count"] == 1


def test_compare_harvests_service_added(tmp_path: Path):
    old_bundle = tmp_path / "old"
    old_bundle.mkdir()
    (old_bundle / "state.json").write_text(
        json.dumps({"inventory": {"packages": {}}, "roles": {"services": []}}),
        encoding="utf-8",
    )

    new_bundle = tmp_path / "new"
    new_bundle.mkdir()
    (new_bundle / "state.json").write_text(
        json.dumps(
            {
                "inventory": {"packages": {}},
                "roles": {"services": [{"unit": "nginx.service"}]},
            }
        ),
        encoding="utf-8",
    )

    report, has_changes = compare_harvests(str(old_bundle), str(new_bundle))
    assert has_changes is True
    assert "nginx.service" in report["services"]["enabled_added"]


def test_compare_harvests_user_added(tmp_path: Path):
    old_bundle = tmp_path / "old"
    old_bundle.mkdir()
    (old_bundle / "state.json").write_text(
        json.dumps({"inventory": {"packages": {}}, "roles": {"users": {"users": []}}}),
        encoding="utf-8",
    )

    new_bundle = tmp_path / "new"
    new_bundle.mkdir()
    (new_bundle / "state.json").write_text(
        json.dumps(
            {
                "inventory": {"packages": {}},
                "roles": {"users": {"users": [{"name": "alice", "uid": 1000}]}},
            }
        ),
        encoding="utf-8",
    )

    report, has_changes = compare_harvests(str(old_bundle), str(new_bundle))
    assert has_changes is True
    assert "alice" in report["users"]["added"]


def test_compare_harvests_with_exclude_paths(tmp_path: Path):
    old_bundle = tmp_path / "old"
    old_bundle.mkdir()
    old_artifacts = old_bundle / "artifacts" / "users"
    old_artifacts.mkdir(parents=True)
    (old_artifacts / "passwd").write_text("old", encoding="utf-8")
    (old_bundle / "state.json").write_text(
        json.dumps(
            {
                "inventory": {"packages": {}},
                "roles": {
                    "users": {
                        "managed_files": [{"path": "/etc/passwd", "src_rel": "passwd"}]
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    new_bundle = tmp_path / "new"
    new_bundle.mkdir()
    new_artifacts = new_bundle / "artifacts" / "users"
    new_artifacts.mkdir(parents=True)
    (new_artifacts / "passwd").write_text("new", encoding="utf-8")
    (new_bundle / "state.json").write_text(
        json.dumps(
            {
                "inventory": {"packages": {}},
                "roles": {
                    "users": {
                        "managed_files": [{"path": "/etc/passwd", "src_rel": "passwd"}]
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    report, has_changes = compare_harvests(
        str(old_bundle), str(new_bundle), exclude_paths=["/etc/passwd"]
    )
    assert "/etc/passwd" not in [f["path"] for f in report["files"]["added"]]
    assert "/etc/passwd" not in [f["path"] for f in report["files"]["removed"]]
    assert "/etc/passwd" not in [f["path"] for f in report["files"]["changed"]]


def test_compare_harvests_rejects_unsafe_artifact_symlink(tmp_path: Path):
    secret = tmp_path / "secret.txt"
    secret.write_text("do not hash me", encoding="utf-8")

    old_bundle = tmp_path / "old"
    old_artifacts = old_bundle / "artifacts" / "users"
    old_artifacts.mkdir(parents=True)
    (old_artifacts / "passwd").symlink_to(secret)
    (old_bundle / "state.json").write_text(
        json.dumps(
            {
                "inventory": {"packages": {}},
                "roles": {
                    "users": {
                        "managed_files": [{"path": "/etc/passwd", "src_rel": "passwd"}]
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    new_bundle = tmp_path / "new"
    new_artifacts = new_bundle / "artifacts" / "users"
    new_artifacts.mkdir(parents=True)
    (new_artifacts / "passwd").write_text("safe", encoding="utf-8")
    (new_bundle / "state.json").write_text(
        json.dumps(
            {
                "inventory": {"packages": {}},
                "roles": {
                    "users": {
                        "managed_files": [{"path": "/etc/passwd", "src_rel": "passwd"}]
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError) as exc_info:
        compare_harvests(str(old_bundle), str(new_bundle))

    # The unsafe symlinked artifact is now rejected when the directory bundle is
    # frozen into a private copy (no-follow traversal), which happens before
    # validation. The diff is still refused; the rejection just fires earlier.
    msg = str(exc_info.value)
    assert "symlink" in msg.lower()


def test_compare_harvests_freezes_directory_bundles_against_source_mutation(
    tmp_path: Path,
):
    """End-to-end: a directory diff must read frozen copies, so mutating a source
    bundle's artifact after compare_harvests has frozen it cannot change the
    result or redirect a read to a secret."""

    def _bundle(name: str, content: str) -> Path:
        b = tmp_path / name
        art = b / "artifacts" / "users"
        art.mkdir(parents=True)
        (art / "passwd").write_text(content, encoding="utf-8")
        (b / "state.json").write_text(
            json.dumps(
                {
                    "inventory": {"packages": {}},
                    "roles": {
                        "users": {
                            "managed_files": [
                                {"path": "/etc/passwd", "src_rel": "passwd"}
                            ]
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        return b

    old_bundle = _bundle("old", "same\n")
    new_bundle = _bundle("new", "same\n")

    # Identical content -> no file content drift.
    report, _ = compare_harvests(str(old_bundle), str(new_bundle))
    changed_paths = [f["path"] for f in report["files"]["changed"]]
    assert "/etc/passwd" not in changed_paths

    # The freeze already happened inside compare_harvests above and was torn down,
    # so to prove immunity during a single call we instead confirm that the frozen
    # copy is what gets hashed: rewrite the source between freeze and hash is not
    # observable to the operator because the consumed tree is a private copy.
    # Confirm at the unit level that a post-freeze swap to a secret symlink is not
    # followed by the hashing path.
    secret = tmp_path / "secret"
    secret.write_text("TOP-SECRET\n", encoding="utf-8")
    frozen_dir, td = freeze_directory_bundle(old_bundle)
    try:
        src = old_bundle / "artifacts" / "users" / "passwd"
        src.unlink()
        src.symlink_to(secret)
        frozen = Path(frozen_dir) / "artifacts" / "users" / "passwd"
        assert not frozen.is_symlink()
        assert frozen.read_text(encoding="utf-8") == "same\n"
    finally:
        td.cleanup()


def test_utc_now_iso():
    result = _utc_now_iso()
    assert "T" in result
    assert "+" in result or "Z" in result


def test_spinner_stop_without_start():
    spinner = _Spinner("Test")
    spinner.stop(final_line="Done")
    # Should not raise


def test_spinner_run_exception(monkeypatch):
    class FakeStderr:
        def write(self, s):
            raise Exception("Write error")

        def flush(self):
            pass

    monkeypatch.setattr(sys, "stderr", FakeStderr())

    spinner = _Spinner("Test")
    spinner.start()
    spinner.stop()


def test_spinner_double_start():
    spinner = _Spinner("Test")
    spinner.start()
    spinner.start()  # Should not raise or spawn another thread
    spinner.stop()


def test_role_tag_normal():
    assert _role_tag("nginx") == "role_nginx"
    assert _role_tag("my-app") == "role_my-app"


def test_role_tag_with_special_chars():
    assert _role_tag("my.app") == "role_my_app"
    assert _role_tag("my app") == "role_my_app"


def test_role_tag_empty():
    assert _role_tag("") == "role_other"
    assert _role_tag("   ") == "role_other"


def test_bundle_from_input_tgz(monkeypatch, tmp_path: Path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    state_file = bundle_dir / "state.json"
    state_file.write_text("{}", encoding="utf-8")

    tar_path = tmp_path / "bundle.tgz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(bundle_dir, arcname="bundle")

    result = _bundle_from_input(str(tar_path), sops_mode=False)
    assert result.dir.exists()
    assert result.tempdir is not None
    result.tempdir.cleanup()


def test_bundle_from_input_sops_mode_no_sops(monkeypatch, tmp_path: Path):
    # Create a fake .sops file
    sops_file = tmp_path / "harvest.sops"
    sops_file.write_bytes(b"encrypted")

    def fake_require():
        raise SopsError("sops not found")

    import enroll.diff as d

    monkeypatch.setattr(d, "require_sops_cmd", fake_require)

    with pytest.raises(SopsError):
        _bundle_from_input(str(sops_file), sops_mode=True)


def test_report_markdown_basic():
    report = {
        "generated_at": "2024-01-01T00:00:00Z",
        "old": {"input": "old.tar.gz", "host": "host1"},
        "new": {"input": "new.tar.gz", "host": "host2"},
        "packages": {"added": ["vim"], "removed": [], "version_changed": []},
        "services": {"enabled_added": [], "enabled_removed": [], "changed": []},
        "users": {"added": [], "removed": [], "changed": []},
        "files": {"added": [], "removed": [], "changed": []},
    }
    result = _report_markdown(report)
    assert "## Packages" in result
    assert "+ vim" in result


def test_report_markdown_with_version_ignored():
    report = {
        "generated_at": "2024-01-01T00:00:00Z",
        "old": {"input": "old.tar.gz"},
        "new": {"input": "new.tar.gz"},
        "packages": {
            "added": [],
            "removed": [],
            "version_changed": [{"package": "vim", "old": "1.0", "new": "2.0"}],
            "version_changed_ignored_count": 1,
        },
        "services": {"enabled_added": [], "enabled_removed": [], "changed": []},
        "users": {"added": [], "removed": [], "changed": []},
        "files": {"added": [], "removed": [], "changed": []},
    }
    result = _report_markdown(report)
    assert "ignored 1" in result


def test_report_markdown_with_service_package_changes():
    report = {
        "generated_at": "2024-01-01T00:00:00Z",
        "old": {"input": "old.tar.gz"},
        "new": {"input": "new.tar.gz"},
        "packages": {"added": [], "removed": [], "version_changed": []},
        "services": {
            "enabled_added": [],
            "enabled_removed": [],
            "changed": [
                {
                    "unit": "nginx.service",
                    "changes": {"packages": {"added": ["nginx-extra"], "removed": []}},
                }
            ],
        },
        "users": {"added": [], "removed": [], "changed": []},
        "files": {"added": [], "removed": [], "changed": []},
    }
    result = _report_markdown(report)
    assert "packages added" in result


def test_report_markdown_empty():
    report = {
        "generated_at": "2024-01-01T00:00:00Z",
        "old": {"input": "old.tar.gz"},
        "new": {"input": "new.tar.gz"},
        "packages": {},
        "services": {},
        "users": {},
        "files": {},
    }
    result = _report_markdown(report)
    assert "## Packages" in result
    assert "## Services" in result


def test_spinner_start_stop(monkeypatch):
    """Test spinner can be started and stopped."""
    import enroll.diff as d

    # Mock threading to avoid actual thread creation
    class FakeThread:
        def __init__(self, target, name, daemon):
            self.target = target
            self.daemon = daemon

        def start(self):
            pass

        def join(self, timeout):
            pass

    monkeypatch.setattr(d.threading, "Thread", FakeThread)

    spinner = d._Spinner("test message")
    spinner.start()
    spinner.stop()


def test_spinner_already_started(monkeypatch):
    """Test spinner doesn't restart if already running."""
    import enroll.diff as d

    class FakeThread:
        def __init__(self, target, name, daemon):
            pass

        def start(self):
            pass

        def join(self, timeout):
            pass

    monkeypatch.setattr(d.threading, "Thread", FakeThread)

    spinner = d._Spinner("test message")
    spinner.start()
    spinner._thread = FakeThread(None, None, True)  # Simulate already running
    spinner.start()  # Should return early


def test_spinner_stop_clears_line(monkeypatch, tmp_path):
    """Test spinner stop clears the line."""
    import enroll.diff as d
    import sys

    class FakeThread:
        def __init__(self, target, name, daemon):
            pass

        def start(self):
            pass

        def join(self, timeout):
            pass

    monkeypatch.setattr(d.threading, "Thread", FakeThread)

    # Capture stderr writes
    writes = []
    original_write = sys.stderr.write

    def capture_write(s):
        writes.append(s)
        return original_write(s)

    monkeypatch.setattr(sys.stderr, "write", capture_write)

    spinner = d._Spinner("test message")
    spinner._last_len = 20
    spinner.stop()

    # Should have written clearing sequence
    assert any("\r" in w for w in writes)


def test_should_show_spinner_disabled_env(monkeypatch):
    """Test spinner disabled via environment variable."""
    import enroll.diff as d

    monkeypatch.setenv("ENROLL_NO_PROGRESS", "1")
    assert d._progress_enabled() is False

    monkeypatch.setenv("ENROLL_NO_PROGRESS", "true")
    assert d._progress_enabled() is False

    monkeypatch.setenv("ENROLL_NO_PROGRESS", "yes")
    assert d._progress_enabled() is False


def test_should_show_spinner_exception_on_isatty(monkeypatch):
    """Test spinner returns False when isatty raises exception."""
    import enroll.diff as d
    import sys

    original_stderr = sys.stderr

    class FakeStderr:
        def isatty(self):
            raise Exception("No tty")

    monkeypatch.setattr(sys, "stderr", FakeStderr())
    assert d._progress_enabled() is False

    # Restore
    monkeypatch.setattr(sys, "stderr", original_stderr)


def test_all_packages_from_state():
    """Test _all_packages extracts sorted package list."""
    import enroll.diff as d

    state = {
        "inventory": {
            "packages": {
                "nginx": [{"version": "1.0"}],
                "vim": [{"version": "2.0"}],
                "bash": [{"version": "3.0"}],
            }
        }
    }

    result = d._all_packages(state)
    assert result == ["bash", "nginx", "vim"]


def test_all_packages_empty_state():
    """Test _all_packages with empty state."""
    import enroll.diff as d

    state = {"inventory": {"packages": {}}}
    result = d._all_packages(state)
    assert result == []


def test_roles_from_state():
    """Test _roles extracts roles from state."""
    import enroll.diff as d

    state = {"roles": {"web": {}, "db": {}}}
    result = d._roles(state)
    assert result == {"web": {}, "db": {}}


def test_roles_empty_state():
    """Test _roles with empty state."""
    import enroll.diff as d

    state = {}
    result = d._roles(state)
    assert result == {}


def test_pkg_version_key_with_multiple_versions():
    """Test _pkg_version_key handles multiple versions."""
    import enroll.diff as d

    entry = {
        "installations": [
            {"version": "1.0", "arch": "amd64"},
            {"version": "2.0", "arch": "arm64"},
        ]
    }

    result = d._pkg_version_key(entry)
    # Just check it returns a non-None value with version info
    assert result is not None
    assert len(result) > 0


def test_pkg_version_key_without_version():
    """Test _pkg_version_key skips entries without version."""
    import enroll.diff as d

    entry = {
        "installations": [
            {"arch": "amd64"},  # No version
        ]
    }

    result = d._pkg_version_key(entry)
    assert result is None


def test_pkg_version_key_with_empty_installations():
    """Test _pkg_version_key with empty installations."""
    import enroll.diff as d

    entry = {"installations": []}
    result = d._pkg_version_key(entry)
    assert result is None


def test_pkg_version_key_without_installations():
    """Test _pkg_version_key without installations key."""
    import enroll.diff as d

    entry = {}
    result = d._pkg_version_key(entry)
    assert result is None


def test_pkg_version_key_with_direct_version():
    """Test _pkg_version_key with direct version field."""
    import enroll.diff as d

    entry = {"version": "1.2.3"}
    result = d._pkg_version_key(entry)
    assert result == "1.2.3"


def test_report_text_with_exclude_paths():
    """Test _report_text includes exclude paths."""
    import enroll.diff as d

    report = {
        "generated_at": "2024-01-01T00:00:00Z",
        "old": {"input": "old.tar.gz", "host": "host1", "state_mtime": "mtime1"},
        "new": {"input": "new.tar.gz", "host": "host2", "state_mtime": "mtime2"},
        "filters": {"exclude_paths": ["/tmp/*", "/var/log/*"]},
        "packages": {"added": [], "removed": [], "version_changed": []},
        "services": {"enabled_added": [], "enabled_removed": [], "changed": []},
        "users": {"added": [], "removed": [], "changed": []},
        "files": {"added": [], "removed": [], "changed": []},
    }
    result = d._report_text(report)
    assert "file exclude patterns" in result
    assert "/tmp/*" in result


def test_report_text_with_ignore_package_versions():
    """Test _report_text includes ignore package versions message."""
    import enroll.diff as d

    report = {
        "generated_at": "2024-01-01T00:00:00Z",
        "old": {"input": "old.tar.gz", "host": "host1", "state_mtime": "mtime1"},
        "new": {"input": "new.tar.gz", "host": "host2", "state_mtime": "mtime2"},
        "filters": {"ignore_package_versions": True},
        "packages": {"version_changed_ignored_count": 5},
        "services": {"enabled_added": [], "enabled_removed": [], "changed": []},
        "users": {"added": [], "removed": [], "changed": []},
        "files": {"added": [], "removed": [], "changed": []},
    }
    result = d._report_text(report)
    assert "package version drift: ignored" in result
    assert "ignored 5 changes" in result
