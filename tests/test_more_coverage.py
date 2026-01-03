from __future__ import annotations

import json
import os
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_cache_dir_defaults_to_home_cache(monkeypatch, tmp_path: Path):
    # Ensure default path uses ~/.cache when XDG_CACHE_HOME is unset.
    from enroll.cache import enroll_cache_dir

    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    p = enroll_cache_dir()
    assert str(p).startswith(str(tmp_path))
    assert p.name == "enroll"


def test_harvest_cache_state_json_property(tmp_path: Path):
    from enroll.cache import HarvestCache

    hc = HarvestCache(tmp_path / "h1")
    assert hc.state_json == hc.dir / "state.json"


def test_cache_dir_security_rejects_symlink(tmp_path: Path):
    from enroll.cache import _ensure_dir_secure

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(RuntimeError, match="Refusing to use symlink"):
        _ensure_dir_secure(link)


def test_cache_dir_chmod_failures_are_ignored(monkeypatch, tmp_path: Path):
    from enroll import cache

    # Make the cache base path deterministic and writable.
    monkeypatch.setattr(cache, "enroll_cache_dir", lambda: tmp_path)

    # Force os.chmod to fail to cover the "except OSError: pass" paths.
    monkeypatch.setattr(
        os, "chmod", lambda *a, **k: (_ for _ in ()).throw(OSError("nope"))
    )

    hc = cache.new_harvest_cache_dir()
    assert hc.dir.exists()
    assert hc.dir.is_dir()


def test_stat_triplet_falls_back_to_numeric_ids(monkeypatch, tmp_path: Path):
    from enroll.fsutil import stat_triplet
    import pwd
    import grp

    p = tmp_path / "x"
    p.write_text("x", encoding="utf-8")

    # Force username/group resolution failures.
    monkeypatch.setattr(
        pwd, "getpwuid", lambda _uid: (_ for _ in ()).throw(KeyError("no user"))
    )
    monkeypatch.setattr(
        grp, "getgrgid", lambda _gid: (_ for _ in ()).throw(KeyError("no group"))
    )

    owner, group, mode = stat_triplet(str(p))
    assert owner.isdigit()
    assert group.isdigit()
    assert len(mode) == 4


def test_ignore_policy_iter_effective_lines_removes_block_comments():
    from enroll.ignore import IgnorePolicy

    pol = IgnorePolicy()
    data = b"""keep1
/*
drop me
*/
keep2
"""
    assert list(pol.iter_effective_lines(data)) == [b"keep1", b"keep2"]


def test_ignore_policy_deny_reason_dir_variants(tmp_path: Path):
    from enroll.ignore import IgnorePolicy

    pol = IgnorePolicy()

    # denied by glob
    assert pol.deny_reason_dir("/etc/shadow") == "denied_path"

    # symlink rejected
    d = tmp_path / "d"
    d.mkdir()
    link = tmp_path / "l"
    link.symlink_to(d, target_is_directory=True)
    assert pol.deny_reason_dir(str(link)) == "symlink"

    # not a directory
    f = tmp_path / "f"
    f.write_text("x", encoding="utf-8")
    assert pol.deny_reason_dir(str(f)) == "not_directory"

    # ok
    assert pol.deny_reason_dir(str(d)) is None


def test_run_jinjaturtle_parses_outputs(monkeypatch, tmp_path: Path):
    # Fully unit-test enroll.jinjaturtle.run_jinjaturtle by stubbing subprocess.run.
    from enroll.jinjaturtle import run_jinjaturtle

    def fake_run(cmd, **kwargs):  # noqa: ARG001
        # cmd includes "-d <defaults> -t <template>"
        d_idx = cmd.index("-d") + 1
        t_idx = cmd.index("-t") + 1
        defaults = Path(cmd[d_idx])
        template = Path(cmd[t_idx])
        defaults.write_text("---\nfoo: 1\n", encoding="utf-8")
        template.write_text("value={{ foo }}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    src = tmp_path / "src.ini"
    src.write_text("foo=1\n", encoding="utf-8")

    res = run_jinjaturtle("/bin/jinjaturtle", str(src), role_name="role1")
    assert "foo: 1" in res.vars_text
    assert "value=" in res.template_text


def test_run_jinjaturtle_raises_on_failure(monkeypatch, tmp_path: Path):
    from enroll.jinjaturtle import run_jinjaturtle

    def fake_run(cmd, **kwargs):  # noqa: ARG001
        return SimpleNamespace(returncode=2, stdout="out", stderr="bad")

    monkeypatch.setattr(subprocess, "run", fake_run)

    src = tmp_path / "src.ini"
    src.write_text("x", encoding="utf-8")
    with pytest.raises(RuntimeError, match="jinjaturtle failed"):
        run_jinjaturtle("/bin/jinjaturtle", str(src), role_name="role1")


def test_require_sops_cmd_errors_when_missing(monkeypatch):
    from enroll.sopsutil import require_sops_cmd, SopsError

    monkeypatch.setattr("enroll.sopsutil.shutil.which", lambda _: None)
    with pytest.raises(SopsError, match="not found on PATH"):
        require_sops_cmd()


def test_get_enroll_version_reports_unknown_on_metadata_failure(monkeypatch):
    import enroll.version as v

    fake_meta = types.ModuleType("importlib.metadata")

    def boom():
        raise RuntimeError("boom")

    fake_meta.packages_distributions = boom
    fake_meta.version = lambda _dist: boom()

    monkeypatch.setitem(sys.modules, "importlib.metadata", fake_meta)
    assert v.get_enroll_version() == "unknown"


def test_get_enroll_version_returns_unknown_if_importlib_metadata_unavailable(
    monkeypatch,
):
    import builtins
    import enroll.version as v

    real_import = builtins.__import__

    def fake_import(
        name, globals=None, locals=None, fromlist=(), level=0
    ):  # noqa: A002
        if name == "importlib.metadata":
            raise ImportError("no metadata")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert v.get_enroll_version() == "unknown"


def test_compare_harvests_and_format_report(tmp_path: Path):
    from enroll.diff import compare_harvests, format_report

    old = tmp_path / "old"
    new = tmp_path / "new"
    (old / "artifacts").mkdir(parents=True)
    (new / "artifacts").mkdir(parents=True)

    def write_state(base: Path, state: dict) -> None:
        base.mkdir(parents=True, exist_ok=True)
        (base / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

    # Old bundle: pkg a@1.0, pkg b@1.0, one service, one user, one managed file.
    old_state = {
        "schema_version": 3,
        "host": {"hostname": "h1"},
        "inventory": {"packages": {"a": {"version": "1.0"}, "b": {"version": "1.0"}}},
        "roles": {
            "services": [
                {
                    "unit": "svc.service",
                    "role_name": "svc",
                    "packages": ["a"],
                    "active_state": "inactive",
                    "sub_state": "dead",
                    "unit_file_state": "enabled",
                    "condition_result": None,
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
                }
            ],
            "packages": [],
            "users": {
                "role_name": "users",
                "users": [{"name": "alice", "shell": "/bin/sh"}],
            },
            "apt_config": {"role_name": "apt_config", "managed_files": []},
            "etc_custom": {"role_name": "etc_custom", "managed_files": []},
            "usr_local_custom": {"role_name": "usr_local_custom", "managed_files": []},
            "extra_paths": {"role_name": "extra_paths", "managed_files": []},
        },
    }
    (old / "artifacts" / "svc" / "etc").mkdir(parents=True, exist_ok=True)
    (old / "artifacts" / "svc" / "etc" / "foo.conf").write_text("old", encoding="utf-8")
    write_state(old, old_state)

    # New bundle: pkg a@2.0, pkg c@1.0, service changed, user changed, file moved role+content.
    new_state = {
        "schema_version": 3,
        "host": {"hostname": "h2"},
        "inventory": {"packages": {"a": {"version": "2.0"}, "c": {"version": "1.0"}}},
        "roles": {
            "services": [
                {
                    "unit": "svc.service",
                    "role_name": "svc",
                    "packages": ["a", "c"],
                    "active_state": "active",
                    "sub_state": "running",
                    "unit_file_state": "enabled",
                    "condition_result": None,
                    "managed_files": [],
                }
            ],
            "packages": [],
            "users": {
                "role_name": "users",
                "users": [{"name": "alice", "shell": "/bin/bash"}, {"name": "bob"}],
            },
            "apt_config": {"role_name": "apt_config", "managed_files": []},
            "etc_custom": {"role_name": "etc_custom", "managed_files": []},
            "usr_local_custom": {"role_name": "usr_local_custom", "managed_files": []},
            "extra_paths": {
                "role_name": "extra_paths",
                "managed_files": [
                    {
                        "path": "/etc/foo.conf",
                        "src_rel": "etc/foo.conf",
                        "owner": "root",
                        "group": "root",
                        "mode": "0600",
                        "reason": "user_include",
                    },
                    {
                        "path": "/etc/added.conf",
                        "src_rel": "etc/added.conf",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "user_include",
                    },
                ],
            },
        },
    }
    (new / "artifacts" / "extra_paths" / "etc").mkdir(parents=True, exist_ok=True)
    (new / "artifacts" / "extra_paths" / "etc" / "foo.conf").write_text(
        "new", encoding="utf-8"
    )
    (new / "artifacts" / "extra_paths" / "etc" / "added.conf").write_text(
        "x", encoding="utf-8"
    )
    write_state(new, new_state)

    report, changed = compare_harvests(str(old), str(new))
    assert changed is True

    txt = format_report(report, fmt="text")
    assert "Packages" in txt

    md = format_report(report, fmt="markdown")
    assert "# enroll diff report" in md

    js = format_report(report, fmt="json")
    parsed = json.loads(js)
    assert parsed["packages"]["added"] == ["c"]
