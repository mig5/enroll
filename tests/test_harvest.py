import json
from pathlib import Path

import enroll.harvest as h
from enroll.systemd import UnitInfo


class AllowAllPolicy:
    def deny_reason(self, path: str):
        return None


def test_harvest_dedup_manual_packages_and_builds_etc_custom(
    monkeypatch, tmp_path: Path
):
    bundle = tmp_path / "bundle"

    import os

    real_isfile = os.path.isfile
    real_isdir = os.path.isdir
    real_exists = os.path.exists
    real_islink = os.path.islink

    # Fake filesystem: two /etc files exist, only one is dpkg-owned.
    # Also include some /usr/local files to populate usr_local_custom.
    files = {
        "/etc/openvpn/server.conf": b"server",
        "/etc/default/keyboard": b"kbd",
        "/usr/local/etc/myapp.conf": b"myapp=1\n",
        "/usr/local/bin/myscript": b"#!/bin/sh\necho hi\n",
        # non-executable text under /usr/local/bin should be skipped
        "/usr/local/bin/readme.txt": b"hello\n",
    }
    dirs = {
        "/etc",
        "/etc/openvpn",
        "/etc/default",
        "/usr",
        "/usr/local",
        "/usr/local/etc",
        "/usr/local/bin",
    }

    def fake_isfile(p: str) -> bool:
        if p.startswith("/etc/") or p == "/etc":
            return p in files
        if p.startswith("/usr/local/"):
            return p in files
        return real_isfile(p)

    def fake_isdir(p: str) -> bool:
        if p.startswith("/etc"):
            return p in dirs
        if p.startswith("/usr/local") or p in ("/usr", "/usr/local"):
            return p in dirs
        return real_isdir(p)

    def fake_islink(p: str) -> bool:
        if p.startswith("/etc"):
            return False
        if p.startswith("/usr/local"):
            return False
        return real_islink(p)

    def fake_exists(p: str) -> bool:
        if p.startswith("/etc"):
            return p in files or p in dirs
        if p.startswith("/usr/local") or p in ("/usr", "/usr/local"):
            return p in files or p in dirs
        return real_exists(p)

    def fake_walk(root: str):
        if root == "/etc":
            yield ("/etc/openvpn", [], ["server.conf"])
            yield ("/etc/default", [], ["keyboard"])
        elif root == "/etc/openvpn":
            yield ("/etc/openvpn", [], ["server.conf"])
        elif root == "/etc/default":
            yield ("/etc/default", [], ["keyboard"])
        elif root == "/usr/local/etc":
            yield ("/usr/local/etc", [], ["myapp.conf"])
        elif root == "/usr/local/bin":
            yield ("/usr/local/bin", [], ["myscript", "readme.txt"])
        else:
            yield (root, [], [])

    monkeypatch.setattr(h.os.path, "isfile", fake_isfile)
    monkeypatch.setattr(h.os.path, "isdir", fake_isdir)
    monkeypatch.setattr(h.os.path, "islink", fake_islink)
    monkeypatch.setattr(h.os.path, "exists", fake_exists)
    monkeypatch.setattr(h.os, "walk", fake_walk)

    # Avoid real system access
    monkeypatch.setattr(h, "list_enabled_services", lambda: ["openvpn.service"])
    monkeypatch.setattr(
        h,
        "get_unit_info",
        lambda unit: UnitInfo(
            name=unit,
            fragment_path="/lib/systemd/system/openvpn.service",
            dropin_paths=[],
            env_files=[],
            exec_paths=["/usr/sbin/openvpn"],
            active_state="inactive",
            sub_state="dead",
            unit_file_state="enabled",
            condition_result=None,
        ),
    )

    # Debian package index: openvpn owns /etc/openvpn/server.conf; keyboard is unowned.
    def fake_build_index():
        owned_etc = {"/etc/openvpn/server.conf"}
        etc_owner_map = {"/etc/openvpn/server.conf": "openvpn"}
        topdir_to_pkgs = {"openvpn": {"openvpn"}}
        pkg_to_etc_paths = {"openvpn": ["/etc/openvpn/server.conf"], "curl": []}
        return owned_etc, etc_owner_map, topdir_to_pkgs, pkg_to_etc_paths

    monkeypatch.setattr(h, "build_dpkg_etc_index", fake_build_index)

    # openvpn conffile hash mismatch => should be captured under service role
    monkeypatch.setattr(
        h,
        "parse_status_conffiles",
        lambda: {"openvpn": {"/etc/openvpn/server.conf": "old"}},
    )
    monkeypatch.setattr(h, "read_pkg_md5sums", lambda pkg: {})
    monkeypatch.setattr(h, "file_md5", lambda path: "new")

    monkeypatch.setattr(
        h, "dpkg_owner", lambda p: "openvpn" if "openvpn" in p else None
    )
    monkeypatch.setattr(h, "list_manual_packages", lambda: ["openvpn", "curl"])
    monkeypatch.setattr(h, "collect_non_system_users", lambda: [])

    def fake_stat_triplet(p: str):
        if p == "/usr/local/bin/myscript":
            return ("root", "root", "0755")
        # /usr/local/bin/readme.txt remains non-executable
        return ("root", "root", "0644")

    monkeypatch.setattr(h, "stat_triplet", fake_stat_triplet)

    # Avoid needing source files on disk by implementing our own bundle copier
    def fake_copy(bundle_dir: str, role_name: str, abs_path: str, src_rel: str):
        dst = Path(bundle_dir) / "artifacts" / role_name / src_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(files.get(abs_path, b""))

    monkeypatch.setattr(h, "_copy_into_bundle", fake_copy)

    state_path = h.harvest(str(bundle), policy=AllowAllPolicy())
    st = json.loads(Path(state_path).read_text(encoding="utf-8"))

    assert "openvpn" in st["manual_packages"]
    assert "curl" in st["manual_packages"]
    assert "openvpn" in st["manual_packages_skipped"]
    assert all(pr["package"] != "openvpn" for pr in st["package_roles"])
    assert any(pr["package"] == "curl" for pr in st["package_roles"])

    # Service role captured modified conffile
    svc = st["services"][0]
    assert svc["unit"] == "openvpn.service"
    assert "openvpn" in svc["packages"]
    assert any(mf["path"] == "/etc/openvpn/server.conf" for mf in svc["managed_files"])

    # Unowned /etc/default/keyboard is attributed to etc_custom only
    etc_custom = st["etc_custom"]
    assert any(
        mf["path"] == "/etc/default/keyboard" for mf in etc_custom["managed_files"]
    )

    # /usr/local content is attributed to usr_local_custom
    ul = st["usr_local_custom"]
    assert any(mf["path"] == "/usr/local/etc/myapp.conf" for mf in ul["managed_files"])
    assert any(mf["path"] == "/usr/local/bin/myscript" for mf in ul["managed_files"])
    assert all(mf["path"] != "/usr/local/bin/readme.txt" for mf in ul["managed_files"])
