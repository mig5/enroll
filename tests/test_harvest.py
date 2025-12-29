import json
from pathlib import Path

import enroll.harvest as h
from enroll.platform import PlatformInfo
from enroll.systemd import UnitInfo


class AllowAllPolicy:
    def deny_reason(self, path: str):
        return None


class FakeBackend:
    """Minimal backend stub for harvest tests.

    The real backends (dpkg/rpm) enumerate the live system (dpkg status, rpm
    databases, etc). These tests instead control all backend behaviour.
    """

    def __init__(
        self,
        *,
        name: str,
        owned_etc: set[str],
        etc_owner_map: dict[str, str],
        topdir_to_pkgs: dict[str, set[str]],
        pkg_to_etc_paths: dict[str, list[str]],
        manual_pkgs: list[str],
        owner_fn,
        modified_by_pkg: dict[str, dict[str, str]] | None = None,
        pkg_config_prefixes: tuple[str, ...] = ("/etc/apt/",),
        installed: dict[str, list[dict[str, str]]] | None = None,
    ):
        self.name = name
        self.pkg_config_prefixes = pkg_config_prefixes
        self._owned_etc = owned_etc
        self._etc_owner_map = etc_owner_map
        self._topdir_to_pkgs = topdir_to_pkgs
        self._pkg_to_etc_paths = pkg_to_etc_paths
        self._manual = manual_pkgs
        self._owner_fn = owner_fn
        self._modified_by_pkg = modified_by_pkg or {}
        self._installed = installed or {}

    def build_etc_index(self):
        return (
            self._owned_etc,
            self._etc_owner_map,
            self._topdir_to_pkgs,
            self._pkg_to_etc_paths,
        )

    def owner_of_path(self, path: str):
        return self._owner_fn(path)

    def list_manual_packages(self):
        return list(self._manual)

    def installed_packages(self):
        """Return mapping package -> installations.

        The real backends return:
          {"pkg": [{"version": "...", "arch": "..."}, ...]}
        """
        return dict(self._installed)

    def specific_paths_for_hints(self, hints: set[str]):
        return []

    def is_pkg_config_path(self, path: str) -> bool:
        for pfx in self.pkg_config_prefixes:
            if path == pfx or path.startswith(pfx):
                return True
        return False

    def modified_paths(self, pkg: str, etc_paths: list[str]):
        # Test-controlled; ignore etc_paths.
        return dict(self._modified_by_pkg.get(pkg, {}))


def test_harvest_dedup_manual_packages_and_builds_etc_custom(
    monkeypatch, tmp_path: Path
):
    bundle = tmp_path / "bundle"

    import os

    real_isfile = os.path.isfile
    real_isdir = os.path.isdir
    real_exists = os.path.exists
    real_islink = os.path.islink

    # Fake filesystem: two /etc files exist, only one is package-owned.
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
    monkeypatch.setattr(h, "list_enabled_timers", lambda: [])
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

    # Package index: openvpn owns /etc/openvpn/server.conf; keyboard is unowned.
    owned_etc = {"/etc/openvpn/server.conf"}
    etc_owner_map = {"/etc/openvpn/server.conf": "openvpn"}
    topdir_to_pkgs = {"openvpn": {"openvpn"}}
    pkg_to_etc_paths = {"openvpn": ["/etc/openvpn/server.conf"], "curl": []}

    backend = FakeBackend(
        name="dpkg",
        owned_etc=owned_etc,
        etc_owner_map=etc_owner_map,
        topdir_to_pkgs=topdir_to_pkgs,
        pkg_to_etc_paths=pkg_to_etc_paths,
        manual_pkgs=["openvpn", "curl"],
        owner_fn=lambda p: "openvpn" if "openvpn" in (p or "") else None,
        modified_by_pkg={
            "openvpn": {"/etc/openvpn/server.conf": "modified_conffile"},
        },
    )

    monkeypatch.setattr(
        h, "detect_platform", lambda: PlatformInfo("debian", "dpkg", {})
    )
    monkeypatch.setattr(h, "get_backend", lambda info=None: backend)

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

    inv = st["inventory"]["packages"]
    assert "openvpn" in inv
    assert "curl" in inv

    # openvpn is managed by the service role, so it should NOT appear as a package role.
    pkg_roles = st["roles"]["packages"]
    assert all(pr["package"] != "openvpn" for pr in pkg_roles)
    assert any(pr["package"] == "curl" for pr in pkg_roles)

    # Inventory provenance: openvpn should be observed via systemd unit.
    openvpn_obs = inv["openvpn"]["observed_via"]
    assert any(
        o.get("kind") == "systemd_unit" and o.get("ref") == "openvpn.service"
        for o in openvpn_obs
    )

    # Service role captured modified conffile
    svc = st["roles"]["services"][0]
    assert svc["unit"] == "openvpn.service"
    assert "openvpn" in svc["packages"]
    assert any(mf["path"] == "/etc/openvpn/server.conf" for mf in svc["managed_files"])

    # Unowned /etc/default/keyboard is attributed to etc_custom only
    etc_custom = st["roles"]["etc_custom"]
    assert any(
        mf["path"] == "/etc/default/keyboard" for mf in etc_custom["managed_files"]
    )

    # /usr/local content is attributed to usr_local_custom
    ul = st["roles"]["usr_local_custom"]
    assert any(mf["path"] == "/usr/local/etc/myapp.conf" for mf in ul["managed_files"])
    assert any(mf["path"] == "/usr/local/bin/myscript" for mf in ul["managed_files"])
    assert all(mf["path"] != "/usr/local/bin/readme.txt" for mf in ul["managed_files"])


def test_shared_cron_snippet_prefers_matching_role_over_lexicographic(
    monkeypatch, tmp_path: Path
):
    """Regression test for shared snippet routing.

    When multiple service roles reference the same owning package, we prefer the
    role whose name matches the snippet/package (e.g. ntpsec) rather than a
    lexicographic tie-break that could incorrectly pick another role.
    """

    bundle = tmp_path / "bundle"

    files = {"/etc/cron.d/ntpsec": b"# cron\n"}
    dirs = {"/etc", "/etc/cron.d"}

    monkeypatch.setattr(h.os.path, "isfile", lambda p: p in files)
    monkeypatch.setattr(h.os.path, "islink", lambda p: False)
    monkeypatch.setattr(h.os.path, "isdir", lambda p: p in dirs)
    monkeypatch.setattr(h.os.path, "exists", lambda p: p in files or p in dirs)
    monkeypatch.setattr(h.os, "walk", lambda root: [("/etc/cron.d", [], ["ntpsec"])])

    # Only include the cron snippet in the system capture set.
    monkeypatch.setattr(
        h, "_iter_system_capture_paths", lambda: [("/etc/cron.d/ntpsec", "system_cron")]
    )

    monkeypatch.setattr(
        h, "list_enabled_services", lambda: ["apparmor.service", "ntpsec.service"]
    )
    monkeypatch.setattr(h, "list_enabled_timers", lambda: [])

    def fake_unit_info(unit: str) -> UnitInfo:
        if unit == "apparmor.service":
            return UnitInfo(
                name=unit,
                fragment_path="/lib/systemd/system/apparmor.service",
                dropin_paths=[],
                env_files=[],
                exec_paths=["/usr/sbin/apparmor"],
                active_state="active",
                sub_state="running",
                unit_file_state="enabled",
                condition_result=None,
            )
        return UnitInfo(
            name=unit,
            fragment_path="/lib/systemd/system/ntpsec.service",
            dropin_paths=[],
            env_files=[],
            exec_paths=["/usr/sbin/ntpd"],
            active_state="active",
            sub_state="running",
            unit_file_state="enabled",
            condition_result=None,
        )

    monkeypatch.setattr(h, "get_unit_info", fake_unit_info)

    # Make apparmor *also* claim the ntpsec package (simulates overly-broad
    # package inference). The snippet routing should still prefer role 'ntpsec'.
    def fake_owner(p: str):
        if p == "/etc/cron.d/ntpsec":
            return "ntpsec"
        if "apparmor" in (p or ""):
            return "ntpsec"  # intentionally misleading
        if "ntpsec" in (p or "") or "ntpd" in (p or ""):
            return "ntpsec"
        return None

    backend = FakeBackend(
        name="dpkg",
        owned_etc=set(),
        etc_owner_map={},
        topdir_to_pkgs={},
        pkg_to_etc_paths={},
        manual_pkgs=[],
        owner_fn=fake_owner,
        modified_by_pkg={},
    )

    monkeypatch.setattr(
        h, "detect_platform", lambda: PlatformInfo("debian", "dpkg", {})
    )
    monkeypatch.setattr(h, "get_backend", lambda info=None: backend)

    monkeypatch.setattr(h, "stat_triplet", lambda p: ("root", "root", "0644"))
    monkeypatch.setattr(h, "collect_non_system_users", lambda: [])

    def fake_copy(bundle_dir: str, role_name: str, abs_path: str, src_rel: str):
        dst = Path(bundle_dir) / "artifacts" / role_name / src_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(files[abs_path])

    monkeypatch.setattr(h, "_copy_into_bundle", fake_copy)

    state_path = h.harvest(str(bundle), policy=AllowAllPolicy())
    st = json.loads(Path(state_path).read_text(encoding="utf-8"))

    # Cron snippet should end up attached to the ntpsec role, not apparmor.
    svc_ntpsec = next(s for s in st["roles"]["services"] if s["role_name"] == "ntpsec")
    assert any(mf["path"] == "/etc/cron.d/ntpsec" for mf in svc_ntpsec["managed_files"])

    svc_apparmor = next(
        s for s in st["roles"]["services"] if s["role_name"] == "apparmor"
    )
    assert all(
        mf["path"] != "/etc/cron.d/ntpsec" for mf in svc_apparmor["managed_files"]
    )
