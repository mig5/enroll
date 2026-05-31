import json
import enroll.harvest as harvest
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


def test_files_differ_binary(tmp_path: Path):
    file1 = tmp_path / "file1.bin"
    file2 = tmp_path / "file2.bin"
    file1.write_bytes(b"\x00\x01\x02\x03")
    file2.write_bytes(b"\x00\x01\x02\x03")
    assert harvest._files_differ(str(file1), str(file2)) is False


def test_files_differ_binary_different(tmp_path: Path):
    file1 = tmp_path / "file1.bin"
    file2 = tmp_path / "file2.bin"
    file1.write_bytes(b"\x00\x01\x02\x03")
    file2.write_bytes(b"\x00\x01\x02\x04")
    assert harvest._files_differ(str(file1), str(file2)) is True


def test_files_differ_non_regular_a(tmp_path: Path):
    directory = tmp_path / "dir"
    directory.mkdir()
    file1 = tmp_path / "file1.txt"
    file1.write_text("content", encoding="utf-8")
    assert harvest._files_differ(str(directory), str(file1)) is True


def test_topdirs_for_package_with_multiple_paths():
    pkg_to_etc_paths = {
        "nginx": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default"],
    }
    result = harvest._topdirs_for_package("nginx", pkg_to_etc_paths)
    assert result == {"nginx"}


def test_topdirs_for_package_with_multiple_topdirs():
    pkg_to_etc_paths = {
        "multi": ["/etc/nginx/nginx.conf", "/etc/ssh/sshd_config"],
    }
    result = harvest._topdirs_for_package("multi", pkg_to_etc_paths)
    assert result == {"nginx", "ssh"}


def test_topdirs_for_package_empty():
    result = harvest._topdirs_for_package("empty", {})
    assert result == set()


def test_topdirs_for_package_no_etc():
    pkg_to_etc_paths = {
        "other": ["/usr/share/doc/file"],
    }
    result = harvest._topdirs_for_package("other", pkg_to_etc_paths)
    assert result == set()


def test_files_differ_same_content(tmp_path: Path):
    """Test that _files_differ returns False for identical content."""
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    file_a.write_text("same content", encoding="utf-8")
    file_b.write_text("same content", encoding="utf-8")
    assert harvest._files_differ(str(file_a), str(file_b)) is False


def test_files_differ_different_content(tmp_path: Path):
    """Test that _files_differ returns True for different content."""
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    file_a.write_text("content a", encoding="utf-8")
    file_b.write_text("content b", encoding="utf-8")
    assert harvest._files_differ(str(file_a), str(file_b)) is True


def test_files_differ_missing_file(tmp_path: Path):
    """Test that _files_differ returns True when one file is missing."""
    file_a = tmp_path / "a.txt"
    file_a.write_text("content", encoding="utf-8")
    file_b = tmp_path / "b.txt"
    assert harvest._files_differ(str(file_a), str(file_b)) is True


def test_files_differ_both_missing(tmp_path: Path):
    """Test that _files_differ returns True when both files are missing."""
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    # Both missing - should return True (they differ in the sense that neither exists)
    assert harvest._files_differ(str(file_a), str(file_b)) is True


def test_files_differ_non_regular_b(tmp_path: Path):
    """Test that _files_differ handles non-regular file (symlink)."""
    file_a = tmp_path / "a.txt"
    file_a.write_text("content", encoding="utf-8")
    link_b = tmp_path / "link"
    link_b.symlink_to(file_a)
    # Symlinks are followed, so content is the same
    assert harvest._files_differ(str(file_a), str(link_b)) is False


def test_files_differ_oserror_on_read(tmp_path: Path, monkeypatch):
    """Test that _files_differ returns True on OSError during read."""
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    file_a.write_text("content", encoding="utf-8")
    file_b.write_text("content", encoding="utf-8")

    def fake_open(path, *args, **kwargs):
        raise OSError("Permission denied")

    monkeypatch.setattr("builtins.open", fake_open, raising=False)
    assert harvest._files_differ(str(file_a), str(file_b)) is True


def test_files_differ_large_file_returns_true(tmp_path: Path):
    """Test that _files_differ returns True for files larger than max_bytes."""
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    # Create files larger than default max_bytes (2MB)
    data = b"x" * 3_000_000
    file_a.write_bytes(data)
    file_b.write_bytes(data)
    # Should return True because files are too large
    assert harvest._files_differ(str(file_a), str(file_b), max_bytes=1_000_000) is True


def test_files_differ_size_mismatch(tmp_path: Path):
    """Test that _files_differ detects size mismatch quickly."""
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    file_a.write_text("short", encoding="utf-8")
    file_b.write_text("much longer content here", encoding="utf-8")
    assert harvest._files_differ(str(file_a), str(file_b)) is True


def test_files_differ_large_files(tmp_path: Path):
    """Test that _files_differ handles large files efficiently."""
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    # Create files with same content but large
    data = b"x" * 10000
    file_a.write_bytes(data)
    file_b.write_bytes(data)
    assert harvest._files_differ(str(file_a), str(file_b)) is False


def test_hint_names_with_unit_and_packages():
    """Test _hint_names extracts hints from unit and packages."""
    result = harvest._hint_names("nginx.service", {"nginx-common", "nginx-core"})
    assert "nginx" in result
    assert "nginx-common" in result
    assert "nginx-core" in result


def test_hint_names_with_template_unit():
    """Test _hint_names handles template units."""
    result = harvest._hint_names("getty@tty1.service", set())
    assert "getty" in result
    assert "getty@tty1" in result


def test_hint_names_with_dotted_unit():
    """Test _hint_names handles dotted unit names."""
    result = harvest._hint_names("nginx.service", set())
    assert "nginx" in result


def test_hint_names_empty():
    """Test _hint_names with empty inputs."""
    result = harvest._hint_names("", set())
    assert result == set()


def test_add_pkgs_from_etc_topdirs():
    """Test _add_pkgs_from_etc_topdirs expands hints."""
    hints = {"nginx"}
    topdir_to_pkgs = {
        "nginx": {"nginx-common", "nginx-core"},
        "ssh": {"openssh-server"},
    }
    pkgs = set()
    harvest._add_pkgs_from_etc_topdirs(hints, topdir_to_pkgs, pkgs)
    # Should add packages from matching topdirs
    assert "nginx-common" in pkgs or "nginx-core" in pkgs


def test_add_pkgs_from_etc_topdirs_empty():
    """Test _add_pkgs_from_etc_topdirs with empty inputs."""
    hints = set()
    topdir_to_pkgs = {}
    pkgs = set()
    harvest._add_pkgs_from_etc_topdirs(hints, topdir_to_pkgs, pkgs)
    assert pkgs == set()


def test_is_confish_with_conf(tmp_path: Path):
    """Test _is_confish recognizes .conf files."""
    file1 = tmp_path / "test.conf"
    file1.write_text("[Unit]", encoding="utf-8")
    assert harvest._is_confish(str(file1)) is True


def test_is_confish_with_yaml(tmp_path: Path):
    """Test _is_confish recognizes .yaml files."""
    file1 = tmp_path / "test.yaml"
    file1.write_text("key: value", encoding="utf-8")
    assert harvest._is_confish(str(file1)) is True


def test_is_confish_with_json(tmp_path: Path):
    """Test _is_confish recognizes .json files."""
    file1 = tmp_path / "test.json"
    file1.write_text('{"key": "value"}', encoding="utf-8")
    assert harvest._is_confish(str(file1)) is True


def test_is_confish_with_service(tmp_path: Path):
    """Test _is_confish recognizes .service files."""
    file1 = tmp_path / "test.service"
    file1.write_text("[Unit]", encoding="utf-8")
    assert harvest._is_confish(str(file1)) is True


def test_is_confish_with_extensionless(tmp_path: Path):
    """Test _is_confish recognizes extensionless config files."""
    file1 = tmp_path / "default"
    file1.write_text("OPTIONS=", encoding="utf-8")
    assert harvest._is_confish(str(file1)) is True


def test_is_confish_not_config(tmp_path: Path):
    """Test _is_confish rejects non-config files."""
    file1 = tmp_path / "test.log"
    file1.write_text("log", encoding="utf-8")
    assert harvest._is_confish(str(file1)) is False


def test_is_confish_nonexistent():
    """Test _is_confish returns False for nonexistent files."""
    assert harvest._is_confish("/nonexistent/file.xyz") is False
