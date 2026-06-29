import json
import os
import pytest

from pathlib import Path

import enroll.harvest as harvest
import enroll.system_paths as system_paths
from enroll.platform import PlatformInfo
from enroll.systemd import UnitInfo
from enroll.pathfilter import PathFilter
import enroll.capture as capture
from enroll.capture import (
    capture_file as _capture_file,
    capture_link as _capture_link,
    capture_user_shell_dotfiles,
    files_differ,
)
from enroll.harvest_types import ExcludedFile, ManagedFile, ManagedLink
from enroll.ignore import IgnorePolicy
from enroll.package_hints import (
    add_pkgs_from_etc_topdirs,
    hint_names as _hint_names,
)
from enroll.system_paths import (
    is_confish as _is_confish,
    iter_matching_files as _iter_matching_files,
    parse_apt_signed_by as _parse_apt_signed_by,
    topdirs_for_package as _topdirs_for_package,
)

from unittest.mock import MagicMock


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

    monkeypatch.setattr(harvest.os.path, "isfile", fake_isfile)
    monkeypatch.setattr(harvest.os.path, "isdir", fake_isdir)
    monkeypatch.setattr(harvest.os.path, "islink", fake_islink)
    monkeypatch.setattr(harvest.os.path, "exists", fake_exists)
    monkeypatch.setattr(harvest.os, "walk", fake_walk)

    # Avoid real system access
    monkeypatch.setattr(harvest, "list_enabled_services", lambda: ["openvpn.service"])
    monkeypatch.setattr(harvest, "list_enabled_timers", lambda: [])
    monkeypatch.setattr(
        harvest,
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
    # curl has a package-owned /etc path, but no changed/custom harvested
    # artifacts. That should still be considered a simple package role.
    pkg_to_etc_paths = {
        "openvpn": ["/etc/openvpn/server.conf"],
        "curl": ["/etc/curl/curlrc"],
    }

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
        harvest, "detect_platform", lambda: PlatformInfo("debian", "dpkg", {})
    )
    monkeypatch.setattr(harvest, "get_backend", lambda info=None: backend)

    monkeypatch.setattr(harvest, "collect_non_system_users", lambda: [])

    import enroll.accounts as accounts

    monkeypatch.setattr(accounts, "find_system_flatpaks", lambda: [])
    monkeypatch.setattr(accounts, "find_system_flatpak_remotes", lambda: [])
    monkeypatch.setattr(
        accounts, "find_user_flatpak_remotes", lambda home, user=None: []
    )
    monkeypatch.setattr(
        accounts,
        "find_system_snaps",
        lambda: [accounts.SnapInstall(name="code", channel="latest/stable")],
    )

    def fake_stat_triplet(p: str):
        if p == "/usr/local/bin/myscript":
            return ("root", "root", "0755")
        # /usr/local/bin/readme.txt remains non-executable
        return ("root", "root", "0644")

    monkeypatch.setattr(harvest, "stat_triplet", fake_stat_triplet)
    monkeypatch.setattr(harvest, "stat_dir_triplet", fake_stat_triplet)
    monkeypatch.setattr(capture, "stat_triplet", fake_stat_triplet)

    # Avoid needing source files on disk by implementing our own bundle copier
    def fake_copy(bundle_dir: str, role_name: str, abs_path: str, src_rel: str):
        dst = Path(bundle_dir) / "artifacts" / role_name / src_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(files.get(abs_path, b""))

    monkeypatch.setattr(capture, "copy_into_bundle", fake_copy)

    state_path = harvest.harvest(str(bundle), policy=AllowAllPolicy())
    st = json.loads(Path(state_path).read_text(encoding="utf-8"))

    inv = st["inventory"]["packages"]
    assert "openvpn" in inv
    assert "curl" in inv

    # openvpn is managed by the service role, so it should NOT appear as a package role.
    pkg_roles = st["roles"]["packages"]
    assert all(pr["package"] != "openvpn" for pr in pkg_roles)
    assert any(pr["package"] == "curl" for pr in pkg_roles)
    curl_role = next(pr for pr in pkg_roles if pr["package"] == "curl")
    assert curl_role["has_config"] is False
    assert any("No changed or custom configuration" in n for n in curl_role["notes"])

    # Inventory provenance: openvpn should be observed via systemd unit.
    openvpn_obs = inv["openvpn"]["observed_via"]
    assert any(
        o.get("kind") == "systemd_unit" and o.get("ref") == "openvpn.service"
        for o in openvpn_obs
    )

    assert st["roles"]["snap"]["role_name"] == "snap"
    assert st["roles"]["snap"]["system_snaps"][0]["name"] == "code"

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

    monkeypatch.setattr(harvest.os.path, "isfile", lambda p: p in files)
    monkeypatch.setattr(harvest.os.path, "islink", lambda p: False)
    monkeypatch.setattr(harvest.os.path, "isdir", lambda p: p in dirs)
    monkeypatch.setattr(harvest.os.path, "exists", lambda p: p in files or p in dirs)
    monkeypatch.setattr(
        harvest.os, "walk", lambda root: [("/etc/cron.d", [], ["ntpsec"])]
    )

    # Only include the cron snippet in the system capture set.
    monkeypatch.setattr(
        system_paths,
        "iter_system_capture_paths",
        lambda: [("/etc/cron.d/ntpsec", "system_cron")],
    )

    monkeypatch.setattr(
        harvest, "list_enabled_services", lambda: ["apparmor.service", "ntpsec.service"]
    )
    monkeypatch.setattr(harvest, "list_enabled_timers", lambda: [])

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

    monkeypatch.setattr(harvest, "get_unit_info", fake_unit_info)

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
        harvest, "detect_platform", lambda: PlatformInfo("debian", "dpkg", {})
    )
    monkeypatch.setattr(harvest, "get_backend", lambda info=None: backend)

    monkeypatch.setattr(harvest, "stat_triplet", lambda p: ("root", "root", "0644"))
    monkeypatch.setattr(harvest, "stat_dir_triplet", lambda p: ("root", "root", "0755"))
    monkeypatch.setattr(capture, "stat_triplet", lambda p: ("root", "root", "0644"))
    monkeypatch.setattr(harvest, "collect_non_system_users", lambda: [])

    def fake_copy(bundle_dir: str, role_name: str, abs_path: str, src_rel: str):
        dst = Path(bundle_dir) / "artifacts" / role_name / src_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(files[abs_path])

    monkeypatch.setattr(capture, "copy_into_bundle", fake_copy)

    state_path = harvest.harvest(str(bundle), policy=AllowAllPolicy())
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
    assert files_differ(str(file1), str(file2)) is False


def test_files_differ_binary_different(tmp_path: Path):
    file1 = tmp_path / "file1.bin"
    file2 = tmp_path / "file2.bin"
    file1.write_bytes(b"\x00\x01\x02\x03")
    file2.write_bytes(b"\x00\x01\x02\x04")
    assert files_differ(str(file1), str(file2)) is True


def test_files_differ_non_regular_a(tmp_path: Path):
    directory = tmp_path / "dir"
    directory.mkdir()
    file1 = tmp_path / "file1.txt"
    file1.write_text("content", encoding="utf-8")
    assert files_differ(str(directory), str(file1)) is True


def test_topdirs_for_package_with_multiple_paths():
    pkg_to_etc_paths = {
        "nginx": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default"],
    }
    result = _topdirs_for_package("nginx", pkg_to_etc_paths)
    assert result == {"nginx"}


def test_topdirs_for_package_with_multiple_topdirs():
    pkg_to_etc_paths = {
        "multi": ["/etc/nginx/nginx.conf", "/etc/ssh/sshd_config"],
    }
    result = _topdirs_for_package("multi", pkg_to_etc_paths)
    assert result == {"nginx", "ssh"}


def test_topdirs_for_package_empty():
    result = _topdirs_for_package("empty", {})
    assert result == set()


def test_topdirs_for_package_no_etc():
    pkg_to_etc_paths = {
        "other": ["/usr/share/doc/file"],
    }
    result = _topdirs_for_package("other", pkg_to_etc_paths)
    assert result == set()


def test_files_differ_same_content(tmp_path: Path):
    """Test that _files_differ returns False for identical content."""
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    file_a.write_text("same content", encoding="utf-8")
    file_b.write_text("same content", encoding="utf-8")
    assert files_differ(str(file_a), str(file_b)) is False


def test_files_differ_different_content(tmp_path: Path):
    """Test that _files_differ returns True for different content."""
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    file_a.write_text("content a", encoding="utf-8")
    file_b.write_text("content b", encoding="utf-8")
    assert files_differ(str(file_a), str(file_b)) is True


def test_files_differ_missing_file(tmp_path: Path):
    """Test that _files_differ returns True when one file is missing."""
    file_a = tmp_path / "a.txt"
    file_a.write_text("content", encoding="utf-8")
    file_b = tmp_path / "b.txt"
    assert files_differ(str(file_a), str(file_b)) is True


def test_files_differ_both_missing(tmp_path: Path):
    """Test that _files_differ returns True when both files are missing."""
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    # Both missing - should return True (they differ in the sense that neither exists)
    assert files_differ(str(file_a), str(file_b)) is True


def test_files_differ_non_regular_b(tmp_path: Path):
    """Test that _files_differ handles non-regular file (symlink)."""
    file_a = tmp_path / "a.txt"
    file_a.write_text("content", encoding="utf-8")
    link_b = tmp_path / "link"
    link_b.symlink_to(file_a)
    # Symlinks are followed, so content is the same
    assert files_differ(str(file_a), str(link_b)) is False


def test_files_differ_oserror_on_read(tmp_path: Path, monkeypatch):
    """Test that _files_differ returns True on OSError during read."""
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    file_a.write_text("content", encoding="utf-8")
    file_b.write_text("content", encoding="utf-8")

    def fake_open(path, *args, **kwargs):
        raise OSError("Permission denied")

    monkeypatch.setattr("builtins.open", fake_open, raising=False)
    assert files_differ(str(file_a), str(file_b)) is True


def test_files_differ_large_file_returns_true(tmp_path: Path):
    """Test that _files_differ returns True for files larger than max_bytes."""
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    # Create files larger than default max_bytes (2MB)
    data = b"x" * 3_000_000
    file_a.write_bytes(data)
    file_b.write_bytes(data)
    # Should return True because files are too large
    assert files_differ(str(file_a), str(file_b), max_bytes=1_000_000) is True


def test_files_differ_size_mismatch(tmp_path: Path):
    """Test that _files_differ detects size mismatch quickly."""
    file_a = tmp_path / "a.txt"
    file_b = tmp_path / "b.txt"
    file_a.write_text("short", encoding="utf-8")
    file_b.write_text("much longer content here", encoding="utf-8")
    assert files_differ(str(file_a), str(file_b)) is True


def test_files_differ_large_files(tmp_path: Path):
    """Test that _files_differ handles large files efficiently."""
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    # Create files with same content but large
    data = b"x" * 10000
    file_a.write_bytes(data)
    file_b.write_bytes(data)
    assert files_differ(str(file_a), str(file_b)) is False


def test_hint_names_with_unit_and_packages():
    """Test _hint_names extracts hints from unit and packages."""
    result = _hint_names("nginx.service", {"nginx-common", "nginx-core"})
    assert "nginx" in result
    assert "nginx-common" in result
    assert "nginx-core" in result


def test_hint_names_with_template_unit():
    """Test _hint_names handles template units."""
    result = _hint_names("getty@tty1.service", set())
    assert "getty" in result
    assert "getty@tty1" in result


def test_hint_names_with_dotted_unit():
    """Test _hint_names handles dotted unit names."""
    result = _hint_names("nginx.service", set())
    assert "nginx" in result


def test_hint_names_empty():
    """Test _hint_names with empty inputs."""
    result = _hint_names("", set())
    assert result == set()


def test_add_pkgs_from_etc_topdirs():
    """Test _add_pkgs_from_etc_topdirs expands hints."""
    hints = {"nginx"}
    topdir_to_pkgs = {
        "nginx": {"nginx-common", "nginx-core"},
        "ssh": {"openssh-server"},
    }
    pkgs = set()
    add_pkgs_from_etc_topdirs(hints, topdir_to_pkgs, pkgs)
    # Should add packages from matching topdirs
    assert "nginx-common" in pkgs or "nginx-core" in pkgs


def test_add_pkgs_from_etc_topdirs_empty():
    """Test _add_pkgs_from_etc_topdirs with empty inputs."""
    hints = set()
    topdir_to_pkgs = {}
    pkgs = set()
    add_pkgs_from_etc_topdirs(hints, topdir_to_pkgs, pkgs)
    assert pkgs == set()


def test_is_confish_with_conf(tmp_path: Path):
    """Test _is_confish recognizes .conf files."""
    file1 = tmp_path / "test.conf"
    file1.write_text("[Unit]", encoding="utf-8")
    assert _is_confish(str(file1)) is True


def test_is_confish_with_yaml(tmp_path: Path):
    """Test _is_confish recognizes .yaml files."""
    file1 = tmp_path / "test.yaml"
    file1.write_text("key: value", encoding="utf-8")
    assert _is_confish(str(file1)) is True


def test_is_confish_with_json(tmp_path: Path):
    """Test _is_confish recognizes .json files."""
    file1 = tmp_path / "test.json"
    file1.write_text('{"key": "value"}', encoding="utf-8")
    assert _is_confish(str(file1)) is True


def test_is_confish_with_service(tmp_path: Path):
    """Test _is_confish recognizes .service files."""
    file1 = tmp_path / "test.service"
    file1.write_text("[Unit]", encoding="utf-8")
    assert _is_confish(str(file1)) is True


def test_is_confish_with_extensionless(tmp_path: Path):
    """Test _is_confish recognizes extensionless config files."""
    file1 = tmp_path / "default"
    file1.write_text("OPTIONS=", encoding="utf-8")
    assert _is_confish(str(file1)) is True


def test_is_confish_not_config(tmp_path: Path):
    """Test _is_confish rejects non-config files."""
    file1 = tmp_path / "test.log"
    file1.write_text("log", encoding="utf-8")
    assert _is_confish(str(file1)) is False


def test_is_confish_nonexistent():
    """Test _is_confish returns False for nonexistent files."""
    assert _is_confish("/nonexistent/file.xyz") is False


"""Additional coverage tests for harvest.py"""


class TestIsConfish:
    """Tests for _is_confish function"""

    def test_is_confish_true_extensions(self, tmp_path):
        """Test files with config extensions are detected."""
        for ext in [".conf", ".cfg", ".ini", ".yaml", ".json", ".cnf"]:
            f = tmp_path / f"test{ext}"
            f.write_text("test", encoding="utf-8")
            assert _is_confish(str(f)) is True

    def test_is_confish_false(self, tmp_path):
        """Test non-config files are not detected."""
        for name in ["data.txt", "script.sh"]:
            f = tmp_path / name
            f.write_text("test", encoding="utf-8")
            assert _is_confish(str(f)) is False


class TestHintNames:
    """Tests for _hint_names function"""

    def test_hint_names_simple(self):
        """Test simple hint name extraction."""
        result = _hint_names("nginx", {"nginx"})
        assert "nginx" in result

    def test_hint_names_multiple(self):
        """Test multiple hint names."""
        result = _hint_names("nginx", {"apache"})
        assert "nginx" in result
        assert "apache" in result

    def test_hint_names_empty(self):
        """Test empty hint names."""
        result = _hint_names("", set())
        assert result == set()

    def test_hint_names_with_service(self):
        """Test hint names with .service suffix."""
        result = _hint_names("nginx.service", set())
        assert "nginx" in result

    def test_hint_names_with_template(self):
        """Test hint names with template unit."""
        result = _hint_names("nginx@.service", set())
        assert "nginx" in result


class TestTopdirsForPackage:
    """Tests for _topdirs_for_package function"""

    def test_topdirs_single_level(self):
        """Test topdirs with single level paths."""
        pkg_to_etc = {"nginx": ["/etc/nginx/nginx.conf"]}
        result = _topdirs_for_package("nginx", pkg_to_etc)
        assert result == {"nginx"}

    def test_topdirs_multiple_paths(self):
        """Test topdirs with multiple paths."""
        pkg_to_etc = {"nginx": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled"]}
        result = _topdirs_for_package("nginx", pkg_to_etc)
        assert result == {"nginx"}

    def test_topdirs_empty(self):
        """Test topdirs with empty package."""
        result = _topdirs_for_package("nonexistent", {})
        assert result == set()


class TestIterMatchingFiles:
    """Tests for _iter_matching_files function"""

    def test_iter_matching_files_glob(self, tmp_path):
        """Test glob pattern matching."""
        (tmp_path / "a.txt").write_text("a", encoding="utf-8")
        (tmp_path / "b.txt").write_text("b", encoding="utf-8")
        (tmp_path / "c.py").write_text("c", encoding="utf-8")

        os.chdir(tmp_path)
        result = _iter_matching_files("*.txt")
        assert len(result) == 2
        assert any("a.txt" in p for p in result)
        assert any("b.txt" in p for p in result)

    def test_iter_matching_files_directory_walk(self, tmp_path):
        """Test directory walking."""
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (tmp_path / "a.txt").write_text("a", encoding="utf-8")
        (subdir / "b.txt").write_text("b", encoding="utf-8")

        os.chdir(tmp_path)
        result = _iter_matching_files(str(tmp_path))
        assert len(result) == 2

    def test_iter_matching_files_cap(self, tmp_path):
        """Test file cap limit."""
        for i in range(100):
            (tmp_path / f"file{i}.txt").write_text(str(i), encoding="utf-8")

        os.chdir(tmp_path)
        result = _iter_matching_files("*.txt", cap=10)
        assert len(result) == 10


class TestParseAptSignedBy:
    """Tests for _parse_apt_signed_by function"""

    def test_parse_apt_signed_by_bracket(self, tmp_path):
        """Test parsing signed-by from bracket notation."""
        sources_list = tmp_path / "sources.list"
        sources_list.write_text(
            "deb [signed-by=/usr/share/keyrings/nginx.gpg] http://nginx.net stable main\n",
            encoding="utf-8",
        )
        result = _parse_apt_signed_by([str(sources_list)])
        assert "/usr/share/keyrings/nginx.gpg" in result

    def test_parse_apt_signed_by_header(self, tmp_path):
        """Test parsing signed-by from header."""
        sources_file = tmp_path / "sources.list"
        sources_file.write_text(
            "Signed-By: /usr/share/keyrings/foo.gpg\n", encoding="utf-8"
        )
        result = _parse_apt_signed_by([str(sources_file)])
        assert "/usr/share/keyrings/foo.gpg" in result

    def test_parse_apt_signed_by_multiple(self, tmp_path):
        """Test parsing multiple signed-by paths."""
        sources_file = tmp_path / "sources.list"
        sources_file.write_text(
            "Signed-By: /usr/share/keyrings/a.gpg, /usr/share/keyrings/b.gpg\n",
            encoding="utf-8",
        )
        result = _parse_apt_signed_by([str(sources_file)])
        assert "/usr/share/keyrings/a.gpg" in result
        assert "/usr/share/keyrings/b.gpg" in result

    def test_parse_apt_signed_by_oserror(self, tmp_path):
        """Test handling of unreadable files."""
        result = _parse_apt_signed_by(["/nonexistent/file"])
        assert result == set()


class TestCaptureLink:
    """Tests for _capture_link function"""

    def test_capture_link_basic(self, tmp_path):
        """Test basic link capture."""
        target = tmp_path / "target.txt"
        target.write_text("content", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        policy = MagicMock(spec=IgnorePolicy)
        policy.deny_reason_link = None
        policy.deny_reason = MagicMock(return_value=None)
        policy.deny_reason_link = None  # No special link denial

        managed: list[ManagedLink] = []
        excluded: list[ExcludedFile] = []
        path_filter = PathFilter([], [])

        result = _capture_link(
            role_name="test_role",
            abs_path=str(link),
            reason="test",
            policy=policy,
            path_filter=path_filter,
            managed_out=managed,
            excluded_out=excluded,
            seen_role=set(),
            seen_global=set(),
        )
        assert result is True
        assert len(managed) == 1
        assert managed[0].path == str(link)

    def test_capture_link_deny(self, tmp_path):
        """Test link capture with deny policy."""
        target = tmp_path / "target.txt"
        target.write_text("content", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        policy = MagicMock(spec=IgnorePolicy)
        policy.deny_reason_link = None
        policy.deny_reason = MagicMock(return_value="policy_deny")

        managed: list[ManagedLink] = []
        excluded: list[ExcludedFile] = []
        path_filter = PathFilter([], [])

        result = _capture_link(
            role_name="test_role",
            abs_path=str(link),
            reason="test",
            policy=policy,
            path_filter=path_filter,
            managed_out=managed,
            excluded_out=excluded,
            seen_role=set(),
            seen_global=set(),
        )
        assert result is False
        assert len(excluded) == 1

    def test_capture_link_not_symlink(self, tmp_path):
        """Test that regular files are rejected."""
        f = tmp_path / "file.txt"
        f.write_text("content", encoding="utf-8")

        policy = MagicMock(spec=IgnorePolicy)
        policy.deny_reason_link = None
        policy.deny_reason = MagicMock(return_value=None)

        managed: list[ManagedLink] = []
        excluded: list[ExcludedFile] = []
        path_filter = PathFilter([], [])

        result = _capture_link(
            role_name="test_role",
            abs_path=str(f),
            reason="test",
            policy=policy,
            path_filter=path_filter,
            managed_out=managed,
            excluded_out=excluded,
            seen_role=set(),
            seen_global=set(),
        )
        assert result is False
        assert len(excluded) == 1

    def test_capture_link_seen_role(self, tmp_path):
        """Test link capture with seen_role deduplication."""
        target = tmp_path / "target.txt"
        target.write_text("content", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        policy = MagicMock(spec=IgnorePolicy)
        policy.deny_reason_link = None
        policy.deny_reason = MagicMock(return_value=None)

        managed: list[ManagedLink] = []
        excluded: list[ExcludedFile] = []
        path_filter = PathFilter([], [])
        seen_role = {str(link)}

        result = _capture_link(
            role_name="test_role",
            abs_path=str(link),
            reason="test",
            policy=policy,
            path_filter=path_filter,
            managed_out=managed,
            excluded_out=excluded,
            seen_role=seen_role,
            seen_global=None,
        )
        assert result is False
        assert len(managed) == 0

    def test_capture_link_seen_global(self, tmp_path):
        """Test link capture with seen_global deduplication."""
        target = tmp_path / "target.txt"
        target.write_text("content", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        policy = MagicMock(spec=IgnorePolicy)
        policy.deny_reason_link = None
        policy.deny_reason = MagicMock(return_value=None)

        managed: list[ManagedLink] = []
        excluded: list[ExcludedFile] = []
        path_filter = PathFilter([], [])
        seen_global = {str(link)}

        result = _capture_link(
            role_name="test_role",
            abs_path=str(link),
            reason="test",
            policy=policy,
            path_filter=path_filter,
            managed_out=managed,
            excluded_out=excluded,
            seen_role=None,
            seen_global=seen_global,
        )
        assert result is False
        assert len(managed) == 0


class TestCaptureFile:
    """Tests for _capture_file function"""

    def test_capture_file_basic(self, tmp_path):
        """Test basic file capture."""
        bundle = tmp_path / "bundle"
        bundle.mkdir()
        (bundle / "artifacts").mkdir()

        source = tmp_path / "source.txt"
        source.write_text("content", encoding="utf-8")

        policy = MagicMock(spec=IgnorePolicy)
        policy.deny_reason_link = None
        policy.deny_reason = MagicMock(return_value=None)

        managed: list[ManagedFile] = []
        excluded: list[ExcludedFile] = []
        path_filter = PathFilter([], [])

        result = _capture_file(
            bundle_dir=str(bundle),
            role_name="test_role",
            abs_path=str(source),
            reason="test",
            policy=policy,
            path_filter=path_filter,
            managed_out=managed,
            excluded_out=excluded,
            seen_role=set(),
            seen_global=set(),
            metadata=None,
        )
        assert result is True
        assert len(managed) == 1

    def test_capture_file_seen_role(self, tmp_path):
        """Test file capture with seen_role deduplication."""
        bundle = tmp_path / "bundle"
        bundle.mkdir()

        source = tmp_path / "source.txt"
        source.write_text("content", encoding="utf-8")

        policy = MagicMock(spec=IgnorePolicy)
        policy.deny_reason_link = None
        policy.deny_reason = MagicMock(return_value=None)

        managed: list[ManagedFile] = []
        excluded: list[ExcludedFile] = []
        path_filter = PathFilter([], [])
        seen_role = {str(source)}

        result = _capture_file(
            bundle_dir=str(bundle),
            role_name="test_role",
            abs_path=str(source),
            reason="test",
            policy=policy,
            path_filter=path_filter,
            managed_out=managed,
            excluded_out=excluded,
            seen_role=seen_role,
            seen_global=None,
            metadata=None,
        )
        assert result is False
        assert len(managed) == 0

    def test_capture_file_seen_global(self, tmp_path):
        """Test file capture with seen_global deduplication."""
        bundle = tmp_path / "bundle"
        bundle.mkdir()

        source = tmp_path / "source.txt"
        source.write_text("content", encoding="utf-8")

        policy = MagicMock(spec=IgnorePolicy)
        policy.deny_reason_link = None
        policy.deny_reason = MagicMock(return_value=None)

        managed: list[ManagedFile] = []
        excluded: list[ExcludedFile] = []
        path_filter = PathFilter([], [])
        seen_global = {str(source)}

        result = _capture_file(
            bundle_dir=str(bundle),
            role_name="test_role",
            abs_path=str(source),
            reason="test",
            policy=policy,
            path_filter=path_filter,
            managed_out=managed,
            excluded_out=excluded,
            seen_role=None,
            seen_global=seen_global,
            metadata=None,
        )
        assert result is False
        assert len(managed) == 0


def test_user_shell_dotfiles_are_not_auto_captured_without_dangerous(tmp_path: Path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    (home / ".bashrc").write_text("export DEMO=value\n", encoding="utf-8")
    (home / ".bash_aliases").write_text("alias ll='ls -la'\n", encoding="utf-8")

    managed: list[ManagedFile] = []
    excluded: list[ExcludedFile] = []

    captured = capture_user_shell_dotfiles(
        bundle_dir=str(tmp_path / "bundle"),
        role_name="users",
        home=str(home),
        skel_dir=str(tmp_path / "skel"),
        enabled=False,
        policy=IgnorePolicy(dangerous=False),
        path_filter=PathFilter(),
        managed_out=managed,
        excluded_out=excluded,
        seen_role=set(),
        seen_global=set(),
    )

    assert captured == 0
    assert managed == []
    assert excluded == []
    assert not (tmp_path / "bundle" / "artifacts" / "users").exists()


def test_user_shell_dotfiles_dangerous_captures_changed_files_only(tmp_path: Path):
    skel = tmp_path / "skel"
    home = tmp_path / "home" / "alice"
    skel.mkdir(parents=True)
    home.mkdir(parents=True)

    (skel / ".bashrc").write_text("# default bashrc\n", encoding="utf-8")
    (home / ".bashrc").write_text("# customised bashrc\n", encoding="utf-8")

    (skel / ".profile").write_text("# default profile\n", encoding="utf-8")
    (home / ".profile").write_text("# default profile\n", encoding="utf-8")

    (home / ".bash_aliases").write_text("alias ll='ls -la'\n", encoding="utf-8")

    target = home / "target"
    target.write_text("# symlink target\n", encoding="utf-8")
    os.symlink(target, home / ".bash_logout")

    managed: list[ManagedFile] = []
    excluded: list[ExcludedFile] = []

    captured = capture_user_shell_dotfiles(
        bundle_dir=str(tmp_path / "bundle"),
        role_name="users",
        home=str(home),
        skel_dir=str(skel),
        enabled=True,
        policy=IgnorePolicy(dangerous=True),
        path_filter=PathFilter(),
        managed_out=managed,
        excluded_out=excluded,
        seen_role=set(),
        seen_global=set(),
    )

    captured_paths = {mf.path for mf in managed}
    assert captured == 2
    assert str(home / ".bashrc") in captured_paths
    assert str(home / ".bash_aliases") in captured_paths
    assert str(home / ".profile") not in captured_paths
    assert str(home / ".bash_logout") not in captured_paths
    assert excluded == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
