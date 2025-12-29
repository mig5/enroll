from __future__ import annotations

from pathlib import Path

import enroll.platform as platform


def test_read_os_release_parses_kv_and_strips_quotes(tmp_path: Path):
    p = tmp_path / "os-release"
    p.write_text(
        """
# comment
ID=fedora
ID_LIKE=\"rhel centos\"
NAME=\"Fedora Linux\"
EMPTY=
NOEQUALS
""",
        encoding="utf-8",
    )

    osr = platform._read_os_release(str(p))
    assert osr["ID"] == "fedora"
    assert osr["ID_LIKE"] == "rhel centos"
    assert osr["NAME"] == "Fedora Linux"
    assert osr["EMPTY"] == ""
    assert "NOEQUALS" not in osr


def test_detect_platform_prefers_os_release(monkeypatch):
    monkeypatch.setattr(
        platform,
        "_read_os_release",
        lambda path="/etc/os-release": {"ID": "fedora", "ID_LIKE": "rhel"},
    )
    # If os-release is decisive we shouldn't need which()
    monkeypatch.setattr(platform.shutil, "which", lambda exe: None)

    info = platform.detect_platform()
    assert info.os_family == "redhat"
    assert info.pkg_backend == "rpm"


def test_detect_platform_fallbacks_to_dpkg_when_unknown(monkeypatch):
    monkeypatch.setattr(platform, "_read_os_release", lambda path="/etc/os-release": {})
    monkeypatch.setattr(
        platform.shutil, "which", lambda exe: "/usr/bin/dpkg" if exe == "dpkg" else None
    )

    info = platform.detect_platform()
    assert info.os_family == "debian"
    assert info.pkg_backend == "dpkg"


def test_get_backend_unknown_prefers_rpm_if_present(monkeypatch):
    monkeypatch.setattr(
        platform.shutil, "which", lambda exe: "/usr/bin/rpm" if exe == "rpm" else None
    )

    b = platform.get_backend(
        platform.PlatformInfo(os_family="unknown", pkg_backend="unknown", os_release={})
    )
    assert isinstance(b, platform.RpmBackend)


def test_rpm_backend_modified_paths_labels_conffiles(monkeypatch):
    b = platform.RpmBackend()

    # Pretend rpm -V says both files changed, but only one is a config file.
    monkeypatch.setattr(b, "_modified_files", lambda pkg: {"/etc/foo.conf", "/etc/bar"})
    monkeypatch.setattr(b, "_config_files", lambda pkg: {"/etc/foo.conf"})

    out = b.modified_paths("mypkg", ["/etc/foo.conf", "/etc/bar", "/etc/dnf/dnf.conf"])
    assert out["/etc/foo.conf"] == "modified_conffile"
    assert out["/etc/bar"] == "modified_packaged_file"
    # Package-manager config paths are excluded.
    assert "/etc/dnf/dnf.conf" not in out


def test_specific_paths_for_hints_differs_between_backends():
    # We can exercise this without instantiating DpkgBackend (which reads dpkg status)
    class Dummy(platform.PackageBackend):
        name = "dummy"
        pkg_config_prefixes = ("/etc/apt/",)

    d = Dummy()
    assert d.is_pkg_config_path("/etc/apt/sources.list")
    assert not d.is_pkg_config_path("/etc/ssh/sshd_config")

    r = platform.RpmBackend()
    paths = set(r.specific_paths_for_hints({"nginx"}))
    assert "/etc/sysconfig/nginx" in paths
    assert "/etc/sysconfig/nginx.conf" in paths
