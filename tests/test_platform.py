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


def test_read_os_release_file_not_found(tmp_path: Path):
    result = platform._read_os_release(str(tmp_path / "nonexistent"))
    assert result == {}


def test_read_os_release_handles_invalid_line(tmp_path: Path):
    p = tmp_path / "os-release"
    p.write_text(
        "ID=ubuntu\n" "NO_EQUALS_SIGN\n" 'VERSION="22.04"\n',
        encoding="utf-8",
    )
    result = platform._read_os_release(str(p))
    assert result["ID"] == "ubuntu"
    assert result["VERSION"] == "22.04"
    assert "NO_EQUALS_SIGN" not in result


def test_detect_platform_debian(monkeypatch):
    def fake_read_os_release(path: str = "/etc/os-release") -> dict:
        return {"ID": "debian", "VERSION_ID": "11"}

    monkeypatch.setattr(platform, "_read_os_release", fake_read_os_release)
    result = platform.detect_platform()
    assert result.os_family == "debian"
    assert result.pkg_backend == "dpkg"


def test_detect_platform_ubuntu(monkeypatch):
    def fake_read_os_release(path: str = "/etc/os-release") -> dict:
        return {"ID": "ubuntu", "VERSION_ID": "22.04"}

    monkeypatch.setattr(platform, "_read_os_release", fake_read_os_release)
    result = platform.detect_platform()
    assert result.os_family == "debian"
    assert result.pkg_backend == "dpkg"


def test_detect_platform_fedora(monkeypatch):
    def fake_read_os_release(path: str = "/etc/os-release") -> dict:
        return {"ID": "fedora", "VERSION_ID": "38"}

    monkeypatch.setattr(platform, "_read_os_release", fake_read_os_release)
    result = platform.detect_platform()
    assert result.os_family == "redhat"
    assert result.pkg_backend == "rpm"


def test_detect_platform_rocky(monkeypatch):
    def fake_read_os_release(path: str = "/etc/os-release") -> dict:
        return {"ID": "rocky", "VERSION_ID": "9"}

    monkeypatch.setattr(platform, "_read_os_release", fake_read_os_release)
    result = platform.detect_platform()
    assert result.os_family == "redhat"
    assert result.pkg_backend == "rpm"


def test_detect_platform_unknown_fallback_to_dpkg(monkeypatch):
    def fake_read_os_release(path: str = "/etc/os-release") -> dict:
        return {"ID": "unknown"}

    monkeypatch.setattr(platform, "_read_os_release", fake_read_os_release)
    monkeypatch.setattr(platform.shutil, "which", lambda x: x == "dpkg")
    result = platform.detect_platform()
    assert result.os_family == "debian"
    assert result.pkg_backend == "dpkg"


def test_detect_platform_unknown_fallback_to_rpm(monkeypatch):
    def fake_read_os_release(path: str = "/etc/os-release") -> dict:
        return {"ID": "unknown"}

    monkeypatch.setattr(platform, "_read_os_release", fake_read_os_release)
    monkeypatch.setattr(platform.shutil, "which", lambda x: x == "rpm")
    result = platform.detect_platform()
    assert result.os_family == "redhat"
    assert result.pkg_backend == "rpm"


def test_detect_platform_completely_unknown(monkeypatch):
    def fake_read_os_release(path: str = "/etc/os-release") -> dict:
        return {"ID": "unknown"}

    monkeypatch.setattr(platform, "_read_os_release", fake_read_os_release)
    monkeypatch.setattr(platform.shutil, "which", lambda x: False)
    result = platform.detect_platform()
    assert result.os_family == "unknown"
    assert result.pkg_backend == "unknown"


def test_detect_platform_debian_like(monkeypatch):
    def fake_read_os_release(path: str = "/etc/os-release") -> dict:
        return {"ID": "linuxmint", "ID_LIKE": "debian"}

    monkeypatch.setattr(platform, "_read_os_release", fake_read_os_release)
    result = platform.detect_platform()
    assert result.os_family == "debian"
    assert result.pkg_backend == "dpkg"


def test_detect_platform_rhel_like(monkeypatch):
    def fake_read_os_release(path: str = "/etc/os-release") -> dict:
        return {"ID": "centos", "ID_LIKE": "rhel fedora"}

    monkeypatch.setattr(platform, "_read_os_release", fake_read_os_release)
    result = platform.detect_platform()
    assert result.os_family == "redhat"
    assert result.pkg_backend == "rpm"


def test_get_backend_returns_dpkg(monkeypatch):
    info = platform.PlatformInfo(os_family="debian", pkg_backend="dpkg", os_release={})
    backend = platform.get_backend(info)
    assert isinstance(backend, platform.DpkgBackend)
    assert backend.name == "dpkg"


def test_get_backend_returns_rpm(monkeypatch):
    info = platform.PlatformInfo(os_family="redhat", pkg_backend="rpm", os_release={})
    backend = platform.get_backend(info)
    assert isinstance(backend, platform.RpmBackend)
    assert backend.name == "rpm"


def test_get_backend_unknown_with_rpm(monkeypatch):
    info = platform.PlatformInfo(
        os_family="unknown", pkg_backend="unknown", os_release={}
    )
    monkeypatch.setattr(platform.shutil, "which", lambda x: x == "rpm")
    backend = platform.get_backend(info)
    assert isinstance(backend, platform.RpmBackend)


def test_get_backend_unknown_with_dpkg(monkeypatch):
    info = platform.PlatformInfo(
        os_family="unknown", pkg_backend="unknown", os_release={}
    )
    monkeypatch.setattr(platform.shutil, "which", lambda x: x == "dpkg")
    backend = platform.get_backend(info)
    assert isinstance(backend, platform.DpkgBackend)


def test_dpkg_backend_specific_paths():
    backend = platform.DpkgBackend()
    paths = backend.specific_paths_for_hints({"nginx"})
    assert "/etc/default/nginx" in paths
    assert "/etc/init.d/nginx" in paths
    assert "/etc/sysctl.d/nginx.conf" in paths


def test_rpm_backend_specific_paths():
    backend = platform.RpmBackend()
    paths = backend.specific_paths_for_hints({"nginx"})
    assert "/etc/sysconfig/nginx" in paths
    assert "/etc/sysconfig/nginx.conf" in paths
    assert "/etc/sysctl.d/nginx.conf" in paths


def test_is_pkg_config_path_dpkg():
    backend = platform.DpkgBackend()
    assert backend.is_pkg_config_path("/etc/apt/sources.list") is True
    assert backend.is_pkg_config_path("/etc/apt/trusted.gpg") is True
    assert backend.is_pkg_config_path("/etc/ssh/sshd_config") is False


def test_is_pkg_config_path_rpm():
    backend = platform.RpmBackend()
    assert backend.is_pkg_config_path("/etc/dnf/dnf.conf") is True
    assert backend.is_pkg_config_path("/etc/yum.conf") is True
    assert backend.is_pkg_config_path("/etc/yum.repos.d/custom.repo") is True
    assert backend.is_pkg_config_path("/etc/ssh/sshd_config") is False
