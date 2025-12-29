from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .fsutil import file_md5


def _read_os_release(path: str = "/etc/os-release") -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"')
                out[k] = v
    except OSError:
        return {}
    return out


@dataclass
class PlatformInfo:
    os_family: str  # debian|redhat|unknown
    pkg_backend: str  # dpkg|rpm|unknown
    os_release: Dict[str, str]


def detect_platform() -> PlatformInfo:
    """Detect platform family and package backend.

    Uses /etc/os-release when available, with a conservative fallback to
    checking for dpkg/rpm binaries.
    """

    osr = _read_os_release()
    os_id = (osr.get("ID") or "").strip().lower()
    likes = (osr.get("ID_LIKE") or "").strip().lower().split()

    deb_ids = {"debian", "ubuntu", "linuxmint", "raspbian", "kali"}
    rhel_ids = {
        "fedora",
        "rhel",
        "centos",
        "rocky",
        "almalinux",
        "ol",
        "oracle",
        "scientific",
    }

    if os_id in deb_ids or "debian" in likes:
        return PlatformInfo(os_family="debian", pkg_backend="dpkg", os_release=osr)
    if os_id in rhel_ids or any(
        x in likes for x in ("rhel", "fedora", "centos", "redhat")
    ):
        return PlatformInfo(os_family="redhat", pkg_backend="rpm", os_release=osr)

    # Fallback heuristics.
    if shutil.which("dpkg"):
        return PlatformInfo(os_family="debian", pkg_backend="dpkg", os_release=osr)
    if shutil.which("rpm"):
        return PlatformInfo(os_family="redhat", pkg_backend="rpm", os_release=osr)
    return PlatformInfo(os_family="unknown", pkg_backend="unknown", os_release=osr)


class PackageBackend:
    """Backend abstraction for package ownership, config detection, and manual package lists."""

    name: str
    pkg_config_prefixes: Tuple[str, ...]

    def owner_of_path(self, path: str) -> Optional[str]:  # pragma: no cover
        raise NotImplementedError

    def list_manual_packages(self) -> List[str]:  # pragma: no cover
        raise NotImplementedError

    def installed_packages(self) -> Dict[str, List[Dict[str, str]]]:  # pragma: no cover
        """Return mapping of package name -> installed instances.

        Each instance is a dict with at least:
          - version: package version string
          - arch: architecture string

        Backends should be best-effort and return an empty mapping on failure.
        """
        raise NotImplementedError

    def build_etc_index(
        self,
    ) -> Tuple[
        Set[str], Dict[str, str], Dict[str, Set[str]], Dict[str, List[str]]
    ]:  # pragma: no cover
        raise NotImplementedError

    def specific_paths_for_hints(self, hints: Set[str]) -> List[str]:
        return []

    def is_pkg_config_path(self, path: str) -> bool:
        for pfx in self.pkg_config_prefixes:
            if path == pfx or path.startswith(pfx):
                return True
        return False

    def modified_paths(self, pkg: str, etc_paths: List[str]) -> Dict[str, str]:
        """Return a mapping of modified file paths -> reason label."""
        return {}


class DpkgBackend(PackageBackend):
    name = "dpkg"
    pkg_config_prefixes = ("/etc/apt/",)

    def __init__(self) -> None:
        from .debian import parse_status_conffiles

        self._conffiles_by_pkg = parse_status_conffiles()

    def owner_of_path(self, path: str) -> Optional[str]:
        from .debian import dpkg_owner

        return dpkg_owner(path)

    def list_manual_packages(self) -> List[str]:
        from .debian import list_manual_packages

        return list_manual_packages()

    def installed_packages(self) -> Dict[str, List[Dict[str, str]]]:
        from .debian import list_installed_packages

        return list_installed_packages()

    def build_etc_index(self):
        from .debian import build_dpkg_etc_index

        return build_dpkg_etc_index()

    def specific_paths_for_hints(self, hints: Set[str]) -> List[str]:
        paths: List[str] = []
        for h in hints:
            paths.extend(
                [
                    f"/etc/default/{h}",
                    f"/etc/init.d/{h}",
                    f"/etc/sysctl.d/{h}.conf",
                ]
            )
        return paths

    def modified_paths(self, pkg: str, etc_paths: List[str]) -> Dict[str, str]:
        from .debian import read_pkg_md5sums

        out: Dict[str, str] = {}
        conff = self._conffiles_by_pkg.get(pkg, {})
        md5sums = read_pkg_md5sums(pkg)

        for path in etc_paths:
            if not path.startswith("/etc/"):
                continue
            if self.is_pkg_config_path(path):
                continue
            if path in conff:
                try:
                    current = file_md5(path)
                except OSError:
                    continue
                if current != conff[path]:
                    out[path] = "modified_conffile"
                continue

            rel = path.lstrip("/")
            baseline = md5sums.get(rel)
            if baseline:
                try:
                    current = file_md5(path)
                except OSError:
                    continue
                if current != baseline:
                    out[path] = "modified_packaged_file"
        return out


class RpmBackend(PackageBackend):
    name = "rpm"
    pkg_config_prefixes = (
        "/etc/dnf/",
        "/etc/yum/",
        "/etc/yum.repos.d/",
        "/etc/yum.conf",
    )

    def __init__(self) -> None:
        self._modified_cache: Dict[str, Set[str]] = {}
        self._config_cache: Dict[str, Set[str]] = {}

    def owner_of_path(self, path: str) -> Optional[str]:
        from .rpm import rpm_owner

        return rpm_owner(path)

    def list_manual_packages(self) -> List[str]:
        from .rpm import list_manual_packages

        return list_manual_packages()

    def installed_packages(self) -> Dict[str, List[Dict[str, str]]]:
        from .rpm import list_installed_packages

        return list_installed_packages()

    def build_etc_index(self):
        from .rpm import build_rpm_etc_index

        return build_rpm_etc_index()

    def specific_paths_for_hints(self, hints: Set[str]) -> List[str]:
        paths: List[str] = []
        for h in hints:
            paths.extend(
                [
                    f"/etc/sysconfig/{h}",
                    f"/etc/sysconfig/{h}.conf",
                    f"/etc/sysctl.d/{h}.conf",
                ]
            )
        return paths

    def _config_files(self, pkg: str) -> Set[str]:
        if pkg in self._config_cache:
            return self._config_cache[pkg]
        from .rpm import rpm_config_files

        s = rpm_config_files(pkg)
        self._config_cache[pkg] = s
        return s

    def _modified_files(self, pkg: str) -> Set[str]:
        if pkg in self._modified_cache:
            return self._modified_cache[pkg]
        from .rpm import rpm_modified_files

        s = rpm_modified_files(pkg)
        self._modified_cache[pkg] = s
        return s

    def modified_paths(self, pkg: str, etc_paths: List[str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        modified = self._modified_files(pkg)
        if not modified:
            return out
        config = self._config_files(pkg)

        for path in etc_paths:
            if not path.startswith("/etc/"):
                continue
            if self.is_pkg_config_path(path):
                continue
            if path not in modified:
                continue
            out[path] = (
                "modified_conffile" if path in config else "modified_packaged_file"
            )
        return out


def get_backend(info: Optional[PlatformInfo] = None) -> PackageBackend:
    info = info or detect_platform()
    if info.pkg_backend == "dpkg":
        return DpkgBackend()
    if info.pkg_backend == "rpm":
        return RpmBackend()
    # Unknown: be conservative and use an rpm backend if rpm exists, otherwise dpkg.
    if shutil.which("rpm"):
        return RpmBackend()
    return DpkgBackend()
