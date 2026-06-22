from __future__ import annotations

from pathlib import Path

from enroll.harvest_collectors.context import HarvestContext
from enroll.harvest_collectors.package_manager import PackageManagerConfigCollector
from enroll.harvest_types import ManagedFile
from enroll.ignore import IgnorePolicy
from enroll.pathfilter import PathFilter


class _Backend:
    def __init__(self, name: str):
        self.name = name


def _context(tmp_path: Path, backend_name: str) -> HarvestContext:
    return HarvestContext(
        bundle_dir=str(tmp_path / "bundle"),
        policy=IgnorePolicy(),
        path_filter=PathFilter(include=(), exclude=()),
        platform={},
        backend=_Backend(backend_name),
        installed_pkgs={},
        installed_names=set(),
        owned_etc=set(),
        etc_owner_map={},
        topdir_to_pkgs={},
        pkg_to_etc_paths={},
        captured_global=set(),
    )


def _fake_capture(**kwargs):
    kwargs["managed_out"].append(
        ManagedFile(
            path=kwargs["abs_path"],
            src_rel=kwargs["abs_path"].lstrip("/"),
            owner="root",
            group="root",
            mode="0644",
            reason=kwargs["reason"],
        )
    )
    return True


def test_package_manager_config_collector_captures_apt_branch(monkeypatch, tmp_path):
    from enroll.harvest_collectors import package_manager as pm

    monkeypatch.setattr(
        pm, "iter_apt_capture_paths", lambda: [("/etc/apt/a.conf", "apt")]
    )
    monkeypatch.setattr(pm, "capture_file", lambda *a, **kw: _fake_capture(**kw))

    result = PackageManagerConfigCollector(_context(tmp_path, "dpkg"), {}).collect()

    assert [m.path for m in result.apt_config_snapshot.managed_files] == [
        "/etc/apt/a.conf"
    ]
    assert result.dnf_config_snapshot.managed_files == []


def test_package_manager_config_collector_captures_dnf_branch(monkeypatch, tmp_path):
    from enroll.harvest_collectors import package_manager as pm

    monkeypatch.setattr(
        pm, "iter_dnf_capture_paths", lambda: [("/etc/dnf/d.conf", "dnf")]
    )
    monkeypatch.setattr(pm, "capture_file", lambda *a, **kw: _fake_capture(**kw))

    result = PackageManagerConfigCollector(_context(tmp_path, "rpm"), {}).collect()

    assert result.apt_config_snapshot.managed_files == []
    assert [m.path for m in result.dnf_config_snapshot.managed_files] == [
        "/etc/dnf/d.conf"
    ]


def test_package_manager_config_collector_unknown_backend_returns_empty(tmp_path):
    result = PackageManagerConfigCollector(_context(tmp_path, "apk"), {}).collect()

    assert result.apt_config_snapshot.managed_files == []
    assert result.dnf_config_snapshot.managed_files == []
