from __future__ import annotations

from enroll.harvest import (
    FirewallRuntimeSnapshot,
    HarvestContext,
    IgnorePolicy,
    PathFilter,
    RuntimeStateCollector,
    SysctlSnapshot,
)


class _Backend:
    name = "dpkg"


def _context(tmp_path):
    return HarvestContext(
        bundle_dir=str(tmp_path),
        policy=IgnorePolicy(),
        path_filter=PathFilter(include=(), exclude=()),
        platform={},
        backend=_Backend(),
        installed_pkgs={},
        installed_names=set(),
        owned_etc=set(),
        etc_owner_map={},
        topdir_to_pkgs={},
        pkg_to_etc_paths={},
        captured_global=set(),
    )


def test_runtime_state_collector_preserves_non_root_skip_schema(monkeypatch, tmp_path):
    monkeypatch.setattr("enroll.harvest.os.geteuid", lambda: 1000)

    result = RuntimeStateCollector(_context(tmp_path)).collect()

    assert isinstance(result.firewall_runtime_snapshot, FirewallRuntimeSnapshot)
    assert isinstance(result.sysctl_snapshot, SysctlSnapshot)
    assert result.firewall_runtime_snapshot.role_name == "firewall_runtime"
    assert result.sysctl_snapshot.role_name == "sysctl"
    assert "not running as root" in result.firewall_runtime_snapshot.notes[0]
    assert "not running as root" in result.sysctl_snapshot.notes[0]
