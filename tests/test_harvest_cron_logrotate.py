from __future__ import annotations

import json
from pathlib import Path

import enroll.harvest as h
import enroll.capture as capture
import enroll.harvest_collectors.cron_logrotate as cron_logrotate
from enroll.platform import PlatformInfo
from enroll.systemd import UnitInfo


class AllowAllPolicy:
    def deny_reason(self, path: str):
        return None


class FakeBackend:
    def __init__(
        self,
        *,
        name: str,
        installed: dict[str, list[dict[str, str]]],
        manual: list[str],
    ):
        self.name = name
        self._installed = dict(installed)
        self._manual = list(manual)

    def build_etc_index(self):
        # No package ownership information needed for this test.
        return set(), {}, {}, {}

    def installed_packages(self):
        return dict(self._installed)

    def list_manual_packages(self):
        return list(self._manual)

    def owner_of_path(self, path: str):
        return None

    def specific_paths_for_hints(self, hints: set[str]):
        return []

    def is_pkg_config_path(self, path: str) -> bool:
        return False

    def modified_paths(self, pkg: str, etc_paths: list[str]):
        return {}


def test_harvest_unifies_cron_and_logrotate_into_dedicated_package_roles(
    monkeypatch, tmp_path: Path
):
    bundle = tmp_path / "bundle"

    # Fake files we want harvested.
    files = {
        "/etc/crontab": b"* * * * * root echo hi\n",
        "/etc/cron.d/php": b"# php cron\n",
        "/var/spool/cron/crontabs/alice": b"@daily echo user\n",
        "/etc/logrotate.conf": b"weekly\n",
        "/etc/logrotate.d/rsyslog": b"/var/log/syslog { rotate 7 }\n",
    }

    monkeypatch.setattr(h.os.path, "islink", lambda p: False)
    monkeypatch.setattr(h.os.path, "isfile", lambda p: p in files)
    monkeypatch.setattr(h.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(h.os.path, "exists", lambda p: (p in files) or False)

    # Expand cron/logrotate globs deterministically.
    def fake_iter_matching(spec: str, cap: int = 10000):
        mapping = {
            "/etc/crontab": ["/etc/crontab"],
            "/etc/cron.d/*": ["/etc/cron.d/php"],
            "/etc/cron.hourly/*": [],
            "/etc/cron.daily/*": [],
            "/etc/cron.weekly/*": [],
            "/etc/cron.monthly/*": [],
            "/etc/cron.allow": [],
            "/etc/cron.deny": [],
            "/etc/anacrontab": [],
            "/etc/anacron/*": [],
            "/var/spool/cron/*": [],
            "/var/spool/cron/crontabs/*": ["/var/spool/cron/crontabs/alice"],
            "/var/spool/crontabs/*": [],
            "/var/spool/anacron/*": [],
            "/etc/logrotate.conf": ["/etc/logrotate.conf"],
            "/etc/logrotate.d/*": ["/etc/logrotate.d/rsyslog"],
        }
        return list(mapping.get(spec, []))[:cap]

    monkeypatch.setattr(cron_logrotate, "iter_matching_files", fake_iter_matching)

    # Avoid real system probing.
    monkeypatch.setattr(
        h, "detect_platform", lambda: PlatformInfo("debian", "dpkg", {})
    )
    backend = FakeBackend(
        name="dpkg",
        installed={
            "cron": [{"version": "1", "arch": "amd64"}],
            "logrotate": [{"version": "1", "arch": "amd64"}],
        },
        # Include cron/logrotate in manual packages to ensure they are skipped in the generic loop.
        manual=["cron", "logrotate"],
    )
    monkeypatch.setattr(h, "get_backend", lambda info=None: backend)

    # Include a service that would collide with cron role naming.
    monkeypatch.setattr(
        h, "list_enabled_services", lambda: ["cron.service", "foo.service"]
    )
    monkeypatch.setattr(h, "list_enabled_timers", lambda: [])
    monkeypatch.setattr(
        h,
        "get_unit_info",
        lambda unit: UnitInfo(
            name=unit,
            fragment_path=None,
            dropin_paths=[],
            env_files=[],
            exec_paths=[],
            active_state="active",
            sub_state="running",
            unit_file_state="enabled",
            condition_result=None,
        ),
    )
    monkeypatch.setattr(h, "collect_non_system_users", lambda: [])
    monkeypatch.setattr(
        capture,
        "stat_triplet",
        lambda p: ("alice" if "alice" in p else "root", "root", "0644"),
    )

    # Avoid needing real source files by implementing our own bundle copier.
    def fake_copy(bundle_dir: str, role_name: str, abs_path: str, src_rel: str):
        dst = Path(bundle_dir) / "artifacts" / role_name / src_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(files.get(abs_path, b""))

    monkeypatch.setattr(capture, "copy_into_bundle", fake_copy)

    state_path = h.harvest(str(bundle), policy=AllowAllPolicy())
    st = json.loads(Path(state_path).read_text(encoding="utf-8"))

    # cron.service must be skipped to avoid colliding with the dedicated "cron" package role.
    svc_units = [s["unit"] for s in st["roles"]["services"]]
    assert "cron.service" not in svc_units
    assert "foo.service" in svc_units

    pkgs = st["roles"]["packages"]
    cron = next(p for p in pkgs if p["role_name"] == "cron")
    logrotate = next(p for p in pkgs if p["role_name"] == "logrotate")

    cron_paths = {mf["path"] for mf in cron["managed_files"]}
    assert "/etc/crontab" in cron_paths
    assert "/etc/cron.d/php" in cron_paths
    # user crontab captured
    assert "/var/spool/cron/crontabs/alice" in cron_paths

    lr_paths = {mf["path"] for mf in logrotate["managed_files"]}
    assert "/etc/logrotate.conf" in lr_paths
    assert "/etc/logrotate.d/rsyslog" in lr_paths
