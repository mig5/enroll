from __future__ import annotations

import pytest


def test_list_enabled_services_and_timers_filters_templates(monkeypatch):
    import enroll.systemd as s

    def fake_run(cmd: list[str]) -> str:
        if "--type=service" in cmd:
            return "\n".join(
                [
                    "nginx.service enabled",
                    "getty@.service enabled",  # template
                    "foo@bar.service enabled",  # instance units are included
                    "ssh.service enabled",
                ]
            )
        if "--type=timer" in cmd:
            return "\n".join(
                [
                    "apt-daily.timer enabled",
                    "foo@.timer enabled",  # template
                ]
            )
        raise AssertionError("unexpected")

    monkeypatch.setattr(s, "_run", fake_run)
    assert s.list_enabled_services() == [
        "foo@bar.service",
        "nginx.service",
        "ssh.service",
    ]
    assert s.list_enabled_timers() == ["apt-daily.timer"]


def test_get_unit_info_parses_fields(monkeypatch):
    import enroll.systemd as s

    class P:
        def __init__(self, rc: int, out: str, err: str = ""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def fake_run(cmd, check, text, capture_output):
        assert cmd[0:2] == ["systemctl", "show"]
        return P(
            0,
            "\n".join(
                [
                    "FragmentPath=/lib/systemd/system/nginx.service",
                    "DropInPaths=/etc/systemd/system/nginx.service.d/override.conf /etc/systemd/system/nginx.service.d/extra.conf",
                    "EnvironmentFiles=-/etc/default/nginx /etc/nginx/env",
                    "ExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon off; }",
                    "ActiveState=active",
                    "SubState=running",
                    "UnitFileState=enabled",
                    "ConditionResult=yes",
                ]
            ),
        )

    monkeypatch.setattr(s.subprocess, "run", fake_run)
    ui = s.get_unit_info("nginx.service")
    assert ui.fragment_path == "/lib/systemd/system/nginx.service"
    assert "/etc/default/nginx" in ui.env_files
    assert "/etc/nginx/env" in ui.env_files
    assert "/usr/sbin/nginx" in ui.exec_paths
    assert ui.active_state == "active"


def test_get_unit_info_raises_unit_query_error(monkeypatch):
    import enroll.systemd as s

    class P:
        def __init__(self, rc: int, out: str, err: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def fake_run(cmd, check, text, capture_output):
        return P(1, "", "no such unit")

    monkeypatch.setattr(s.subprocess, "run", fake_run)
    with pytest.raises(s.UnitQueryError) as ei:
        s.get_unit_info("missing.service")
    assert "missing.service" in str(ei.value)
    assert ei.value.unit == "missing.service"


def test_get_timer_info_parses_fields(monkeypatch):
    import enroll.systemd as s

    class P:
        def __init__(self, rc: int, out: str, err: str = ""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def fake_run(cmd, text, capture_output):
        return P(
            0,
            "\n".join(
                [
                    "FragmentPath=/lib/systemd/system/apt-daily.timer",
                    "DropInPaths=",
                    "EnvironmentFiles=-/etc/default/apt",
                    "Unit=apt-daily.service",
                    "ActiveState=active",
                    "SubState=waiting",
                    "UnitFileState=enabled",
                    "ConditionResult=yes",
                ]
            ),
        )

    monkeypatch.setattr(s.subprocess, "run", fake_run)
    ti = s.get_timer_info("apt-daily.timer")
    assert ti.trigger_unit == "apt-daily.service"
    assert "/etc/default/apt" in ti.env_files
