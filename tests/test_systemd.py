from __future__ import annotations

import pytest
import enroll.systemd as s


def test_list_enabled_services_and_timers_filters_templates(monkeypatch):
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


def test_list_enabled_services_empty_output(monkeypatch):
    def fake_run(cmd: list[str]) -> str:
        return ""

    monkeypatch.setattr(s, "_run", fake_run)
    result = s.list_enabled_services()
    assert result == []


def test_list_enabled_timers_empty_output(monkeypatch):
    def fake_run(cmd: list[str]) -> str:
        return ""

    monkeypatch.setattr(s, "_run", fake_run)
    result = s.list_enabled_timers()
    assert result == []


def test_list_enabled_services_with_only_templates(monkeypatch):
    def fake_run(cmd: list[str]) -> str:
        return "getty@.service enabled\n"

    monkeypatch.setattr(s, "_run", fake_run)
    result = s.list_enabled_services()
    assert result == []


def test_list_enabled_timers_with_only_templates(monkeypatch):
    def fake_run(cmd: list[str]) -> str:
        return "foo@.timer enabled\n"

    monkeypatch.setattr(s, "_run", fake_run)
    result = s.list_enabled_timers()
    assert result == []


def test_get_timer_info_raises_on_failure(monkeypatch):
    class P:
        def __init__(self, rc: int, out: str, err: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def fake_run(cmd, text, capture_output):
        return P(1, "", "timer not found")

    monkeypatch.setattr(s.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError) as exc_info:
        s.get_timer_info("nonexistent.timer")

    assert "nonexistent.timer" in str(exc_info.value)


def test_get_timer_info_with_empty_fields(monkeypatch):
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
                    "FragmentPath=",
                    "DropInPaths=",
                    "EnvironmentFiles=",
                    "Unit=",
                    "ActiveState=",
                    "SubState=",
                    "UnitFileState=",
                    "ConditionResult=",
                ]
            ),
        )

    monkeypatch.setattr(s.subprocess, "run", fake_run)
    ti = s.get_timer_info("empty.timer")
    assert ti.fragment_path is None
    assert ti.dropin_paths == []
    assert ti.env_files == []
    assert ti.trigger_unit is None
    assert ti.active_state is None


def test_get_unit_info_with_empty_fields(monkeypatch):
    class P:
        def __init__(self, rc: int, out: str, err: str = ""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def fake_run(cmd, check, text, capture_output):
        return P(
            0,
            "\n".join(
                [
                    "FragmentPath=",
                    "DropInPaths=",
                    "EnvironmentFiles=",
                    "ExecStart=",
                    "ActiveState=",
                    "SubState=",
                    "UnitFileState=",
                    "ConditionResult=",
                ]
            ),
        )

    monkeypatch.setattr(s.subprocess, "run", fake_run)
    ui = s.get_unit_info("empty.service")
    assert ui.fragment_path is None
    assert ui.dropin_paths == []
    assert ui.env_files == []
    assert ui.exec_paths == []
    assert ui.active_state is None
