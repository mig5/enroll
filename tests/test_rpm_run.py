from __future__ import annotations

import types

import pytest

import enroll.rpm as rpm


def test_run_raises_on_nonzero_returncode_when_not_allow_fail(monkeypatch):
    def fake_run(cmd, check, text, stdout, stderr):
        return types.SimpleNamespace(returncode=1, stdout="OUT", stderr="ERR")

    monkeypatch.setattr(rpm.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError) as e:
        rpm._run(["rpm", "-q"])  # type: ignore[attr-defined]
    assert "Command failed" in str(e.value)
    assert "ERR" in str(e.value)
    assert "OUT" in str(e.value)


def test_run_merge_err_includes_stderr_in_stdout(monkeypatch):
    def fake_run(cmd, check, text, stdout, stderr):
        # When merge_err is True, stderr is redirected to STDOUT, so we only
        # rely on stdout in our wrapper.
        return types.SimpleNamespace(returncode=0, stdout="COMBINED", stderr=None)

    monkeypatch.setattr(rpm.subprocess, "run", fake_run)
    rc, out = rpm._run(["rpm", "-q"], merge_err=True)
    assert rc == 0
    assert out == "COMBINED"
