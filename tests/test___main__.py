from __future__ import annotations

import runpy


def test_module_main_invokes_cli_main(monkeypatch):
    import enroll.cli

    called = {"ok": False}

    def fake_main() -> None:
        called["ok"] = True

    monkeypatch.setattr(enroll.cli, "main", fake_main)

    # Execute enroll.__main__ as if `python -m enroll`.
    runpy.run_module("enroll.__main__", run_name="__main__")
    assert called["ok"] is True
