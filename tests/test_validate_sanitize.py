"""Security regression (audit finding): ValidationResult.to_text()/to_dict()
render error and warning messages that embed harvested, attacker-influenceable
values (a managed_file src_rel, a role name, artifact paths). A src_rel with an
embedded newline passes the schema (pattern ``^[^/].*``) and could otherwise
forge an extra message line, and a control byte could smuggle a terminal escape
sequence when the validation result is printed or piped.

The pass/fail decision (``ok``) is unaffected by sanitisation; only the rendered
output is neutralised.
"""

from __future__ import annotations

import json

from enroll.validate import ValidationResult


def _malicious_result():
    return ValidationResult(
        errors=[
            "missing artifact for role etc_custom: "
            "artifacts/etc_custom/foo\n## FORGED ERROR\x1b[31m\nOK: fake pass",
        ],
        warnings=["unreferenced artifact: bar\x07\nFORGED WARNING LINE"],
    )


def test_to_text_neutralises_injection():
    txt = _malicious_result().to_text()

    for line in txt.splitlines():
        stripped = line.lstrip("- ").lstrip()
        assert not stripped.startswith("## FORGED ERROR")
        assert not stripped.startswith("FORGED WARNING LINE")
        # A forged "OK:" line must not be injectable (there ARE errors here).
        assert stripped != "OK: fake pass"
    assert "\x1b" not in txt
    assert "\x07" not in txt


def test_to_dict_strips_control_bytes():
    d = _malicious_result().to_dict()
    blob = json.dumps(d)
    assert "\x1b" not in blob
    assert "\x07" not in blob
    # Sanitisation must not flip the verdict.
    assert d["ok"] is False


def test_benign_messages_are_preserved():
    vr = ValidationResult(errors=["missing state.json at /tmp/x"], warnings=[])
    txt = vr.to_text()
    assert "missing state.json at /tmp/x" in txt
    assert vr.to_dict()["errors"] == ["missing state.json at /tmp/x"]
    assert vr.ok is False


def test_ok_result_unchanged():
    vr = ValidationResult(errors=[], warnings=[])
    assert "OK: harvest bundle validated" in vr.to_text()
    assert vr.to_dict()["ok"] is True
