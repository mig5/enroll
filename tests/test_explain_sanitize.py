"""Security regression (audit finding): the human-readable ``enroll explain``
text output embeds harvested, attacker-influenceable values (host name, captured
file paths shown as examples, include/exclude patterns, snapshot notes). A value
containing a raw newline could forge an additional output line, and a control
byte could smuggle a terminal escape sequence when the explanation is printed to
a terminal or written with ``--out``. These must be neutralised. The JSON output
is unaffected (json.dumps escapes control characters and cannot be restructured
by a string value).
"""

from __future__ import annotations

import json

from enroll.explain import explain_state


def _write_harvest(tmp_path, *, hostname, file_path, note):
    state = {
        "enroll": {"version": "0.1", "harvest_time": 1},
        "host": {
            "hostname": hostname,
            "os": "debian",
            "pkg_backend": "dpkg",
            "os_release": {},
        },
        "inventory": {"packages": {}},
        "roles": {
            "etc_custom": {
                "role_name": "etc_custom",
                "managed_files": [
                    {
                        "path": file_path,
                        "src_rel": "etc/x",
                        "owner": "root",
                        "group": "root",
                        "mode": "0644",
                        "reason": "custom_unowned",
                    }
                ],
                "managed_dirs": [],
                "excluded": [],
                "notes": [note],
            }
        },
    }
    d = tmp_path / "harvest"
    (d / "artifacts" / "etc_custom" / "etc").mkdir(parents=True)
    (d / "state.json").write_text(json.dumps(state))
    (d / "artifacts" / "etc_custom" / "etc" / "x").write_text("data")
    return str(d)


def test_explain_text_neutralises_injection(tmp_path):
    harvest = _write_harvest(
        tmp_path,
        hostname="h1\x1b[31m\n## FORGED HOST LINE\nx",
        file_path="/etc/x\nFORGED: injected path line",
        note="real note\x07\nFORGED NOTE LINE",
    )
    txt = explain_state(harvest, fmt="text")

    # No harvested payload may forge its own output line.
    for line in txt.splitlines():
        stripped = line.lstrip()
        assert not stripped.startswith("## FORGED HOST LINE")
        assert not stripped.startswith("FORGED:")
        assert not stripped.startswith("FORGED NOTE LINE")
    # No terminal escape / control bytes survive into the printed text.
    assert "\x1b" not in txt
    assert "\x07" not in txt


def test_explain_json_is_unaffected_and_valid(tmp_path):
    harvest = _write_harvest(
        tmp_path,
        hostname="h1\n## x",
        file_path="/etc/x\ny",
        note="n\x07",
    )
    parsed = json.loads(explain_state(harvest, fmt="json"))
    # JSON faithfully preserves the raw values (escaped) and stays structurally
    # valid; the control bytes are encoded, not executable.
    assert parsed["host"]["hostname"].startswith("h1")
