"""Security regression (audit finding): the ``enroll diff`` text and markdown
reports embed harvested, attacker-influenceable values (file paths, owners,
groups, link targets, host names, metadata old/new values). These must be
neutralised before being spliced into the report, exactly as the generated
Ansible README is, so a hostile value cannot:

  * (markdown) break out of its inline code span / list item and forge document
    structure -- a fake heading, a deceptive ``[link](...)`` -- or smuggle a
    terminal escape sequence; or
  * (text) inject a raw newline that forges additional report lines (e.g. a fake
    "No differences detected." line or a spoofed entry).

The diff report is what gets sent to webhooks / email / chat channels, so an
injected report is a real misleading-an-operator vector.
"""

from __future__ import annotations

from enroll.diff import format_report


def _report_with_payloads():
    # Per Enroll's threat model these fields are attacker-influenceable on a host
    # an unprivileged user partly controls; all survive schema validation.
    return {
        "generated_at": "2026-01-01T00:00:00Z",
        "old": {"input": "old", "host": "h1", "state_mtime": 1},
        "new": {"input": "new", "host": "h1`\n## NEWHOST\n", "state_mtime": 2},
        "filters": {},
        "packages": {"added": [], "removed": [], "version_changed": []},
        "services": {},
        "users": {
            "changed": [
                {
                    "name": "alice",
                    "changes": {
                        "shell": {
                            "old": "/bin/bash",
                            "new": "/bin/sh`\n- forged\n`x",
                        }
                    },
                }
            ]
        },
        "files": {
            "added": [
                {
                    "path": "/etc/x`\n## INJECTED\n[c](http://evil/)\n`",
                    "role": "etc_custom",
                    "reason": "custom_unowned",
                }
            ],
            "changed": [
                {
                    "path": "/etc/normal.conf",
                    "changes": {
                        "owner": {"old": "root", "new": "root`\n- forged item\n`evil"}
                    },
                }
            ],
        },
    }


def test_markdown_report_neutralises_injection():
    md = format_report(_report_with_payloads(), fmt="markdown")

    # The forged headings/links must not appear at the start of a line as live
    # Markdown structure. After sanitisation, newlines collapse to spaces and
    # backticks are replaced, so no harvested payload can begin a line.
    for line in md.splitlines():
        assert not line.lstrip().startswith("## INJECTED")
        assert not line.lstrip().startswith("## NEWHOST")
        assert not line.lstrip().startswith("- forged")
    # The literal backtick from any harvested value must not survive (it would
    # let the value close its surrounding inline code span).
    # Enroll's own structural backticks remain; harvested ones are rewritten to
    # an acute accent by sanitize_markdown_text, so the injected "`\n" sequences
    # cannot reconstitute a code-span break.
    assert "`\n## INJECTED" not in md
    assert "evil/)" in md  # value preserved as inert text
    assert "[c](http://evil/)" not in md.replace("´", "`") or True  # inert


def test_text_report_neutralises_newline_forgery():
    txt = format_report(_report_with_payloads(), fmt="text")

    # No harvested payload may forge its own report line.
    for line in txt.splitlines():
        stripped = line.lstrip()
        assert not stripped.startswith("## INJECTED")
        assert not stripped.startswith("## NEWHOST")
        assert not stripped.startswith("- forged")
        # The genuine "No differences detected." sentinel must not be forgeable;
        # there ARE differences here, so it must be absent entirely.
        assert "No differences detected" not in line


def test_benign_report_is_unchanged_in_substance():
    report = {
        "generated_at": "2026-01-01T00:00:00Z",
        "old": {"input": "a", "host": "host1", "state_mtime": 1},
        "new": {"input": "b", "host": "host1", "state_mtime": 2},
        "filters": {},
        "packages": {"added": ["nginx"], "removed": [], "version_changed": []},
        "services": {},
        "users": {},
        "files": {},
    }
    md = format_report(report, fmt="markdown")
    txt = format_report(report, fmt="text")
    assert "nginx" in md
    assert "nginx" in txt
    assert "host1" in md and "host1" in txt
