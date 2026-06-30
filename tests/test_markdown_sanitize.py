"""Security regression: harvested values embedded in the generated Ansible
``README.md`` must be neutralised so an attacker-influenceable host name, file
path, or note cannot inject Markdown structure (a forged heading, deceptive
link/command block) or a terminal escape sequence into the documentation.

Harvested values are not executed by Ansible, but the README is the
human-readable summary an operator reads before applying a manifest, so a value
that breaks out of its surrounding list item / inline code span and forges
document structure is misleading and must be prevented.
"""

from __future__ import annotations

from enroll.cm import (
    markdown_list,
    sanitize_markdown_text,
    snapshot_excluded_lines,
    snapshot_note_lines,
)


def test_sanitize_collapses_newlines_and_strips_controls():
    # A newline would let a value break out of its Markdown line; a backtick
    # would close an inline code span; ESC/BEL are terminal escape vectors.
    payload = "host`\n## Injected\n[x](http://evil)\n`y\x1b[31mRED\x07\ttab"
    out = sanitize_markdown_text(payload)

    assert "\n" not in out and "\r" not in out
    assert "`" not in out  # backticks replaced so a code span cannot be closed
    assert "\x1b" not in out and "\x07" not in out  # control bytes stripped
    # The visible text is preserved on a single line (heading marker is now inert
    # because it no longer starts a line).
    assert "## Injected" in out
    assert "http://evil" in out


def test_sanitize_is_idempotent_and_handles_non_str():
    once = sanitize_markdown_text("a\nb")
    assert sanitize_markdown_text(once) == once
    assert sanitize_markdown_text(1234) == "1234"
    assert sanitize_markdown_text(None) == "None"


def test_markdown_list_does_not_gain_extra_lines_from_payload():
    # Even if a pre-composed line still contained a newline, markdown_list must
    # not emit more bullets than it was given.
    out = markdown_list(["clean line", "two\nlines should be one bullet"])
    # Two input items -> at most two leading "- " bullets.
    assert out.count("\n- ") <= 1


def test_snapshot_note_lines_neutralises_injected_note():
    roles = {
        "etc_custom": {
            "role_name": "etc_custom",
            "notes": ["benign`\n## PWNED\n- fake bullet\x1b[5m"],
        }
    }
    lines = snapshot_note_lines(roles)
    assert len(lines) == 1
    line = lines[0]
    # The role name code span is intact; the payload is folded onto one line
    # with backticks and control bytes removed.
    assert line.startswith("`etc_custom`: ")
    assert "\n" not in line
    assert "\x1b" not in line
    # Only the (structural) backticks around the role name remain -- the
    # payload's backtick was neutralised.
    assert line.count("`") == 2


def test_snapshot_excluded_lines_neutralises_injected_path():
    roles = {
        "etc_custom": {
            "role_name": "etc_custom",
            "excluded": [
                {"path": "/etc/`\n## fake-heading\nx", "reason": "denied_path"}
            ],
        }
    }
    lines = snapshot_excluded_lines(roles)
    assert len(lines) == 1
    line = lines[0]
    assert "\n" not in line
    assert line.startswith("`etc_custom`: ")
    assert line.count("`") == 2  # only the structural role-name span
    assert "(denied_path)" in line
