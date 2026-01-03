from __future__ import annotations

from pathlib import Path


def test_iter_effective_lines_skips_comments_and_block_comments():
    from enroll.ignore import IgnorePolicy

    policy = IgnorePolicy(deny_globs=[])

    content = b"""
# comment
; semi
// slash
* c-star

valid=1
/* block
ignored=1
*/
valid=2
"""

    lines = [l.strip() for l in policy.iter_effective_lines(content)]
    assert lines == [b"valid=1", b"valid=2"]


def test_deny_reason_dir_behaviour(tmp_path: Path):
    from enroll.ignore import IgnorePolicy

    # Use an absolute pattern matching our temporary path.
    deny_glob = str(tmp_path / "deny") + "/*"
    pol = IgnorePolicy(deny_globs=[deny_glob], dangerous=False)

    d = tmp_path / "dir"
    d.mkdir()
    f = tmp_path / "file"
    f.write_text("x", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(d)

    assert pol.deny_reason_dir(str(d)) is None
    assert pol.deny_reason_dir(str(link)) == "symlink"
    assert pol.deny_reason_dir(str(f)) == "not_directory"

    # Denied by glob.
    deny_path = tmp_path / "deny" / "x"
    deny_path.mkdir(parents=True)
    assert pol.deny_reason_dir(str(deny_path)) == "denied_path"

    # Missing/unreadable.
    assert pol.deny_reason_dir(str(tmp_path / "missing")) == "unreadable"

    # Dangerous disables deny_globs.
    pol2 = IgnorePolicy(deny_globs=[deny_glob], dangerous=True)
    assert pol2.deny_reason_dir(str(deny_path)) is None
