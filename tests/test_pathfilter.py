from __future__ import annotations

import os
from pathlib import Path


def test_compile_and_match_prefix_glob_and_regex(tmp_path: Path):
    from enroll.pathfilter import PathFilter, compile_path_pattern

    # prefix semantics: matches the exact path and subtree
    p = compile_path_pattern("/etc/nginx")
    assert p.kind == "prefix"
    assert p.matches("/etc/nginx")
    assert p.matches("/etc/nginx/nginx.conf")
    assert not p.matches("/etc/nginx2/nginx.conf")

    # glob semantics
    g = compile_path_pattern("/etc/**/*.conf")
    assert g.kind == "glob"
    assert g.matches("/etc/nginx/nginx.conf")
    assert not g.matches("/var/etc/nginx.conf")

    # explicit glob
    g2 = compile_path_pattern("glob:/home/*/.bashrc")
    assert g2.kind == "glob"
    assert g2.matches("/home/alice/.bashrc")

    # regex semantics (search, not match)
    r = compile_path_pattern(r"re:/home/[^/]+/\.ssh/authorized_keys$")
    assert r.kind == "regex"
    assert r.matches("/home/alice/.ssh/authorized_keys")
    assert not r.matches("/home/alice/.ssh/authorized_keys2")

    # invalid regex: never matches
    bad = compile_path_pattern("re:[")
    assert bad.kind == "regex"
    assert not bad.matches("/etc/passwd")

    # exclude wins
    pf = PathFilter(exclude=["/etc/nginx"], include=["/etc/nginx/nginx.conf"])
    assert pf.is_excluded("/etc/nginx/nginx.conf")


def test_expand_includes_respects_exclude_symlinks_and_caps(tmp_path: Path):
    from enroll.pathfilter import PathFilter, compile_path_pattern, expand_includes

    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    (root / "a" / "one.txt").write_text("1", encoding="utf-8")
    (root / "a" / "two.txt").write_text("2", encoding="utf-8")
    (root / "b").mkdir()
    (root / "b" / "secret.txt").write_text("s", encoding="utf-8")

    # symlink file should be ignored
    os.symlink(str(root / "a" / "one.txt"), str(root / "a" / "link.txt"))

    exclude = PathFilter(exclude=[str(root / "b")])

    pats = [
        compile_path_pattern(str(root / "a")),
        compile_path_pattern("glob:" + str(root / "**" / "*.txt")),
    ]

    paths, notes = expand_includes(pats, exclude=exclude, max_files=2)
    # cap should limit to 2 files
    assert len(paths) == 2
    assert any("cap" in n.lower() for n in notes)
    # excluded dir should not contribute
    assert all("/b/" not in p for p in paths)
    # symlink ignored
    assert all(not p.endswith("link.txt") for p in paths)


def test_expand_includes_notes_on_no_matches(tmp_path: Path):
    from enroll.pathfilter import compile_path_pattern, expand_includes

    pats = [compile_path_pattern(str(tmp_path / "does_not_exist"))]
    paths, notes = expand_includes(pats, max_files=10)
    assert paths == []
    assert any("matched no files" in n.lower() for n in notes)
