from __future__ import annotations

import os
from pathlib import Path

import enroll.pathfilter as pf


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


def test_expand_includes_supports_regex_with_inferred_root(tmp_path: Path):
    """Regex includes are expanded by walking an inferred literal prefix root."""
    from enroll.pathfilter import compile_path_pattern, expand_includes

    root = tmp_path / "root"
    (root / "home" / "alice" / ".config" / "myapp").mkdir(parents=True)
    target = root / "home" / "alice" / ".config" / "myapp" / "settings.ini"
    target.write_text("x=1\n", encoding="utf-8")

    # This is anchored and begins with an absolute path, so expand_includes should
    # infer a narrow walk root instead of scanning '/'.
    rex = rf"re:^{root}/home/[^/]+/\.config/myapp/.*$"
    pat = compile_path_pattern(rex)
    paths, notes = expand_includes([pat], max_files=10)
    assert str(target) in paths
    assert notes == []


def test_compile_path_pattern_normalises_relative_prefix():
    from enroll.pathfilter import compile_path_pattern

    p = compile_path_pattern("etc/ssh")
    assert p.kind == "prefix"
    assert p.value == "/etc/ssh"


def test_norm_abs_empty_string_is_root():
    assert pf._norm_abs("") == "/"


def test_posix_match_invalid_pattern_fails_closed(monkeypatch):
    # Force PurePosixPath.match to raise to cover the exception handler.
    real_match = pf.PurePosixPath.match

    def boom(self, pat):
        raise ValueError("bad pattern")

    monkeypatch.setattr(pf.PurePosixPath, "match", boom)
    try:
        assert pf._posix_match("/etc/hosts", "[bad") is False
    finally:
        monkeypatch.setattr(pf.PurePosixPath, "match", real_match)


def test_regex_literal_prefix_handles_escapes():
    # Prefix stops at meta chars but includes escaped literals.
    assert pf._regex_literal_prefix(r"^/etc/\./foo") == "/etc/./foo"


def test_expand_includes_maybe_add_file_skips_non_files(monkeypatch, tmp_path: Path):
    # Drive the _maybe_add_file branch that rejects symlinks/non-files.
    pats = [pf.compile_path_pattern(str(tmp_path / "missing"))]

    monkeypatch.setattr(pf.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(pf.os.path, "islink", lambda p: False)
    monkeypatch.setattr(pf.os.path, "isdir", lambda p: False)

    paths, notes = pf.expand_includes(pats, max_files=10)
    assert paths == []
    assert any("matched no files" in n for n in notes)


def test_expand_includes_prunes_excluded_dirs(monkeypatch):
    include = [pf.compile_path_pattern("/root/**")]
    exclude = pf.PathFilter(exclude=["/root/skip/**"])

    # Simulate filesystem walk:
    # /root has dirnames ['skip', 'keep'] but skip should be pruned.
    monkeypatch.setattr(
        pf.os.path,
        "isdir",
        lambda p: p in {"/root", "/root/keep", "/root/skip"},
    )
    monkeypatch.setattr(pf.os.path, "islink", lambda p: False)
    monkeypatch.setattr(pf.os.path, "isfile", lambda p: True)

    def walk(root, followlinks=False):
        assert root == "/root"
        yield ("/root", ["skip", "keep"], [])
        yield ("/root/keep", [], ["a.txt"])
        # If pruning works, we should never walk into /root/skip.

    monkeypatch.setattr(pf.os, "walk", walk)

    paths, _notes = pf.expand_includes(include, exclude=exclude, max_files=10)
    assert "/root/keep/a.txt" in paths
    assert not any(p.startswith("/root/skip") for p in paths)


def test_expand_includes_respects_max_files(monkeypatch):
    include = [pf.compile_path_pattern("/root/**")]
    monkeypatch.setattr(pf.os.path, "isdir", lambda p: p == "/root")
    monkeypatch.setattr(pf.os.path, "islink", lambda p: False)
    monkeypatch.setattr(pf.os.path, "isfile", lambda p: True)
    monkeypatch.setattr(
        pf.os,
        "walk",
        lambda root, followlinks=False: [("/root", [], ["a", "b", "c"])],
    )
    paths, notes = pf.expand_includes(include, max_files=2)
    assert len(paths) == 2
    assert "/root/c" not in paths
