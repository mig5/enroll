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


def test_has_glob_chars():
    assert pf._has_glob_chars("*.txt") is True
    assert pf._has_glob_chars("file?.log") is True
    assert pf._has_glob_chars("[abc]") is True
    assert pf._has_glob_chars("file.txt") is False
    assert pf._has_glob_chars("") is False


def test_compile_path_pattern_regex_valid():
    result = pf.compile_path_pattern("re:^/home/.*$")
    assert result.kind == "regex"
    assert result.regex is not None
    assert result.regex.search("/home/user/file.txt") is not None
    assert result.regex.search("/var/file.txt") is None


def test_compile_path_pattern_glob_forced():
    result = pf.compile_path_pattern("glob:/etc/*.conf")
    assert result.kind == "glob"
    assert result.value == "/etc/*.conf"


def test_compile_path_pattern_glob_heuristic():
    result = pf.compile_path_pattern("/etc/*.conf")
    assert result.kind == "glob"


def test_compile_path_pattern_prefix():
    result = pf.compile_path_pattern("/etc/nginx")
    assert result.kind == "prefix"
    assert result.value == "/etc/nginx"


def test_compiled_pattern_matches_prefix():
    pat = pf.compile_path_pattern("/etc/nginx")
    assert pat.matches("/etc/nginx") is True
    assert pat.matches("/etc/nginx/conf.d") is True
    assert pat.matches("/etc/ssh") is False


def test_compiled_pattern_matches_glob():
    pat = pf.compile_path_pattern("/etc/*.conf")
    assert pat.matches("/etc/ssh.conf") is True
    assert pat.matches("/etc/ssh/sshd.conf") is False


def test_compiled_pattern_matches_regex():
    pat = pf.compile_path_pattern("re:^/home/[^/]+/.bashrc$")
    assert pat.matches("/home/alice/.bashrc") is True
    assert pat.matches("/home/bob/.bashrc") is True
    assert pat.matches("/home/alice/.profile") is False
    assert pat.matches("/var/.bashrc") is False


def test_path_filter_is_excluded():
    pf_filter = pf.PathFilter(exclude=["/tmp/*", "/var/log"])
    assert pf_filter.is_excluded("/tmp/file.txt") is True
    assert pf_filter.is_excluded("/var/log/syslog") is True
    assert pf_filter.is_excluded("/etc/ssh") is False


def test_path_filter_empty():
    pf_filter = pf.PathFilter()
    assert pf_filter.is_excluded("/anything") is False
    assert pf_filter.iter_include_patterns() == []


def test_expand_includes_prefix_existing(tmp_path: Path):
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    (etc_dir / "file1.txt").write_text("a")
    (etc_dir / "file2.txt").write_text("b")

    patterns = [pf.compile_path_pattern(str(etc_dir))]
    paths, notes = pf.expand_includes(patterns, max_files=10)

    assert len(paths) == 2
    assert notes == []


def test_expand_includes_prefix_nonexistent():
    patterns = [pf.compile_path_pattern("/nonexistent/path")]
    paths, notes = pf.expand_includes(patterns, max_files=10)

    assert paths == []
    assert len(notes) == 1
    assert "matched no files" in notes[0]


def test_expand_includes_glob_no_matches():
    patterns = [pf.compile_path_pattern("/nonexistent/*.txt")]
    paths, notes = pf.expand_includes(patterns, max_files=10)

    assert paths == []
    assert len(notes) == 1


def test_expand_includes_skips_symlinks(tmp_path: Path):
    real_file = tmp_path / "real.txt"
    real_file.write_text("x")
    link = tmp_path / "link.txt"
    os.symlink(str(real_file), str(link))

    patterns = [pf.compile_path_pattern(str(tmp_path))]
    paths, notes = pf.expand_includes(patterns, max_files=10)

    assert len(paths) == 1
    assert paths[0].endswith("real.txt")


def test_expand_includes_excludes_pattern(tmp_path: Path):
    etc_dir = tmp_path / "etc"
    etc_dir.mkdir()
    (etc_dir / "include.txt").write_text("a")
    (etc_dir / "exclude.txt").write_text("b")

    patterns = [pf.compile_path_pattern(str(etc_dir))]
    exclude = pf.PathFilter(exclude=["*exclude*"])
    paths, notes = pf.expand_includes(patterns, exclude=exclude, max_files=10)

    assert len(paths) == 1
    assert paths[0].endswith("include.txt")


def test_expand_includes_skips_directories(tmp_path: Path):
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    (tmp_path / "file.txt").write_text("x")

    patterns = [pf.compile_path_pattern(str(subdir))]
    paths, notes = pf.expand_includes(patterns, max_files=10)

    assert paths == []


def test_regex_literal_prefix_simple():
    assert pf._regex_literal_prefix("/etc/nginx/") == "/etc/nginx/"


def test_regex_literal_prefix_with_anchor():
    assert pf._regex_literal_prefix("^/etc/nginx/") == "/etc/nginx/"


def test_regex_literal_prefix_with_regex_chars():
    assert pf._regex_literal_prefix("^/etc/.*\\.conf$") == "/etc/"


def test_path_filter_with_include_patterns():
    pf_filter = pf.PathFilter(include=["/etc/*.conf"], exclude=["/etc/secret.conf"])
    patterns = pf_filter.iter_include_patterns()
    assert len(patterns) == 1
    assert patterns[0].kind == "glob"


def test_expand_includes_skips_file_through_symlinked_parent(tmp_path: Path):
    from enroll.pathfilter import compile_path_pattern, expand_includes

    real = tmp_path / "real"
    (real / "child").mkdir(parents=True)
    target = real / "child" / "secret.conf"
    target.write_text("secret", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    paths, _notes = expand_includes(
        [compile_path_pattern(str(link / "child" / "secret.conf"))], max_files=10
    )

    assert paths == []


def test_expand_includes_skips_directory_through_symlinked_parent(tmp_path: Path):
    from enroll.pathfilter import compile_path_pattern, expand_includes

    real = tmp_path / "real"
    (real / "child").mkdir(parents=True)
    target = real / "child" / "secret.conf"
    target.write_text("secret", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    paths, _notes = expand_includes(
        [compile_path_pattern(str(link / "child"))], max_files=10
    )

    assert paths == []
