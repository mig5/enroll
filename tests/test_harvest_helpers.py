from __future__ import annotations

import os
from pathlib import Path

import enroll.harvest as h


def test_iter_matching_files_skips_symlinks_and_walks_dirs(monkeypatch, tmp_path: Path):
    # Layout:
    #   root/real.txt (file)
    #   root/sub/nested.txt
    #   root/link -> ... (ignored)
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "real.txt").write_text("a", encoding="utf-8")
    (root / "sub" / "nested.txt").write_text("b", encoding="utf-8")

    paths = {
        str(root): "dir",
        str(root / "real.txt"): "file",
        str(root / "sub"): "dir",
        str(root / "sub" / "nested.txt"): "file",
        str(root / "link"): "link",
    }

    monkeypatch.setattr(h.glob, "glob", lambda spec: [str(root), str(root / "link")])
    monkeypatch.setattr(h.os.path, "islink", lambda p: paths.get(p) == "link")
    monkeypatch.setattr(h.os.path, "isfile", lambda p: paths.get(p) == "file")
    monkeypatch.setattr(h.os.path, "isdir", lambda p: paths.get(p) == "dir")
    monkeypatch.setattr(
        h.os,
        "walk",
        lambda p: [
            (str(root), ["sub"], ["real.txt", "link"]),
            (str(root / "sub"), [], ["nested.txt"]),
        ],
    )

    out = h._iter_matching_files("/whatever/*", cap=100)
    assert str(root / "real.txt") in out
    assert str(root / "sub" / "nested.txt") in out
    assert str(root / "link") not in out


def test_parse_apt_signed_by_extracts_keyrings(tmp_path: Path):
    f1 = tmp_path / "a.list"
    f1.write_text(
        "deb [signed-by=/usr/share/keyrings/foo.gpg] https://example.invalid stable main\n",
        encoding="utf-8",
    )
    f2 = tmp_path / "b.sources"
    f2.write_text(
        "Types: deb\nSigned-By: /etc/apt/keyrings/bar.gpg, /usr/share/keyrings/baz.gpg\n",
        encoding="utf-8",
    )
    f3 = tmp_path / "c.sources"
    f3.write_text("Signed-By: | /bin/echo nope\n", encoding="utf-8")

    out = h._parse_apt_signed_by([str(f1), str(f2), str(f3)])
    assert "/usr/share/keyrings/foo.gpg" in out
    assert "/etc/apt/keyrings/bar.gpg" in out
    assert "/usr/share/keyrings/baz.gpg" in out


def test_iter_apt_capture_paths_includes_signed_by_keyring(monkeypatch):
    # Simulate:
    #   /etc/apt/apt.conf.d/00test
    #   /etc/apt/sources.list.d/test.list (signed-by outside /etc/apt)
    #   /usr/share/keyrings/ext.gpg
    files = {
        "/etc/apt/apt.conf.d/00test": "file",
        "/etc/apt/sources.list.d/test.list": "file",
        "/usr/share/keyrings/ext.gpg": "file",
    }

    monkeypatch.setattr(h.os.path, "isdir", lambda p: p in {"/etc/apt"})
    monkeypatch.setattr(
        h.os,
        "walk",
        lambda root: [
            ("/etc/apt", ["apt.conf.d", "sources.list.d"], []),
            ("/etc/apt/apt.conf.d", [], ["00test"]),
            ("/etc/apt/sources.list.d", [], ["test.list"]),
        ],
    )
    monkeypatch.setattr(h.os.path, "islink", lambda p: False)
    monkeypatch.setattr(h.os.path, "isfile", lambda p: files.get(p) == "file")

    # Only treat the sources glob as having a hit.
    def fake_iter_matching(spec: str, cap: int = 10000):
        if spec == "/etc/apt/sources.list.d/*.list":
            return ["/etc/apt/sources.list.d/test.list"]
        return []

    monkeypatch.setattr(h, "_iter_matching_files", fake_iter_matching)

    # Provide file contents for the sources file.
    real_open = open

    def fake_open(path, *a, **k):
        if path == "/etc/apt/sources.list.d/test.list":
            return real_open(os.devnull, "r", encoding="utf-8")  # placeholder
        return real_open(path, *a, **k)

    # Easier: patch _parse_apt_signed_by directly to avoid filesystem reads.
    monkeypatch.setattr(
        h, "_parse_apt_signed_by", lambda sfs: {"/usr/share/keyrings/ext.gpg"}
    )

    out = h._iter_apt_capture_paths()
    paths = {p for p, _r in out}
    reasons = {p: r for p, r in out}
    assert "/etc/apt/apt.conf.d/00test" in paths
    assert "/etc/apt/sources.list.d/test.list" in paths
    assert "/usr/share/keyrings/ext.gpg" in paths
    assert reasons["/usr/share/keyrings/ext.gpg"] == "apt_signed_by_keyring"


def test_iter_dnf_capture_paths(monkeypatch):
    files = {
        "/etc/dnf/dnf.conf": "file",
        "/etc/yum/yum.conf": "file",
        "/etc/yum.conf": "file",
        "/etc/yum.repos.d/test.repo": "file",
        "/etc/pki/rpm-gpg/RPM-GPG-KEY": "file",
    }

    def isdir(p):
        return p in {"/etc/dnf", "/etc/yum", "/etc/yum.repos.d", "/etc/pki/rpm-gpg"}

    def walk(root):
        if root == "/etc/dnf":
            return [("/etc/dnf", [], ["dnf.conf"])]
        if root == "/etc/yum":
            return [("/etc/yum", [], ["yum.conf"])]
        if root == "/etc/pki/rpm-gpg":
            return [("/etc/pki/rpm-gpg", [], ["RPM-GPG-KEY"])]
        return []

    monkeypatch.setattr(h.os.path, "isdir", isdir)
    monkeypatch.setattr(h.os, "walk", walk)
    monkeypatch.setattr(h.os.path, "islink", lambda p: False)
    monkeypatch.setattr(h.os.path, "isfile", lambda p: files.get(p) == "file")
    monkeypatch.setattr(
        h,
        "_iter_matching_files",
        lambda spec, cap=10000: (
            ["/etc/yum.repos.d/test.repo"] if spec.endswith("*.repo") else []
        ),
    )

    out = h._iter_dnf_capture_paths()
    paths = {p for p, _r in out}
    assert "/etc/dnf/dnf.conf" in paths
    assert "/etc/yum/yum.conf" in paths
    assert "/etc/yum.conf" in paths
    assert "/etc/yum.repos.d/test.repo" in paths
    assert "/etc/pki/rpm-gpg/RPM-GPG-KEY" in paths


def test_iter_system_capture_paths_dedupes_first_reason(monkeypatch):
    monkeypatch.setattr(h, "_SYSTEM_CAPTURE_GLOBS", [("/a", "r1"), ("/b", "r2")])
    monkeypatch.setattr(
        h,
        "_iter_matching_files",
        lambda spec, cap=10000: ["/dup"] if spec in {"/a", "/b"} else [],
    )
    out = h._iter_system_capture_paths()
    assert out == [("/dup", "r1")]
