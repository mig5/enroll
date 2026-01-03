from __future__ import annotations

from collections import defaultdict


def test_dpkg_backend_modified_paths_marks_conffiles_and_packaged(monkeypatch):
    from enroll.platform import DpkgBackend

    # Provide fake conffiles md5sums.
    monkeypatch.setattr(
        "enroll.debian.parse_status_conffiles",
        lambda: {"mypkg": {"/etc/mypkg.conf": "aaaa"}},
    )
    monkeypatch.setattr(
        "enroll.debian.read_pkg_md5sums",
        lambda _pkg: {"etc/other.conf": "bbbb"},
    )

    # Fake file_md5 values (avoids touching /etc).
    def fake_md5(p: str):
        if p == "/etc/mypkg.conf":
            return "zzzz"  # differs from conffile baseline
        if p == "/etc/other.conf":
            return "cccc"  # differs from packaged baseline
        if p == "/etc/apt/sources.list":
            return "bbbb"
        return None

    monkeypatch.setattr("enroll.platform.file_md5", fake_md5)

    b = DpkgBackend()
    out = b.modified_paths(
        "mypkg",
        ["/etc/mypkg.conf", "/etc/other.conf", "/etc/apt/sources.list"],
    )

    assert out["/etc/mypkg.conf"] == "modified_conffile"
    assert out["/etc/other.conf"] == "modified_packaged_file"
    # pkg config paths (like /etc/apt/...) are excluded.
    assert "/etc/apt/sources.list" not in out


def test_rpm_backend_modified_paths_caches_queries(monkeypatch):
    from enroll.platform import RpmBackend

    calls = defaultdict(int)

    def fake_modified(_pkg=None):
        calls["modified"] += 1
        return {"/etc/foo.conf", "/etc/bar.conf"}

    def fake_config(_pkg=None):
        calls["config"] += 1
        return {"/etc/foo.conf"}

    monkeypatch.setattr("enroll.rpm.rpm_modified_files", fake_modified)
    monkeypatch.setattr("enroll.rpm.rpm_config_files", fake_config)

    b = RpmBackend()
    etc = ["/etc/foo.conf", "/etc/bar.conf", "/etc/baz.conf"]

    out1 = b.modified_paths("ignored", etc)
    out2 = b.modified_paths("ignored", etc)

    assert out1 == out2
    assert out1["/etc/foo.conf"] == "modified_conffile"
    assert out1["/etc/bar.conf"] == "modified_packaged_file"
    assert "/etc/baz.conf" not in out1

    # Caches should mean we only queried rpm once.
    assert calls["modified"] == 1
    assert calls["config"] == 1
