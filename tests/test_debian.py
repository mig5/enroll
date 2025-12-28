from __future__ import annotations

import hashlib
from pathlib import Path


def test_dpkg_owner_parses_output(monkeypatch):
    import enroll.debian as d

    class P:
        def __init__(self, rc: int, out: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    def fake_run(cmd, text, capture_output):
        assert cmd[:2] == ["dpkg", "-S"]
        return P(
            0,
            """
            diversion by foo from: /etc/something
            nginx-common:amd64: /etc/nginx/nginx.conf
            nginx-common, nginx: /etc/nginx/sites-enabled/default
            """,
        )

    monkeypatch.setattr(d.subprocess, "run", fake_run)
    assert d.dpkg_owner("/etc/nginx/nginx.conf") == "nginx-common"

    def fake_run_none(cmd, text, capture_output):
        return P(1, "")

    monkeypatch.setattr(d.subprocess, "run", fake_run_none)
    assert d.dpkg_owner("/missing") is None


def test_list_manual_packages_parses_and_sorts(monkeypatch):
    import enroll.debian as d

    class P:
        def __init__(self, rc: int, out: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    def fake_run(cmd, text, capture_output):
        assert cmd == ["apt-mark", "showmanual"]
        return P(0, "\n# comment\nnginx\nvim\nnginx\n")

    monkeypatch.setattr(d.subprocess, "run", fake_run)
    assert d.list_manual_packages() == ["nginx", "vim"]


def test_build_dpkg_etc_index(tmp_path: Path):
    import enroll.debian as d

    info = tmp_path / "info"
    info.mkdir()
    (info / "nginx.list").write_text(
        "/etc/nginx/nginx.conf\n/etc/nginx/sites-enabled/default\n/usr/bin/nginx\n",
        encoding="utf-8",
    )
    (info / "vim:amd64.list").write_text(
        "/etc/vim/vimrc\n/usr/bin/vim\n",
        encoding="utf-8",
    )

    owned, owner_map, topdir_to_pkgs, pkg_to_etc = d.build_dpkg_etc_index(str(info))
    assert "/etc/nginx/nginx.conf" in owned
    assert owner_map["/etc/nginx/nginx.conf"] == "nginx"
    assert "nginx" in topdir_to_pkgs
    assert topdir_to_pkgs["nginx"] == {"nginx"}
    assert pkg_to_etc["vim"] == ["/etc/vim/vimrc"]


def test_parse_status_conffiles_handles_continuations(tmp_path: Path):
    import enroll.debian as d

    status = tmp_path / "status"
    status.write_text(
        "\n".join(
            [
                "Package: nginx",
                "Version: 1",
                "Conffiles:",
                " /etc/nginx/nginx.conf abcdef",
                " /etc/nginx/mime.types 123456",
                "",
                "Package: other",
                "Version: 2",
                "",
            ]
        ),
        encoding="utf-8",
    )
    m = d.parse_status_conffiles(str(status))
    assert m["nginx"]["/etc/nginx/nginx.conf"] == "abcdef"
    assert m["nginx"]["/etc/nginx/mime.types"] == "123456"
    assert "other" not in m


def test_read_pkg_md5sums_and_file_md5(tmp_path: Path, monkeypatch):
    import enroll.debian as d

    # Patch /var/lib/dpkg/info/<pkg>.md5sums lookup to a tmp file.
    md5_file = tmp_path / "pkg.md5sums"
    md5_file.write_text("0123456789abcdef  etc/foo.conf\n", encoding="utf-8")

    def fake_exists(path: str) -> bool:
        return path.endswith("/var/lib/dpkg/info/p1.md5sums")

    real_open = open

    def fake_open(path: str, *args, **kwargs):
        if path.endswith("/var/lib/dpkg/info/p1.md5sums"):
            return real_open(md5_file, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(d.os.path, "exists", fake_exists)
    monkeypatch.setattr("builtins.open", fake_open)

    m = d.read_pkg_md5sums("p1")
    assert m == {"etc/foo.conf": "0123456789abcdef"}

    content = b"hello world\n"
    p = tmp_path / "x"
    p.write_bytes(content)
    assert d.file_md5(str(p)) == hashlib.md5(content).hexdigest()


def test_stat_triplet_fallbacks(tmp_path: Path, monkeypatch):
    import enroll.debian as d
    import sys

    p = tmp_path / "f"
    p.write_text("x", encoding="utf-8")

    class FakePwdMod:
        @staticmethod
        def getpwuid(_):  # pragma: no cover
            raise KeyError

    class FakeGrpMod:
        @staticmethod
        def getgrgid(_):  # pragma: no cover
            raise KeyError

    # stat_triplet imports pwd/grp inside the function, so patch sys.modules.
    monkeypatch.setitem(sys.modules, "pwd", FakePwdMod)
    monkeypatch.setitem(sys.modules, "grp", FakeGrpMod)
    owner, group, mode = d.stat_triplet(str(p))
    assert owner.isdigit()
    assert group.isdigit()
    assert mode.isdigit() and len(mode) == 4
