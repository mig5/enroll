from __future__ import annotations

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
