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


def test_dpkg_owner_returns_none_on_diversion_only(monkeypatch):
    import enroll.debian as d

    class P:
        def __init__(self, rc: int, out: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    def fake_run(cmd, text, capture_output):
        return P(0, "diversion by foo from: /etc/something\n")

    monkeypatch.setattr(d.subprocess, "run", fake_run)
    assert d.dpkg_owner("/etc/something") is None


def test_dpkg_owner_handles_line_without_colon(monkeypatch):
    import enroll.debian as d

    class P:
        def __init__(self, rc: int, out: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    def fake_run(cmd, text, capture_output):
        return P(0, "invalid line without colon\n")

    monkeypatch.setattr(d.subprocess, "run", fake_run)
    assert d.dpkg_owner("/etc/foo") is None


def test_list_manual_packages_returns_empty_on_error(monkeypatch):
    import enroll.debian as d

    class P:
        def __init__(self, rc: int, out: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    def fake_run(cmd, text, capture_output):
        return P(1, "error")

    monkeypatch.setattr(d.subprocess, "run", fake_run)
    assert d.list_manual_packages() == []


def test_list_installed_packages_handles_exception(monkeypatch):
    import enroll.debian as d

    def fake_run(*args, **kwargs):
        raise Exception("simulated error")

    monkeypatch.setattr(d.subprocess, "run", fake_run)
    assert d.list_installed_packages() == {}


def test_list_installed_packages_parses_output():
    import enroll.debian as d

    class P:
        def __init__(self, rc: int, out: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    original_run = d.subprocess.run

    def fake_run(cmd, text, capture_output, check):
        return P(0, "nginx\t1.18.0\tamd64\nvim\t8.2\tamd64\n")

    d.subprocess.run = fake_run
    try:
        result = d.list_installed_packages()
        assert "nginx" in result
        assert result["nginx"][0]["version"] == "1.18.0"
        assert result["nginx"][0]["arch"] == "amd64"
        assert "vim" in result
    finally:
        d.subprocess.run = original_run


def test_list_installed_packages_skips_invalid_lines():
    import enroll.debian as d

    class P:
        def __init__(self, rc: int, out: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    original_run = d.subprocess.run

    def fake_run(cmd, text, capture_output, check):
        return P(0, "nginx\t1.18.0\tamd64\ninvalid_line\n\t1.0\tamd64\n")

    d.subprocess.run = fake_run
    try:
        result = d.list_installed_packages()
        assert "nginx" in result
        assert "invalid_line" not in result
    finally:
        d.subprocess.run = original_run


def test_list_installed_packages_handles_empty_name():
    import enroll.debian as d

    class P:
        def __init__(self, rc: int, out: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    original_run = d.subprocess.run

    def fake_run(cmd, text, capture_output, check):
        return P(0, "\t1.0\tamd64\nnginx\t1.18.0\tamd64\n")

    d.subprocess.run = fake_run
    try:
        result = d.list_installed_packages()
        assert "" not in result
        assert "nginx" in result
    finally:
        d.subprocess.run = original_run


def test_list_installed_packages_sorts_output():
    import enroll.debian as d

    class P:
        def __init__(self, rc: int, out: str):
            self.returncode = rc
            self.stdout = out
            self.stderr = ""

    original_run = d.subprocess.run

    def fake_run(cmd, text, capture_output, check):
        return P(0, "nginx\t1.18.0\tamd64\nnginx\t1.19.0\tarm64\n")

    d.subprocess.run = fake_run
    try:
        result = d.list_installed_packages()
        assert len(result["nginx"]) == 2
        assert result["nginx"][0]["arch"] == "amd64"
        assert result["nginx"][1]["arch"] == "arm64"
    finally:
        d.subprocess.run = original_run


def test_build_dpkg_etc_index_handles_missing_file(tmp_path: Path):
    import enroll.debian as d

    info = tmp_path / "info"
    info.mkdir()
    # Don't create any .list files

    owned, owner_map, topdir_to_pkgs, pkg_to_etc = d.build_dpkg_etc_index(str(info))
    assert owned == set()
    assert owner_map == {}
    assert topdir_to_pkgs == {}
    assert pkg_to_etc == {}


def test_build_dpkg_etc_index_skips_non_etc_paths(tmp_path: Path):
    import enroll.debian as d

    info = tmp_path / "info"
    info.mkdir()
    (info / "foo.list").write_text("/usr/bin/foo\n/etc/bar\n", encoding="utf-8")

    owned, owner_map, topdir_to_pkgs, pkg_to_etc = d.build_dpkg_etc_index(str(info))
    assert "/usr/bin/foo" not in owned
    assert "/etc/bar" in owned
    assert "foo" not in topdir_to_pkgs


def test_parse_status_conffiles_handles_empty_status(tmp_path: Path):
    import enroll.debian as d

    status = tmp_path / "status"
    status.write_text("", encoding="utf-8")
    m = d.parse_status_conffiles(str(status))
    assert m == {}


def test_parse_status_conffiles_handles_package_without_conffiles(tmp_path: Path):
    import enroll.debian as d

    status = tmp_path / "status"
    status.write_text(
        "Package: nginx\nVersion: 1\nStatus: install ok installed\n",
        encoding="utf-8",
    )
    m = d.parse_status_conffiles(str(status))
    assert m == {}


def test_read_pkg_md5sums_returns_empty_if_file_not_exists(tmp_path: Path):
    import enroll.debian as d

    result = d.read_pkg_md5sums("nonexistent_package")
    assert result == {}


def test_read_pkg_md5sums_parses_md5sums_file(tmp_path: Path, monkeypatch):
    import enroll.debian as d

    info_dir = tmp_path / "info"
    info_dir.mkdir()
    md5_file = info_dir / "nginx.md5sums"
    md5_file.write_text(
        "abcdef1234567890abcdef1234567890  etc/nginx/nginx.conf\n"
        "1234567890abcdef1234567890abcdef  etc/nginx/sites-enabled/default\n",
        encoding="utf-8",
    )

    def fake_exists(path):
        return str(path).endswith("nginx.md5sums")

    monkeypatch.setattr(d.os.path, "exists", fake_exists)

    original_open = open

    def fake_open(path, *args, **kwargs):
        if "nginx.md5sums" in str(path):
            return original_open(md5_file, *args, **kwargs)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open, raising=False)

    result = d.read_pkg_md5sums("nginx")
    assert result["etc/nginx/nginx.conf"] == "abcdef1234567890abcdef1234567890"
    assert (
        result["etc/nginx/sites-enabled/default"] == "1234567890abcdef1234567890abcdef"
    )
