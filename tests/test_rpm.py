from __future__ import annotations
import pytest

import enroll.rpm as rpm


def test_rpm_owner_returns_none_when_unowned(monkeypatch):
    monkeypatch.setattr(
        rpm,
        "_run",
        lambda cmd, allow_fail=False, merge_err=False: (
            1,
            "file /etc/x is not owned by any package\n",
        ),
    )
    assert rpm.rpm_owner("/etc/x") is None


def test_rpm_owner_parses_name(monkeypatch):
    monkeypatch.setattr(
        rpm, "_run", lambda cmd, allow_fail=False, merge_err=False: (0, "bash\n")
    )
    assert rpm.rpm_owner("/bin/bash") == "bash"


def test_strip_arch_strips_known_arches():
    assert rpm._strip_arch("vim-enhanced.x86_64") == "vim-enhanced"
    assert rpm._strip_arch("foo.noarch") == "foo"
    assert rpm._strip_arch("weird.token") == "weird.token"


def test_list_manual_packages_prefers_dnf_repoquery(monkeypatch):
    monkeypatch.setattr(
        rpm.shutil, "which", lambda exe: "/usr/bin/dnf" if exe == "dnf" else None
    )

    def fake_run(cmd, allow_fail=False, merge_err=False):
        # First repoquery form returns usable output.
        if cmd[:3] == ["dnf", "-q", "repoquery"]:
            return 0, "vim-enhanced.x86_64\nhtop\nvim-enhanced.x86_64\n"
        raise AssertionError(f"unexpected cmd: {cmd}")

    monkeypatch.setattr(rpm, "_run", fake_run)

    pkgs = rpm.list_manual_packages()
    assert pkgs == ["htop", "vim-enhanced"]


def test_list_manual_packages_falls_back_to_history(monkeypatch):
    monkeypatch.setattr(
        rpm.shutil, "which", lambda exe: "/usr/bin/dnf" if exe == "dnf" else None
    )

    def fake_run(cmd, allow_fail=False, merge_err=False):
        # repoquery fails
        if cmd[:3] == ["dnf", "-q", "repoquery"]:
            return 1, ""
        if cmd[:3] == ["dnf", "-q", "history"]:
            return (
                0,
                "Installed Packages\nvim-enhanced.x86_64\nLast metadata expiration check: 0:01:00 ago\n",
            )
        raise AssertionError(f"unexpected cmd: {cmd}")

    monkeypatch.setattr(rpm, "_run", fake_run)

    pkgs = rpm.list_manual_packages()
    assert pkgs == ["vim-enhanced"]


def test_build_rpm_etc_index_uses_fallback_when_rpm_output_mismatches(monkeypatch):
    # Two files in /etc, one owned, one unowned.
    monkeypatch.setattr(
        rpm, "_walk_etc_files", lambda: ["/etc/owned.conf", "/etc/unowned.conf"]
    )

    # Simulate chunk query producing unexpected extra line (mismatch) -> triggers per-file fallback.
    monkeypatch.setattr(
        rpm,
        "_run",
        lambda cmd, allow_fail=False, merge_err=False: (0, "ownedpkg\nEXTRA\nTHIRD\n"),
    )
    monkeypatch.setattr(
        rpm, "rpm_owner", lambda p: "ownedpkg" if p == "/etc/owned.conf" else None
    )

    owned, owner_map, topdir_to_pkgs, pkg_to_etc = rpm.build_rpm_etc_index()

    assert owned == {"/etc/owned.conf"}
    assert owner_map["/etc/owned.conf"] == "ownedpkg"
    assert "owned.conf" in topdir_to_pkgs
    assert pkg_to_etc["ownedpkg"] == ["/etc/owned.conf"]


def test_build_rpm_etc_index_parses_chunk_output(monkeypatch):
    monkeypatch.setattr(
        rpm, "_walk_etc_files", lambda: ["/etc/ssh/sshd_config", "/etc/notowned"]
    )

    def fake_run(cmd, allow_fail=False, merge_err=False):
        # One output line per input path.
        return 0, "openssh-server\nfile /etc/notowned is not owned by any package\n"

    monkeypatch.setattr(rpm, "_run", fake_run)

    owned, owner_map, topdir_to_pkgs, pkg_to_etc = rpm.build_rpm_etc_index()

    assert "/etc/ssh/sshd_config" in owned
    assert "/etc/notowned" not in owned
    assert owner_map["/etc/ssh/sshd_config"] == "openssh-server"
    assert "ssh" in topdir_to_pkgs
    assert "openssh-server" in topdir_to_pkgs["ssh"]
    assert pkg_to_etc["openssh-server"] == ["/etc/ssh/sshd_config"]


def test_rpm_config_files_and_modified_files_parsing(monkeypatch):
    monkeypatch.setattr(
        rpm,
        "_run",
        lambda cmd, allow_fail=False, merge_err=False: (
            0,
            "/etc/foo.conf\n/usr/bin/tool\n",
        ),
    )
    assert rpm.rpm_config_files("mypkg") == {"/etc/foo.conf", "/usr/bin/tool"}

    # rpm -V returns only changed/missing files
    out = "S.5....T.  c /etc/foo.conf\nmissing   /etc/bar\n"
    monkeypatch.setattr(
        rpm, "_run", lambda cmd, allow_fail=False, merge_err=False: (1, out)
    )
    assert rpm.rpm_modified_files("mypkg") == {"/etc/foo.conf", "/etc/bar"}


def test_list_manual_packages_uses_yum_fallback(monkeypatch):
    # No dnf, yum present.
    monkeypatch.setattr(
        rpm.shutil, "which", lambda exe: "/usr/bin/yum" if exe == "yum" else None
    )

    def fake_run(cmd, allow_fail=False, merge_err=False):
        assert cmd[:3] == ["yum", "-q", "history"]
        return 0, "Installed Packages\nvim-enhanced.x86_64\nhtop\n"

    monkeypatch.setattr(rpm, "_run", fake_run)

    assert rpm.list_manual_packages() == ["htop", "vim-enhanced"]


def test_list_installed_packages_parses_epoch_and_sorts(monkeypatch):
    out = (
        "bash\t0\t5.2.26\t1.el9\tx86_64\n"
        "bash\t1\t5.2.26\t1.el9\taarch64\n"
        "coreutils\t(none)\t9.1\t2.el9\tx86_64\n"
    )
    monkeypatch.setattr(
        rpm, "_run", lambda cmd, allow_fail=False, merge_err=False: (0, out)
    )
    pkgs = rpm.list_installed_packages()
    assert pkgs["bash"][0]["arch"] == "aarch64"  # sorted by arch then version
    assert pkgs["bash"][0]["version"].startswith("1:")
    assert pkgs["coreutils"][0]["version"] == "9.1-2.el9"


def test_rpm_config_files_returns_empty_on_failure(monkeypatch):
    monkeypatch.setattr(
        rpm, "_run", lambda cmd, allow_fail=False, merge_err=False: (1, "")
    )
    assert rpm.rpm_config_files("missing") == set()


def test_rpm_owner_strips_epoch_prefix_when_present(monkeypatch):
    # Defensive: rpm output might include epoch-like token.
    monkeypatch.setattr(
        rpm,
        "_run",
        lambda cmd, allow_fail=False, merge_err=False: (0, "1:bash\n"),
    )
    assert rpm.rpm_owner("/bin/bash") == "bash"


def test_strip_arch_no_suffix():
    assert rpm._strip_arch("vim") == "vim"
    assert rpm._strip_arch("nginx ") == "nginx"


def test_strip_arch_with_unknown_suffix():
    assert rpm._strip_arch("package.unknown") == "package.unknown"


def test_run_command_raises_on_fail():
    with pytest.raises(RuntimeError):
        rpm._run(["sh", "-c", "echo stderr >&2; exit 1"], allow_fail=False)


def test_rpm_owner_empty_path():
    assert rpm.rpm_owner("") is None


def test_rpm_modified_files_empty(monkeypatch):
    monkeypatch.setattr(
        rpm, "_run", lambda cmd, allow_fail=False, merge_err=False: (0, "")
    )
    assert rpm.rpm_modified_files("vim") == set()


def test_list_manual_packages_no_commands_available(monkeypatch):
    monkeypatch.setattr(rpm.shutil, "which", lambda exe: None)
    assert rpm.list_manual_packages() == []
