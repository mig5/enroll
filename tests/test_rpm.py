from __future__ import annotations

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
