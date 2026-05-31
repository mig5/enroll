from __future__ import annotations

import os
from pathlib import Path


def test_parse_login_defs_parses_known_keys(tmp_path: Path):
    from enroll.accounts import parse_login_defs

    p = tmp_path / "login.defs"
    p.write_text(
        """
        # comment
        UID_MIN 1000
        UID_MAX 60000
        SYS_UID_MIN 100
        SYS_UID_MAX 999
        UID_MIN not_an_int
        OTHER 123
        """,
        encoding="utf-8",
    )

    vals = parse_login_defs(str(p))
    assert vals["UID_MIN"] == 1000
    assert vals["UID_MAX"] == 60000
    assert vals["SYS_UID_MIN"] == 100
    assert vals["SYS_UID_MAX"] == 999
    assert "OTHER" not in vals


def test_parse_passwd_and_group_and_ssh_files(tmp_path: Path):
    from enroll.accounts import find_user_ssh_files, parse_group, parse_passwd

    passwd = tmp_path / "passwd"
    passwd.write_text(
        "\n".join(
            [
                "root:x:0:0:root:/root:/bin/bash",
                "# comment",
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
                "bob:x:1001:1000:Bob:/home/bob:/usr/sbin/nologin",
                "badline",
                "cathy:x:notint:1000:Cathy:/home/cathy:/bin/bash",
                "",
            ]
        ),
        encoding="utf-8",
    )

    group = tmp_path / "group"
    group.write_text(
        "\n".join(
            [
                "root:x:0:",
                "users:x:1000:alice,bob",
                "admins:x:1002:alice",
                "badgroup:x:notint:alice",
                "",
            ]
        ),
        encoding="utf-8",
    )

    rows = parse_passwd(str(passwd))
    assert ("alice", 1000, 1000, "Alice", "/home/alice", "/bin/bash") in rows
    assert all(r[0] != "cathy" for r in rows)  # skipped invalid UID

    gid_to_name, name_to_gid, members = parse_group(str(group))
    assert gid_to_name[1000] == "users"
    assert name_to_gid["admins"] == 1002
    assert "alice" in members["admins"]

    # ssh discovery: only authorized_keys, no symlinks
    home = tmp_path / "home" / "alice"
    sshdir = home / ".ssh"
    sshdir.mkdir(parents=True)
    ak = sshdir / "authorized_keys"
    ak.write_text("ssh-ed25519 AAA...", encoding="utf-8")
    # a symlink should be ignored
    (sshdir / "authorized_keys2").write_text("x", encoding="utf-8")
    os.symlink(str(sshdir / "authorized_keys2"), str(sshdir / "authorized_keys_link"))
    assert find_user_ssh_files(str(home)) == [str(ak)]


def test_collect_non_system_users(monkeypatch, tmp_path: Path):
    import enroll.accounts as a

    orig_parse_login_defs = a.parse_login_defs
    orig_parse_passwd = a.parse_passwd
    orig_parse_group = a.parse_group

    # Provide controlled passwd/group/login.defs inputs via monkeypatch.
    passwd = tmp_path / "passwd"
    passwd.write_text(
        "\n".join(
            [
                "root:x:0:0:root:/root:/bin/bash",
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
                "sysuser:x:200:200:Sys:/home/sys:/bin/bash",
                "bob:x:1001:1000:Bob:/home/bob:/bin/false",
                "",
            ]
        ),
        encoding="utf-8",
    )
    group = tmp_path / "group"
    group.write_text(
        "\n".join(
            [
                "users:x:1000:alice,bob",
                "admins:x:1002:alice",
                "",
            ]
        ),
        encoding="utf-8",
    )

    defs = tmp_path / "login.defs"
    defs.write_text("UID_MIN 1000\n", encoding="utf-8")

    monkeypatch.setattr(
        a, "parse_login_defs", lambda path=str(defs): orig_parse_login_defs(path)
    )
    monkeypatch.setattr(
        a, "parse_passwd", lambda path=str(passwd): orig_parse_passwd(path)
    )
    monkeypatch.setattr(
        a, "parse_group", lambda path=str(group): orig_parse_group(path)
    )

    # Use a stable fake ssh discovery.
    monkeypatch.setattr(
        a, "find_user_ssh_files", lambda home: [f"{home}/.ssh/authorized_keys"]
    )

    users = a.collect_non_system_users()
    assert [u.name for u in users] == ["alice"]
    u = users[0]
    assert u.primary_group == "users"
    assert u.supplementary_groups == ["admins"]
    assert u.ssh_files == ["/home/alice/.ssh/authorized_keys"]


def test_parse_login_defs_file_not_found(tmp_path: Path):
    from enroll.accounts import parse_login_defs

    nonexistent = tmp_path / "nonexistent" / "login.defs"
    vals = parse_login_defs(str(nonexistent))
    assert vals == {}


def test_parse_login_defs_handles_invalid_numbers(tmp_path: Path):
    from enroll.accounts import parse_login_defs

    p = tmp_path / "login.defs"
    p.write_text("UID_MIN not_a_number\nUID_MAX 60000\n", encoding="utf-8")
    vals = parse_login_defs(str(p))
    assert "UID_MIN" not in vals
    assert vals["UID_MAX"] == 60000


def test_parse_group_handles_invalid_gid(tmp_path: Path):
    from enroll.accounts import parse_group

    p = tmp_path / "group"
    p.write_text(
        "valid:x:1000:user1\n" "invalid_gid:x:notanint:user2\n",
        encoding="utf-8",
    )
    gid_to_name, name_to_gid, members = parse_group(str(p))
    assert 1000 in gid_to_name
    assert gid_to_name[1000] == "valid"
    assert "invalid_gid" not in name_to_gid


def test_parse_group_line_too_short(tmp_path: Path):
    from enroll.accounts import parse_group

    p = tmp_path / "group"
    p.write_text(
        "valid:x:1000:user1\n" "shortline:x:1001\n",
        encoding="utf-8",
    )
    gid_to_name, name_to_gid, members = parse_group(str(p))
    assert 1000 in gid_to_name
    assert 1001 not in gid_to_name


def test_is_human_user_filters_by_uid_and_shell():
    from enroll.accounts import is_human_user

    assert is_human_user(1000, "/bin/bash", 1000) is True
    assert is_human_user(999, "/bin/bash", 1000) is False
    assert is_human_user(1000, "/usr/sbin/nologin", 1000) is False
    assert is_human_user(1000, "/usr/bin/nologin", 1000) is False
    assert is_human_user(1000, "/bin/false", 1000) is False
    assert is_human_user(1000, "", 1000) is True


def test_find_user_ssh_files_no_ssh_dir(tmp_path: Path):
    from enroll.accounts import find_user_ssh_files

    home = tmp_path / "home" / "user"
    home.mkdir(parents=True)
    assert find_user_ssh_files(str(home)) == []


def test_find_user_ssh_files_ignores_symlink(tmp_path: Path):
    from enroll.accounts import find_user_ssh_files

    home = tmp_path / "home" / "user"
    sshdir = home / ".ssh"
    sshdir.mkdir(parents=True)
    target = sshdir / "real_file"
    target.write_text("x", encoding="utf-8")
    os.symlink(str(target), str(sshdir / "authorized_keys"))

    result = find_user_ssh_files(str(home))
    assert result == []


def test_find_user_ssh_files_handles_home_not_starting_with_slash():
    from enroll.accounts import find_user_ssh_files

    assert find_user_ssh_files("relative/path") == []
    assert find_user_ssh_files("") == []


def test_collect_non_system_users_skips_nologin_users(tmp_path: Path):
    import enroll.accounts as a

    orig_parse_login_defs = a.parse_login_defs
    orig_parse_passwd = a.parse_passwd
    orig_parse_group = a.parse_group

    passwd = tmp_path / "passwd"
    passwd.write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "sysuser:x:100:100:Sys:/home/sys:/bin/bash\n",
        encoding="utf-8",
    )
    group = tmp_path / "group"
    group.write_text("users:x:1000:alice\n", encoding="utf-8")
    defs = tmp_path / "login.defs"
    defs.write_text("UID_MIN 1000\n", encoding="utf-8")

    monkeypatch_wrapper = lambda fn, p: lambda path=str(p): fn(path)

    a.parse_login_defs = monkeypatch_wrapper(orig_parse_login_defs, defs)
    a.parse_passwd = monkeypatch_wrapper(orig_parse_passwd, passwd)
    a.parse_group = monkeypatch_wrapper(orig_parse_group, group)
    a.find_user_ssh_files = lambda home: []

    users = a.collect_non_system_users()
    assert [u.name for u in users] == ["alice"]


def test_collect_non_system_users_skips_below_uid_min(tmp_path: Path):
    import enroll.accounts as a

    orig_parse_login_defs = a.parse_login_defs
    orig_parse_passwd = a.parse_passwd
    orig_parse_group = a.parse_group

    passwd = tmp_path / "passwd"
    passwd.write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "sysuser:x:999:999:Sys:/home/sys:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        encoding="utf-8",
    )
    group = tmp_path / "group"
    group.write_text("users:x:1000:alice\n", encoding="utf-8")
    defs = tmp_path / "login.defs"
    defs.write_text("UID_MIN 1000\n", encoding="utf-8")

    a.parse_login_defs = lambda path=str(defs): orig_parse_login_defs(path)
    a.parse_passwd = lambda path=str(passwd): orig_parse_passwd(path)
    a.parse_group = lambda path=str(group): orig_parse_group(path)
    a.find_user_ssh_files = lambda home: []

    users = a.collect_non_system_users()
    assert [u.name for u in users] == ["alice"]
