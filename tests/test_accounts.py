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


def test_find_user_ssh_files_ignores_symlinked_ssh_dir(tmp_path: Path):
    """A user who replaces ~/.ssh with a symlink to a sensitive directory must
    not have files inside it harvested through the symlinked parent. os.path.isdir
    follows symlinks, so the directory itself must be checked with islink().
    """

    from enroll.accounts import find_user_ssh_files

    sensitive = tmp_path / "sensitive"
    sensitive.mkdir()
    (sensitive / "authorized_keys").write_text("ssh-rsa AAAA...\n", encoding="utf-8")

    home = tmp_path / "home" / "mallory"
    home.mkdir(parents=True)
    os.symlink(str(sensitive), str(home / ".ssh"))

    assert find_user_ssh_files(str(home)) == []


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


def test_parse_group_handles_empty_lines(tmp_path: Path):
    from enroll.accounts import parse_group

    p = tmp_path / "group"
    p.write_text(
        "valid:x:1000:user1\n" "\n" "another:x:1001:user2\n",
        encoding="utf-8",
    )
    gid_to_name, name_to_gid, members = parse_group(str(p))
    assert 1000 in gid_to_name
    assert 1001 in gid_to_name


def test_parse_group_handles_short_lines(tmp_path: Path):
    from enroll.accounts import parse_group

    p = tmp_path / "group"
    p.write_text(
        "valid:x:1000:user1\n" "short:x:1001\n" "another:x:1002:user2\n",
        encoding="utf-8",
    )
    gid_to_name, name_to_gid, members = parse_group(str(p))
    assert 1000 in gid_to_name
    assert 1001 not in gid_to_name  # skipped due to short line
    assert 1002 in gid_to_name


def test_find_flatpaks_in_root_detects_remote_branch_and_arch(tmp_path: Path):
    import enroll.accounts as a

    root = tmp_path / "flatpak"
    (root / "repo").mkdir(parents=True)
    (root / "repo" / "config").write_text(
        '[remote "acme"]\nurl=https://flatpak.example/repo/\n',
        encoding="utf-8",
    )
    ref = (
        root
        / "repo"
        / "refs"
        / "remotes"
        / "acme"
        / "app"
        / "com.example.App"
        / "x86_64"
        / "stable"
    )
    ref.parent.mkdir(parents=True)
    ref.write_text("checksum\n", encoding="utf-8")
    active = root / "app" / "com.example.App" / "x86_64" / "stable" / "active"
    active.mkdir(parents=True)

    remotes = a.find_flatpak_remotes(str(root), method="system")
    assert [(r.name, r.url, r.method) for r in remotes] == [
        ("acme", "https://flatpak.example/repo/", "system")
    ]

    apps = a._find_flatpaks_in_root(str(root), method="system")
    assert len(apps) == 1
    assert apps[0].name == "com.example.App"
    assert apps[0].remote == "acme"
    assert apps[0].branch == "stable"
    assert apps[0].arch == "x86_64"


def test_parse_snap_list_output_detects_channel_revision_and_modes():
    import enroll.accounts as a

    output = """Name       Version  Rev   Tracking       Publisher   Notes
code       abc      123   latest/stable  vscode✓     classic
mydev      1.0      42    latest/edge    example     devmode,dangerous
bare       1.0      5     latest/stable  canonical✓  base
"""

    snaps = {snap.name: snap for snap in a._parse_snap_list_output(output)}
    assert snaps["code"].channel == "latest/stable"
    assert snaps["code"].revision == 123
    assert snaps["code"].classic is True
    assert snaps["mydev"].devmode is True
    assert snaps["mydev"].dangerous is True
    assert snaps["bare"].notes == ["base"]


def test_parse_flatpak_list_output_detects_system_refs():
    from enroll.accounts import _parse_flatpak_list_output

    output = "\n".join(
        [
            "app/org.example.App/x86_64/stable\tflathub\tstable\tx86_64",
            "runtime/org.freedesktop.Platform/x86_64/24.08\tflathub\t24.08\tx86_64",
        ]
    )

    refs = _parse_flatpak_list_output(
        output, method="system", columns=("ref", "origin", "branch", "arch")
    )

    assert [(r.kind, r.name, r.remote, r.branch, r.arch) for r in refs] == [
        ("app", "org.example.App", "flathub", "stable", "x86_64"),
        ("runtime", "org.freedesktop.Platform", "flathub", "24.08", "x86_64"),
    ]
    assert refs[0].source == "flatpak-list"


def test_find_system_flatpaks_prefers_flatpak_list(monkeypatch):
    import subprocess
    import enroll.accounts as a

    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args == ["flatpak", "list", "--columns=help"]:
            return subprocess.CompletedProcess(
                args,
                0,
                stdout="application\norigin\nbranch\narch\n",
                stderr="",
            )
        return subprocess.CompletedProcess(
            args,
            0,
            stdout="app/org.example.App/x86_64/stable\tacme\tstable\tx86_64\n",
            stderr="",
        )

    monkeypatch.setattr(a.shutil, "which", lambda cmd: "/usr/bin/flatpak")
    monkeypatch.setattr(a.subprocess, "run", fake_run)
    monkeypatch.setattr(
        a,
        "_find_flatpaks_in_root",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("fallback used")),
    )

    refs = a.find_system_flatpaks()

    assert calls[0] == ["flatpak", "list", "--columns=help"]
    assert calls[1][:3] == ["flatpak", "list", "--system"]
    assert refs[0].name == "org.example.App"
    assert refs[0].method == "system"
    assert refs[0].remote == "acme"


def test_parse_flatpak_list_output_detects_application_columns():
    from enroll.accounts import _parse_flatpak_list_output

    output = "org.example.App\tflathub\tstable\tx86_64\n"
    refs = _parse_flatpak_list_output(
        output, method="system", columns=("application", "origin", "branch", "arch")
    )

    assert len(refs) == 1
    assert refs[0].name == "org.example.App"
    assert refs[0].kind is None
    assert refs[0].remote == "flathub"
    assert refs[0].branch == "stable"
    assert refs[0].arch == "x86_64"


def test_parse_plain_flatpak_list_output_like_default_table():
    from enroll.accounts import _parse_flatpak_list_output

    output = """Name                               Application ID                                  Version           Branch               Installation
Mesa                               org.freedesktop.Platform.GL.default             26.0.6            25.08                system
Mesa (Extra)                       org.freedesktop.Platform.GL.default             26.0.6            25.08-extra          system
Codecs Extra Extension             org.freedesktop.Platform.codecs-extra                             25.08-extra          system
KDE Application Platform           org.kde.Platform                                                  6.10                 system
OnionShare                         org.onionshare.OnionShare                       2.6.4             stable               system
"""

    refs = _parse_flatpak_list_output(output, method="system", columns=None)
    by_name_branch = {(r.name, r.branch) for r in refs}

    assert ("org.onionshare.OnionShare", "stable") in by_name_branch
    assert ("org.freedesktop.Platform.GL.default", "25.08") in by_name_branch
    assert ("org.freedesktop.Platform.GL.default", "25.08-extra") in by_name_branch
    assert ("org.kde.Platform", "6.10") in by_name_branch


def test_parse_flatpak_columns_help_handles_description_table():
    from enroll.accounts import _parse_flatpak_columns_help

    output = """
Available columns:
  application  The application ID
  branch       The branch
  installation The installation
"""

    assert _parse_flatpak_columns_help(output) >= {
        "application",
        "branch",
        "installation",
    }


def test_flatpak_list_attempts_respect_supported_columns():
    from enroll.accounts import _flatpak_list_attempts

    attempts = _flatpak_list_attempts(
        "--system", {"application", "branch", "installation"}
    )
    command_strings = [" ".join(args) for args, _columns in attempts]

    assert any("--columns=application,branch" in cmd for cmd in command_strings)
    assert not any("origin" in cmd for cmd in command_strings)
    assert command_strings[-1] == "flatpak list --system"


def test_user_flatpak_origin_symlink_is_not_read(tmp_path: Path):
    import enroll.accounts as a

    home = tmp_path / "home"
    active = (
        home
        / ".local"
        / "share"
        / "flatpak"
        / "app"
        / "org.evil.App"
        / "x86_64"
        / "stable"
        / "active"
    )
    active.mkdir(parents=True)
    secret = tmp_path / "root-only-secret"
    secret.write_text("ROOTSECRET\n", encoding="utf-8")
    (active / "origin").symlink_to(secret)

    apps = a.find_user_flatpaks(str(home), user="alice")

    assert len(apps) == 1
    assert apps[0].name == "org.evil.App"
    assert apps[0].remote is None


def test_user_flatpak_repo_config_symlink_is_not_read(tmp_path: Path):
    import enroll.accounts as a

    home = tmp_path / "home"
    flatpak_root = home / ".local" / "share" / "flatpak"
    (flatpak_root / "repo").mkdir(parents=True)
    secret = tmp_path / "root-only-secret"
    secret.write_text(
        '[remote "ROOTSECRET"]\nurl=https://evil.example/\n', encoding="utf-8"
    )
    (flatpak_root / "repo" / "config").symlink_to(secret)

    assert a.find_user_flatpak_remotes(str(home), user="alice") == []


def test_user_flatpak_tree_with_symlinked_parent_is_not_walked(tmp_path: Path):
    import enroll.accounts as a

    home = tmp_path / "home"
    real = tmp_path / "real-flatpak"
    active = (
        real
        / "share"
        / "flatpak"
        / "app"
        / "org.evil.App"
        / "x86_64"
        / "stable"
        / "active"
    )
    active.mkdir(parents=True)
    (active / "origin").write_text("evil\n", encoding="utf-8")
    home.mkdir()
    (home / ".local").symlink_to(real, target_is_directory=True)

    assert a.find_user_flatpaks(str(home), user="alice") == []
