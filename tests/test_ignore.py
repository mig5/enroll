from enroll.ignore import IgnorePolicy


def test_ignore_policy_denies_common_backup_files():
    pol = IgnorePolicy()
    assert pol.deny_reason("/etc/shadow-") == "backup_file"
    assert pol.deny_reason("/etc/passwd-") == "backup_file"
    assert pol.deny_reason("/etc/group-") == "backup_file"
    assert pol.deny_reason("/etc/something~") == "backup_file"
    assert pol.deny_reason("/foobar") == "unreadable"


def test_ignore_policy_deny_reason_link(tmp_path):
    pol = IgnorePolicy()

    target = tmp_path / "target.txt"
    target.write_text("hello", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    # File is not a symlink.
    assert pol.deny_reason_link(str(target)) == "not_symlink"

    # Symlink is accepted if readable.
    assert pol.deny_reason_link(str(link)) is None

    # Missing path should be unreadable.
    assert pol.deny_reason_link(str(tmp_path / "missing")) == "unreadable"
