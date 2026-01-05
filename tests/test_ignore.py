from enroll.ignore import IgnorePolicy


def test_ignore_policy_denies_common_backup_files():
    pol = IgnorePolicy()
    assert pol.deny_reason("/etc/shadow-") == "backup_file"
    assert pol.deny_reason("/etc/passwd-") == "backup_file"
    assert pol.deny_reason("/etc/group-") == "backup_file"
    assert pol.deny_reason("/etc/something~") == "backup_file"
    assert pol.deny_reason("/foobar") == "unreadable"
