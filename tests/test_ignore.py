from enroll.ignore import IgnorePolicy


def test_ignore_policy_denies_common_backup_files():
    pol = IgnorePolicy()
    assert pol.deny_reason("/etc/shadow-") == "denied_path"
    assert pol.deny_reason("/etc/passwd-") == "denied_path"
    assert pol.deny_reason("/etc/group-") == "denied_path"
    assert pol.deny_reason("/foobar") == "unreadable"
