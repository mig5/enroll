from enroll.secrets import SecretPolicy


def test_secret_policy_denies_common_backup_files():
    pol = SecretPolicy()
    assert pol.deny_reason("/etc/shadow-") == "denied_path"
    assert pol.deny_reason("/etc/passwd-") == "denied_path"
    assert pol.deny_reason("/etc/group-") == "denied_path"
