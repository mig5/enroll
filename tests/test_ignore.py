from __future__ import annotations

import os
from pathlib import Path

from enroll.ignore import IgnorePolicy


def test_ignore_policy_denies_common_backup_files():
    pol = IgnorePolicy()
    assert pol.deny_reason("/etc/shadow-") == "backup_file"
    assert pol.deny_reason("/etc/passwd-") == "backup_file"
    assert pol.deny_reason("/etc/group-") == "backup_file"
    assert pol.deny_reason("/etc/something~") == "backup_file"
    assert pol.deny_reason("/foobar") == "unreadable"


def test_deny_reason_dir_with_denied_path():
    pol = IgnorePolicy()
    assert pol.deny_reason_dir("/etc/ssl/private/key") == "denied_path"
    assert pol.deny_reason_dir("/etc/ssh/ssh_host_key") == "denied_path"
    assert pol.deny_reason_dir("/etc/ssh") is None


def test_deny_reason_dir_unreadable(tmp_path: Path):
    pol = IgnorePolicy()
    nonexistent = tmp_path / "nonexistent"
    assert pol.deny_reason_dir(str(nonexistent)) == "unreadable"


def test_deny_reason_dir_symlink(tmp_path: Path):
    pol = IgnorePolicy()
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link = tmp_path / "link"
    os.symlink(str(real_dir), str(link))
    assert pol.deny_reason_dir(str(link)) == "symlink"


def test_deny_reason_dir_not_directory(tmp_path: Path):
    pol = IgnorePolicy()
    regular_file = tmp_path / "file.txt"
    regular_file.write_text("content", encoding="utf-8")
    assert pol.deny_reason_dir(str(regular_file)) == "not_directory"


def test_deny_reason_dir_dangerous_mode(tmp_path: Path):
    pol = IgnorePolicy(dangerous=True)
    real_dir = tmp_path / "private"
    real_dir.mkdir()
    assert pol.deny_reason_dir(str(real_dir)) is None


def test_deny_reason_link_basic(tmp_path: Path):
    pol = IgnorePolicy()
    real_file = tmp_path / "real"
    real_file.write_text("content", encoding="utf-8")
    link = tmp_path / "link"
    os.symlink(str(real_file), str(link))
    assert pol.deny_reason_link(str(link)) is None


def test_deny_reason_link_denied_path():
    pol = IgnorePolicy()
    assert pol.deny_reason_link("/etc/ssh/ssh_host_rsa_key") == "denied_path"


def test_deny_reason_link_unreadable(tmp_path: Path):
    pol = IgnorePolicy()
    # Create a symlink in a directory that doesn't exist
    # This simulates an unreadable path
    broken_link = tmp_path / "broken_link"
    os.symlink("/nonexistent/target", str(broken_link))
    # Broken symlinks are still readable (we can readlink them)
    # So they return None (allowed) unless they match deny globs
    result = pol.deny_reason_link(str(broken_link))
    # Broken symlinks are allowed - we can still read the link target
    assert result is None


def test_deny_reason_link_not_symlink(tmp_path: Path):
    pol = IgnorePolicy()
    regular_file = tmp_path / "file.txt"
    regular_file.write_text("content", encoding="utf-8")
    assert pol.deny_reason_link(str(regular_file)) == "not_symlink"


def test_deny_reason_link_log_file():
    pol = IgnorePolicy()
    assert pol.deny_reason_link("/var/log/something.log") == "log_file"


def test_deny_reason_link_backup_file():
    pol = IgnorePolicy()
    assert pol.deny_reason_link("/etc/passwd-") == "backup_file"
    assert pol.deny_reason_link("/etc/something~") == "backup_file"


def test_deny_reason_link_dangerous_mode(tmp_path: Path):
    pol = IgnorePolicy(dangerous=True)
    real_file = tmp_path / "real"
    real_file.write_text("content", encoding="utf-8")
    link = tmp_path / "link"
    os.symlink(str(real_file), str(link))
    assert pol.deny_reason_link(str(link)) is None


def test_iter_effective_lines_with_comments():
    pol = IgnorePolicy()
    content = b"""
# This is a comment
; This is also a comment
* continuation
def main():
    pass
"""
    lines = list(pol.iter_effective_lines(content))
    assert b"def main():" in lines
    assert b"# This is a comment" not in lines


def test_iter_effective_lines_with_block_comments():
    pol = IgnorePolicy()
    content = b"""
/* This is a block comment
   spanning multiple lines */
int x = 5;
"""
    lines = list(pol.iter_effective_lines(content))
    assert b"int x = 5;" in lines
    assert b"/*" not in lines


def test_iter_effective_lines_empty():
    pol = IgnorePolicy()
    content = b""
    lines = list(pol.iter_effective_lines(content))
    assert lines == []


def test_deny_reason_binary_not_allowed(tmp_path: Path):
    pol = IgnorePolicy()
    binary = tmp_path / "random.bin"
    binary.write_bytes(b"\x00\x01\x02\x03")
    reason = pol.deny_reason(str(binary))
    assert reason == "binary_like"


def test_deny_reason_sensitive_content(tmp_path: Path):
    pol = IgnorePolicy()
    config = tmp_path / "config.txt"
    config.write_text("password=secret123", encoding="utf-8")
    reason = pol.deny_reason(str(config))
    assert reason == "sensitive_content"


def test_deny_reason_sensitive_api_key(tmp_path: Path):
    pol = IgnorePolicy()
    config = tmp_path / "config.txt"
    config.write_text("api_key=abc123", encoding="utf-8")
    reason = pol.deny_reason(str(config))
    assert reason == "sensitive_content"


def test_deny_reason_private_key(tmp_path: Path):
    pol = IgnorePolicy()
    key = tmp_path / "key.pem"
    key.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...", encoding="utf-8"
    )
    reason = pol.deny_reason(str(key))
    assert reason == "sensitive_content"


def test_deny_reason_sensitive_common_assignment_keys(tmp_path: Path):
    pol = IgnorePolicy()
    cases = {
        "password_yaml": "password: hunter2\n",
        "password_json": '{"password": "hunter2"}\n',
        "db_password": "db_password: hunter2\n",
        "client_secret": "client_secret: abc123\n",
        "secret_key": "secret_key = abc123\n",
        "auth_token": "auth_token: abc123\n",
        "passphrase": "passphrase: abc123\n",
        "credentials": "credentials = abc123\n",
    }
    for name, text in cases.items():
        config = tmp_path / name
        config.write_text(text, encoding="utf-8")
        assert pol.deny_reason(str(config)) == "sensitive_content", name


def test_deny_reason_sensitive_common_cloud_assignment_keys(tmp_path: Path):
    pol = IgnorePolicy()
    cases = {
        "aws_access_key_id": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
        "aws_secret_access_key": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY\n",
        "azure_client_secret": "azure_client_secret: abc123\n",
        "google_application_credentials": "GOOGLE_APPLICATION_CREDENTIALS=/etc/app/key.json\n",
        "gcp_service_account": "gcp_service_account: svc@example.iam.gserviceaccount.com\n",
        "service_account_key": "service_account_key: abc123\n",
    }
    for name, text in cases.items():
        config = tmp_path / name
        config.write_text(text, encoding="utf-8")
        assert pol.deny_reason(str(config)) == "sensitive_content", name


def test_deny_reason_too_large(tmp_path: Path):
    pol = IgnorePolicy(max_file_bytes=100)
    large = tmp_path / "large.txt"
    large.write_bytes(b"x" * 200)
    reason = pol.deny_reason(str(large))
    assert reason == "too_large"


def test_deny_reason_unreadable(tmp_path: Path):
    pol = IgnorePolicy()
    nonexistent = tmp_path / "nonexistent"
    reason = pol.deny_reason(str(nonexistent))
    assert reason == "unreadable"


def test_deny_reason_not_regular_file(tmp_path: Path):
    pol = IgnorePolicy()
    directory = tmp_path / "dir"
    directory.mkdir()
    reason = pol.deny_reason(str(directory))
    assert reason == "not_regular_file"


def test_deny_reason_symlink_file(tmp_path: Path):
    pol = IgnorePolicy()
    real_file = tmp_path / "real"
    real_file.write_text("content", encoding="utf-8")
    link = tmp_path / "link"
    os.symlink(str(real_file), str(link))
    reason = pol.deny_reason(str(link))
    # A symlinked path (final component or parent) is refused with the
    # dedicated symlink_component reason so operators can tell symlink
    # redirection apart from genuine non-regular files (sockets, devices).
    assert reason == "symlink_component"


def test_deny_reason_logs(tmp_path: Path):
    pol = IgnorePolicy()
    log = tmp_path / "test.log"
    log.write_text("log content", encoding="utf-8")
    assert pol.deny_reason(str(log)) == "log_file"


def test_deny_reason_backup_file(tmp_path: Path):
    pol = IgnorePolicy()
    backup = tmp_path / "file~"
    backup.write_text("backup", encoding="utf-8")
    assert pol.deny_reason(str(backup)) == "backup_file"


def test_deny_reason_shadow_file():
    pol = IgnorePolicy()
    assert pol.deny_reason("/etc/shadow") == "denied_path"
    assert pol.deny_reason("/etc/gshadow") == "denied_path"


def test_deny_reason_ssl_private():
    pol = IgnorePolicy()
    assert pol.deny_reason("/etc/ssl/private/key.pem") == "denied_path"


def test_deny_reason_ssh_host_keys():
    pol = IgnorePolicy()
    assert pol.deny_reason("/etc/ssh/ssh_host_rsa_key") == "denied_path"
    assert pol.deny_reason("/etc/ssh/ssh_host_ed25519_key") == "denied_path"


def test_deny_reason_letsencrypt():
    pol = IgnorePolicy()
    assert (
        pol.deny_reason("/etc/letsencrypt/live/example.com/fullchain.pem")
        == "denied_path"
    )


def test_deny_reason_shadow_backup():
    pol = IgnorePolicy()
    assert pol.deny_reason("/etc/shadow-") == "backup_file"
    assert pol.deny_reason("/etc/passwd-") == "backup_file"


def test_detects_encrypted_private_key_marker(tmp_path):
    p = tmp_path / "key.pem"
    p.write_text(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc\n-----END ENCRYPTED PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    assert IgnorePolicy().deny_reason(str(p)) == "sensitive_content"


def test_detects_pgp_private_key_marker(tmp_path):
    p = tmp_path / "pgp.asc"
    p.write_text(
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----\n",
        encoding="utf-8",
    )
    assert IgnorePolicy().deny_reason(str(p)) == "sensitive_content"


def test_secret_scan_reads_whole_file_under_size_cap(tmp_path):
    p = tmp_path / "large.conf"
    p.write_bytes(b"A" * 70_000 + b"\nlate_token = abc123\n")
    assert IgnorePolicy().deny_reason(str(p)) == "sensitive_content"


def test_normalize_for_match_collapses_noncanonical_paths():
    from enroll.ignore import normalize_for_match

    assert normalize_for_match("/etc/shadow") == "/etc/shadow"
    assert normalize_for_match("/etc//shadow") == "/etc/shadow"
    assert normalize_for_match("/etc/foo/../shadow") == "/etc/shadow"
    assert normalize_for_match("/etc/./shadow") == "/etc/shadow"
    assert normalize_for_match("/etc/shadow/") == "/etc/shadow"
    # A leading "//" is POSIX-significant to normpath but must collapse for
    # glob matching anchored at "/".
    assert normalize_for_match("//etc/shadow") == "/etc/shadow"
    # "///" collapses to "/" via normpath already; ensure we don't mangle it.
    assert normalize_for_match("///etc/shadow") == "/etc/shadow"
    # Empty stays empty (no crash).
    assert normalize_for_match("") == ""


def test_deny_reason_denies_noncanonical_sensitive_paths():
    # Regression: non-canonical spellings of a denied path must still be denied
    # rather than slipping past the deny glob. Defense-in-depth on top of the
    # O_NOFOLLOW open in inspect_file(); see normalize_for_match().
    pol = IgnorePolicy()
    assert pol._path_deny_reason("/etc//shadow") == "denied_path"
    assert pol._path_deny_reason("/etc/foo/../shadow") == "denied_path"
    assert pol._path_deny_reason("/etc/./shadow") == "denied_path"
    assert pol._path_deny_reason("/etc/ssl/private/../private/key") == "denied_path"
    assert pol._path_deny_reason("//etc/shadow") == "denied_path"
    # A normal config path is unaffected.
    assert pol._path_deny_reason("/etc/nginx/nginx.conf") is None


def test_deny_reason_dir_denies_noncanonical_sensitive_paths():
    pol = IgnorePolicy()
    # normpath("/etc/ssl/private/../private") -> "/etc/ssl/private" which is the
    # glob root itself, so use paths that still resolve to a child of it.
    assert pol.deny_reason_dir("/etc/ssl/private/sub/../child") == "denied_path"
    assert pol.deny_reason_dir("/etc//ssl/private/sub") == "denied_path"


def test_deny_reason_link_denies_noncanonical_sensitive_paths():
    pol = IgnorePolicy()
    assert pol.deny_reason_link("/etc/ssh/../ssh/ssh_host_rsa_key") == "denied_path"
    assert pol.deny_reason_link("/etc//ssh/ssh_host_ed25519_key") == "denied_path"


def test_noncanonical_backup_and_log_fastpaths():
    pol = IgnorePolicy()
    assert pol._path_deny_reason("/var/log/foo/../bar.log") == "log_file"
    assert pol._path_deny_reason("/etc/foo/../something~") == "backup_file"
    assert pol._path_deny_reason("/etc//passwd-") == "backup_file"


def test_inspect_file_refuses_symlinked_parent_directory(tmp_path: Path):
    """A regular file reached through a symlinked *parent* directory must be
    refused, even though O_NOFOLLOW alone would only guard the final
    component. Otherwise a file whose real location is deny-globbed (or whose
    content is benign) could be captured while its logical path looks safe.
    """

    pol = IgnorePolicy()
    secret = tmp_path / "secretroot"
    secret.mkdir()
    (secret / "config").write_text("listen_port=8080\n", encoding="utf-8")
    (tmp_path / "allowed").symlink_to(secret)

    reason, inspection = pol.inspect_file(str(tmp_path / "allowed" / "config"))
    assert reason == "symlink_component"
    assert inspection is None


def test_inspect_file_refuses_denyglob_evasion_via_symlinked_parent(tmp_path: Path):
    """The strongest variant: the real file lives under a deny-globbed dir,
    but is reached via a symlinked parent so the *logical* path does not match
    the deny glob. Content is non-secret-looking (DH params), so only the
    parent-symlink check stands between the operator and disclosure.
    """

    pol = IgnorePolicy()
    realdir = tmp_path / "ssl_private"
    realdir.mkdir()
    (realdir / "dhparam.pem").write_text(
        "-----BEGIN DH PARAMETERS-----\nMII...\n-----END DH PARAMETERS-----\n",
        encoding="utf-8",
    )
    (tmp_path / "innocent").symlink_to(realdir)

    reason, inspection = pol.inspect_file(str(tmp_path / "innocent" / "dhparam.pem"))
    assert reason == "symlink_component"
    assert inspection is None


def test_inspect_file_still_captures_normal_nested_file(tmp_path: Path):
    """Regression guard: ordinary files in real (non-symlinked) directories
    must still be inspected and returned.
    """

    pol = IgnorePolicy()
    nested = tmp_path / "etc" / "myapp"
    nested.mkdir(parents=True)
    (nested / "app.conf").write_text("workers=4\n", encoding="utf-8")

    reason, inspection = pol.inspect_file(str(nested / "app.conf"))
    assert reason is None
    assert inspection is not None
    assert inspection.data == b"workers=4\n"


def test_inspect_file_refuses_hardlinked_source(tmp_path: Path):
    pol = IgnorePolicy()
    original = tmp_path / "original.conf"
    original.write_text("safe=true\n", encoding="utf-8")
    alias = tmp_path / "alias.conf"
    os.link(original, alias)

    reason, inspection = pol.inspect_file(str(alias))

    assert reason == "hardlink_source"
    assert inspection is None


def test_inspect_file_refuses_hardlinked_source_even_in_dangerous_mode(tmp_path: Path):
    pol = IgnorePolicy(dangerous=True)
    original = tmp_path / "original.conf"
    original.write_text("safe=true\n", encoding="utf-8")
    alias = tmp_path / "alias.conf"
    os.link(original, alias)

    reason, inspection = pol.inspect_file(str(alias))

    assert reason == "hardlink_source"
    assert inspection is None
