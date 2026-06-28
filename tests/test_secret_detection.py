"""Regression test: safe-mode content sniff must catch URI-embedded credentials
and HTTP Authorization headers, not just assignment-style credential keys."""

from enroll.ignore import IgnorePolicy


def test_uri_embedded_credentials_denied():
    pol = IgnorePolicy(dangerous=False)
    leaking = [
        b"DATABASE_URL=postgresql://admin:S3cr3tPass@db:5432/app\n",
        b"REDIS_URL=redis://:mypassword@localhost:6379/0\n",
        b"broker_url = amqp://guest:guest@rabbit:5672//\n",
        b"uri: mongodb+srv://user:p%40ss@cluster0.mongodb.net\n",
    ]
    for data in leaking:
        assert (
            pol._content_deny_reason("/etc/svc/app.conf", data) == "sensitive_content"
        ), data


def test_authorization_headers_denied():
    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"Authorization: Bearer eyJhbGciOiJIUzI1NiIs\n",
        b"Authorization: Basic dXNlcjpwYXNzd29yZA==\n",
        b"Proxy-Authorization: Bearer xyz\n",
    ]:
        assert (
            pol._content_deny_reason("/etc/svc/app.conf", data) == "sensitive_content"
        ), data


def test_benign_urls_not_false_positive():
    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"homepage = https://example.com/docs\n",
        b"server = http://localhost:8080/api\n",
        b"origin = git://github.com/u/repo.git\n",
        b"bind = http://[::1]:9000/\n",
        b"contact = mailto:admin@example.com\n",
        b"log_level = info\nworkers = 4\n",
    ]:
        assert pol._content_deny_reason("/etc/svc/app.conf", data) is None, data


def test_bare_word_password_denied():
    """Credential lines using the word password/passphrase/credentials without
    an assignment delimiter (netrc, ppp, space/tab separated) must be denied."""
    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"machine api.example.com login bob password s3cret\n",
        b"passphrase mysecretphrase\n",
        b"credentials /run/creds/db\n",
    ]:
        assert (
            pol._content_deny_reason("/etc/svc.conf", data) == "sensitive_content"
        ), data


def test_ppp_secrets_paths_denied():
    pol = IgnorePolicy(dangerous=False)
    for p in ("/etc/ppp/chap-secrets", "/etc/ppp/pap-secrets", "/etc/ppp/my-secrets"):
        assert pol._path_deny_reason(p) == "denied_path", p


def test_password_keyword_no_false_positives():
    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"passive_mode = true\n",
        b"PassengerRoot /usr/lib\n",
        b"description = reset the account\n",
        b"compression = gzip\n",
    ]:
        assert pol._content_deny_reason("/etc/app.conf", data) is None, data


def test_block_comment_open_cannot_mask_private_key():
    """Security regression: a line beginning with ``/*`` must not put the content
    scanner into a runaway block-comment state that hides later real secrets.

    Previously, any line starting with ``/*`` suppressed scanning of every
    subsequent line until a ``*/`` appeared. An unterminated (or hostile) block
    open therefore masked a PEM private key / password in an arbitrary config
    file (one not covered by a path deny-glob)."""
    pol = IgnorePolicy(dangerous=False)
    leaking = [
        # leading /* with no closing */ masking a PEM private key
        b"/* app config\n"
        b"tls_key = -----BEGIN PRIVATE KEY-----\n"
        b"MIIBVw...\n"
        b"-----END PRIVATE KEY-----\n",
        # leading /* masking an assignment-style password
        b"/* app config\npassword = realSecret123\n",
        # unterminated block masking an age secret key
        b"/* doc\nAGE-SECRET-KEY-1ABCDEF0123456789\n",
        # inline open+close then a secret on the same line
        b"/* note */ password = realSecret123\n",
    ]
    for data in leaking:
        assert (
            pol._content_deny_reason("/etc/app/app.conf", data) == "sensitive_content"
        ), data


def test_high_confidence_key_material_denied_regardless_of_comments():
    """Private-key material is denied even inside comment framing, because it is
    unambiguous secret material rather than a soft keyword heuristic."""
    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"# -----BEGIN OPENSSH PRIVATE KEY-----\n",
        b"; PGP PRIVATE KEY BLOCK\n",
        b"/* -----BEGIN RSA PRIVATE KEY----- */\n",
    ]:
        assert (
            pol._content_deny_reason("/etc/app/app.conf", data) == "sensitive_content"
        ), data


def test_commented_value_less_keyword_hints_still_ignored():
    """Genuinely value-less commented hints remain ignored, so Enroll stays
    useful for harvesting ordinary config files that ship commented examples.

    Only a bare credential *word* with no assigned value is tolerated in a
    comment; a populated commented assignment is treated as a real (disabled)
    secret -- see test_commented_out_credential_values_require_dangerous."""
    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"# token\n",
        b"; secret\n",
        b"// password\n",
        b"#PasswordAuthentication yes\n",  # space-separated directive, not an assignment
        b"/* see the password docs */\n",
        b"log_level = info\nworkers = 4\n",
    ]:
        assert pol._content_deny_reason("/etc/app/app.conf", data) is None, data


def test_commented_out_credential_values_require_dangerous():
    """Conservative-by-default: a commented-out credential *value* (a populated
    assignment, URI creds, or Authorization header) is very often a real secret
    that was merely disabled. Such a file is refused in safe mode and requires
    --dangerous, regardless of comment style or block-comment framing."""
    safe = IgnorePolicy(dangerous=False)
    dangerous = IgnorePolicy(dangerous=True)
    commented_real_secrets = [
        b"# password = realProductionPass\n",
        b"; auth_token = abc123secret\n",
        b"// client_secret: deadbeef\n",
        b"/* password = changeme123 */\n",
        b"/*\n  api_key = AKIA0123\n*/\nlisten = 8080\n",
        b"# DATABASE_URL=postgres://user:pass@host/db\n",
        b"# -----BEGIN OPENSSH PRIVATE KEY-----\n",
        b"/*\nAuthorization: Bearer eyJabc\n*/\n",
    ]
    for data in commented_real_secrets:
        # Refused in safe mode...
        assert (
            safe._content_deny_reason("/etc/app/app.conf", data) == "sensitive_content"
        ), data
        # ...but --dangerous still collects it (operator's explicit choice).
        assert dangerous._content_deny_reason("/etc/app/app.conf", data) is None, data
