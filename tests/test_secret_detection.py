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
