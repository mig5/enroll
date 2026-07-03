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


def test_commented_authorization_headers_denied():
    """A commented-out populated Authorization header is a real (disabled)
    credential and must still be refused in safe mode, regardless of the
    single-line comment marker used. This is high-confidence material, so it is
    scanned against the raw bytes; the pattern must not anchor to the physical
    start of line, or a leading comment marker defeats it (the soft/comment-aware
    tier never sees it because that tier strips comment lines)."""

    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"# Authorization: Bearer eyJhbGciOiJIUzI1NiIs\n",
        b"#Authorization: Bearer eyJhbGciOiJIUzI1NiIs\n",
        b"; Authorization: Basic dXNlcjpwYXNzd29yZA==\n",
        b"// Authorization: Digest abc123\n",
        b"   //Authorization: Bearer abc123\n",
        b"* Authorization: Bearer abc123\n",  # block-comment continuation line
        b"\t# Authorization: Token abc123\n",
        b"dnl Authorization: Bearer abc123\n",  # m4-style comment
        b"-- Proxy-Authorization: Basic abc123\n",  # sql/lua-style comment
        b"REM Authorization: Bearer abc123\n",  # bat-style comment
        b"# Proxy-Authorization: Bearer xyz\n",
    ]:
        assert (
            pol._content_deny_reason("/etc/svc/app.conf", data) == "sensitive_content"
        ), data


def test_authorization_header_word_not_false_positive():
    """The Authorization-header pattern must not fire on benign prose mentions,
    a non-scheme value, or an identifier that merely ends in 'authorization'."""

    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"# how to set the authorization header is documented elsewhere\n",
        b"authorization: required\n",
        b"my_authorization: bearer x\n",
    ]:
        assert pol._content_deny_reason("/etc/svc/app.conf", data) is None, data


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
        b"pin 1234\n",
    ]:
        assert (
            pol._content_deny_reason("/etc/svc.conf", data) == "sensitive_content"
        ), data


def test_ppp_secrets_paths_denied():
    pol = IgnorePolicy(dangerous=False)
    for p in ("/etc/ppp/chap-secrets", "/etc/ppp/pap-secrets", "/etc/ppp/my-secrets"):
        assert pol._path_deny_reason(p) == "denied_path", p


def test_short_credential_key_components_denied():
    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"pass = hunter2\n",
        b"db_pass = hunter2\n",
        b"pass_key = hunter2\n",
        b"db-pass: hunter2\n",
        b"pin = 1234\n",
        b"db_pin = 1234\n",
        b"pin-key: 1234\n",
    ]:
        assert (
            pol._content_deny_reason("/etc/app.conf", data) == "sensitive_content"
        ), data


def test_password_keyword_no_false_positives():
    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"passive_mode = true\n",
        b"PassengerRoot /usr/lib\n",
        b"pinboard = enabled\n",
        b"pinot_region = noir\n",
        b"description = reset the account\n",
        b"compression = gzip\n",
    ]:
        assert pol._content_deny_reason("/etc/app.conf", data) is None, data


def test_pw_abbreviation_credential_key_denied():
    """The ``pw`` abbreviation is an extremely common password key form
    (``db_pw``, ``DB_PW``, ``root_pw``). It must be treated like ``pwd``/``pass``
    so a real assignment-style credential using ``pw`` is not silently harvested
    in default safe mode."""
    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"pw = hunter2\n",
        b"db_pw = SuperSecret123\n",
        b"DB_PW=hunter2\n",
        b"root_pw: aaaa\n",
        b"master_pw = topsecret\n",
        b"ftp_pw=x\n",
        b"mysql_root_pw: x\n",
        b"pw_hash = abc\n",
        b'"pw": "x"\n',
    ]:
        assert (
            pol._content_deny_reason("/etc/app.conf", data) == "sensitive_content"
        ), data


def test_pw_abbreviation_no_false_positives():
    """Adding the short ``pw`` token must not flag ordinary keys that merely
    contain the letters ``pw`` without it being a delimited credential token.
    The surrounding token-boundary structure (a keyword must stand alone between
    ``[_.-]`` delimiters) is what keeps these benign."""
    pol = IgnorePolicy(dangerous=False)
    for data in [
        b"pwned = 1\n",
        b"software = x\n",
        b"hardware = y\n",
        b"firmware: z\n",
        b"spwd = z\n",
        b"powerline = on\n",
        b"wallpaper = img\n",
        b"pwm_freq = 1000\n",
        b"cpwd_check=1\n",
        b"newpwx = 1\n",
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


def test_whitespace_separated_compound_credentials_denied():
    """Security regression (audit finding): a populated credential assignment
    that uses whitespace (space/tab) instead of ':'/'=' as the separator must
    still be refused in safe mode when the key is a *compound* credential name.

    The soft keyword tier cannot catch these because its ``\\b`` boundary is
    defeated by the leading underscore in a compound key (e.g. the ``secret`` in
    ``client_secret`` is preceded by ``_``, a word character), and the
    assignment tier only recognised ``:``/``=`` separators. Some real config
    styles (.netrc-like files, some daemon configs) use whitespace separators,
    so a value such as ``aws_secret_access_key wJalr...`` would previously leak.
    """
    safe = IgnorePolicy(dangerous=False)
    dangerous = IgnorePolicy(dangerous=True)
    leaking = [
        b"aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        b"aws_access_key_id AKIAIOSFODNN7EXAMPLE\n",
        b"client_secret hunter2deadbeef\n",
        b"oauth_token ya29.A0ARrdaReALlOOkINgToKeN\n",
        b"refresh_token 1//0longrefreshvalue\n",
        b"my_token deadbeef1234\n",
        b"app_password s3cr3tValue\n",
        b"db_pw s3cr3tvalue\n",
        b"private_key /etc/ssl/private/app.pem\n",
        b"session_key 0xDEADBEEFCAFE\n",
        b"\tapi_key   AKIA12345678\n",
    ]
    for data in leaking:
        assert (
            safe._content_deny_reason("/root/.netrc", data) == "sensitive_content"
        ), data
        # --dangerous remains the explicit opt-in to collect such material.
        assert dangerous._content_deny_reason("/root/.netrc", data) is None, data


def test_whitespace_separated_non_credentials_still_allowed():
    """The whitespace-separated credential rule must not false-positive on
    ordinary config or PAM directives. It is intentionally restricted to
    *compound* credential keys with a value-like token, so standalone words and
    common config lines are not affected by it.

    (Standalone ``password``/``token``/``secret`` words on a non-comment line
    are still caught by the comment-aware soft tier; that is unchanged. The
    cases here are ones that must remain collectable: PAM stack directives, SSH
    key-file path directives, and plain settings.)
    """
    pol = IgnorePolicy(dangerous=False)
    allowed = [
        # SSH key-file path directives (key material is denied by path globs,
        # not by content here).
        b"HostKey /etc/ssh/ssh_host_ed25519_key\n",
        b"host_key /etc/ssh/known\n",
        b"public_key /home/u/.ssh/id_rsa.pub\n",
        # Plain numeric / boolean settings.
        b"max_connections 1024\n",
        b"PermitRootLogin no\n",
        b"PasswordAuthentication yes\n",
    ]
    for data in allowed:
        assert pol._content_deny_reason("/etc/app/app.conf", data) is None, data


def test_binary_keyring_allowlist_still_scans_for_private_key_material():
    """A binary file on the keyring allow-list must still be refused in safe
    mode if it embeds private-key material.

    ``DEFAULT_ALLOW_BINARY_GLOBS`` exists so genuinely-binary *public* keyrings
    (APT/RPM GPG keyrings) survive the ``binary_like`` denial. It must not
    become a hole through which a keybox/keyring carrying *private* key material
    is captured unscanned. The high-confidence secret-material scan therefore
    runs on the raw bytes before the binary allow-list decision.
    """
    pol = IgnorePolicy(dangerous=False)

    private_binary = (
        b"\x99\x01\x0d\x04"
        + b"\x00" * 20
        + b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret\n"
        + b"-----END PGP PRIVATE KEY BLOCK-----"
        + b"\x00" * 8
    )
    for path in (
        "/etc/apt/trusted.gpg",
        "/etc/apt/trusted.gpg.d/mykey.gpg",
        "/etc/apt/keyrings/mykey.gpg",
        "/etc/pki/rpm-gpg/RPM-GPG-KEY-mine",
        "/usr/share/keyrings/mykey.gpg",
    ):
        assert (
            pol._content_deny_reason(path, private_binary) == "sensitive_content"
        ), path

    # A genuinely non-secret binary keyring at those same paths is still allowed
    # (the allow-list still exempts it from the binary_like denial).
    public_binary = b"\x99\x01\x0d\x04" + b"\x00" * 40 + b"public key packet data"
    for path in (
        "/etc/apt/keyrings/pub.gpg",
        "/usr/share/keyrings/pub.gpg",
        "/etc/pki/rpm-gpg/RPM-GPG-KEY-pub",
    ):
        assert pol._content_deny_reason(path, public_binary) is None, path

    # --dangerous still collects everything.
    dangerous = IgnorePolicy(dangerous=True)
    assert (
        dangerous._content_deny_reason("/etc/apt/keyrings/mykey.gpg", private_binary)
        is None
    )


def test_authorization_assignment_form_is_denied():
    """A populated Authorization/Proxy-Authorization credential is refused
    whether written HTTP-style with ':' or config-style with '='.

    The header scanner previously only anchored on ':', so a config assignment
    such as ``Authorization = Bearer <token>`` (and ``proxy_authorization``/
    ``http_authorization`` spellings) slipped through safe mode.
    """
    pol = IgnorePolicy(dangerous=False)
    leaking = [
        b"Authorization = Bearer supersecretvalue\n",
        b"Authorization: Bearer supersecretvalue\n",
        b"authorization=Bearer abcdef123456\n",
        b"proxy_authorization = Basic abcdef123456\n",
        b"Proxy-Authorization: Bearer abcdef123456\n",
        b"http_authorization = Bearer abcdef123456\n",
    ]
    for data in leaking:
        assert (
            pol._content_deny_reason("/etc/example.conf", data) == "sensitive_content"
        ), data


def test_underscore_and_camelcase_token_keys_are_denied():
    """Token keys the general assignment pattern misses -- a leading-underscore
    npm token, a camelCase ``authToken``, or a ``bearerToken`` spelling -- are
    refused when they carry a populated value."""
    pol = IgnorePolicy(dangerous=False)
    leaking = [
        b"_authToken=npm_abcdefghijklmnopqrstuvwxyz\n",
        b"//registry.npmjs.org/:_authToken=npm_abcdefghijklmnop\n",
        b"authToken=abcdefghijklmnopqrstuvwxyz\n",
        b"bearerToken=abcdefghijklmnopqrstuvwxyz\n",
        b"bearer_token = abcdef123456\n",
        b"auth_token: ya29.aRealLookingToken\n",
    ]
    for data in leaking:
        assert (
            pol._content_deny_reason("/etc/app/app.conf", data) == "sensitive_content"
        ), data


def test_authorization_and_token_keys_no_false_positives():
    """The broadened Authorization/token-key rules must not fire on ordinary
    config: a scheme keyword + value is required for the header form, and a
    populated value is required for the token-key form, so boolean/numeric
    settings and value-less mentions stay collectable."""
    pol = IgnorePolicy(dangerous=False)
    allowed = [
        # Authorization-ish keys with no bearer/basic/... scheme + value.
        b"AuthorizationEnabled = true\n",
        b"authorization = true\n",
        b"my_authorization: somevalue\n",
        # Token-ish keys that are not populated credentials.
        b"authTokenEnabled = true\n",
        b"authTokenTimeout = 30\n",
        b"AuthorizedKeysFile .ssh/authorized_keys\n",
    ]
    for data in allowed:
        assert pol._content_deny_reason("/etc/app/app.conf", data) is None, data

    # --dangerous still collects everything.
    dangerous = IgnorePolicy(dangerous=True)
    assert (
        dangerous._content_deny_reason(
            "/etc/example.conf", b"Authorization = Bearer secret\n"
        )
        is None
    )
