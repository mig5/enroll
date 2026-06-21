from __future__ import annotations

import types

import pytest


def test_post_webhook_success(monkeypatch):
    from enroll.diff import post_webhook

    class FakeResp:
        status = 204

        def read(self):
            return b"OK"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(
        "enroll.diff.urllib.request.urlopen",
        lambda req, timeout=30: FakeResp(),
    )

    status, body = post_webhook("https://example.com", b"x")
    assert status == 204
    assert body == "OK"


def test_post_webhook_raises_on_error(monkeypatch):
    from enroll.diff import post_webhook

    def boom(_req, timeout=30):
        raise OSError("nope")

    monkeypatch.setattr("enroll.diff.urllib.request.urlopen", boom)

    with pytest.raises(RuntimeError):
        post_webhook("https://example.com", b"x")


def test_send_email_uses_sendmail_when_present(monkeypatch):
    from enroll.diff import send_email

    calls = {}

    monkeypatch.setattr("enroll.diff.shutil.which", lambda name: "/usr/sbin/sendmail")

    def fake_run(argv, input=None, check=False, **_kwargs):
        calls["argv"] = argv
        calls["input"] = input
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr("enroll.diff.subprocess.run", fake_run)

    send_email(
        subject="Subj",
        body="Body",
        from_addr="a@example.com",
        to_addrs=["b@example.com"],
    )

    assert calls["argv"][0].endswith("sendmail")
    msg = (calls["input"] or b"").decode("utf-8", errors="replace")
    assert "Subject: Subj" in msg
    assert "To: b@example.com" in msg


def test_send_email_raises_when_no_delivery_method(monkeypatch):
    from enroll.diff import send_email

    monkeypatch.setattr("enroll.diff.shutil.which", lambda name: None)

    with pytest.raises(RuntimeError):
        send_email(
            subject="Subj",
            body="Body",
            from_addr="a@example.com",
            to_addrs=["b@example.com"],
        )


def test_send_email_refuses_smtp_auth_without_starttls(monkeypatch):
    from enroll.diff import send_email

    class FakeSMTP:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def ehlo(self):
            pass

        def starttls(self):
            raise RuntimeError("no starttls")

        def login(self, *_args):
            raise AssertionError("login should not be called without TLS")

        def send_message(self, *_args):
            raise AssertionError("message should not be sent without TLS")

    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)

    with pytest.raises(RuntimeError, match="STARTTLS failed"):
        send_email(
            subject="Subj",
            body="Body",
            from_addr="a@example.com",
            to_addrs=["b@example.com"],
            smtp="smtp.example.com:587",
            smtp_user="user",
            smtp_password="secret",
        )
