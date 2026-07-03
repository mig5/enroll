from __future__ import annotations

import io
import tarfile
import warnings
from pathlib import Path

import pytest


# The remote harvest now SHA-256-verifies the uploaded zipapp on the remote
# before executing it. Tests mock _build_enroll_pyz to write these fixed bytes
# and return (path, _FAKE_PYZ_SHA256); the fake SSH routers below answer the
# verification command with the same digest so the happy paths proceed.
_FAKE_PYZ_BYTES = b"PYZ"
_FAKE_PYZ_SHA256 = "d6f4e1dbf7ba69af6c798c6f6f67383c978e68f4201bf31902275ef37e6263e1"


def _fake_build_enroll_pyz(td) -> tuple[Path, str]:
    """Stand-in for remote._build_enroll_pyz used across remote tests.

    Writes a tiny fixed payload instead of a real zipapp and returns the
    (path, sha256) tuple the production builder now returns.
    """
    p = Path(td) / "enroll.pyz"
    p.write_bytes(_FAKE_PYZ_BYTES)
    return p, _FAKE_PYZ_SHA256


def _is_pyz_verify_cmd(cmd: str) -> bool:
    """True if *cmd* is the remote pyz SHA-256 integrity check."""
    return "hashlib.sha256" in cmd and "enroll.pyz" in cmd


def _make_tgz_bytes(files: dict[str, bytes]) -> bytes:
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for name, content in files.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(content)
            tf.addfile(ti, io.BytesIO(content))
    return bio.getvalue()


def test_safe_extract_tar_rejects_path_traversal(tmp_path: Path):
    from enroll.remote import _safe_extract_tar

    # Build an unsafe tar with ../ traversal
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="../evil")
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        with pytest.raises(RuntimeError, match="Unsafe tar member path"):
            _safe_extract_tar(tf, tmp_path)


def test_safe_extract_tar_rejects_symlinks(tmp_path: Path):
    from enroll.remote import _safe_extract_tar

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="link")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        tf.addfile(ti)

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        with pytest.raises(RuntimeError, match="Refusing to extract"):
            _safe_extract_tar(tf, tmp_path)


def test_remote_harvest_happy_path(tmp_path: Path, monkeypatch):
    import sys

    import enroll.remote as r

    # Avoid building a real zipapp; just create a file.
    monkeypatch.setattr(r, "_build_enroll_pyz", _fake_build_enroll_pyz)

    # Prepare a tiny harvest bundle tar stream from the "remote".
    tgz = _make_tgz_bytes({"state.json": b'{"ok": true}\n'})

    # Track each SSH exec_command call with whether a PTY was requested.
    calls: list[tuple[str, bool]] = []

    class _Chan:
        def __init__(self, out: bytes = b"", err: bytes = b"", rc: int = 0):
            self._out = out
            self._err = err
            self._out_i = 0
            self._err_i = 0
            self._rc = rc
            self._closed = False

        def recv_ready(self) -> bool:
            return (not self._closed) and self._out_i < len(self._out)

        def recv(self, n: int) -> bytes:
            if self._closed:
                return b""
            chunk = self._out[self._out_i : self._out_i + n]
            self._out_i += len(chunk)
            return chunk

        def recv_stderr_ready(self) -> bool:
            return (not self._closed) and self._err_i < len(self._err)

        def recv_stderr(self, n: int) -> bytes:
            if self._closed:
                return b""
            chunk = self._err[self._err_i : self._err_i + n]
            self._err_i += len(chunk)
            return chunk

        def exit_status_ready(self) -> bool:
            return self._closed or (
                self._out_i >= len(self._out) and self._err_i >= len(self._err)
            )

        def recv_exit_status(self) -> int:
            return self._rc

        def shutdown_write(self) -> None:
            return

        def close(self) -> None:
            self._closed = True

    class _Stdout:
        def __init__(self, payload: bytes = b"", rc: int = 0, err: bytes = b""):
            self._bio = io.BytesIO(payload)
            # _ssh_run reads stdout/stderr via the underlying channel.
            self.channel = _Chan(out=payload, err=err, rc=rc)

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

    class _Stderr:
        def __init__(self, payload: bytes = b""):
            self._bio = io.BytesIO(payload)

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

    class _SFTP:
        def __init__(self):
            self.put_calls: list[tuple[str, str]] = []

        def put(self, local: str, remote: str) -> None:
            self.put_calls.append((local, remote))

        def close(self) -> None:
            return

    class FakeSSH:
        def __init__(self):
            self._sftp = _SFTP()

        def load_system_host_keys(self):
            return

        def set_missing_host_key_policy(self, _policy):
            return

        def connect(self, **kwargs):
            # Accept any connect parameters.
            return

        def open_sftp(self):
            return self._sftp

        def exec_command(self, cmd: str, *, get_pty: bool = False, **_kwargs):
            # Integrity check of the uploaded pyz (added with SHA-256 verify).
            if _is_pyz_verify_cmd(cmd):
                return (None, _Stdout(_FAKE_PYZ_SHA256.encode()), _Stderr())
            calls.append((cmd, bool(get_pty)))
            # The tar stream uses exec_command directly.
            if cmd.startswith("tar -cz -C"):
                return (None, _Stdout(tgz, rc=0), _Stderr(b""))

            # _ssh_run path: id -un, mktemp -d, chmod, sudo harvest, sudo chown, rm -rf
            if cmd == "id -un":
                return (None, _Stdout(b"alice\n"), _Stderr())
            if cmd == "mktemp -d":
                return (None, _Stdout(b"/tmp/enroll-remote-123\n"), _Stderr())
            if cmd.startswith("sudo -n") and " mktemp -d" in cmd:
                return (None, _Stdout(b"/tmp/enroll-root-123\n"), _Stderr())
            if (
                cmd.startswith("sudo -n")
                and " chmod 700 -- /tmp/enroll-root-123" in cmd
            ):
                return (None, _Stdout(b""), _Stderr())
            if cmd.startswith("chmod 700"):
                return (None, _Stdout(b""), _Stderr())
            if cmd.startswith("sudo -n") and " harvest " in cmd:
                if not get_pty:
                    msg = b"sudo: sorry, you must have a tty to run sudo\n"
                    return (None, _Stdout(b"", rc=1, err=msg), _Stderr(msg))
                return (None, _Stdout(b"", rc=0), _Stderr(b""))
            if cmd.startswith("sudo -S") and " harvest " in cmd:
                return (None, _Stdout(b""), _Stderr())
            if " harvest " in cmd:
                return (None, _Stdout(b""), _Stderr())
            if cmd.startswith("sudo -n") and " chown -R" in cmd:
                if not get_pty:
                    msg = b"sudo: sorry, you must have a tty to run sudo\n"
                    return (None, _Stdout(b"", rc=1, err=msg), _Stderr(msg))
                return (None, _Stdout(b"", rc=0), _Stderr(b""))
            if cmd.startswith("sudo -n") and " rm -rf -- /tmp/enroll-root-123" in cmd:
                return (None, _Stdout(b""), _Stderr())
            if cmd.startswith("rm -rf"):
                return (None, _Stdout(b""), _Stderr())

            return (None, _Stdout(b""), _Stderr(b"unknown"))

        def close(self):
            return

    import types

    class RejectPolicy:
        pass

    FakeParamiko = types.SimpleNamespace(SSHClient=FakeSSH, RejectPolicy=RejectPolicy)

    # Provide a fake paramiko module.
    monkeypatch.setitem(sys.modules, "paramiko", FakeParamiko)

    out_dir = tmp_path / "out"
    state_path = r.remote_harvest(
        ask_become_pass=False,
        local_out_dir=out_dir,
        remote_host="example.com",
        remote_port=2222,
        remote_user=None,
        include_paths=["/etc/nginx/nginx.conf"],
        exclude_paths=["/etc/shadow"],
        dangerous=True,
        no_sudo=False,
    )

    assert state_path == out_dir / "state.json"
    assert state_path.exists()
    assert b"ok" in state_path.read_bytes()

    # Ensure we attempted remote harvest with sudo and passed include/exclude and dangerous.
    joined = "\n".join([c for c, _pty in calls])
    assert "sudo" in joined
    assert "--dangerous" in joined
    assert "--include-path" in joined
    assert "--exclude-path" in joined
    assert "sudo -n -p '' -- mktemp -d" in joined
    assert "--out /tmp/enroll-root-123/bundle" in joined
    assert "--out /tmp/enroll-remote-123/bundle" not in joined
    assert "chown -R -- alice /tmp/enroll-root-123" in joined
    assert "tar -cz -C /tmp/enroll-root-123/bundle ." in joined

    # Ensure we fall back to PTY only when sudo reports it is required.
    assert any(c == "id -un" and pty is False for c, pty in calls)

    sudo_harvest = [
        (c, pty) for c, pty in calls if c.startswith("sudo -n") and " harvest " in c
    ]
    assert any(pty is False for _c, pty in sudo_harvest)
    assert any(pty is True for _c, pty in sudo_harvest)

    sudo_chown = [
        (c, pty) for c, pty in calls if c.startswith("sudo -n") and " chown -R" in c
    ]
    assert any(pty is False for _c, pty in sudo_chown)
    assert any(pty is True for _c, pty in sudo_chown)

    assert any(c.startswith("tar -cz -C") and pty is False for c, pty in calls)


def test_remote_harvest_no_sudo_does_not_request_pty_or_chown(
    tmp_path: Path, monkeypatch
):
    """When --no-sudo is used we should not request a PTY nor run sudo chown."""
    import sys

    import enroll.remote as r

    monkeypatch.setattr(r, "_build_enroll_pyz", _fake_build_enroll_pyz)

    tgz = _make_tgz_bytes({"state.json": b"{}"})
    calls: list[tuple[str, bool]] = []

    class _Chan:
        def __init__(self, out: bytes = b"", err: bytes = b"", rc: int = 0):
            self._out = out
            self._err = err
            self._out_i = 0
            self._err_i = 0
            self._rc = rc
            self._closed = False

        def recv_ready(self) -> bool:
            return (not self._closed) and self._out_i < len(self._out)

        def recv(self, n: int) -> bytes:
            if self._closed:
                return b""
            chunk = self._out[self._out_i : self._out_i + n]
            self._out_i += len(chunk)
            return chunk

        def recv_stderr_ready(self) -> bool:
            return (not self._closed) and self._err_i < len(self._err)

        def recv_stderr(self, n: int) -> bytes:
            if self._closed:
                return b""
            chunk = self._err[self._err_i : self._err_i + n]
            self._err_i += len(chunk)
            return chunk

        def exit_status_ready(self) -> bool:
            return self._closed or (
                self._out_i >= len(self._out) and self._err_i >= len(self._err)
            )

        def recv_exit_status(self) -> int:
            return self._rc

        def shutdown_write(self) -> None:
            return

        def close(self) -> None:
            self._closed = True

    class _Stdout:
        def __init__(self, payload: bytes = b"", rc: int = 0, err: bytes = b""):
            self._bio = io.BytesIO(payload)
            # _ssh_run reads stdout/stderr via the underlying channel.
            self.channel = _Chan(out=payload, err=err, rc=rc)

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

    class _Stderr:
        def __init__(self, payload: bytes = b""):
            self._bio = io.BytesIO(payload)

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

    class _SFTP:
        def put(self, _local: str, _remote: str) -> None:
            return

        def close(self) -> None:
            return

    class FakeSSH:
        def __init__(self):
            self._sftp = _SFTP()

        def load_system_host_keys(self):
            return

        def set_missing_host_key_policy(self, _policy):
            return

        def connect(self, **_kwargs):
            return

        def open_sftp(self):
            return self._sftp

        def exec_command(self, cmd: str, *, get_pty: bool = False, **_kwargs):
            # Integrity check of the uploaded pyz (added with SHA-256 verify).
            if _is_pyz_verify_cmd(cmd):
                return (None, _Stdout(_FAKE_PYZ_SHA256.encode()), _Stderr())
            calls.append((cmd, bool(get_pty)))
            if cmd == "mktemp -d":
                return (None, _Stdout(b"/tmp/enroll-remote-456\n"), _Stderr())
            if cmd.startswith("chmod 700"):
                return (None, _Stdout(b""), _Stderr())
            if cmd.startswith("tar -cz -C"):
                return (None, _Stdout(tgz, rc=0), _Stderr())
            if " harvest " in cmd:
                return (None, _Stdout(b""), _Stderr())
            if cmd.startswith("rm -rf"):
                return (None, _Stdout(b""), _Stderr())
            return (None, _Stdout(b""), _Stderr())

        def close(self):
            return

    import types

    class RejectPolicy:
        pass

    monkeypatch.setitem(
        sys.modules,
        "paramiko",
        types.SimpleNamespace(SSHClient=FakeSSH, RejectPolicy=RejectPolicy),
    )

    out_dir = tmp_path / "out"
    r.remote_harvest(
        ask_become_pass=False,
        local_out_dir=out_dir,
        remote_host="example.com",
        remote_user="alice",
        no_sudo=True,
    )

    joined = "\n".join([c for c, _pty in calls])
    assert "sudo" not in joined
    assert "sudo chown" not in joined
    assert any(" harvest " in c and pty is False for c, pty in calls)


def test_remote_harvest_sudo_password_retry_uses_sudo_s_and_writes_password(
    tmp_path: Path, monkeypatch
):
    """If sudo requires a password, we should fall back from -n to -S and feed stdin."""
    import sys
    import types

    import enroll.remote as r

    # Avoid building a real zipapp; just create a file.
    monkeypatch.setattr(r, "_build_enroll_pyz", _fake_build_enroll_pyz)

    tgz = _make_tgz_bytes({"state.json": b'{"ok": true}\n'})
    calls: list[tuple[str, bool]] = []
    stdin_by_cmd: dict[str, list[str]] = {}

    class _Chan:
        def __init__(self, out: bytes = b"", err: bytes = b"", rc: int = 0):
            self._out = out
            self._err = err
            self._out_i = 0
            self._err_i = 0
            self._rc = rc
            self._closed = False

        def recv_ready(self) -> bool:
            return (not self._closed) and self._out_i < len(self._out)

        def recv(self, n: int) -> bytes:
            if self._closed:
                return b""
            chunk = self._out[self._out_i : self._out_i + n]
            self._out_i += len(chunk)
            return chunk

        def recv_stderr_ready(self) -> bool:
            return (not self._closed) and self._err_i < len(self._err)

        def recv_stderr(self, n: int) -> bytes:
            if self._closed:
                return b""
            chunk = self._err[self._err_i : self._err_i + n]
            self._err_i += len(chunk)
            return chunk

        def exit_status_ready(self) -> bool:
            return self._closed or (
                self._out_i >= len(self._out) and self._err_i >= len(self._err)
            )

        def recv_exit_status(self) -> int:
            return self._rc

        def shutdown_write(self) -> None:
            return

        def close(self) -> None:
            self._closed = True

    class _Stdout:
        def __init__(self, payload: bytes = b"", rc: int = 0, err: bytes = b""):
            self._bio = io.BytesIO(payload)
            # _ssh_run reads stdout/stderr via the underlying channel.
            self.channel = _Chan(out=payload, err=err, rc=rc)

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

    class _Stderr:
        def __init__(self, payload: bytes = b""):
            self._bio = io.BytesIO(payload)

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

    class _Stdin:
        def __init__(self, cmd: str):
            self._cmd = cmd
            stdin_by_cmd.setdefault(cmd, [])

        def write(self, s: str) -> None:
            stdin_by_cmd[self._cmd].append(s)

        def flush(self) -> None:
            return

    class _SFTP:
        def put(self, _local: str, _remote: str) -> None:
            return

        def close(self) -> None:
            return

    class FakeSSH:
        def __init__(self):
            self._sftp = _SFTP()

        def load_system_host_keys(self):
            return

        def set_missing_host_key_policy(self, _policy):
            return

        def connect(self, **_kwargs):
            return

        def open_sftp(self):
            return self._sftp

        def exec_command(self, cmd: str, *, get_pty: bool = False, **_kwargs):
            # Integrity check of the uploaded pyz (added with SHA-256 verify).
            if _is_pyz_verify_cmd(cmd):
                return (None, _Stdout(_FAKE_PYZ_SHA256.encode()), _Stderr())
            calls.append((cmd, bool(get_pty)))

            # Tar stream
            if cmd.startswith("tar -cz -C"):
                return (_Stdin(cmd), _Stdout(tgz, rc=0), _Stderr(b""))

            if cmd == "mktemp -d":
                return (_Stdin(cmd), _Stdout(b"/tmp/enroll-remote-789\n"), _Stderr())
            if cmd.startswith("sudo -n") and " mktemp -d" in cmd:
                return (_Stdin(cmd), _Stdout(b"/tmp/enroll-root-789\n"), _Stderr())
            if (
                cmd.startswith("sudo -n")
                and " chmod 700 -- /tmp/enroll-root-789" in cmd
            ):
                return (_Stdin(cmd), _Stdout(b""), _Stderr())
            if cmd.startswith("chmod 700"):
                return (_Stdin(cmd), _Stdout(b""), _Stderr())

            # First attempt: sudo -n fails, prompting is not allowed.
            if cmd.startswith("sudo -n") and " harvest " in cmd:
                return (
                    _Stdin(cmd),
                    _Stdout(b"", rc=1, err=b"sudo: a password is required\n"),
                    _Stderr(b"sudo: a password is required\n"),
                )

            # Retry: sudo -S succeeds and should have been fed the password via stdin.
            if cmd.startswith("sudo -S") and " harvest " in cmd:
                return (_Stdin(cmd), _Stdout(b"", rc=0), _Stderr(b""))

            # chown succeeds passwordlessly (e.g., sudo timestamp is warm).
            if cmd.startswith("sudo -n") and " chown -R" in cmd:
                return (_Stdin(cmd), _Stdout(b"", rc=0), _Stderr(b""))

            if cmd.startswith("sudo -n") and " rm -rf -- /tmp/enroll-root-789" in cmd:
                return (_Stdin(cmd), _Stdout(b"", rc=0), _Stderr(b""))
            if cmd.startswith("rm -rf"):
                return (_Stdin(cmd), _Stdout(b"", rc=0), _Stderr(b""))

            # Fallback for unexpected commands.
            return (_Stdin(cmd), _Stdout(b"", rc=0), _Stderr(b""))

        def close(self):
            return

    class RejectPolicy:
        pass

    monkeypatch.setitem(
        sys.modules,
        "paramiko",
        types.SimpleNamespace(SSHClient=FakeSSH, RejectPolicy=RejectPolicy),
    )

    out_dir = tmp_path / "out"
    state_path = r.remote_harvest(
        ask_become_pass=True,
        getpass_fn=lambda _prompt="": "s3cr3t",
        local_out_dir=out_dir,
        remote_host="example.com",
        remote_user="alice",
        no_sudo=False,
    )

    assert state_path.exists()
    assert b"ok" in state_path.read_bytes()

    # Ensure we attempted with sudo -n first, then sudo -S.
    sudo_n = [c for c, _pty in calls if c.startswith("sudo -n") and " harvest " in c]
    sudo_s = [c for c, _pty in calls if c.startswith("sudo -S") and " harvest " in c]
    assert len(sudo_n) == 1
    assert len(sudo_s) == 1
    joined = "\n".join([c for c, _pty in calls])
    assert "sudo -n -p '' -- mktemp -d" in joined
    assert "--out /tmp/enroll-root-789/bundle" in joined
    assert "--out /tmp/enroll-remote-789/bundle" not in joined

    # Ensure the password was written to stdin for the -S invocation.
    assert stdin_by_cmd.get(sudo_s[0]) == ["s3cr3t\n"]


def test_sudo_password_required_detection():
    from enroll.remote import _sudo_password_required

    assert _sudo_password_required("", "a password is required") is True
    assert _sudo_password_required("", "password is required") is True
    assert (
        _sudo_password_required("", "a terminal is required to read the password")
        is True
    )
    assert (
        _sudo_password_required("", "no tty present and no askpass program specified")
        is True
    )
    assert _sudo_password_required("", "must have a tty to run sudo") is True
    assert _sudo_password_required("", "sudo: sorry, you must have a tty") is True
    assert _sudo_password_required("", "askpass") is True
    assert _sudo_password_required("success", "") is False


def test_sudo_not_permitted_detection():
    from enroll.remote import _sudo_not_permitted

    assert _sudo_not_permitted("", "user is not in the sudoers file") is True
    assert _sudo_not_permitted("", "not allowed to execute") is True
    assert _sudo_not_permitted("", "may not run sudo") is True
    assert _sudo_not_permitted("", "sorry, user") is True
    assert _sudo_not_permitted("success", "") is False


def test_sudo_tty_required_detection():
    from enroll.remote import _sudo_tty_required

    assert _sudo_tty_required("", "must have a tty") is True
    assert _sudo_tty_required("", "sorry, you must have a tty") is True
    assert _sudo_tty_required("", "sudo: sorry, you must have a tty") is True
    assert _sudo_tty_required("", "must have a tty to run sudo") is True
    assert _sudo_tty_required("success", "") is False


def test_resolve_become_password_prompts_when_asked(monkeypatch):
    from enroll.remote import _resolve_become_password

    prompted = []

    def fake_getpass(prompt):
        prompted.append(prompt)
        return "secret"

    result = _resolve_become_password(
        True, prompt="sudo password: ", getpass_fn=fake_getpass
    )
    assert result == "secret"
    assert len(prompted) == 1


def test_resolve_become_password_returns_none_when_not_asked():
    from enroll.remote import _resolve_become_password

    result = _resolve_become_password(False)
    assert result is None


def test_resolve_ssh_key_passphrase_from_env(monkeypatch):
    from enroll.remote import _resolve_ssh_key_passphrase

    monkeypatch.setenv("SSH_KEY_PASS", "env_secret")

    result = _resolve_ssh_key_passphrase(False, env_var="SSH_KEY_PASS")
    assert result == "env_secret"


def test_resolve_ssh_key_passphrase_raises_when_env_not_set(monkeypatch):
    from enroll.remote import _resolve_ssh_key_passphrase

    monkeypatch.delenv("SSH_KEY_PASS", raising=False)

    with pytest.raises(RuntimeError, match="SSH key passphrase environment variable"):
        _resolve_ssh_key_passphrase(False, env_var="SSH_KEY_PASS")


def test_resolve_ssh_key_passphrase_prompts_when_asked(monkeypatch):
    from enroll.remote import _resolve_ssh_key_passphrase

    prompted = []

    def fake_getpass(prompt):
        prompted.append(prompt)
        return "prompt_secret"

    result = _resolve_ssh_key_passphrase(
        True, prompt="SSH key passphrase: ", getpass_fn=fake_getpass
    )
    assert result == "prompt_secret"
    assert len(prompted) == 1


def test_resolve_ssh_key_passphrase_returns_none_when_not_asked():
    from enroll.remote import _resolve_ssh_key_passphrase

    result = _resolve_ssh_key_passphrase(False, env_var=None)
    assert result is None


def test_safe_extract_tar_rejects_absolute_paths(tmp_path: Path):
    from enroll.remote import _safe_extract_tar

    import io
    import tarfile

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="/etc/passwd")
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        with pytest.raises(RuntimeError, match="Unsafe tar member path"):
            _safe_extract_tar(tf, tmp_path)


def test_safe_extract_tar_rejects_hardlinks(tmp_path: Path):
    from enroll.remote import _safe_extract_tar

    import io
    import tarfile

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="hardlink")
        ti.type = tarfile.LNKTYPE
        ti.linkname = "/etc/passwd"
        tf.addfile(ti)

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        with pytest.raises(RuntimeError, match="Refusing to extract"):
            _safe_extract_tar(tf, tmp_path)


def test_safe_extract_tar_rejects_device_nodes(tmp_path: Path):
    from enroll.remote import _safe_extract_tar

    import io
    import tarfile

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="device")
        ti.type = tarfile.CHRTYPE
        tf.addfile(ti)

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        with pytest.raises(RuntimeError, match="Refusing to extract"):
            _safe_extract_tar(tf, tmp_path)


def test_safe_extract_tar_accepts_dot_entry(tmp_path: Path):
    from enroll.remote import _safe_extract_tar

    import io
    import tarfile

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name=".")
        ti.size = 0
        tf.addfile(ti, io.BytesIO(b""))

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        _safe_extract_tar(tf, tmp_path)


def test_safe_extract_tar_accepts_valid_files(tmp_path: Path):
    from enroll.remote import _safe_extract_tar

    import io
    import tarfile

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="foo/bar.txt")
        ti.size = 5
        tf.addfile(ti, io.BytesIO(b"hello"))

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            _safe_extract_tar(tf, tmp_path)

    assert not any(
        "Python 3.14" in str(w.message) and issubclass(w.category, DeprecationWarning)
        for w in caught
    )
    assert (tmp_path / "foo" / "bar.txt").read_bytes() == b"hello"


def test_remote_harvest_ssh_key_passphrase_retry(monkeypatch, tmp_path: Path):
    import sys

    import enroll.remote as r

    monkeypatch.setattr(r, "_build_enroll_pyz", _fake_build_enroll_pyz)

    tgz = _make_tgz_bytes({"state.json": b'{"ok": true}\n'})

    class _Chan:
        def __init__(self, out: bytes = b"", err: bytes = b"", rc: int = 0):
            self._out = out
            self._err = err
            self._out_i = 0
            self._err_i = 0
            self._rc = rc
            self._closed = False

        def recv_ready(self) -> bool:
            return (not self._closed) and self._out_i < len(self._out)

        def recv(self, n: int) -> bytes:
            if self._closed:
                return b""
            chunk = self._out[self._out_i : self._out_i + n]
            self._out_i += len(chunk)
            return chunk

        def recv_stderr_ready(self) -> bool:
            return (not self._closed) and self._err_i < len(self._err)

        def recv_stderr(self, n: int) -> bytes:
            if self._closed:
                return b""
            chunk = self._err[self._err_i : self._err_i + n]
            self._err_i += len(chunk)
            return chunk

        def exit_status_ready(self) -> bool:
            return self._closed or (
                self._out_i >= len(self._out) and self._err_i >= len(self._err)
            )

        def recv_exit_status(self) -> int:
            return self._rc

        def shutdown_write(self) -> None:
            return

        def close(self) -> None:
            self._closed = True

    class _Stdout:
        def __init__(self, payload: bytes = b"", rc: int = 0, err: bytes = b""):
            self._bio = io.BytesIO(payload)
            self.channel = _Chan(out=payload, err=err, rc=rc)

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

    class _Stderr:
        def __init__(self, payload: bytes = b""):
            self._bio = io.BytesIO(payload)

        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)

    class _Stdin:
        def __init__(self, cmd: str):
            self._cmd = cmd

        def write(self, s: str) -> None:
            pass

        def flush(self) -> None:
            return

    class _SFTP:
        def put(self, _local: str, _remote: str) -> None:
            return

        def close(self) -> None:
            return

    class FakeSSH:
        def __init__(self):
            self._sftp = _SFTP()

        def load_system_host_keys(self):
            return

        def set_missing_host_key_policy(self, _policy):
            return

        def connect(self, **_kwargs):
            return

        def open_sftp(self):
            return self._sftp

        def exec_command(self, cmd: str, *, get_pty: bool = False, **_kwargs):
            # Integrity check of the uploaded pyz (added with SHA-256 verify).
            if _is_pyz_verify_cmd(cmd):
                return (None, _Stdout(_FAKE_PYZ_SHA256.encode()), _Stderr())
            if cmd.startswith("tar -cz -C"):
                return (_Stdin(cmd), _Stdout(tgz, rc=0), _Stderr(b""))
            if cmd == "mktemp -d":
                return (_Stdin(cmd), _Stdout(b"/tmp/enroll-remote-789\n"), _Stderr())
            if cmd.startswith("chmod 700"):
                return (_Stdin(cmd), _Stdout(b""), _Stderr())
            if " harvest " in cmd:
                return (_Stdin(cmd), _Stdout(b""), _Stderr())
            if cmd.startswith("rm -rf"):
                return (_Stdin(cmd), _Stdout(b""), _Stderr())
            return (_Stdin(cmd), _Stdout(b""), _Stderr())

        def close(self):
            return

    RejectPolicy4 = type("RejectPolicy", (), {})

    class FakeParamiko:
        SSHClient = FakeSSH
        RejectPolicy = RejectPolicy4  # type: ignore
        PasswordRequiredException = Exception  # type: ignore

    monkeypatch.setitem(sys.modules, "paramiko", FakeParamiko)

    prompts = []

    def fake_getpass(prompt):
        prompts.append(prompt)
        return "passphrase"

    out_dir = tmp_path / "out"
    state_path = r.remote_harvest(
        ask_key_passphrase=True,
        getpass_fn=fake_getpass,
        local_out_dir=out_dir,
        remote_host="example.com",
        remote_user="alice",
        no_sudo=True,
    )

    assert state_path.exists()
    assert len(prompts) == 1


def test_remote_harvest_ssh_key_passphrase_raises_when_not_interactive(
    monkeypatch, tmp_path: Path
):
    import sys

    import enroll.remote as r

    monkeypatch.setattr(r, "_build_enroll_pyz", _fake_build_enroll_pyz)

    class _Chan:
        def __init__(self):
            self._closed = False

        def recv_ready(self) -> bool:
            return False

        def recv(self, n: int) -> bytes:
            return b""

        def recv_stderr_ready(self) -> bool:
            return False

        def recv_stderr(self, n: int) -> bytes:
            return b""

        def exit_status_ready(self) -> bool:
            return True

        def recv_exit_status(self) -> int:
            return 0

        def shutdown_write(self) -> None:
            return

        def close(self) -> None:
            self._closed = True

    class _Stdout:
        def __init__(self):
            self.channel = _Chan()

        def read(self, n: int = -1) -> bytes:
            return b""

    class _Stderr:
        def read(self, n: int = -1) -> bytes:
            return b""

    class _SFTP:
        def put(self, _local: str, _remote: str) -> None:
            return

        def close(self) -> None:
            return

    class FakeSSH:
        def __init__(self):
            self._sftp = _SFTP()

        def load_system_host_keys(self):
            return

        def set_missing_host_key_policy(self, _policy):
            return

        def connect(self, **_kwargs):
            raise Exception("PasswordRequired")

        def open_sftp(self):
            return self._sftp

        def exec_command(self, cmd: str, **_kwargs):
            # Integrity check of the uploaded pyz (added with SHA-256 verify).
            if _is_pyz_verify_cmd(cmd):
                return (None, _Stdout(_FAKE_PYZ_SHA256.encode()), _Stderr())
            return (_Stdout(), _Stdout(), _Stderr())

            def close(self):
                return

    class RejectPolicy:
        pass

    RejectPolicy3 = RejectPolicy

    class FakeParamiko:
        SSHClient = FakeSSH
        RejectPolicy = RejectPolicy3  # type: ignore
        PasswordRequiredException = Exception  # type: ignore

    monkeypatch.setitem(sys.modules, "paramiko", FakeParamiko)

    out_dir = tmp_path / "out"

    with pytest.raises(RuntimeError, match="SSH private key is encrypted"):
        r.remote_harvest(
            ask_key_passphrase=False,
            local_out_dir=out_dir,
            remote_host="example.com",
            stdin=io.StringIO(),
        )


# --------------------------------------------------------------------------- #
# Integrity of the uploaded zipapp before remote (root) execution.
# --------------------------------------------------------------------------- #


class _VerifyChan:
    """Minimal Paramiko-channel stand-in for _ssh_run consumption."""

    def __init__(self, out: bytes = b"", err: bytes = b"", rc: int = 0):
        self._out, self._err, self._rc = out, err, rc
        self._oi = self._ei = 0
        self._closed = False

    def recv_ready(self) -> bool:
        return (not self._closed) and self._oi < len(self._out)

    def recv(self, n: int) -> bytes:
        chunk = self._out[self._oi : self._oi + n]
        self._oi += len(chunk)
        return chunk

    def recv_stderr_ready(self) -> bool:
        return (not self._closed) and self._ei < len(self._err)

    def recv_stderr(self, n: int) -> bytes:
        chunk = self._err[self._ei : self._ei + n]
        self._ei += len(chunk)
        return chunk

    def exit_status_ready(self) -> bool:
        return self._closed or (
            self._oi >= len(self._out) and self._ei >= len(self._err)
        )

    def recv_exit_status(self) -> int:
        return self._rc

    def shutdown_write(self) -> None:
        return

    def close(self) -> None:
        self._closed = True


class _VerifyStdio:
    def __init__(self, chan: _VerifyChan):
        self.channel = chan


def _verify_ssh(out: bytes, *, rc: int = 0):
    chan = _VerifyChan(out=out, rc=rc)

    class FakeSSH:
        def exec_command(self, cmd, *, get_pty=False, **_kw):
            assert "hashlib.sha256" in cmd  # this is the verify command
            return (io.StringIO(), _VerifyStdio(chan), _VerifyStdio(chan))

    return FakeSSH()


def test_remote_verify_pyz_sha256_rejects_mismatch():
    import enroll.remote as r

    ssh = _verify_ssh(b"0" * 64)
    with pytest.raises(RuntimeError, match="Integrity check failed"):
        r._remote_verify_pyz_sha256(
            ssh, "/tmp/x/enroll.pyz", "a" * 64, remote_python="python3"
        )


def test_remote_verify_pyz_sha256_accepts_match():
    import enroll.remote as r

    expected = "a" * 64
    ssh = _verify_ssh(expected.encode())
    # Should not raise.
    r._remote_verify_pyz_sha256(
        ssh, "/tmp/x/enroll.pyz", expected, remote_python="python3"
    )


def test_remote_verify_pyz_sha256_rejects_empty():
    import enroll.remote as r

    ssh = _verify_ssh(b"")
    with pytest.raises(RuntimeError, match="empty SHA-256"):
        r._remote_verify_pyz_sha256(
            ssh, "/tmp/x/enroll.pyz", "a" * 64, remote_python="python3"
        )


def test_remote_verify_pyz_sha256_rejects_nonzero_rc():
    import enroll.remote as r

    ssh = _verify_ssh(b"", rc=2)
    with pytest.raises(RuntimeError, match="verify the integrity"):
        r._remote_verify_pyz_sha256(
            ssh, "/tmp/x/enroll.pyz", "a" * 64, remote_python="python3"
        )


def test_build_enroll_pyz_excludes_tests_and_caches_and_returns_sha(tmp_path: Path):
    import zipfile

    import enroll.remote as r

    pyz, sha = r._build_enroll_pyz(tmp_path)
    assert isinstance(sha, str) and len(sha) == 64
    assert sha == r._sha256_file(pyz)

    names = zipfile.ZipFile(pyz).namelist()
    assert any(n.endswith("schema/state.schema.json") for n in names)
    for n in names:
        leaf = n.rsplit("/", 1)[-1]
        assert "__pycache__" not in n
        assert not n.endswith((".pyc", ".pyo"))
        assert "/tests/" not in n
        assert not leaf.startswith("test_")
        assert leaf != "conftest.py"


def test_safe_extract_tar_rejects_too_many_members(tmp_path: Path, monkeypatch):
    import enroll.remote as r

    monkeypatch.setattr(r, "_TAR_MAX_MEMBERS", 3)

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for i in range(10):
            ti = tarfile.TarInfo(name=f"f{i}")
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        with pytest.raises(RuntimeError, match="too many members"):
            r._safe_extract_tar(tf, tmp_path)


def test_safe_extract_tar_rejects_oversized_member(tmp_path: Path, monkeypatch):
    import enroll.remote as r

    monkeypatch.setattr(r, "_TAR_MAX_FILE_BYTES", 100)

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="big")
        payload = b"x" * 500
        ti.size = len(payload)
        tf.addfile(ti, io.BytesIO(payload))

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        with pytest.raises(RuntimeError, match="too large"):
            r._safe_extract_tar(tf, tmp_path)


def test_safe_extract_tar_rejects_aggregate_size_bomb(tmp_path: Path, monkeypatch):
    import enroll.remote as r

    # Each member is under the per-file cap, but the sum exceeds the total cap.
    monkeypatch.setattr(r, "_TAR_MAX_TOTAL_BYTES", 1000)

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for i in range(10):
            ti = tarfile.TarInfo(name=f"f{i}")
            payload = b"x" * 300
            ti.size = len(payload)
            tf.addfile(ti, io.BytesIO(payload))

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        with pytest.raises(RuntimeError, match="uncompressed size exceeds"):
            r._safe_extract_tar(tf, tmp_path)


def test_safe_extract_tar_rejects_excessive_path_depth(tmp_path: Path, monkeypatch):
    import enroll.remote as r

    monkeypatch.setattr(r, "_TAR_MAX_PATH_DEPTH", 4)

    deep = "/".join(f"d{i}" for i in range(10)) + "/file"
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name=deep)
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        with pytest.raises(RuntimeError, match="too deeply nested"):
            r._safe_extract_tar(tf, tmp_path)


def test_safe_extract_tar_allows_normal_bundle(tmp_path: Path):
    """A normal, modestly-sized bundle still extracts cleanly under the caps."""
    import enroll.remote as r

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for name, data in (
            ("state.json", b"{}"),
            ("artifacts/etc_custom/etc/app.conf", b"k=1\n"),
        ):
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        r._safe_extract_tar(tf, tmp_path)

    assert (tmp_path / "state.json").is_file()
    assert (tmp_path / "artifacts" / "etc_custom" / "etc" / "app.conf").is_file()
