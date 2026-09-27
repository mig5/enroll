from __future__ import annotations

import hashlib
import io
import shlex
import tarfile
import warnings
from pathlib import Path

import pytest

# Sudo harvests promote and verify the upload into a root-private directory;
# no-sudo harvests retain the direct remote digest check. Tests mock the local
# builder with these fixed bytes and digest so both paths can be exercised.
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


def _is_pyz_promote_cmd(cmd: str) -> bool:
    """True if *cmd* is the privileged copy-and-verify operation."""
    return ".enroll.pyz.tmp" in cmd and "os.link" in cmd


def _is_pyz_verify_cmd(cmd: str) -> bool:
    """True if *cmd* is the no-sudo remote pyz SHA-256 check."""
    return (
        "hashlib.sha256" in cmd and "enroll.pyz" in cmd and not _is_pyz_promote_cmd(cmd)
    )


def _is_remote_uid_cmd(cmd: str) -> bool:
    return "os.getuid" in cmd


def _is_archive_hash_cmd(cmd: str) -> bool:
    return "hashlib.sha256" in cmd and "bundle.tgz" in cmd


def _archive_sha256(payload: bytes) -> bytes:
    return hashlib.sha256(payload).hexdigest().encode()


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

        def get(self, _remote: str, local: str, callback=None) -> None:
            Path(local).write_bytes(tgz)
            if callback is not None:
                callback(len(tgz), len(tgz))

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
            if _is_pyz_promote_cmd(cmd):
                calls.append((cmd, bool(get_pty)))
                return (None, _Stdout(b""), _Stderr())
            if _is_pyz_verify_cmd(cmd):
                return (None, _Stdout(_FAKE_PYZ_SHA256.encode()), _Stderr())
            calls.append((cmd, bool(get_pty)))
            if _is_remote_uid_cmd(cmd):
                return (None, _Stdout(b"1000"), _Stderr())
            if _is_archive_hash_cmd(cmd):
                return (None, _Stdout(_archive_sha256(tgz)), _Stderr())
            # The tar stream uses exec_command directly.
            if cmd.startswith("tar -cz -C"):
                return (None, _Stdout(tgz, rc=0), _Stderr(b""))

            # _ssh_run path: mktemp -d, chmod, sudo harvest,
            # root tar creation/permissions, rm -rf
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
            if cmd.startswith("sudo -n") and " tar -czf " in cmd:
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
        harvest_firewall=True,
        harvest_sysctl=True,
        include_paths=["/etc/nginx/nginx.conf"],
        exclude_paths=["/etc/shadow"],
        dangerous=True,
        no_sudo=False,
    )

    assert state_path == out_dir / "state.json"
    assert state_path.exists()
    assert b"ok" in state_path.read_bytes()

    # Ensure remote harvest used sudo and passed include/exclude/dangerous.
    joined = "\n".join([c for c, _pty in calls])
    assert "sudo" in joined
    assert "--dangerous" in joined
    assert "--harvest-firewall" in joined
    assert "--harvest-sysctl" in joined
    assert "--include-path" in joined
    assert "--exclude-path" in joined
    assert "sudo -n -p '' -- mktemp -d" in joined
    assert "--out /tmp/enroll-root-123/bundle" in joined
    assert "--out /tmp/enroll-remote-123/bundle" not in joined
    assert "chown -R" not in joined
    assert (
        "tar -czf /tmp/enroll-root-123/bundle.tgz " "-C /tmp/enroll-root-123/bundle ."
    ) in joined
    assert "chmod 0400 -- /tmp/enroll-root-123/bundle.tgz" in joined
    assert "chown -- 1000 /tmp/enroll-root-123/bundle.tgz" in joined
    assert "chmod 0711 -- /tmp/enroll-root-123" in joined

    # The upload is promoted and verified before harvest, and sudo executes
    # only the root-owned copy. A later replacement of the SSH-user path can no
    # longer alter the bytes that Python opens as root.
    promote_i, promote_cmd = next(
        (i, c) for i, (c, _pty) in enumerate(calls) if _is_pyz_promote_cmd(c)
    )
    harvest_i, harvest_cmd = next(
        (i, c)
        for i, (c, _pty) in enumerate(calls)
        if c.startswith("sudo -n") and " harvest " in c
    )
    assert promote_i < harvest_i
    promote_argv = shlex.split(promote_cmd)
    assert "/tmp/enroll-remote-123" in promote_argv
    assert "/tmp/enroll-root-123" in promote_argv
    assert promote_argv.count("enroll.pyz") >= 2
    assert "/tmp/enroll-root-123/enroll.pyz" in harvest_cmd
    assert "/tmp/enroll-remote-123/enroll.pyz" not in harvest_cmd
    harvest_argv = shlex.split(harvest_cmd)
    pyz_i = harvest_argv.index("/tmp/enroll-root-123/enroll.pyz")
    assert harvest_argv[pyz_i - 2 : pyz_i] == ["-I", "-S"]
    assert not any(_is_pyz_verify_cmd(c) for c, _pty in calls)

    # The trusted digest must be obtained while the archive is still private,
    # before ownership/read access is handed to the SSH account.
    archive_hash_i = next(
        i for i, (c, _pty) in enumerate(calls) if _is_archive_hash_cmd(c)
    )
    chown_i = next(i for i, (c, _pty) in enumerate(calls) if "chown -- 1000" in c)
    expose_i = next(i for i, (c, _pty) in enumerate(calls) if "chmod 0711" in c)
    assert archive_hash_i < chown_i < expose_i

    # Ensure we fall back to PTY only when sudo reports it is required.
    sudo_harvest = [
        (c, pty) for c, pty in calls if c.startswith("sudo -n") and " harvest " in c
    ]
    assert any(pty is False for _c, pty in sudo_harvest)
    assert any(pty is True for _c, pty in sudo_harvest)

    sudo_tar = [
        (c, pty) for c, pty in calls if c.startswith("sudo -n") and " tar -czf " in c
    ]
    assert any(pty is False for _c, pty in sudo_tar)
    assert any(pty is True for _c, pty in sudo_tar)


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

        def get(self, _remote: str, local: str, callback=None) -> None:
            Path(local).write_bytes(tgz)
            if callback is not None:
                callback(len(tgz), len(tgz))

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
            if _is_pyz_promote_cmd(cmd):
                calls.append((cmd, bool(get_pty)))
                return (None, _Stdout(b""), _Stderr())
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

        def get(self, _remote: str, local: str, callback=None) -> None:
            Path(local).write_bytes(tgz)
            if callback is not None:
                callback(len(tgz), len(tgz))

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
            if _is_pyz_promote_cmd(cmd):
                calls.append((cmd, bool(get_pty)))
                return (None, _Stdout(b""), _Stderr())
            if _is_pyz_verify_cmd(cmd):
                return (None, _Stdout(_FAKE_PYZ_SHA256.encode()), _Stderr())
            calls.append((cmd, bool(get_pty)))
            if _is_remote_uid_cmd(cmd):
                return (None, _Stdout(b"1000"), _Stderr())
            if _is_archive_hash_cmd(cmd):
                return (None, _Stdout(_archive_sha256(tgz)), _Stderr())

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

        def get(self, _remote: str, local: str, callback=None) -> None:
            Path(local).write_bytes(tgz)
            if callback is not None:
                callback(len(tgz), len(tgz))

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
            if _is_pyz_promote_cmd(cmd):
                return (None, _Stdout(b""), _Stderr())
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

        def get(self, _remote: str, local: str, callback=None) -> None:
            Path(local).write_bytes(b"")
            if callback is not None:
                callback(0, 0)

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
            if _is_pyz_promote_cmd(cmd):
                return (None, _Stdout(b""), _Stderr())
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


def test_build_enroll_pyz_harvest_starts_without_site_packages(tmp_path: Path):
    """The remote payload must not depend on packages installed on the target.

    ``-S`` disables site-packages, reproducing a target that has Python but no
    jsonschema/PyYAML. ``-I`` also ignores PYTHON* environment variables and
    the current directory. The old eager CLI imports failed here before
    argparse could dispatch to ``harvest``.
    """
    import subprocess
    import sys

    import enroll.remote as r

    pyz, _sha = r._build_enroll_pyz(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-I", "-S", str(pyz), "harvest", "--help"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    )

    assert proc.returncode == 0, proc.stderr
    assert "usage: enroll harvest" in proc.stdout
    assert "ModuleNotFoundError" not in proc.stderr
    assert "jsonschema" not in proc.stderr
    assert "yaml" not in proc.stderr.lower()


def test_build_enroll_pyz_runs_harvest_without_site_packages(tmp_path: Path):
    """Exercise command dispatch and the actual harvest implementation under -S."""
    import subprocess
    import sys

    import enroll.remote as r

    build_dir = tmp_path / "build"
    build_dir.mkdir()
    pyz, _sha = r._build_enroll_pyz(build_dir)
    out_dir = tmp_path / "bundle"
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(pyz),
            "harvest",
            "--out",
            str(out_dir),
            "--exclude-path",
            "/**",
            "--assume-safe-path",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )

    assert proc.returncode == 0, proc.stderr
    assert (out_dir / "state.json").is_file()
    assert "ModuleNotFoundError" not in proc.stderr
    assert "jsonschema" not in proc.stderr
    assert "yaml" not in proc.stderr.lower()


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


def test_downloaded_remote_archive_digest_mismatch_is_rejected(
    tmp_path: Path,
):
    import enroll.remote as r

    archive = tmp_path / "bundle.tgz"
    archive.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="integrity check failed"):
        r._verify_downloaded_archive_sha256(archive, "0" * 64)


def test_downloaded_remote_archive_digest_match_is_accepted(tmp_path: Path):
    import enroll.remote as r

    archive = tmp_path / "bundle.tgz"
    archive.write_bytes(b"original")
    expected = hashlib.sha256(b"original").hexdigest()
    r._verify_downloaded_archive_sha256(archive, expected)


def test_remote_archive_download_size_is_bounded(monkeypatch):
    import enroll.remote as r

    monkeypatch.setattr(r, "_TAR_MAX_COMPRESSED_BYTES", 10)
    r._check_tar_download_size(10)
    with pytest.raises(RuntimeError, match="compressed download limit"):
        r._check_tar_download_size(11)


def test_safe_extract_tar_does_not_eagerly_index_archive(tmp_path: Path):
    """The safety caps must apply while parsing, before getmembers() can
    materialise an attacker-sized member list in memory."""
    import enroll.remote as r

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="state.json")
        ti.size = 2
        tf.addfile(ti, io.BytesIO(b"{}"))

    bio.seek(0)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        tf.getmembers = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
            AssertionError("getmembers() must not be used for untrusted archives")
        )
        r._safe_extract_tar(tf, tmp_path)

    assert (tmp_path / "state.json").read_bytes() == b"{}"


def test_safe_extract_tar_counts_dot_entries_against_member_cap(
    tmp_path: Path, monkeypatch
):
    import enroll.remote as r

    monkeypatch.setattr(r, "_TAR_MAX_MEMBERS", 2)
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tf:
        for _ in range(3):
            tf.addfile(tarfile.TarInfo(name="."))

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
