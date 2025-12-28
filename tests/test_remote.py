from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest


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
    def fake_build(_td: Path) -> Path:
        p = _td / "enroll.pyz"
        p.write_bytes(b"PYZ")
        return p

    monkeypatch.setattr(r, "_build_enroll_pyz", fake_build)

    # Prepare a tiny harvest bundle tar stream from the "remote".
    tgz = _make_tgz_bytes({"state.json": b'{"ok": true}\n'})

    calls: list[str] = []

    class _Chan:
        def __init__(self, rc: int = 0):
            self._rc = rc

        def recv_exit_status(self) -> int:
            return self._rc

    class _Stdout:
        def __init__(self, payload: bytes = b"", rc: int = 0):
            self._bio = io.BytesIO(payload)
            self.channel = _Chan(rc)

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

        def exec_command(self, cmd: str):
            calls.append(cmd)
            # The tar stream uses exec_command directly.
            if cmd.startswith("tar -cz -C"):
                return (None, _Stdout(tgz, rc=0), _Stderr(b""))

            # _ssh_run path: id -un, mktemp -d, chmod, sudo harvest, sudo chown, rm -rf
            if cmd == "id -un":
                return (None, _Stdout(b"alice\n"), _Stderr())
            if cmd == "mktemp -d":
                return (None, _Stdout(b"/tmp/enroll-remote-123\n"), _Stderr())
            if cmd.startswith("chmod 700"):
                return (None, _Stdout(b""), _Stderr())
            if " harvest " in cmd:
                return (None, _Stdout(b""), _Stderr())
            if cmd.startswith("sudo chown -R"):
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
    joined = "\n".join(calls)
    assert "sudo" in joined
    assert "--dangerous" in joined
    assert "--include-path" in joined
    assert "--exclude-path" in joined
