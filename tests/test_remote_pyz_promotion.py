from __future__ import annotations

import hashlib
import os
import shlex
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import enroll.remote as remote


_TRUSTED_PYZ = b"trusted enroll zipapp bytes\n"
_TRUSTED_SHA256 = hashlib.sha256(_TRUSTED_PYZ).hexdigest()


def _prepare_dirs(tmp_path: Path) -> tuple[Path, Path]:
    stage_dir = tmp_path / "user-stage"
    root_dir = tmp_path / "root-stage"
    stage_dir.mkdir(mode=0o700)
    root_dir.mkdir(mode=0o700)
    # mkdir is affected by umask; the production flow explicitly chmods 0700.
    root_dir.chmod(0o700)
    return stage_dir, root_dir


def _load_promotion_function():
    namespace = {"__name__": "enroll_promotion_test"}
    exec(remote._REMOTE_PROMOTE_PYZ_SCRIPT, namespace)
    return namespace["_promote"]


def _promotion_args(
    stage_dir: Path,
    root_dir: Path,
    *,
    expected_sha256: str = _TRUSTED_SHA256,
    expected_size: int = len(_TRUSTED_PYZ),
    source_name: str = "enroll.pyz",
    destination_name: str = "enroll.pyz",
    expected_owner_uid: int | None = None,
) -> list[str]:
    if expected_owner_uid is None:
        expected_owner_uid = os.geteuid()
    return [
        str(stage_dir),
        source_name,
        str(root_dir),
        destination_name,
        expected_sha256,
        str(expected_size),
        str(expected_owner_uid),
    ]


def _promote_direct(
    stage_dir: Path,
    root_dir: Path,
    **kwargs,
) -> None:
    _load_promotion_function()(_promotion_args(stage_dir, root_dir, **kwargs))


def _run_promotion_subprocess(
    stage_dir: Path,
    root_dir: Path,
    *,
    timeout: float = 5,
    **kwargs,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            remote._REMOTE_PROMOTE_PYZ_SCRIPT,
            *_promotion_args(stage_dir, root_dir, **kwargs),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _assert_no_promoted_copy(root_dir: Path) -> None:
    assert not (root_dir / "enroll.pyz").exists()
    assert not (root_dir / ".enroll.pyz.tmp").exists()


def test_promotion_script_entrypoint_publishes_exact_private_copy(tmp_path: Path):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    (stage_dir / "enroll.pyz").write_bytes(_TRUSTED_PYZ)

    result = _run_promotion_subprocess(stage_dir, root_dir)

    assert result.returncode == 0, result.stderr
    promoted = root_dir / "enroll.pyz"
    assert promoted.read_bytes() == _TRUSTED_PYZ
    promoted_stat = promoted.stat()
    assert stat.S_IMODE(promoted_stat.st_mode) == 0o500
    assert promoted_stat.st_nlink == 1
    assert not (root_dir / ".enroll.pyz.tmp").exists()


def test_replacing_user_path_after_promotion_cannot_change_root_copy(tmp_path: Path):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    source = stage_dir / "enroll.pyz"
    source.write_bytes(_TRUSTED_PYZ)

    _promote_direct(stage_dir, root_dir)

    replacement = stage_dir / "replacement.pyz"
    replacement.write_bytes(b"print('attacker code')\n")
    os.replace(replacement, source)

    assert source.read_bytes() != _TRUSTED_PYZ
    assert (root_dir / "enroll.pyz").read_bytes() == _TRUSTED_PYZ


def test_digest_mismatch_fails_closed_and_removes_partial_copy(tmp_path: Path):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    payload = b"attacker-controlled bytes"
    (stage_dir / "enroll.pyz").write_bytes(payload)

    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        _promote_direct(stage_dir, root_dir, expected_size=len(payload))

    _assert_no_promoted_copy(root_dir)


@pytest.mark.parametrize(
    "reported_size", [0, len(_TRUSTED_PYZ) - 1, len(_TRUSTED_PYZ) + 1]
)
def test_unexpected_source_size_fails_before_publication(
    tmp_path: Path, reported_size: int
):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    (stage_dir / "enroll.pyz").write_bytes(_TRUSTED_PYZ)

    with pytest.raises(RuntimeError, match="unexpected size"):
        _promote_direct(stage_dir, root_dir, expected_size=reported_size)

    _assert_no_promoted_copy(root_dir)


def test_source_symlink_is_rejected_without_following_it(tmp_path: Path):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    target = stage_dir / "payload"
    target.write_bytes(_TRUSTED_PYZ)
    (stage_dir / "enroll.pyz").symlink_to(target.name)

    with pytest.raises(OSError):
        _promote_direct(stage_dir, root_dir)

    _assert_no_promoted_copy(root_dir)


def test_hardlinked_source_is_rejected(tmp_path: Path):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    source = stage_dir / "enroll.pyz"
    source.write_bytes(_TRUSTED_PYZ)
    os.link(source, stage_dir / "second-name")

    with pytest.raises(RuntimeError, match="must not be hard-linked"):
        _promote_direct(stage_dir, root_dir)

    _assert_no_promoted_copy(root_dir)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO test requires POSIX")
def test_fifo_source_is_rejected_without_blocking(tmp_path: Path):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    os.mkfifo(stage_dir / "enroll.pyz", mode=0o600)

    result = _run_promotion_subprocess(
        stage_dir,
        root_dir,
        expected_sha256=hashlib.sha256(b"").hexdigest(),
        expected_size=0,
        timeout=2,
    )

    assert result.returncode != 0
    assert "not a regular file" in result.stderr
    _assert_no_promoted_copy(root_dir)


def test_directory_source_is_rejected(tmp_path: Path):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    (stage_dir / "enroll.pyz").mkdir()

    with pytest.raises(RuntimeError, match="not a regular file"):
        _promote_direct(stage_dir, root_dir)

    _assert_no_promoted_copy(root_dir)


def test_symlink_destination_directory_is_rejected(tmp_path: Path):
    stage_dir = tmp_path / "user-stage"
    stage_dir.mkdir()
    (stage_dir / "enroll.pyz").write_bytes(_TRUSTED_PYZ)
    real_root = tmp_path / "real-root"
    real_root.mkdir(mode=0o700)
    real_root.chmod(0o700)
    root_link = tmp_path / "root-link"
    root_link.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(OSError):
        _promote_direct(stage_dir, root_link)

    _assert_no_promoted_copy(real_root)


def test_non_private_destination_directory_is_rejected(tmp_path: Path):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    (stage_dir / "enroll.pyz").write_bytes(_TRUSTED_PYZ)
    root_dir.chmod(0o755)

    with pytest.raises(RuntimeError, match="not mode 0700"):
        _promote_direct(stage_dir, root_dir)

    _assert_no_promoted_copy(root_dir)


def test_promotion_requires_expected_effective_uid(tmp_path: Path):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    (stage_dir / "enroll.pyz").write_bytes(_TRUSTED_PYZ)

    with pytest.raises(RuntimeError, match="not running as the expected user"):
        _promote_direct(
            stage_dir,
            root_dir,
            expected_owner_uid=os.geteuid() + 1,
        )

    _assert_no_promoted_copy(root_dir)


def test_existing_temporary_name_is_not_overwritten(tmp_path: Path):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    (stage_dir / "enroll.pyz").write_bytes(_TRUSTED_PYZ)
    temporary = root_dir / ".enroll.pyz.tmp"
    temporary.write_bytes(b"pre-existing")

    with pytest.raises(FileExistsError):
        _promote_direct(stage_dir, root_dir)

    assert temporary.read_bytes() == b"pre-existing"
    assert not (root_dir / "enroll.pyz").exists()


def test_existing_final_name_is_not_replaced_and_partial_copy_is_removed(
    tmp_path: Path,
):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    (stage_dir / "enroll.pyz").write_bytes(_TRUSTED_PYZ)
    final = root_dir / "enroll.pyz"
    final.write_bytes(b"pre-existing")

    with pytest.raises(FileExistsError):
        _promote_direct(stage_dir, root_dir)

    assert final.read_bytes() == b"pre-existing"
    assert not (root_dir / ".enroll.pyz.tmp").exists()


def test_path_replacement_after_open_cannot_change_promoted_inode(
    tmp_path: Path, monkeypatch
):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    source = stage_dir / "enroll.pyz"
    source.write_bytes(_TRUSTED_PYZ)
    replacement = stage_dir / "attacker.pyz"
    replacement.write_bytes(b"print('attacker code')\n")

    promote = _load_promotion_function()
    real_read = os.read
    replaced = False

    def replace_path_before_first_read(fd: int, count: int) -> bytes:
        nonlocal replaced
        if not replaced:
            replaced = True
            os.replace(replacement, source)
        return real_read(fd, count)

    monkeypatch.setattr(os, "read", replace_path_before_first_read)
    promote(_promotion_args(stage_dir, root_dir))

    assert replaced is True
    assert source.read_bytes() != _TRUSTED_PYZ
    assert (root_dir / "enroll.pyz").read_bytes() == _TRUSTED_PYZ


def test_in_place_mutation_after_fstat_fails_digest_and_cleans_output(
    tmp_path: Path, monkeypatch
):
    stage_dir, root_dir = _prepare_dirs(tmp_path)
    source = stage_dir / "enroll.pyz"
    source.write_bytes(_TRUSTED_PYZ)

    promote = _load_promotion_function()
    real_read = os.read
    attacker_fd = os.open(source, os.O_WRONLY)
    mutated = False

    def mutate_inode_before_first_read(fd: int, count: int) -> bytes:
        nonlocal mutated
        if not mutated:
            mutated = True
            os.lseek(attacker_fd, 0, os.SEEK_SET)
            os.write(attacker_fd, b"X" * len(_TRUSTED_PYZ))
            os.fsync(attacker_fd)
        return real_read(fd, count)

    monkeypatch.setattr(os, "read", mutate_inode_before_first_read)
    try:
        with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
            promote(_promotion_args(stage_dir, root_dir))
    finally:
        os.close(attacker_fd)

    assert mutated is True
    _assert_no_promoted_copy(root_dir)


def test_remote_promote_builds_one_privileged_atomic_command(monkeypatch):
    captured: dict[str, object] = {}

    def fake_ssh_run_sudo(ssh, cmd, *, sudo_password, get_pty):
        captured.update(
            ssh=ssh,
            cmd=cmd,
            sudo_password=sudo_password,
            get_pty=get_pty,
        )
        return 0, "", ""

    monkeypatch.setattr(remote, "_ssh_run_sudo", fake_ssh_run_sudo)
    marker = object()

    result = remote._remote_promote_verified_pyz(
        marker,
        "/tmp/user-stage/enroll.pyz",
        "/tmp/root-stage",
        _TRUSTED_SHA256,
        len(_TRUSTED_PYZ),
        remote_python="/usr/bin/python3",
        sudo_password="secret",
    )

    assert result == "/tmp/root-stage/enroll.pyz"
    assert captured["ssh"] is marker
    assert captured["sudo_password"] == "secret"
    assert captured["get_pty"] is True
    argv = shlex.split(str(captured["cmd"]))
    assert argv == [
        "/usr/bin/python3",
        "-I",
        "-c",
        remote._REMOTE_PROMOTE_PYZ_SCRIPT,
        "/tmp/user-stage",
        "enroll.pyz",
        "/tmp/root-stage",
        "enroll.pyz",
        _TRUSTED_SHA256,
        str(len(_TRUSTED_PYZ)),
        "0",
    ]


@pytest.mark.parametrize(
    ("uploaded", "root_dir", "digest", "size"),
    [
        ("relative/enroll.pyz", "/tmp/root", _TRUSTED_SHA256, len(_TRUSTED_PYZ)),
        ("/tmp/stage/enroll.pyz", "relative/root", _TRUSTED_SHA256, len(_TRUSTED_PYZ)),
        ("/tmp/stage/enroll.pyz", "/tmp/root", "not-a-digest", len(_TRUSTED_PYZ)),
        ("/tmp/stage/enroll.pyz", "/tmp/root", _TRUSTED_SHA256, -1),
    ],
)
def test_remote_promote_rejects_invalid_local_parameters_before_sudo(
    monkeypatch, uploaded: str, root_dir: str, digest: str, size: int
):
    called = False

    def unexpected_sudo(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("sudo must not run")

    monkeypatch.setattr(remote, "_ssh_run_sudo", unexpected_sudo)

    with pytest.raises(ValueError):
        remote._remote_promote_verified_pyz(
            object(),
            uploaded,
            root_dir,
            digest,
            size,
            remote_python="python3",
            sudo_password=None,
        )
    assert called is False


def test_remote_promote_reports_privileged_failure(monkeypatch):
    monkeypatch.setattr(
        remote,
        "_ssh_run_sudo",
        lambda *_args, **_kwargs: (1, "", "digest mismatch"),
    )

    with pytest.raises(RuntimeError, match="Refusing to execute"):
        remote._remote_promote_verified_pyz(
            object(),
            "/tmp/stage/enroll.pyz",
            "/tmp/root",
            _TRUSTED_SHA256,
            len(_TRUSTED_PYZ),
            remote_python="python3",
            sudo_password=None,
        )


def test_sudo_harvest_stops_before_execution_when_promotion_fails(
    tmp_path: Path, monkeypatch
):
    import types

    # The fake builder must create the file because _remote_harvest reads its size.
    def build_pyz(td):
        pyz = Path(td) / "enroll.pyz"
        pyz.write_bytes(_TRUSTED_PYZ)
        return pyz, _TRUSTED_SHA256

    monkeypatch.setattr(remote, "_build_enroll_pyz", build_pyz)
    monkeypatch.setattr(
        remote,
        "_remote_promote_verified_pyz",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("promotion rejected attacker bytes")
        ),
    )

    user_commands: list[str] = []
    sudo_commands: list[str] = []

    def fake_run(_ssh, cmd, **_kwargs):
        user_commands.append(cmd)
        if cmd == "mktemp -d":
            return 0, "/tmp/user-stage\n", ""
        return 0, "", ""

    def fake_sudo(_ssh, cmd, **_kwargs):
        sudo_commands.append(cmd)
        if cmd == "mktemp -d":
            return 0, "/tmp/root-stage\n", ""
        return 0, "", ""

    monkeypatch.setattr(remote, "_ssh_run", fake_run)
    monkeypatch.setattr(remote, "_ssh_run_sudo", fake_sudo)

    class FakeSFTP:
        def put(self, _local, _remote):
            return None

        def close(self):
            return None

    class FakeSSH:
        def load_system_host_keys(self):
            return None

        def set_missing_host_key_policy(self, _policy):
            return None

        def connect(self, **_kwargs):
            return None

        def open_sftp(self):
            return FakeSFTP()

        def close(self):
            return None

    monkeypatch.setitem(
        sys.modules,
        "paramiko",
        types.SimpleNamespace(
            SSHClient=FakeSSH,
            RejectPolicy=type("RejectPolicy", (), {}),
        ),
    )

    with pytest.raises(RuntimeError, match="promotion rejected attacker bytes"):
        remote._remote_harvest(
            local_out_dir=tmp_path / "out",
            remote_host="example.com",
            no_sudo=False,
        )

    assert not any(" harvest " in command for command in sudo_commands)
    assert any(command == "rm -rf -- /tmp/root-stage" for command in sudo_commands)
    assert any(command == "rm -rf -- /tmp/user-stage" for command in user_commands)
