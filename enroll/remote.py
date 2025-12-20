from __future__ import annotations

import os
import shlex
import shutil
import tarfile
import tempfile
import zipapp
from pathlib import Path
from pathlib import PurePosixPath
from typing import Optional


def _safe_extract_tar(tar: tarfile.TarFile, dest: Path) -> None:
    """Safely extract a tar archive into dest.

    Protects against path traversal (e.g. entries containing ../).
    """

    # Note: tar member names use POSIX separators regardless of platform.
    dest = dest.resolve()

    for m in tar.getmembers():
        name = m.name

        # Some tar implementations include a top-level '.' entry when created
        # with `tar -C <dir> .`. That's harmless and should be allowed.
        if name in {".", "./"}:
            continue

        # Reject absolute paths and any '..' components up front.
        p = PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts:
            raise RuntimeError(f"Unsafe tar member path: {name}")

        # Refuse to extract links or device nodes from an untrusted archive.
        # (A symlink can be used to redirect subsequent writes outside dest.)
        if m.issym() or m.islnk() or m.isdev():
            raise RuntimeError(f"Refusing to extract special tar member: {name}")

        member_path = (dest / Path(*p.parts)).resolve()
        if member_path != dest and not str(member_path).startswith(str(dest) + os.sep):
            raise RuntimeError(f"Unsafe tar member path: {name}")

    # Extract members one-by-one after validation.
    for m in tar.getmembers():
        if m.name in {".", "./"}:
            continue
        tar.extract(m, path=dest)


def _build_enroll_pyz(tmpdir: Path) -> Path:
    """Build a self-contained enroll zipapp (pyz) on the local machine.

    The resulting file is stdlib-only and can be executed on the remote host
    as long as it has Python 3 available.
    """
    import enroll as pkg

    pkg_dir = Path(pkg.__file__).resolve().parent
    stage = tmpdir / "stage"
    (stage / "enroll").mkdir(parents=True, exist_ok=True)

    def _ignore(d: str, names: list[str]) -> set[str]:
        return {
            n
            for n in names
            if n in {"__pycache__", ".pytest_cache"} or n.endswith(".pyc")
        }

    shutil.copytree(pkg_dir, stage / "enroll", dirs_exist_ok=True, ignore=_ignore)

    pyz_path = tmpdir / "enroll.pyz"
    zipapp.create_archive(
        stage,
        target=pyz_path,
        main="enroll.cli:main",
        compressed=True,
    )
    return pyz_path


def _ssh_run(ssh, cmd: str) -> tuple[int, str, str]:
    """Run a command over a Paramiko SSHClient."""
    _stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def remote_harvest(
    *,
    local_out_dir: Path,
    remote_host: str,
    remote_port: int = 22,
    remote_user: Optional[str] = None,
    remote_python: str = "python3",
    dangerous: bool = False,
    no_sudo: bool = False,
    include_paths: Optional[list[str]] = None,
    exclude_paths: Optional[list[str]] = None,
) -> Path:
    """Run enroll harvest on a remote host via SSH and pull the bundle locally.

    Returns the local path to state.json inside local_out_dir.
    """

    try:
        import paramiko  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "Remote harvesting requires the 'paramiko' package. "
            "Install it with: pip install paramiko"
        ) from e

    local_out_dir = Path(local_out_dir)
    local_out_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(local_out_dir, 0o700)
    except OSError:
        pass

    # Build a zipapp locally and upload it to the remote.
    with tempfile.TemporaryDirectory(prefix="enroll-remote-") as td:
        td_path = Path(td)
        pyz = _build_enroll_pyz(td_path)
        local_tgz = td_path / "bundle.tgz"

        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        # Default: refuse unknown host keys.
        # Users should add the key to known_hosts.
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

        ssh.connect(
            hostname=remote_host,
            port=int(remote_port),
            username=remote_user,
            allow_agent=True,
            look_for_keys=True,
        )

        # If no username was explicitly provided, SSH may have selected a default.
        # We need a concrete username for the (sudo) chown step below.
        resolved_user = remote_user
        if not resolved_user:
            rc, out, err = _ssh_run(ssh, "id -un")
            if rc == 0 and out.strip():
                resolved_user = out.strip()

        sftp = ssh.open_sftp()
        rtmp: Optional[str] = None
        try:
            rc, out, err = _ssh_run(ssh, "mktemp -d")
            if rc != 0:
                raise RuntimeError(f"Remote mktemp failed: {err.strip()}")
            rtmp = out.strip()

            # Be explicit: restrict the remote staging area to the current user.
            rc, out, err = _ssh_run(ssh, f"chmod 700 {rtmp}")
            if rc != 0:
                raise RuntimeError(f"Remote chmod failed: {err.strip()}")

            rapp = f"{rtmp}/enroll.pyz"
            rbundle = f"{rtmp}/bundle"

            sftp.put(str(pyz), rapp)

            # Run remote harvest.
            argv: list[str] = [
                remote_python,
                rapp,
                "harvest",
                "--out",
                rbundle,
            ]
            if dangerous:
                argv.append("--dangerous")
            for p in include_paths or []:
                argv.extend(["--include-path", str(p)])
            for p in exclude_paths or []:
                argv.extend(["--exclude-path", str(p)])

            _cmd = " ".join(shlex.quote(a) for a in argv)
            if not no_sudo:
                cmd = f"sudo {_cmd}"
            else:
                cmd = _cmd
            rc, out, err = _ssh_run(ssh, cmd)
            if rc != 0:
                raise RuntimeError(
                    "Remote harvest failed.\n"
                    f"Command: {cmd}\n"
                    f"Exit code: {rc}\n"
                    f"Stderr: {err.strip()}"
                )

            if not no_sudo:
                # Ensure user can read the files, before we tar it
                if not resolved_user:
                    raise RuntimeError(
                        "Unable to determine remote username for chown. "
                        "Pass --remote-user explicitly or use --no-sudo."
                    )
                cmd = f"sudo chown -R {resolved_user} {rbundle}"
                rc, out, err = _ssh_run(ssh, cmd)
                if rc != 0:
                    raise RuntimeError(
                        "chown of harvest failed.\n"
                        f"Command: {cmd}\n"
                        f"Exit code: {rc}\n"
                        f"Stderr: {err.strip()}"
                    )

            # Stream a tarball back to the local machine (avoid creating a tar file on the remote).
            cmd = f"tar -cz -C {rbundle} ."
            _stdin, stdout, stderr = ssh.exec_command(cmd)  # nosec
            with open(local_tgz, "wb") as f:
                while True:
                    chunk = stdout.read(1024 * 128)
                    if not chunk:
                        break
                    f.write(chunk)
            rc = stdout.channel.recv_exit_status()
            err_text = stderr.read().decode("utf-8", errors="replace")
            if rc != 0:
                raise RuntimeError(
                    "Remote tar stream failed.\n"
                    f"Command: {cmd}\n"
                    f"Exit code: {rc}\n"
                    f"Stderr: {err_text.strip()}"
                )

            # Extract into the destination.
            with tarfile.open(local_tgz, mode="r:gz") as tf:
                _safe_extract_tar(tf, local_out_dir)

        finally:
            # Cleanup remote tmpdir even on failure.
            if rtmp:
                _ssh_run(ssh, f"rm -rf {rtmp}")
            try:
                sftp.close()
                ssh.close()
            except Exception:
                ssh.close()
                raise RuntimeError("Something went wrong generating the harvest")

    return local_out_dir / "state.json"
