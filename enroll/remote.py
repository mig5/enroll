from __future__ import annotations

import getpass
import os
import shlex
import shutil
import sys
import time
import tarfile
import tempfile
import zipapp
from pathlib import Path
from pathlib import PurePosixPath
from typing import Optional, Callable, TextIO


class RemoteSudoPasswordRequired(RuntimeError):
    """Raised when sudo requires a password but none was provided."""


def _sudo_password_required(out: str, err: str) -> bool:
    """Return True if sudo output indicates it needs a password/TTY."""
    blob = (out + "\n" + err).lower()
    patterns = (
        "a password is required",
        "password is required",
        "a terminal is required to read the password",
        "no tty present and no askpass program specified",
        "must have a tty to run sudo",
        "sudo: sorry, you must have a tty",
        "askpass",
    )
    return any(p in blob for p in patterns)


def _sudo_not_permitted(out: str, err: str) -> bool:
    """Return True if sudo output indicates the user cannot sudo at all."""
    blob = (out + "\n" + err).lower()
    patterns = (
        "is not in the sudoers file",
        "not allowed to execute",
        "may not run sudo",
        "sorry, user",
    )
    return any(p in blob for p in patterns)


def _sudo_tty_required(out: str, err: str) -> bool:
    """Return True if sudo output indicates it requires a TTY (sudoers requiretty)."""
    blob = (out + "\n" + err).lower()
    patterns = (
        "must have a tty",
        "sorry, you must have a tty",
        "sudo: sorry, you must have a tty",
        "must have a tty to run sudo",
    )
    return any(p in blob for p in patterns)


def _resolve_become_password(
    ask_become_pass: bool,
    *,
    prompt: str = "sudo password: ",
    getpass_fn: Callable[[str], str] = getpass.getpass,
) -> Optional[str]:
    if ask_become_pass:
        return getpass_fn(prompt)
    return None


def remote_harvest(
    *,
    ask_become_pass: bool = False,
    no_sudo: bool = False,
    prompt: str = "sudo password: ",
    getpass_fn: Optional[Callable[[str], str]] = None,
    stdin: Optional[TextIO] = None,
    **kwargs,
):
    """Call _remote_harvest, with a safe sudo password fallback.

    Behavior:
      - Run without a password unless --ask-become-pass is set.
      - If the remote sudo policy requires a password and none was provided,
        prompt and retry when running interactively.
    """

    # Resolve defaults at call time (easier to test/monkeypatch, and avoids capturing
    # sys.stdin / getpass.getpass at import time).
    if getpass_fn is None:
        getpass_fn = getpass.getpass
    if stdin is None:
        stdin = sys.stdin

    sudo_password = _resolve_become_password(
        ask_become_pass and not no_sudo,
        prompt=prompt,
        getpass_fn=getpass_fn,
    )

    try:
        return _remote_harvest(sudo_password=sudo_password, no_sudo=no_sudo, **kwargs)
    except RemoteSudoPasswordRequired:
        if sudo_password is not None:
            raise

        # Fallback prompt if interactive
        if stdin is not None and getattr(stdin, "isatty", lambda: False)():
            pw = getpass_fn(prompt)
            return _remote_harvest(sudo_password=pw, no_sudo=no_sudo, **kwargs)

        raise RemoteSudoPasswordRequired(
            "Remote sudo requires a password. Re-run with --ask-become-pass."
        )


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


def _ssh_run(
    ssh,
    cmd: str,
    *,
    get_pty: bool = False,
    stdin_text: Optional[str] = None,
    close_stdin: bool = False,
) -> tuple[int, str, str]:
    """Run a command over a Paramiko SSHClient.

    Paramiko's exec_command runs commands without a TTY by default.
    Some hosts have sudoers "requiretty" enabled, which causes sudo to
    fail even when passwordless sudo is configured. For those commands,
    request a PTY.

    We do not request a PTY for commands that stream binary data
    (e.g. tar/gzip output), as a PTY can corrupt the byte stream.
    """
    stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=get_pty)
    # All three file-like objects share the same underlying Channel.
    chan = stdout.channel

    if stdin_text is not None and stdin is not None:
        try:
            stdin.write(stdin_text)
            stdin.flush()
        except Exception:
            # If the remote side closed stdin early, ignore.
            pass  # nosec
        finally:
            if close_stdin:
                # For sudo -S, a wrong password causes sudo to re-prompt and wait
                # forever for more input. We try hard to deliver EOF so sudo can
                # fail fast.
                try:
                    chan.shutdown_write()  # sends EOF to the remote process
                except Exception:
                    pass  # nosec
                try:
                    stdin.close()
                except Exception:
                    pass  # nosec

    # Read incrementally to avoid blocking forever on stdout.read()/stderr.read()
    # if the remote process is waiting for more input (e.g. sudo password retry).
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    # Keep a small tail of stderr to detect sudo retry messages without
    # repeatedly joining potentially large buffers.
    err_tail = b""

    while True:
        progressed = False
        if chan.recv_ready():
            out_chunks.append(chan.recv(1024 * 64))
            progressed = True
        if chan.recv_stderr_ready():
            chunk = chan.recv_stderr(1024 * 64)
            err_chunks.append(chunk)
            err_tail = (err_tail + chunk)[-4096:]
            progressed = True

        # If we just attempted sudo -S with a single password line and sudo is
        # asking again, detect it and stop waiting.
        if close_stdin and stdin_text is not None:
            blob = err_tail.lower()
            if b"sorry, try again" in blob or b"incorrect password" in blob:
                try:
                    chan.close()
                except Exception:
                    pass  # nosec
                break

        # Exit once the process has exited and we have drained the buffers.
        if (
            chan.exit_status_ready()
            and not chan.recv_ready()
            and not chan.recv_stderr_ready()
        ):
            break

        if not progressed:
            time.sleep(0.05)

    out = b"".join(out_chunks).decode("utf-8", errors="replace")
    err = b"".join(err_chunks).decode("utf-8", errors="replace")
    rc = chan.recv_exit_status() if chan.exit_status_ready() else 1
    return rc, out, err


def _ssh_run_sudo(
    ssh,
    cmd: str,
    *,
    sudo_password: Optional[str] = None,
    get_pty: bool = True,
) -> tuple[int, str, str]:
    """Run cmd via sudo with a safe non-interactive-first strategy.

    Strategy:
      1) Try `sudo -n`.
      2) If sudo reports a password is required and we have one, retry with
         `sudo -S` and feed it via stdin.
      3) If sudo reports a password is required and we *don't* have one, raise
         RemoteSudoPasswordRequired.

    We avoid requesting a PTY unless the remote sudo policy requires it.
    This makes sudo -S behavior more reliable (wrong passwords fail fast
    instead of blocking on a PTY).
    """
    cmd_n = f"sudo -n -p '' -- {cmd}"

    # First try: never prompt, and prefer no PTY.
    rc, out, err = _ssh_run(ssh, cmd_n, get_pty=False)
    need_pty = False

    # Some sudoers configurations require a TTY even for passwordless sudo.
    if get_pty and rc != 0 and _sudo_tty_required(out, err):
        need_pty = True
        rc, out, err = _ssh_run(ssh, cmd_n, get_pty=True)

    if rc == 0:
        return rc, out, err

    if _sudo_not_permitted(out, err):
        return rc, out, err

    if _sudo_password_required(out, err):
        if sudo_password is None:
            raise RemoteSudoPasswordRequired(
                "Remote sudo requires a password, but none was provided."
            )
        cmd_s = f"sudo -S -p '' -- {cmd}"
        return _ssh_run(
            ssh,
            cmd_s,
            get_pty=need_pty,
            stdin_text=str(sudo_password) + "\n",
            close_stdin=True,
        )

    return rc, out, err


def _remote_harvest(
    *,
    local_out_dir: Path,
    remote_host: str,
    remote_port: int = 22,
    remote_user: Optional[str] = None,
    remote_python: str = "python3",
    dangerous: bool = False,
    no_sudo: bool = False,
    sudo_password: Optional[str] = None,
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

            _cmd = " ".join(map(shlex.quote, argv))
            if not no_sudo:
                # Prefer non-interactive sudo first; retry with -S only when needed.
                rc, out, err = _ssh_run_sudo(
                    ssh, _cmd, sudo_password=sudo_password, get_pty=True
                )
                cmd = f"sudo {_cmd}"
            else:
                cmd = _cmd
                rc, out, err = _ssh_run(ssh, cmd, get_pty=False)
            if rc != 0:
                raise RuntimeError(
                    "Remote harvest failed.\n"
                    f"Command: {cmd}\n"
                    f"Exit code: {rc}\n"
                    f"Stdout: {out.strip()}\n"
                    f"Stderr: {err.strip()}"
                )

            if not no_sudo:
                # Ensure user can read the files, before we tar it.
                if not resolved_user:
                    raise RuntimeError(
                        "Unable to determine remote username for chown. "
                        "Pass --remote-user explicitly or use --no-sudo."
                    )
                chown_cmd = f"chown -R {resolved_user} {rbundle}"
                rc, out, err = _ssh_run_sudo(
                    ssh,
                    chown_cmd,
                    sudo_password=sudo_password,
                    get_pty=True,
                )
                if rc != 0:
                    raise RuntimeError(
                        "chown of harvest failed.\n"
                        f"Command: sudo {chown_cmd}\n"
                        f"Exit code: {rc}\n"
                        f"Stdout: {out.strip()}\n"
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
