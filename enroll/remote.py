from __future__ import annotations

import getpass
import hashlib
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

from .harvest_safety import ensure_private_empty_dir, prepare_new_private_dir


class RemoteSudoPasswordRequired(RuntimeError):
    """Raised when sudo requires a password but none was provided."""


class RemoteSSHKeyPassphraseRequired(RuntimeError):
    """Raised when SSH private key decryption needs a passphrase."""


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


def _resolve_ssh_key_passphrase(
    ask_key_passphrase: bool,
    *,
    env_var: Optional[str] = None,
    prompt: str = "SSH key passphrase: ",
    getpass_fn: Callable[[str], str] = getpass.getpass,
) -> Optional[str]:
    """Resolve SSH private-key passphrase from env and/or prompt.

    Precedence:
      1) --ssh-key-passphrase-env style input (env_var)
      2) --ask-key-passphrase style interactive prompt
      3) None
    """
    if env_var:
        val = os.environ.get(str(env_var))
        if val is None:
            raise RuntimeError(
                "SSH key passphrase environment variable is not set: " f"{env_var}"
            )
        return val

    if ask_key_passphrase:
        return getpass_fn(prompt)

    return None


def remote_harvest(
    *,
    ask_become_pass: bool = False,
    ask_key_passphrase: bool = False,
    ssh_key_passphrase_env: Optional[str] = None,
    no_sudo: bool = False,
    prompt: str = "sudo password: ",
    key_prompt: str = "SSH key passphrase: ",
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
    ssh_key_passphrase = _resolve_ssh_key_passphrase(
        ask_key_passphrase,
        env_var=ssh_key_passphrase_env,
        prompt=key_prompt,
        getpass_fn=getpass_fn,
    )

    allow_existing_output = bool(kwargs.pop("allow_existing_output", False))
    output_prepared = False

    while True:
        try:
            return _remote_harvest(
                sudo_password=sudo_password,
                no_sudo=no_sudo,
                ssh_key_passphrase=ssh_key_passphrase,
                allow_existing_output=allow_existing_output or output_prepared,
                **kwargs,
            )
        except RemoteSSHKeyPassphraseRequired:
            # Already tried a passphrase and still failed.
            if ssh_key_passphrase is not None:
                raise RemoteSSHKeyPassphraseRequired(
                    "SSH private key could not be decrypted with the supplied "
                    "passphrase."
                ) from None

            # Fallback prompt if interactive.
            if stdin is not None and getattr(stdin, "isatty", lambda: False)():
                ssh_key_passphrase = getpass_fn(key_prompt)
                output_prepared = True
                continue

            raise RemoteSSHKeyPassphraseRequired(
                "SSH private key is encrypted and needs a passphrase. "
                "Re-run with --ask-key-passphrase or "
                "--ssh-key-passphrase-env VAR."
            )

        except RemoteSudoPasswordRequired:
            if sudo_password is not None:
                raise

            # Fallback prompt if interactive.
            if stdin is not None and getattr(stdin, "isatty", lambda: False)():
                sudo_password = getpass_fn(prompt)
                output_prepared = True
                continue

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

    # Extract members one-by-one after validation.  Pass an explicit tarfile
    # extraction filter on Python versions that support it so Python 3.12/3.13
    # do not warn about the Python 3.14 default changing.  Keep the older call
    # path for Python 3.10/3.11, where the filter argument is unavailable.
    supports_filter = hasattr(tarfile, "data_filter")
    for m in tar.getmembers():
        if m.name in {".", "./"}:
            continue
        if supports_filter:
            tar.extract(m, path=dest, filter="data")
        else:
            tar.extract(m, path=dest)


def _build_enroll_pyz(tmpdir: Path) -> tuple[Path, str]:
    """Build a self-contained enroll zipapp (pyz) on the local machine.

    The resulting file is stdlib-only and can be executed on the remote host
    as long as it has Python 3 available.

    Returns ``(pyz_path, sha256_hex)``. The digest is computed on the exact
    bytes written locally so the caller can verify, on the remote side, that the
    file that is about to be executed as root is byte-for-byte the one we built
    (see ``_remote_verify_pyz_sha256``). This is transport/staging integrity
    defence-in-depth: it detects a swap of the staged file between upload and
    execution by anyone who gained write access to the staging directory. It is
    NOT a defence against a remote host that is already root-compromised -- such
    a host can subvert the interpreter regardless, and is out of scope per
    SECURITY.md.
    """
    import enroll as pkg

    pkg_dir = Path(pkg.__file__).resolve().parent
    stage = tmpdir / "stage"
    (stage / "enroll").mkdir(parents=True, exist_ok=True)

    # Names that must never end up in the remote zipapp. The remote only ever
    # runs ``harvest``; test suites, caches, editor/VCS scratch, and compiled
    # artifacts are never needed at runtime and should not be shipped to (or
    # executed on) a harvested host. Excluding them keeps the payload minimal
    # and avoids transferring irrelevant code to every target.
    _ignore_dirs = {
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".git",
        ".hg",
        ".svn",
        "tests",
        "test",
    }
    _ignore_suffixes = (".pyc", ".pyo", ".orig", ".rej", ".bak")

    def _ignore(directory: str, names: list[str]) -> set[str]:
        dropped: set[str] = set()
        for n in names:
            if n in _ignore_dirs:
                dropped.add(n)
                continue
            if n.endswith(_ignore_suffixes):
                dropped.add(n)
                continue
            # Defensive: never ship test modules even if they are colocated in
            # the package directory by a future packaging change.
            if n.startswith("test_") and n.endswith(".py"):
                dropped.add(n)
                continue
            if n == "conftest.py":
                dropped.add(n)
                continue
        return dropped

    shutil.copytree(pkg_dir, stage / "enroll", dirs_exist_ok=True, ignore=_ignore)

    # The JSON Schema is a required runtime data file for ``validate``/``manifest``
    # consumers of the harvest; the remote harvest itself does not validate, but
    # the bundle it produces is validated locally, and the schema travels with
    # the package. Fail loudly if a future ignore rule ever drops it rather than
    # silently shipping a package that cannot self-validate.
    staged_schema = stage / "enroll" / "schema" / "state.schema.json"
    if not staged_schema.is_file():
        raise RuntimeError(
            "internal error: enroll.pyz staging is missing the bundled JSON "
            "schema (schema/state.schema.json); refusing to build an "
            "incomplete remote payload"
        )

    pyz_path = tmpdir / "enroll.pyz"
    zipapp.create_archive(
        stage,
        target=pyz_path,
        main="enroll.cli:main",
        compressed=True,
    )

    sha256_hex = _sha256_file(pyz_path)
    return pyz_path, sha256_hex


def _sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file, read in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _remote_verify_pyz_sha256(
    ssh,
    remote_pyz_path: str,
    expected_sha256: str,
    *,
    remote_python: str,
) -> None:
    """Verify the uploaded zipapp's SHA-256 on the remote before executing it.

    This is transport/staging integrity defence-in-depth. The check runs on the
    remote, immediately before the (root) execution of the zipapp, and fails
    closed if the digest does not match the bytes we built locally. It shrinks
    the window in which a *non-root* tamperer who somehow gained write access to
    the staging directory could swap the file between upload and execution.

    It deliberately does NOT establish trust in a root-compromised remote: a
    host that is already root can forge any check it runs about itself. Per
    SECURITY.md, such a host is outside Enroll's threat model. The value here is
    catching accidental corruption and unprivileged-local-user staging races,
    not defeating a compromised root.

    The hashing is done with Python's hashlib (already required to run the
    zipapp) rather than a ``sha256sum`` binary, so it does not depend on
    coreutils being present or on PATH resolution of a hashing tool.
    """

    # Hash the staged file using the same interpreter that will execute it.
    # ``-I`` isolates the interpreter from site/user customisation; the script
    # prints only the lowercase hex digest.
    hash_script = (
        "import hashlib,sys;"
        "h=hashlib.sha256();"
        "f=open(sys.argv[1],'rb');"
        "[h.update(c) for c in iter(lambda:f.read(1048576),b'')];"
        "sys.stdout.write(h.hexdigest())"
    )
    cmd = " ".join(
        shlex.quote(tok)
        for tok in (remote_python, "-I", "-c", hash_script, remote_pyz_path)
    )
    rc, out, err = _ssh_run(ssh, cmd, get_pty=False)
    if rc != 0:
        raise RuntimeError(
            "Failed to verify the integrity of the uploaded enroll.pyz on the "
            f"remote host.\nCommand: {cmd}\nExit code: {rc}\nStderr: {err.strip()}"
        )
    remote_digest = out.strip().lower()
    expected = expected_sha256.strip().lower()
    if not remote_digest:
        raise RuntimeError(
            "Remote integrity check returned an empty SHA-256 for enroll.pyz; "
            "refusing to execute it."
        )
    if remote_digest != expected:
        raise RuntimeError(
            "Integrity check failed for the uploaded enroll.pyz: the staged "
            "file's SHA-256 on the remote does not match the locally built "
            "payload. Refusing to execute it as root.\n"
            f"  expected: {expected}\n"
            f"  remote:   {remote_digest}\n"
            "This can indicate the staging directory was tampered with between "
            "upload and execution, or transfer corruption."
        )


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
    remote_port: Optional[int] = None,
    remote_user: Optional[str] = None,
    remote_ssh_config: Optional[str] = None,
    remote_python: str = "python3",
    dangerous: bool = False,
    no_sudo: bool = False,
    sudo_password: Optional[str] = None,
    ssh_key_passphrase: Optional[str] = None,
    include_paths: Optional[list[str]] = None,
    exclude_paths: Optional[list[str]] = None,
    allow_existing_output: bool = False,
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

    local_out_dir = (
        ensure_private_empty_dir(local_out_dir, label="remote harvest output")
        if allow_existing_output
        else prepare_new_private_dir(local_out_dir, label="remote harvest output")
    )

    # Build a zipapp locally and upload it to the remote.
    with tempfile.TemporaryDirectory(prefix="enroll-remote-") as td:
        td_path = Path(td)
        pyz, pyz_sha256 = _build_enroll_pyz(td_path)
        local_tgz = td_path / "bundle.tgz"

        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        # Default: refuse unknown host keys.
        # Users should add the key to known_hosts.
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

        # Resolve SSH connection parameters.
        connect_host = remote_host
        connect_port = int(remote_port) if remote_port is not None else 22
        connect_user = remote_user
        key_filename = None
        sock = None
        hostkey_name = connect_host

        # Timeouts derived from ssh_config if set (ConnectTimeout).
        # Used both for socket connect (when we create one) and Paramiko handshake/auth.
        connect_timeout: Optional[float] = None

        if remote_ssh_config:
            from paramiko.config import SSHConfig  # type: ignore
            from paramiko.proxy import ProxyCommand  # type: ignore
            import socket as _socket

            cfg_path = Path(str(remote_ssh_config)).expanduser()
            if not cfg_path.exists():
                raise RuntimeError(f"SSH config file not found: {cfg_path}")

            cfg = SSHConfig()
            with cfg_path.open("r", encoding="utf-8") as _fp:
                cfg.parse(_fp)
            hcfg = cfg.lookup(remote_host)

            connect_host = str(hcfg.get("hostname") or remote_host)
            hostkey_name = str(hcfg.get("hostkeyalias") or connect_host)

            if remote_port is None and hcfg.get("port"):
                try:
                    connect_port = int(str(hcfg.get("port")))
                except ValueError:
                    pass
            if connect_user is None and hcfg.get("user"):
                connect_user = str(hcfg.get("user"))

            ident = hcfg.get("identityfile")
            if ident:
                if isinstance(ident, (list, tuple)):
                    key_filename = [str(Path(p).expanduser()) for p in ident]
                else:
                    key_filename = str(Path(str(ident)).expanduser())

            # Honour OpenSSH ConnectTimeout (seconds) if present.
            if hcfg.get("connecttimeout"):
                try:
                    connect_timeout = float(str(hcfg.get("connecttimeout")))
                except (TypeError, ValueError):
                    connect_timeout = None

            proxycmd = hcfg.get("proxycommand")

            # AddressFamily support: inet (IPv4 only), inet6 (IPv6 only), any (default).
            addrfam = str(hcfg.get("addressfamily") or "any").strip().lower()
            family: Optional[int] = None
            if addrfam == "inet":
                family = _socket.AF_INET
            elif addrfam == "inet6":
                family = _socket.AF_INET6

            if proxycmd:
                # ProxyCommand provides the transport; AddressFamily doesn't apply here.
                sock = ProxyCommand(str(proxycmd))
            elif family is not None:
                # Enforce the requested address family by pre-connecting the socket and
                # passing it into Paramiko via sock=.
                last_err: Optional[OSError] = None
                infos = _socket.getaddrinfo(
                    connect_host, connect_port, family, _socket.SOCK_STREAM
                )
                for af, socktype, proto, _, sa in infos:
                    s = _socket.socket(af, socktype, proto)
                    if connect_timeout is not None:
                        s.settimeout(connect_timeout)
                    try:
                        s.connect(sa)
                        sock = s
                        break
                    except OSError as e:
                        last_err = e
                        try:
                            s.close()
                        except Exception:
                            pass  # nosec
                if sock is None and last_err is not None:
                    raise last_err
            elif hostkey_name != connect_host:
                # If HostKeyAlias is used, connect to HostName via a socket but
                # use HostKeyAlias for known_hosts lookups.
                sock = _socket.create_connection(
                    (connect_host, connect_port), timeout=connect_timeout
                )

        # If we created a socket (sock!=None), pass hostkey_name as hostname so
        # known_hosts lookup uses HostKeyAlias (or whatever hostkey_name resolved to).
        try:
            ssh.connect(
                hostname=hostkey_name if sock is not None else connect_host,
                port=connect_port,
                username=connect_user,
                key_filename=key_filename,
                sock=sock,
                allow_agent=True,
                look_for_keys=True,
                timeout=connect_timeout,
                banner_timeout=connect_timeout,
                auth_timeout=connect_timeout,
                passphrase=ssh_key_passphrase,
            )
        except paramiko.PasswordRequiredException as e:  # type: ignore[attr-defined]
            raise RemoteSSHKeyPassphraseRequired(
                "SSH private key is encrypted and no passphrase was provided."
            ) from e

        # If no username was explicitly provided, SSH may have selected a default.
        # We need a concrete username for the (sudo) chown step below.
        resolved_user = remote_user
        if not resolved_user:
            rc, out, err = _ssh_run(ssh, "id -un")
            if rc == 0 and out.strip():
                resolved_user = out.strip()

        sftp = ssh.open_sftp()
        rtmp: Optional[str] = None
        remote_root_tmp: Optional[str] = None
        try:
            rc, out, err = _ssh_run(ssh, "mktemp -d")
            if rc != 0:
                raise RuntimeError(f"Remote mktemp failed: {err.strip()}")
            rtmp = out.strip()
            if not rtmp:
                raise RuntimeError("Remote mktemp returned an empty path")

            # Be explicit: restrict the remote staging area to the current user.
            rc, out, err = _ssh_run(ssh, f"chmod 700 -- {shlex.quote(rtmp)}")
            if rc != 0:
                raise RuntimeError(f"Remote chmod failed: {err.strip()}")

            rapp = f"{rtmp}/enroll.pyz"
            sftp.put(str(pyz), rapp)

            # Before executing the uploaded zipapp (as root, under sudo), verify
            # on the remote that the staged bytes match what we built locally.
            # This is staging/transport integrity defence-in-depth: it fails
            # closed if the file was swapped or corrupted between upload and
            # execution. It does not (and cannot) defend against a remote that
            # is already root-compromised; see _remote_verify_pyz_sha256.
            _remote_verify_pyz_sha256(
                ssh, rapp, pyz_sha256, remote_python=remote_python
            )

            if not no_sudo:
                # The remote zipapp is staged as the SSH user, but the harvest
                # itself runs as root.  Root must not write its bundle under the
                # SSH user's mktemp directory: the root-output safety checks
                # deliberately reject user-owned parents to avoid symlink/race
                # issues.  Create a separate sudo-owned tempdir for the bundle.
                rc, out, err = _ssh_run_sudo(
                    ssh, "mktemp -d", sudo_password=sudo_password, get_pty=True
                )
                if rc != 0:
                    raise RuntimeError(f"Remote sudo mktemp failed: {err.strip()}")
                remote_root_tmp = out.strip()
                if not remote_root_tmp:
                    raise RuntimeError("Remote sudo mktemp returned an empty path")

                rc, out, err = _ssh_run_sudo(
                    ssh,
                    f"chmod 700 -- {shlex.quote(remote_root_tmp)}",
                    sudo_password=sudo_password,
                    get_pty=True,
                )
                if rc != 0:
                    raise RuntimeError(f"Remote sudo chmod failed: {err.strip()}")
                rbundle = f"{remote_root_tmp}/bundle"
            else:
                rbundle = f"{rtmp}/bundle"

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
                chown_target = remote_root_tmp or rbundle
                chown_cmd = (
                    "chown -R -- "
                    f"{shlex.quote(resolved_user)} {shlex.quote(chown_target)}"
                )
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
            cmd = f"tar -cz -C {shlex.quote(rbundle)} ."
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
            # Cleanup remote tmpdirs even on failure.  The sudo-owned harvest
            # tempdir may still be root-owned if harvest/chown failed, so remove
            # it via sudo and avoid masking the original error if cleanup fails.
            if remote_root_tmp:
                try:
                    _ssh_run_sudo(
                        ssh,
                        f"rm -rf -- {shlex.quote(remote_root_tmp)}",
                        sudo_password=sudo_password,
                        get_pty=True,
                    )
                except Exception:
                    pass  # nosec - best-effort remote cleanup
            if rtmp:
                _ssh_run(ssh, f"rm -rf -- {shlex.quote(rtmp)}")
            try:
                sftp.close()
                ssh.close()
            except Exception:
                ssh.close()
                raise RuntimeError("Something went wrong generating the harvest")

    return local_out_dir / "state.json"
