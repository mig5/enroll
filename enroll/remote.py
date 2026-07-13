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


# Resource caps for untrusted tar extraction. These mirror the directory-bundle
# freeze limits (see manifest_safety._FREEZE_MAX_ENTRIES /
# _FREEZE_MAX_FILE_BYTES)
# so a harvest delivered as a tarball is bounded the same way as one delivered as
# a directory. The total-size cap additionally guards against a decompression
# bomb whose members are each individually under the per-file cap.
_TAR_MAX_MEMBERS = 200_000
_TAR_MAX_FILE_BYTES = 64 * 1024 * 1024
_TAR_MAX_TOTAL_BYTES = 10 * 1024 * 1024 * 1024
_TAR_MAX_COMPRESSED_BYTES = 12 * 1024 * 1024 * 1024
_TAR_MAX_PATH_DEPTH = 64


def _check_tar_download_size(size: int) -> None:
    """Reject a remote tar stream before it can exhaust local disk."""
    if size > _TAR_MAX_COMPRESSED_BYTES:
        raise RuntimeError(
            "remote harvest archive exceeds compressed download "
            f"limit ({_TAR_MAX_COMPRESSED_BYTES} bytes)"
        )


def _safe_extract_tar(tar: tarfile.TarFile, dest: Path) -> None:
    """Safely extract a tar archive into dest.

    Protects against path traversal (e.g. entries containing ../) and, as
    availability defence-in-depth, against resource-exhaustion by a structurally
    valid but abusive archive (a decompression bomb, a huge member, or millions
    of tiny members). The caps mirror the directory-bundle freeze limits so a
    tar bundle and a directory bundle are bounded the same way. A remote or
    user-supplied harvest tarball is untrusted input, so these limits keep a
    malicious archive from exhausting disk, inodes, memory, or time during local
    extraction/validation.
    """
    # Note: tar member names use POSIX separators regardless of platform.
    dest = dest.resolve()

    member_count = 0
    total_size = 0
    safe_members: list[tarfile.TarInfo] = []

    # Iterate lazily. TarFile.getmembers() first scans and materialises the
    # *entire* archive, which lets an abusive archive consume memory/CPU before
    # our member-count or size limits are checked. Keeping only the already
    # validated, bounded prefix means the limits take effect while the archive
    # is being parsed rather than after it has all been indexed.
    for m in tar:
        member_count += 1
        if member_count > _TAR_MAX_MEMBERS:
            raise RuntimeError(
                f"tar archive has too many members (> {_TAR_MAX_MEMBERS})"
            )

        name = m.name

        # Some tar implementations include a top-level '.' entry when created
        # with `tar -C <dir> .`. That's harmless and should be allowed, but it
        # still counts against the member cap so repeated '.' entries cannot be
        # used to bypass the archive-work limit.
        if name in {".", "./"}:
            continue

        # Reject absolute paths and any '..' components up front.
        p = PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts:
            raise RuntimeError(f"Unsafe tar member path: {name}")

        if len(p.parts) > _TAR_MAX_PATH_DEPTH:
            raise RuntimeError(f"tar member path is too deeply nested: {name}")

        # Refuse to extract links or device nodes from an untrusted archive.
        # (A symlink can be used to redirect subsequent writes outside dest.)
        if m.issym() or m.islnk() or m.isdev():
            raise RuntimeError(f"Refusing to extract special tar member: {name}")

        if m.isfile():
            if m.size > _TAR_MAX_FILE_BYTES:
                raise RuntimeError(f"tar member is too large: {name}")
            total_size += int(m.size)
            if total_size > _TAR_MAX_TOTAL_BYTES:
                raise RuntimeError(
                    "tar archive uncompressed size exceeds limit "
                    f"(> {_TAR_MAX_TOTAL_BYTES} bytes)"
                )

        member_path = (dest / Path(*p.parts)).resolve()
        if member_path != dest and not str(member_path).startswith(str(dest) + os.sep):
            raise RuntimeError(f"Unsafe tar member path: {name}")

        safe_members.append(m)

    # Extract members one-by-one after validation.  Pass an explicit tarfile
    # extraction filter on Python versions that support it so Python 3.12/3.13
    # do not warn about the Python 3.14 default changing.  Keep the older call
    # path for Python 3.10/3.11, where the filter argument is unavailable.
    supports_filter = hasattr(tarfile, "data_filter")
    for m in safe_members:
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


def _remote_current_uid(ssh, *, remote_python: str) -> str:
    """Return the authenticated SSH account's numeric uid.

    Use the same explicitly selected Python interpreter as the remote zipapp
    instead of relying on a shell ``id`` binary resolved through the remote
    account's PATH. The uid is used only to grant that exact account temporary
    read access to a root-created harvest archive.
    """

    script = "import os,sys;sys.stdout.write(str(os.getuid()))"
    cmd = " ".join(shlex.quote(tok) for tok in (remote_python, "-I", "-c", script))
    rc, out, err = _ssh_run(ssh, cmd, get_pty=False)
    uid = out.strip()
    if rc != 0 or not uid.isascii() or not uid.isdigit():
        raise RuntimeError(
            "Unable to determine the numeric uid of the authenticated SSH "
            "account before exposing the remote harvest archive.\n"
            f"Command: {cmd}\nExit code: {rc}\nStderr: {err.strip()}"
        )
    value = int(uid)
    if value < 0 or value > 2**32 - 1:
        raise RuntimeError(f"Remote SSH account returned an invalid uid: {uid}")
    return uid


def _verify_downloaded_archive_sha256(path: Path, expected_sha256: str) -> None:
    """Fail closed if a downloaded remote archive changed after root hashed it."""

    downloaded_sha256 = _sha256_file(path)
    if downloaded_sha256 != expected_sha256:
        raise RuntimeError(
            "Remote harvest archive integrity check failed after download: "
            "the archive changed after root packaged it. Refusing to extract "
            "potentially tampered state.\n"
            f"  expected: {expected_sha256}\n"
            f"  received: {downloaded_sha256}"
        )


def _remote_file_sha256_sudo(
    ssh,
    remote_path: str,
    *,
    remote_python: str,
    sudo_password: Optional[str],
) -> str:
    """Hash a root-owned remote file before granting the SSH user access."""

    hash_script = (
        "import hashlib,sys;"
        "h=hashlib.sha256();"
        "f=open(sys.argv[1],'rb');"
        "[h.update(c) for c in iter(lambda:f.read(1048576),b'')];"
        "sys.stdout.write(h.hexdigest())"
    )
    cmd = " ".join(
        shlex.quote(tok)
        for tok in (remote_python, "-I", "-c", hash_script, remote_path)
    )
    rc, out, err = _ssh_run_sudo(ssh, cmd, sudo_password=sudo_password, get_pty=True)
    digest = out.strip().lower()
    if rc != 0:
        raise RuntimeError(
            "Failed to hash the root-created remote harvest archive.\n"
            f"Command: sudo {cmd}\nExit code: {rc}\nStderr: {err.strip()}"
        )
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise RuntimeError(
            "Remote harvest archive integrity check returned an invalid "
            f"SHA-256 digest: {digest!r}"
        )
    return digest


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
                # Keep the root-created bundle root-owned until after it has
                # been packaged. The old flow recursively chowned the bundle to
                # the SSH user and then ran tar as that user, creating a window
                # in which the just-harvested state/artifacts could be modified
                # before Enroll downloaded them. Instead, root creates and
                # hashes the archive while it is still private. Only that one
                # archive is then made readable by the authenticated SSH uid.
                # The SSH user owns the temporary archive and could chmod/edit
                # it, so the locally downloaded bytes are required to match the
                # root-computed digest before extraction. The root-owned parent
                # remains non-writable, preventing path replacement.
                if remote_root_tmp is None:
                    raise RuntimeError(
                        "Internal error: remote root staging directory was not initialised"
                    )

                remote_tgz = f"{remote_root_tmp}/bundle.tgz"
                remote_uid = _remote_current_uid(ssh, remote_python=remote_python)
                tar_cmd = (
                    f"tar -czf {shlex.quote(remote_tgz)} "
                    f"-C {shlex.quote(rbundle)} ."
                )
                rc, out, err = _ssh_run_sudo(
                    ssh,
                    tar_cmd,
                    sudo_password=sudo_password,
                    get_pty=True,
                )
                if rc != 0:
                    raise RuntimeError(
                        "Remote root tar creation failed.\n"
                        f"Command: sudo {tar_cmd}\n"
                        f"Exit code: {rc}\n"
                        f"Stdout: {out.strip()}\n"
                        f"Stderr: {err.strip()}"
                    )

                # Set a private mode while the archive is still root-owned,
                # then hash it. Only after the trusted digest has been captured
                # do we transfer ownership of this one file to the SSH uid and
                # make the root-owned parent traversable. Unlike mode 0444, this
                # does not expose the harvest to every local account.
                secure_cmd = f"chmod 0400 -- {shlex.quote(remote_tgz)}"
                rc, out, err = _ssh_run_sudo(
                    ssh,
                    secure_cmd,
                    sudo_password=sudo_password,
                    get_pty=True,
                )
                if rc != 0:
                    raise RuntimeError(
                        "Unable to secure the root-created harvest archive.\n"
                        f"Command: sudo {secure_cmd}\n"
                        f"Exit code: {rc}\n"
                        f"Stdout: {out.strip()}\n"
                        f"Stderr: {err.strip()}"
                    )

                expected_archive_sha256 = _remote_file_sha256_sudo(
                    ssh,
                    remote_tgz,
                    remote_python=remote_python,
                    sudo_password=sudo_password,
                )

                for expose_cmd in (
                    f"chown -- {shlex.quote(remote_uid)} {shlex.quote(remote_tgz)}",
                    f"chmod 0711 -- {shlex.quote(remote_root_tmp)}",
                ):
                    rc, out, err = _ssh_run_sudo(
                        ssh,
                        expose_cmd,
                        sudo_password=sudo_password,
                        get_pty=True,
                    )
                    if rc != 0:
                        raise RuntimeError(
                            "Unable to expose the integrity-protected harvest "
                            "archive to the authenticated SSH account.\n"
                            f"Command: sudo {expose_cmd}\n"
                            f"Exit code: {rc}\n"
                            f"Stdout: {out.strip()}\n"
                            f"Stderr: {err.strip()}"
                        )

                def _download_progress(transferred: int, _total: int) -> None:
                    _check_tar_download_size(transferred)

                sftp.get(
                    remote_tgz,
                    str(local_tgz),
                    callback=_download_progress,
                )
                _verify_downloaded_archive_sha256(local_tgz, expected_archive_sha256)
            else:
                # Without sudo there is no privilege boundary between the SSH
                # user and the harvested bundle, so stream it directly as
                # before.
                cmd = f"tar -cz -C {shlex.quote(rbundle)} ."
                _stdin, stdout, stderr = ssh.exec_command(cmd)  # nosec
                downloaded = 0
                with open(local_tgz, "wb") as f:
                    while True:
                        chunk = stdout.read(1024 * 128)
                        if not chunk:
                            break
                        downloaded += len(chunk)
                        try:
                            _check_tar_download_size(downloaded)
                        except RuntimeError:
                            try:
                                stdout.channel.close()
                            except Exception:
                                pass  # nosec - best-effort remote stream abort
                            raise
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
            # tempdir remains root-owned throughout the sudo flow, so remove
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
