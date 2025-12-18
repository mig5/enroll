from __future__ import annotations

import os
import shutil
import subprocess  # nosec
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional


class SopsError(RuntimeError):
    pass


def find_sops_cmd() -> Optional[str]:
    """Return the `sops` executable path if present on PATH."""
    return shutil.which("sops")


def require_sops_cmd() -> str:
    exe = find_sops_cmd()
    if not exe:
        raise SopsError(
            "--sops was requested but `sops` was not found on PATH. "
            "Install sops and ensure it is available as `sops`."
        )
    return exe


def _pgp_arg(fingerprints: Iterable[str]) -> str:
    fps = [f.strip() for f in fingerprints if f and f.strip()]
    if not fps:
        raise SopsError("No GPG fingerprints provided for --sops")
    # sops accepts a comma-separated list for --pgp.
    return ",".join(fps)


def encrypt_file_binary(
    src_path: Path,
    dst_path: Path,
    *,
    pgp_fingerprints: List[str],
    mode: int = 0o600,
) -> None:
    """Encrypt src_path with sops (binary) and write to dst_path atomically."""
    sops = require_sops_cmd()
    src_path = Path(src_path)
    dst_path = Path(dst_path)
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    res = subprocess.run(
        [
            sops,
            "--encrypt",
            "--input-type",
            "binary",
            "--output-type",
            "binary",
            "--pgp",
            _pgp_arg(pgp_fingerprints),
            str(src_path),
        ],
        capture_output=True,
        check=False,
    )  # nosec
    if res.returncode != 0:
        raise SopsError(
            "sops encryption failed:\n"
            f"  cmd: {sops} --encrypt ... {src_path}\n"
            f"  rc: {res.returncode}\n"
            f"  stderr: {res.stderr.decode('utf-8', errors='replace').strip()}"
        )

    # Write atomically in the destination directory.
    fd, tmp = tempfile.mkstemp(prefix=".enroll-sops-", dir=str(dst_path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(res.stdout)
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, dst_path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def decrypt_file_binary_to(
    src_path: Path,
    dst_path: Path,
    *,
    mode: int = 0o600,
) -> None:
    """Decrypt a sops-encrypted file (binary) into dst_path."""
    sops = require_sops_cmd()
    src_path = Path(src_path)
    dst_path = Path(dst_path)
    dst_path.parent.mkdir(parents=True, exist_ok=True)

    res = subprocess.run(
        [
            sops,
            "--decrypt",
            "--input-type",
            "binary",
            "--output-type",
            "binary",
            str(src_path),
        ],
        capture_output=True,
        check=False,
    )  # nosec
    if res.returncode != 0:
        raise SopsError(
            "sops decryption failed:\n"
            f"  cmd: {sops} --decrypt ... {src_path}\n"
            f"  rc: {res.returncode}\n"
            f"  stderr: {res.stderr.decode('utf-8', errors='replace').strip()}"
        )

    fd, tmp = tempfile.mkstemp(prefix=".enroll-sops-", dir=str(dst_path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(res.stdout)
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, dst_path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
