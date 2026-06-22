from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, TextIO, Union

from .fsutil import open_no_follow_path

BundlePath = Union[str, Path]
State = Dict[str, Any]

# state.json should contain structured metadata, not harvested file content.  Keep
# this generous so large package inventories still work while rejecting obvious
# accidental/malicious memory-exhaustion inputs.
MAX_STATE_JSON_BYTES = 16 * 1024 * 1024


class StateSafetyError(RuntimeError):
    """Raised when a harvest bundle's state.json is unsafe to parse."""


def state_path(bundle_dir: BundlePath) -> Path:
    """Return the canonical state.json path for a harvest bundle."""

    return Path(bundle_dir) / "state.json"


def _check_state_stat(path: Path, st: os.stat_result, *, max_bytes: int) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise StateSafetyError(f"state.json is a symlink; refusing to read: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise StateSafetyError(f"state.json is not a regular file: {path}")
    if st.st_nlink > 1:
        raise StateSafetyError(f"state.json is hardlinked; refusing to read: {path}")
    if st.st_size > max_bytes:
        raise StateSafetyError(
            f"state.json is too large to parse safely "
            f"({st.st_size} bytes > {max_bytes} bytes): {path}"
        )


def open_state_file(bundle_dir: BundlePath, *, max_bytes: int | None = None) -> TextIO:
    """Open state.json only after verifying it is safe to parse.

    Direct directory bundles are more mutable than SOPS/tar/remote bundles, so do
    not follow a symlinked state.json and do not parse special files, hardlinks, or
    unexpectedly huge inputs.  The final open also uses no-follow semantics and the
    inode is compared with the pre-open lstat result to catch swaps between the
    check and open.
    """

    if max_bytes is None:
        max_bytes = MAX_STATE_JSON_BYTES

    path = state_path(bundle_dir)
    try:
        pre = path.lstat()
    except FileNotFoundError:
        raise FileNotFoundError(f"missing state.json: {path}")

    _check_state_stat(path, pre, max_bytes=max_bytes)

    fd = -1
    try:
        fd = open_no_follow_path(str(path), write=False)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (pre.st_dev, pre.st_ino):
            raise StateSafetyError(
                f"state.json changed while it was being opened; refusing to read: {path}"
            )
        _check_state_stat(path, opened, max_bytes=max_bytes)
        f = os.fdopen(fd, "r", encoding="utf-8")
        fd = -1
        return f
    except OSError as e:
        raise StateSafetyError(f"unable to safely open state.json: {path}: {e}") from e
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def load_state(bundle_dir: BundlePath) -> State:
    """Load state.json from a harvest bundle directory."""

    with open_state_file(bundle_dir) as f:
        return json.load(f)


def write_state(
    bundle_dir: BundlePath,
    state: Mapping[str, Any],
    *,
    indent: int = 2,
    sort_keys: bool = True,
) -> Path:
    """Write state.json to a harvest bundle directory and return its path."""

    path = state_path(bundle_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd = -1
    tmp_name = ""
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent), text=True
        )
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1
            json.dump(state, f, indent=indent, sort_keys=sort_keys)
        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
    return path


def roles_from_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the roles mapping from a harvest state, or an empty mapping."""

    roles = state.get("roles")
    return dict(roles) if isinstance(roles, dict) else {}


def inventory_packages_from_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Return inventory.packages from a harvest state, or an empty mapping."""

    inventory = state.get("inventory")
    if not isinstance(inventory, dict):
        return {}
    packages = inventory.get("packages")
    return dict(packages) if isinstance(packages, dict) else {}
