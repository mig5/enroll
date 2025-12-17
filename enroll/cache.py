from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


def _safe_component(s: str) -> str:
    s = s.strip()
    if not s:
        return "unknown"
    s = re.sub(r"[^A-Za-z0-9_.-]+", "_", s)
    s = re.sub(r"_+", "_", s)
    return s[:64]


def enroll_cache_dir() -> Path:
    """Return the base cache directory for enroll.

    We default to ~/.local/cache to match common Linux conventions in personal
    homedirs, but honour XDG_CACHE_HOME if set.
    """
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        root = Path(base).expanduser()
    else:
        root = Path.home() / ".local" / "cache"
    return root / "enroll"


@dataclass(frozen=True)
class HarvestCache:
    """A locally-persistent directory that holds a harvested bundle."""

    dir: Path

    @property
    def state_json(self) -> Path:
        return self.dir / "state.json"


def _ensure_dir_secure(path: Path) -> None:
    """Create a directory with restrictive permissions; refuse symlinks."""
    # Refuse a symlink at the leaf.
    if path.exists() and path.is_symlink():
        raise RuntimeError(f"Refusing to use symlink path: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError:
        # Best-effort; on some FS types chmod may fail.
        pass


def new_harvest_cache_dir(*, hint: Optional[str] = None) -> HarvestCache:
    """Create a new, unpredictable harvest directory under the user's cache.

    This mitigates pre-guessing attacks (e.g. an attacker creating a directory
    in advance in a shared temp location) by creating the bundle directory under
    the user's home and using mkdtemp() randomness.
    """
    base = enroll_cache_dir() / "harvest"
    _ensure_dir_secure(base)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = _safe_component(hint or "harvest")
    prefix = f"{ts}-{safe}-"

    # mkdtemp creates a new directory with a random suffix.
    d = Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return HarvestCache(dir=d)
