from __future__ import annotations


def get_enroll_version() -> str:
    """
    Best-effort version lookup that works when installed via:
      - poetry/pip/wheel
      - deb/rpm system packages
    Falls back to "0+unknown" when running from an unpacked source tree.
    """
    try:
        from importlib.metadata import (
            packages_distributions,
            version,
        )
    except Exception:
        # Very old Python or unusual environment
        return "unknown"

    # Map import package -> dist(s)
    dist_names = []
    try:
        dist_names = (packages_distributions() or {}).get("enroll", []) or []
    except Exception:
        dist_names = []

    # Try mapped dists first, then a reasonable default
    for dist in [*dist_names, "enroll"]:
        try:
            return version(dist)
        except Exception:
            return "unknown"
