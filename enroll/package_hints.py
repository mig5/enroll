from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

from .role_names import avoid_reserved_role_name


# Directories that are shared across many packages. Never attribute all unowned
# files in these trees to one single package.
SHARED_ETC_TOPDIRS = {
    "apparmor.d",
    "apt",
    "cron.d",
    "cron.daily",
    "cron.weekly",
    "cron.monthly",
    "cron.hourly",
    "default",
    "init.d",
    "logrotate.d",
    "modprobe.d",
    "network",
    "pam.d",
    "ssh",
    "ssl",
    "sudoers.d",
    "sysctl.d",
    "systemd",
    # RPM-family shared trees
    "dnf",
    "yum",
    "yum.repos.d",
    "sysconfig",
    "pki",
    "firewalld",
}


def safe_name(s: str) -> str:
    out: List[str] = []
    for ch in s:
        out.append(ch if ch.isalnum() or ch in ("_", "-") else "_")
    return "".join(out).replace("-", "_")


def role_id(raw: str) -> str:
    # normalise separators first
    s = re.sub(r"[^A-Za-z0-9]+", "_", raw)
    # split CamelCase -> snake_case
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = s.lower()
    s = re.sub(r"_+", "_", s).strip("_")
    if not re.match(r"^[a-z_]", s):
        s = "r_" + s
    return s


def role_name_from_unit(unit: str) -> str:
    base = role_id(unit.removesuffix(".service"))
    return avoid_reserved_role_name(safe_name(base), prefix="service")


def role_name_from_pkg(pkg: str) -> str:
    return avoid_reserved_role_name(safe_name(pkg), prefix="package")


def package_section_from_installations(
    installs: List[Dict[str, str]],
) -> Optional[str]:
    """Return a stable package grouping label from installed package metadata."""

    values: Set[str] = set()
    for inst in installs or []:
        value = (inst.get("section") or inst.get("group") or "").strip()
        if not value:
            continue
        if value.lower() in {"(none)", "none", "unspecified"}:
            continue
        values.add(value)

    if not values:
        return None
    return sorted(values)[0]


def hint_names(unit: str, pkgs: Set[str]) -> Set[str]:
    base = unit.removesuffix(".service")
    hints = {base}
    if "@" in base:
        hints.add(base.split("@", 1)[0])
    hints |= set(pkgs)
    hints |= {h.split(".", 1)[0] for h in list(hints) if "." in h}
    return {h for h in hints if h}


def add_pkgs_from_etc_topdirs(
    hints: Set[str], topdir_to_pkgs: Dict[str, Set[str]], pkgs: Set[str]
) -> None:
    """Expand a service's package set using package-owned /etc top-level dirs."""

    for h in hints:
        for top in (h, f"{h}.d"):
            if top in SHARED_ETC_TOPDIRS:
                continue
            for p in topdir_to_pkgs.get(top, set()):
                pkgs.add(p)


def maybe_add_specific_paths(hints: Set[str], backend) -> List[str]:
    # Delegate to backend-specific conventions (e.g. /etc/default on Debian,
    # /etc/sysconfig on Fedora/RHEL). Always include sysctl.d.
    try:
        return backend.specific_paths_for_hints(hints)
    except Exception:
        # Best-effort fallback (Debian-ish).
        paths: List[str] = []
        for h in hints:
            paths.extend(
                [
                    f"/etc/default/{h}",
                    f"/etc/init.d/{h}",
                    f"/etc/sysctl.d/{h}.conf",
                ]
            )
        return paths
