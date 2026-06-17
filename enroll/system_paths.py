from __future__ import annotations

import glob
import os
import re
from typing import Dict, List, Set, Tuple


ALLOWED_UNOWNED_EXTS = {
    ".cfg",
    ".cnf",
    ".conf",
    ".ini",
    ".json",
    ".link",
    ".mount",
    ".netdev",
    ".network",
    ".path",
    ".rules",
    ".service",
    ".socket",
    ".target",
    ".timer",
    ".toml",
    ".yaml",
    ".yml",
    "",  # allow extensionless (common in /etc/default and /etc/init.d)
}

MAX_FILES_CAP = 4000
MAX_UNOWNED_FILES_PER_ROLE = 500


def is_confish(path: str) -> bool:
    base = os.path.basename(path)
    _, ext = os.path.splitext(base)
    return ext in ALLOWED_UNOWNED_EXTS


def scan_unowned_under_roots(
    roots: List[str],
    owned_etc: Set[str],
    limit: int = MAX_UNOWNED_FILES_PER_ROLE,
    *,
    confish_only: bool = True,
) -> List[str]:
    found: List[str] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            if len(found) >= limit:
                return found
            for fn in filenames:
                if len(found) >= limit:
                    return found
                p = os.path.join(dirpath, fn)
                if not p.startswith("/etc/"):
                    continue
                if p in owned_etc:
                    continue
                if not os.path.isfile(p) or os.path.islink(p):
                    continue
                if confish_only and not is_confish(p):
                    continue
                found.append(p)
    return found


def topdirs_for_package(pkg: str, pkg_to_etc_paths: Dict[str, List[str]]) -> Set[str]:
    topdirs: Set[str] = set()
    for path in pkg_to_etc_paths.get(pkg, []):
        parts = path.split("/", 3)
        if len(parts) >= 3 and parts[1] == "etc" and parts[2]:
            topdirs.add(parts[2])
    return topdirs


_APT_SOURCE_GLOBS = [
    "/etc/apt/sources.list",
    "/etc/apt/sources.list.d/*.list",
    "/etc/apt/sources.list.d/*.sources",
]

_SYSTEM_CAPTURE_GLOBS: List[Tuple[str, str]] = [
    ("/etc/fstab", "system_mounts"),
    ("/etc/crypttab", "system_mounts"),
    ("/etc/sysctl.conf", "system_sysctl"),
    ("/etc/sysctl.d/*", "system_sysctl"),
    ("/etc/modprobe.d/*", "system_modprobe"),
    ("/etc/modules", "system_modprobe"),
    ("/etc/modules-load.d/*", "system_modprobe"),
    ("/etc/netplan/*", "system_network"),
    ("/etc/systemd/network/*", "system_network"),
    ("/etc/network/interfaces", "system_network"),
    ("/etc/network/interfaces.d/*", "system_network"),
    ("/etc/resolvconf.conf", "system_network"),
    ("/etc/resolvconf/resolv.conf.d/*", "system_network"),
    ("/etc/NetworkManager/system-connections/*", "system_network"),
    ("/etc/sysconfig/network*", "system_network"),
    ("/etc/sysconfig/network-scripts/*", "system_network"),
    ("/etc/nftables.conf", "system_firewall"),
    ("/etc/nftables.d/*", "system_firewall"),
    ("/etc/iptables/rules.v4", "system_firewall"),
    ("/etc/iptables/rules.v6", "system_firewall"),
    ("/etc/sysconfig/iptables", "system_firewall"),
    ("/etc/sysconfig/ip6tables", "system_firewall"),
    ("/etc/ipset.conf", "system_firewall"),
    ("/etc/ipset/*", "system_firewall"),
    ("/etc/ipset.d/*", "system_firewall"),
    ("/etc/sysconfig/ipset", "system_firewall"),
    ("/etc/default/ipset", "system_firewall"),
    ("/etc/ufw/*", "system_firewall"),
    ("/etc/default/ufw", "system_firewall"),
    ("/etc/firewalld/*", "system_firewall"),
    ("/etc/firewalld/zones/*", "system_firewall"),
    ("/etc/selinux/config", "system_security"),
    ("/etc/rc.local", "system_rc"),
]

_PERSISTENT_IPTABLES_V4_GLOBS = [
    "/etc/iptables/rules.v4",
    "/etc/sysconfig/iptables",
]

_PERSISTENT_IPTABLES_V6_GLOBS = [
    "/etc/iptables/rules.v6",
    "/etc/sysconfig/ip6tables",
]

_PERSISTENT_IPSET_GLOBS = [
    "/etc/ipset.conf",
    "/etc/ipset/*",
    "/etc/ipset.d/*",
    "/etc/sysconfig/ipset",
]


def persistent_ipset_globs() -> List[str]:
    return list(_PERSISTENT_IPSET_GLOBS)


def persistent_iptables_v4_globs() -> List[str]:
    return list(_PERSISTENT_IPTABLES_V4_GLOBS)


def persistent_iptables_v6_globs() -> List[str]:
    return list(_PERSISTENT_IPTABLES_V6_GLOBS)


def persistent_firewall_files(globs: List[str]) -> List[str]:
    """Return persistent firewall files matching ``globs``."""

    seen: Set[str] = set()
    out: List[str] = []
    for spec in globs:
        for path in iter_matching_files(spec):
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return sorted(out)


def iter_matching_files(spec: str, *, cap: int = MAX_FILES_CAP) -> List[str]:
    """Expand a glob spec and also walk directories to collect files."""

    out: List[str] = []
    for p in glob.glob(spec):
        if len(out) >= cap:
            break
        if os.path.islink(p):
            continue
        if os.path.isfile(p):
            out.append(p)
            continue
        if os.path.isdir(p):
            for dirpath, _, filenames in os.walk(p):
                for fn in filenames:
                    if len(out) >= cap:
                        break
                    fp = os.path.join(dirpath, fn)
                    if os.path.islink(fp) or not os.path.isfile(fp):
                        continue
                    out.append(fp)
                if len(out) >= cap:
                    break
    return out


def parse_apt_signed_by(source_files: List[str]) -> Set[str]:
    """Return absolute keyring paths referenced via signed-by / Signed-By."""

    out: Set[str] = set()
    re_signed_by = re.compile(r"signed-by\s*=\s*([^\]\s]+)", re.IGNORECASE)
    re_signed_by_hdr = re.compile(r"^\s*Signed-By\s*:\s*(.+)$", re.IGNORECASE)

    for sf in source_files:
        try:
            with open(sf, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue

                    m = re_signed_by_hdr.match(line)
                    if m:
                        val = m.group(1).strip()
                        if val.startswith("|"):
                            continue
                        toks = re.split(r"[\s,]+", val)
                        for t in toks:
                            if t.startswith("/"):
                                out.add(t)
                        continue

                    if "[" in line and "]" in line:
                        bracket = line.split("[", 1)[1].split("]", 1)[0]
                        for mm in re_signed_by.finditer(bracket):
                            val = mm.group(1).strip().strip("\"'")
                            for t in re.split(r"[\s,]+", val):
                                if t.startswith("/"):
                                    out.add(t)
                        continue

                    for mm in re_signed_by.finditer(line):
                        val = mm.group(1).strip().strip("\"'")
                        for t in re.split(r"[\s,]+", val):
                            if t.startswith("/"):
                                out.add(t)
        except OSError:
            continue

    return out


def iter_apt_capture_paths() -> List[Tuple[str, str]]:
    """Return (path, reason) pairs for APT configuration."""

    reasons: Dict[str, str] = {}

    if os.path.isdir("/etc/apt"):
        for dirpath, _, filenames in os.walk("/etc/apt"):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                reasons.setdefault(p, "apt_config")

    apt_sources: List[str] = []
    for g in _APT_SOURCE_GLOBS:
        apt_sources.extend(iter_matching_files(g))
    for p in sorted(set(apt_sources)):
        reasons[p] = "apt_source"

    for g in (
        "/etc/apt/trusted.gpg",
        "/etc/apt/trusted.gpg.d/*",
        "/etc/apt/keyrings/*",
    ):
        for p in iter_matching_files(g):
            reasons[p] = "apt_keyring"

    signed_by = parse_apt_signed_by(sorted(set(apt_sources)))
    for p in sorted(signed_by):
        if os.path.islink(p) or not os.path.isfile(p):
            continue
        if p.startswith("/etc/apt/"):
            reasons[p] = "apt_keyring"
        else:
            reasons[p] = "apt_signed_by_keyring"

    return [(p, reasons[p]) for p in sorted(reasons.keys())]


def iter_dnf_capture_paths() -> List[Tuple[str, str]]:
    """Return (path, reason) pairs for DNF/YUM configuration on RPM systems."""

    reasons: Dict[str, str] = {}

    for root, tag in (
        ("/etc/dnf", "dnf_config"),
        ("/etc/yum", "yum_config"),
    ):
        if os.path.isdir(root):
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    p = os.path.join(dirpath, fn)
                    if os.path.islink(p) or not os.path.isfile(p):
                        continue
                    reasons.setdefault(p, tag)

    for p in iter_matching_files("/etc/yum.conf"):
        reasons[p] = "yum_conf"
    for p in iter_matching_files("/etc/yum.repos.d/*.repo"):
        reasons[p] = "yum_repo"
    for p in iter_matching_files("/etc/pki/rpm-gpg/*"):
        reasons[p] = "rpm_gpg_key"

    return [(p, reasons[p]) for p in sorted(reasons.keys())]


def iter_system_capture_paths() -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    for spec, reason in _SYSTEM_CAPTURE_GLOBS:
        for path in iter_matching_files(spec):
            if path in seen:
                continue
            seen.add(path)
            out.append((path, reason))
    return sorted(out, key=lambda x: x[0])
