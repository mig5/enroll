from __future__ import annotations

import glob
import hashlib
import os
import subprocess  # nosec
from typing import Dict, List, Optional, Set, Tuple

_DIVERSION_PREFIX = "diversion by "


def _run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, check=False, text=True, capture_output=True)  # nosec
    if p.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{p.stderr}")
    return p.stdout


def dpkg_owner(path: str) -> Optional[str]:
    p = subprocess.run(["dpkg", "-S", path], text=True, capture_output=True)  # nosec
    if p.returncode != 0:
        return None

    for raw in (p.stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        # dpkg diversion chatter; not an ownership line
        if line.startswith(_DIVERSION_PREFIX):
            continue

        # Expected: "<pkg>[, <pkg2>...][:<arch>]: <path>"
        if ":" not in line:
            continue

        left, _ = line.split(":", 1)

        # If multiple pkgs listed, pick the first (common case is just one)
        left = left.split(",", 1)[0].strip()

        # Strip any ":arch" suffix from left side
        pkg = left.split(":", 1)[0].strip()

        if pkg and not pkg.startswith(_DIVERSION_PREFIX):
            return pkg

    return None


def list_manual_packages() -> List[str]:
    """Return packages marked as manually installed (apt-mark showmanual)."""
    p = subprocess.run(
        ["apt-mark", "showmanual"], text=True, capture_output=True
    )  # nosec
    if p.returncode != 0:
        return []
    pkgs: List[str] = []
    for line in (p.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pkgs.append(line)
    return sorted(set(pkgs))


def build_dpkg_etc_index(
    info_dir: str = "/var/lib/dpkg/info",
) -> Tuple[Set[str], Dict[str, str], Dict[str, Set[str]], Dict[str, List[str]]]:
    """
    Returns:
      owned_etc_paths: set of /etc paths owned by dpkg
      etc_owner_map: /etc/path -> pkg
      topdir_to_pkgs: "nginx" -> {"nginx-common", ...} based on /etc/<topdir>/...
      pkg_to_etc_paths: pkg -> list of /etc paths it installs
    """
    owned: Set[str] = set()
    owner: Dict[str, str] = {}
    topdir_to_pkgs: Dict[str, Set[str]] = {}
    pkg_to_etc: Dict[str, List[str]] = {}

    for list_path in glob.glob(os.path.join(info_dir, "*.list")):
        pkg_raw = os.path.basename(list_path)[:-5]  # strip ".list"
        pkg = pkg_raw.split(":", 1)[0]  # drop arch suffix if present

        etc_paths: List[str] = []
        try:
            with open(list_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    p = line.rstrip("\n")
                    if not p.startswith("/etc/"):
                        continue
                    owned.add(p)
                    owner.setdefault(p, pkg)
                    etc_paths.append(p)

                    parts = p.split("/", 3)
                    if len(parts) >= 3 and parts[2]:
                        top = parts[2]
                        topdir_to_pkgs.setdefault(top, set()).add(pkg)
        except FileNotFoundError:
            continue

        if etc_paths:
            pkg_to_etc.setdefault(pkg, []).extend(etc_paths)

    for k, v in list(pkg_to_etc.items()):
        pkg_to_etc[k] = sorted(set(v))

    return owned, owner, topdir_to_pkgs, pkg_to_etc


def parse_status_conffiles(
    status_path: str = "/var/lib/dpkg/status",
) -> Dict[str, Dict[str, str]]:
    """
    pkg -> { "/etc/foo": md5hex, ... } based on dpkg status "Conffiles" field.
    This md5 is the packaged baseline for the conffile.
    """
    out: Dict[str, Dict[str, str]] = {}

    cur: Dict[str, str] = {}
    key: Optional[str] = None

    def flush() -> None:
        pkg = cur.get("Package")
        if not pkg:
            return
        raw = cur.get("Conffiles")
        if not raw:
            return
        m: Dict[str, str] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith("/"):
                m[parts[0]] = parts[1]
        if m:
            out[pkg] = m

    with open(status_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip() == "":
                if cur:
                    flush()
                cur = {}
                key = None
                continue
            if line[0].isspace() and key:
                cur[key] += line
            else:
                if ":" in line:
                    k, v = line.split(":", 1)
                    key = k
                    cur[key] = v.lstrip()

    if cur:
        flush()
    return out


def read_pkg_md5sums(pkg: str) -> Dict[str, str]:
    """
    relpath -> md5hex from /var/lib/dpkg/info/<pkg>.md5sums
    relpath has no leading slash, e.g. 'etc/nginx/nginx.conf'
    """
    path = f"/var/lib/dpkg/info/{pkg}.md5sums"
    if not os.path.exists(path):
        return {}
    m: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            md5, rel = line.split(None, 1)
            m[rel.strip()] = md5.strip()
    return m


def file_md5(path: str) -> str:
    h = hashlib.md5()  # nosec
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stat_triplet(path: str) -> Tuple[str, str, str]:
    st = os.stat(path, follow_symlinks=True)
    mode = oct(st.st_mode & 0o777)[2:].zfill(4)

    import pwd, grp

    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return owner, group, mode
