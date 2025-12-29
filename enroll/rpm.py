from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec
from typing import Dict, List, Optional, Set, Tuple


def _run(
    cmd: list[str], *, allow_fail: bool = False, merge_err: bool = False
) -> tuple[int, str]:
    """Run a command and return (rc, stdout).

    If merge_err is True, stderr is merged into stdout to preserve ordering.
    """
    p = subprocess.run(
        cmd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=(subprocess.STDOUT if merge_err else subprocess.PIPE),
    )  # nosec
    out = p.stdout or ""
    if (not allow_fail) and p.returncode != 0:
        err = "" if merge_err else (p.stderr or "")
        raise RuntimeError(f"Command failed: {cmd}\n{err}{out}")
    return p.returncode, out


def rpm_owner(path: str) -> Optional[str]:
    """Return owning package name for a path, or None if unowned."""
    if not path:
        return None
    rc, out = _run(
        ["rpm", "-qf", "--qf", "%{NAME}\n", path], allow_fail=True, merge_err=True
    )
    if rc != 0:
        return None
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if "is not owned" in line:
            return None
        # With --qf we expect just the package name.
        if re.match(r"^[A-Za-z0-9_.+:-]+$", line):
            # Strip any accidental epoch/name-version-release output.
            return line.split(":", 1)[-1].strip() if line else None
    return None


_ARCH_SUFFIXES = {
    "noarch",
    "x86_64",
    "i686",
    "aarch64",
    "armv7hl",
    "ppc64le",
    "s390x",
    "riscv64",
}


def _strip_arch(token: str) -> str:
    """Strip a trailing .ARCH from a yum/dnf package token."""
    t = token.strip()
    if "." not in t:
        return t
    head, tail = t.rsplit(".", 1)
    if tail in _ARCH_SUFFIXES:
        return head
    return t


def list_manual_packages() -> List[str]:
    """Return packages considered "user-installed" on RPM-based systems.

    Best-effort:
      1) dnf repoquery --userinstalled
      2) dnf history userinstalled
      3) yum history userinstalled

    If none are available, returns an empty list.
    """

    def _dedupe(pkgs: List[str]) -> List[str]:
        return sorted({p for p in (pkgs or []) if p})

    if shutil.which("dnf"):
        # Prefer a machine-friendly output.
        for cmd in (
            ["dnf", "-q", "repoquery", "--userinstalled", "--qf", "%{name}\n"],
            ["dnf", "-q", "repoquery", "--userinstalled"],
        ):
            rc, out = _run(cmd, allow_fail=True, merge_err=True)
            if rc == 0 and out.strip():
                pkgs = []
                for line in out.splitlines():
                    line = line.strip()
                    if not line or line.startswith("Loaded plugins"):
                        continue
                    pkgs.append(_strip_arch(line.split()[0]))
                if pkgs:
                    return _dedupe(pkgs)

        # Fallback
        rc, out = _run(
            ["dnf", "-q", "history", "userinstalled"], allow_fail=True, merge_err=True
        )
        if rc == 0 and out.strip():
            pkgs = []
            for line in out.splitlines():
                line = line.strip()
                if not line or line.startswith("Installed") or line.startswith("Last"):
                    continue
                # Often: "vim-enhanced.x86_64"
                tok = line.split()[0]
                pkgs.append(_strip_arch(tok))
            if pkgs:
                return _dedupe(pkgs)

    if shutil.which("yum"):
        rc, out = _run(
            ["yum", "-q", "history", "userinstalled"], allow_fail=True, merge_err=True
        )
        if rc == 0 and out.strip():
            pkgs = []
            for line in out.splitlines():
                line = line.strip()
                if (
                    not line
                    or line.startswith("Installed")
                    or line.startswith("Loaded")
                ):
                    continue
                tok = line.split()[0]
                pkgs.append(_strip_arch(tok))
            if pkgs:
                return _dedupe(pkgs)

    return []


def list_installed_packages() -> Dict[str, List[Dict[str, str]]]:
    """Return mapping of installed package name -> installed instances.

    Uses `rpm -qa` and is expected to work on RHEL/Fedora-like systems.

    Output format:
      {"pkg": [{"version": "...", "arch": "..."}, ...], ...}

    The version string is formatted as:
      - "<version>-<release>" for typical packages
      - "<epoch>:<version>-<release>" if a non-zero epoch is present
    """

    try:
        _, out = _run(
            [
                "rpm",
                "-qa",
                "--qf",
                "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n",
            ],
            allow_fail=False,
            merge_err=True,
        )
    except Exception:
        return {}

    pkgs: Dict[str, List[Dict[str, str]]] = {}
    for raw in (out or "").splitlines():
        line = raw.strip("\n")
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        name, epoch, ver, rel, arch = [p.strip() for p in parts[:5]]
        if not name or not ver:
            continue

        # Normalise epoch.
        epoch = epoch.strip()
        if epoch.lower() in ("(none)", "none", ""):
            epoch = "0"

        v = f"{ver}-{rel}" if rel else ver
        if epoch and epoch.isdigit() and epoch != "0":
            v = f"{epoch}:{v}"

        pkgs.setdefault(name, []).append({"version": v, "arch": arch})

    for k in list(pkgs.keys()):
        pkgs[k] = sorted(
            pkgs[k], key=lambda x: (x.get("arch") or "", x.get("version") or "")
        )
    return pkgs


def _walk_etc_files() -> List[str]:
    out: List[str] = []
    for dirpath, _, filenames in os.walk("/etc"):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            out.append(p)
    return out


def build_rpm_etc_index() -> (
    Tuple[Set[str], Dict[str, str], Dict[str, Set[str]], Dict[str, List[str]]]
):
    """Best-effort equivalent of build_dpkg_etc_index for RPM systems.

    This builds indexes by walking the live /etc tree and querying RPM ownership
    for each file.

    Returns:
      owned_etc_paths: set of /etc paths owned by rpm
      etc_owner_map: /etc/path -> pkg
      topdir_to_pkgs: "nginx" -> {"nginx", ...} based on /etc/<topdir>/...
      pkg_to_etc_paths: pkg -> list of owned /etc paths
    """

    owned: Set[str] = set()
    owner: Dict[str, str] = {}
    topdir_to_pkgs: Dict[str, Set[str]] = {}
    pkg_to_etc: Dict[str, List[str]] = {}

    paths = _walk_etc_files()

    # Query in chunks to avoid excessive process spawns.
    chunk_size = 250

    not_owned_re = re.compile(
        r"^file\s+(?P<path>.+?)\s+is\s+not\s+owned\s+by\s+any\s+package", re.IGNORECASE
    )

    for i in range(0, len(paths), chunk_size):
        chunk = paths[i : i + chunk_size]
        rc, out = _run(
            ["rpm", "-qf", "--qf", "%{NAME}\n", *chunk],
            allow_fail=True,
            merge_err=True,
        )

        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        # Heuristic: rpm prints one output line per input path. If that isn't
        # true (warnings/errors), fall back to per-file queries for this chunk.
        if len(lines) != len(chunk):
            for p in chunk:
                pkg = rpm_owner(p)
                if not pkg:
                    continue
                owned.add(p)
                owner.setdefault(p, pkg)
                pkg_to_etc.setdefault(pkg, []).append(p)
                parts = p.split("/", 3)
                if len(parts) >= 3 and parts[2]:
                    topdir_to_pkgs.setdefault(parts[2], set()).add(pkg)
            continue

        for pth, line in zip(chunk, lines):
            if not line:
                continue
            if not_owned_re.match(line) or "is not owned" in line:
                continue
            pkg = line.split()[0].strip()
            if not pkg:
                continue
            owned.add(pth)
            owner.setdefault(pth, pkg)
            pkg_to_etc.setdefault(pkg, []).append(pth)
            parts = pth.split("/", 3)
            if len(parts) >= 3 and parts[2]:
                topdir_to_pkgs.setdefault(parts[2], set()).add(pkg)

    for k, v in list(pkg_to_etc.items()):
        pkg_to_etc[k] = sorted(set(v))

    return owned, owner, topdir_to_pkgs, pkg_to_etc


def rpm_config_files(pkg: str) -> Set[str]:
    """Return config files for a package (rpm -qc)."""
    rc, out = _run(["rpm", "-qc", pkg], allow_fail=True, merge_err=True)
    if rc != 0:
        return set()
    files: Set[str] = set()
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("/"):
            files.add(line)
    return files


def rpm_modified_files(pkg: str) -> Set[str]:
    """Return files reported as modified by rpm verification (rpm -V).

    rpm -V only prints lines for differences/missing files.
    """
    rc, out = _run(["rpm", "-V", pkg], allow_fail=True, merge_err=True)
    # rc is non-zero when there are differences; we still want the output.
    files: Set[str] = set()
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Typical forms:
        #   S.5....T.  c /etc/foo.conf
        #   missing   /etc/bar
        m = re.search(r"\s(/\S+)$", line)
        if m:
            files.add(m.group(1))
            continue
        if line.startswith("missing"):
            parts = line.split()
            if parts and parts[-1].startswith("/"):
                files.add(parts[-1])
    return files
