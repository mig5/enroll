from __future__ import annotations

import configparser
import os
import re
import stat
import shutil
import subprocess  # nosec
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .fsutil import (
    is_dir_no_symlink_components,
    open_no_follow_path,
    path_has_symlink_component,
)


@dataclass
class FlatpakInstall:
    name: str
    method: str
    remote: Optional[str] = None
    branch: Optional[str] = None
    arch: Optional[str] = None
    kind: Optional[str] = None
    ref: Optional[str] = None
    user: Optional[str] = None
    home: Optional[str] = None
    source: str = "filesystem"


@dataclass
class FlatpakRemote:
    name: str
    method: str
    url: str
    user: Optional[str] = None
    home: Optional[str] = None
    source: str = "filesystem"


@dataclass
class SnapInstall:
    name: str
    channel: Optional[str] = None
    revision: Optional[int] = None
    classic: bool = False
    devmode: bool = False
    dangerous: bool = False
    notes: List[str] = field(default_factory=list)
    source: str = "snap-list"


@dataclass
class UserRecord:
    name: str
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str
    primary_group: str
    supplementary_groups: List[str]
    ssh_files: List[str]
    flatpaks: List[FlatpakInstall] = field(default_factory=list)


def parse_login_defs(path: str = "/etc/login.defs") -> Dict[str, int]:
    vals: Dict[str, int] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] in {
                    "UID_MIN",
                    "UID_MAX",
                    "SYS_UID_MIN",
                    "SYS_UID_MAX",
                }:
                    try:
                        vals[parts[0]] = int(parts[1])
                    except ValueError:
                        continue
    except FileNotFoundError:
        pass
    return vals


def parse_passwd(
    path: str = "/etc/passwd",
) -> List[Tuple[str, int, int, str, str, str]]:
    rows: List[Tuple[str, int, int, str, str, str]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name = parts[0]
            try:
                uid = int(parts[2])
                gid = int(parts[3])
            except ValueError:
                continue
            gecos = parts[4]
            home = parts[5]
            shell = parts[6]
            rows.append((name, uid, gid, gecos, home, shell))
    return rows


def parse_group(
    path: str = "/etc/group",
) -> Tuple[Dict[int, str], Dict[str, int], Dict[str, Set[str]]]:
    gid_to_name: Dict[int, str] = {}
    name_to_gid: Dict[str, int] = {}
    members: Dict[str, Set[str]] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            name = parts[0]
            try:
                gid = int(parts[2])
            except ValueError:
                continue
            mem = set([m for m in parts[3].split(",") if m])
            gid_to_name[gid] = name
            name_to_gid[name] = gid
            members[name] = mem
    return gid_to_name, name_to_gid, members


def is_human_user(uid: int, shell: str, uid_min: int) -> bool:
    if uid < uid_min:
        return False
    shell = (shell or "").strip()
    if shell in {"/usr/sbin/nologin", "/usr/bin/nologin", "/bin/false"}:
        return False
    return True


def find_user_ssh_files(home: str) -> List[str]:
    sshdir = os.path.join(home, ".ssh")
    out: List[str] = []
    # ``os.path.isdir`` follows symlinks, so a user who replaces ``~/.ssh``
    # with a link to a sensitive directory (e.g. /etc/ssl/private) could
    # otherwise have a regular file inside it harvested through the symlinked
    # parent.  Refuse a symlinked .ssh outright; capture_file() applies the
    # same parent-symlink protection at copy time as defense in depth.
    if os.path.islink(sshdir) or not os.path.isdir(sshdir):
        return out

    ak = os.path.join(sshdir, "authorized_keys")
    if os.path.isfile(ak) and not os.path.islink(ak):
        out.append(ak)

    return sorted(set(out))


def _read_first_existing_text(
    paths: List[str], *, max_bytes: int = 8192
) -> Optional[str]:
    """Read the first small regular text file without following symlinks.

    Per-user Flatpak metadata lives under user-controlled home directories.
    When Enroll is run as root, plain ``open()`` would let a user replace
    ``active/origin`` or ``repo/config`` with a symlink to a privileged file and
    have its contents copied into state.json.  Use the same no-symlink component
    invariant as the normal harvester, require a regular file, and cap reads to
    avoid device/large-file DoS.
    """

    for path in paths:
        fd: Optional[int] = None
        try:
            fd = open_no_follow_path(path)
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_nlink > 1
                or st.st_size > max_bytes
            ):
                continue
            data = os.read(fd, max_bytes + 1)
            if len(data) > max_bytes:
                continue
            value = data.decode("utf-8", errors="replace").strip()
            if value:
                return value
        except OSError:
            continue
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
    return None


def _parse_flatpak_ref(
    ref: str,
) -> Tuple[Optional[str], str, Optional[str], Optional[str]]:
    """Return (kind, name, arch, branch) for a Flatpak ref.

    refs look like app/org.example.App/x86_64/stable or
    runtime/org.example.Platform/x86_64/23.08. If the value is already just an
    application/runtime ID, keep it as the name and leave the other fields empty.
    """
    parts = [p for p in (ref or "").strip().split("/") if p]
    if len(parts) >= 4 and parts[0] in {"app", "runtime"}:
        return parts[0], parts[1], parts[2], parts[3]
    return None, (ref or "").strip(), None, None


def _parse_plain_flatpak_list_output(
    output: str,
    *,
    method: str,
    user: Optional[str] = None,
    home: Optional[str] = None,
) -> List[FlatpakInstall]:
    """Parse default `flatpak list` table output.

    Example:
    Name              Application ID                  Version  Branch  Installation
    OnionShare        org.onionshare.OnionShare       2.6.4    stable  system
    """
    out: List[FlatpakInstall] = []
    seen: Set[
        Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]]
    ] = set()
    id_re = re.compile(r"\b(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9_-]+\b")
    for line in output.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        if "Application ID" in line and "Installation" in line:
            continue
        match = id_re.search(line)
        if not match:
            continue
        name = match.group(0)
        tail = line[match.end() :].split()
        installation = tail[-1] if tail else ""
        if installation in {"system", "user"} and installation != method:
            continue
        branch = None
        if len(tail) >= 2 and tail[-1] in {"system", "user"}:
            branch = tail[-2]
        elif tail:
            branch = tail[-1]

        key = (name, None, branch, None, None)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            FlatpakInstall(
                name=name,
                method=method,
                remote=None,
                branch=branch,
                arch=None,
                kind=None,
                ref=None,
                user=user,
                home=home,
                source="flatpak-list",
            )
        )
    return sorted(out, key=lambda f: (f.name, f.branch or ""))


def _parse_flatpak_list_output(
    output: str,
    *,
    method: str,
    columns: Optional[Tuple[str, ...]] = None,
    user: Optional[str] = None,
    home: Optional[str] = None,
) -> List[FlatpakInstall]:
    """Parse Flatpak list output.

    If columns is None, parse the default table. Otherwise columns names must
    match the order passed to `flatpak list --columns=...`.
    """
    if columns is None:
        return _parse_plain_flatpak_list_output(
            output, method=method, user=user, home=home
        )

    out: List[FlatpakInstall] = []
    seen: Set[
        Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]]
    ] = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("ref") or lower.startswith("application id"):
            continue

        parts = line.split("\t")
        if len(parts) < len(columns):
            parts = line.split()
        if not parts:
            continue

        fields = {
            name: parts[idx].strip()
            for idx, name in enumerate(columns)
            if idx < len(parts)
        }
        ref = fields.get("ref") or fields.get("application") or ""
        kind, name, ref_arch, ref_branch = _parse_flatpak_ref(ref)
        if not name:
            continue

        remote = fields.get("origin") or None
        branch = fields.get("branch") or ref_branch
        arch = fields.get("arch") or ref_arch
        if remote in {"", "-"}:
            remote = None
        if branch in {"", "-"}:
            branch = None
        if arch in {"", "-"}:
            arch = None

        key = (name, remote, branch, arch, kind)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            FlatpakInstall(
                name=name,
                method=method,
                remote=remote,
                branch=branch,
                arch=arch,
                kind=kind,
                ref=ref if "/" in ref else None,
                user=user,
                home=home,
                source="flatpak-list",
            )
        )
    return sorted(
        out,
        key=lambda f: (
            f.kind or "",
            f.name,
            f.remote or "",
            f.branch or "",
            f.arch or "",
        ),
    )


_KNOWN_FLATPAK_LIST_COLUMNS = {
    "name",
    "description",
    "application",
    "version",
    "branch",
    "arch",
    "origin",
    "installation",
    "ref",
    "active",
    "latest",
    "size",
    "options",
}


def _parse_flatpak_columns_help(output: str) -> Set[str]:
    """Parse `flatpak list --columns=help` output into supported fields."""
    supported: Set[str] = set()
    for line in output.splitlines():
        # Help output varies a bit between Flatpak versions. Treat any known
        # token as a supported field, whether it appears alone or in a
        # description table.
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_-]*", line.lower()):
            if token in _KNOWN_FLATPAK_LIST_COLUMNS:
                supported.add(token)
    return supported


def _run_flatpak_columns_help() -> Optional[Set[str]]:
    if shutil.which("flatpak") is None:
        return None
    try:
        proc = subprocess.run(  # nosec
            ["flatpak", "list", "--columns=help"],
            shell=False,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    supported = _parse_flatpak_columns_help(proc.stdout or "")
    return supported or None


def _flatpak_list_attempts(
    scope: str, supported: Optional[Set[str]]
) -> List[Tuple[List[str], Optional[Tuple[str, ...]]]]:
    def supported_columns(*wanted: str) -> Optional[Tuple[str, ...]]:
        if supported is not None and not set(wanted).issubset(supported):
            return None
        return tuple(wanted)

    column_sets: List[Tuple[str, ...]] = []
    for wanted in (
        ("application", "origin", "branch", "arch"),
        ("application", "branch", "arch"),
        ("application", "branch"),
        ("application",),
        ("ref", "origin", "branch", "arch"),
        ("ref", "branch", "arch"),
        ("ref", "branch"),
        ("ref",),
    ):
        cols = supported_columns(*wanted)
        if cols is not None and cols not in column_sets:
            column_sets.append(cols)

    attempts: List[Tuple[List[str], Optional[Tuple[str, ...]]]] = [
        (
            ["flatpak", "list", scope, "--columns=" + ",".join(cols)],
            cols,
        )
        for cols in column_sets
    ]
    attempts.append((["flatpak", "list", scope], None))
    return attempts


def _run_flatpak_list(method: str) -> Optional[Tuple[str, Optional[Tuple[str, ...]]]]:
    if shutil.which("flatpak") is None:
        return None

    scope = "--system" if method == "system" else "--user"
    supported = _run_flatpak_columns_help()
    for args, columns in _flatpak_list_attempts(scope, supported):
        try:
            proc = subprocess.run(  # nosec
                args,
                shell=False,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except Exception:  # nosec B112
            continue
        if proc.returncode == 0:
            return proc.stdout or "", columns
    return None


def _flatpak_remote_from_ref(
    flatpak_root: str, app_id: str, arch: str, branch: str, remote_names: List[str]
) -> Optional[str]:
    for remote_name in remote_names:
        ref = os.path.join(
            flatpak_root,
            "repo",
            "refs",
            "remotes",
            remote_name,
            "app",
            app_id,
            arch,
            branch,
        )
        if not path_has_symlink_component(ref) and os.path.exists(ref):
            return remote_name
    return None


def _parse_flatpak_deploy_origin(branch_dir: str) -> Optional[str]:
    active_dir = os.path.join(branch_dir, "active")
    candidates = [
        os.path.join(active_dir, "origin"),
        os.path.join(active_dir, "metadata"),
    ]

    origin = _read_first_existing_text([candidates[0]])
    if origin:
        return origin

    metadata = _read_first_existing_text([candidates[1]])
    if metadata:
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(metadata)
        except Exception:
            return None
        for section in ("Application", "Runtime"):
            if parser.has_option(section, "origin"):
                value = parser.get(section, "origin", fallback="").strip()
                if value:
                    return value
    return None


def _find_flatpaks_in_root(
    flatpak_root: str,
    *,
    method: str,
    user: Optional[str] = None,
    home: Optional[str] = None,
) -> List[FlatpakInstall]:
    apps_dir = os.path.join(flatpak_root, "app")
    if not is_dir_no_symlink_components(apps_dir):
        return []

    remote_names = [
        r.name
        for r in find_flatpak_remotes(flatpak_root, method=method, user=user, home=home)
    ]
    out: List[FlatpakInstall] = []

    try:
        app_ids = sorted(os.listdir(apps_dir))
    except OSError:
        return []

    seen: Set[Tuple[str, Optional[str], Optional[str], Optional[str]]] = set()
    for app_id in app_ids:
        app_path = os.path.join(apps_dir, app_id)
        if not is_dir_no_symlink_components(app_path):
            continue
        try:
            arches = sorted(os.listdir(app_path))
        except OSError:
            continue
        for arch in arches:
            arch_path = os.path.join(app_path, arch)
            if not is_dir_no_symlink_components(arch_path):
                continue
            try:
                branches = sorted(os.listdir(arch_path))
            except OSError:
                continue
            for branch in branches:
                branch_path = os.path.join(arch_path, branch)
                if not is_dir_no_symlink_components(branch_path):
                    continue
                active_dir = os.path.join(branch_path, "active")
                if not is_dir_no_symlink_components(active_dir):
                    continue
                remote = _parse_flatpak_deploy_origin(branch_path)
                if not remote:
                    remote = _flatpak_remote_from_ref(
                        flatpak_root, app_id, arch, branch, remote_names
                    )
                key = (app_id, remote, branch, arch)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    FlatpakInstall(
                        name=app_id,
                        method=method,
                        remote=remote,
                        branch=branch or None,
                        arch=arch or None,
                        kind="app",
                        ref=f"app/{app_id}/{arch}/{branch}",
                        user=user,
                        home=home,
                    )
                )

    return sorted(
        out, key=lambda f: (f.name, f.remote or "", f.branch or "", f.arch or "")
    )


def find_flatpak_remotes(
    flatpak_root: str,
    *,
    method: str,
    user: Optional[str] = None,
    home: Optional[str] = None,
) -> List[FlatpakRemote]:
    """Return configured Flatpak remotes for a Flatpak installation root.

    Flatpak stores remotes in the OSTree repo config. This gives us the remote
    names and repository URLs. It does not reliably preserve the original
    .flatpakref/.flatpakrepo URL that was used during installation.
    """
    config_path = os.path.join(flatpak_root, "repo", "config")
    config_text = _read_first_existing_text([config_path])
    if not config_text:
        return []

    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(config_text)
    except Exception:
        return []

    out: List[FlatpakRemote] = []
    for section in parser.sections():
        match = re.fullmatch(r'remote\s+"(.+)"', section)
        if not match:
            continue
        name = match.group(1).strip()
        url = parser.get(section, "url", fallback="").strip()
        if not name or not url:
            continue
        out.append(
            FlatpakRemote(
                name=name,
                method=method,
                url=url,
                user=user,
                home=home,
            )
        )

    return sorted(out, key=lambda r: (r.method, r.user or "", r.name))


def find_user_flatpaks(home: str, user: Optional[str] = None) -> List[FlatpakInstall]:
    """Return per-user Flatpak applications installed under a home directory."""
    flatpak_root = os.path.join(home, ".local", "share", "flatpak")
    return _find_flatpaks_in_root(flatpak_root, method="user", user=user, home=home)


def find_user_flatpak_remotes(
    home: str, user: Optional[str] = None
) -> List[FlatpakRemote]:
    flatpak_root = os.path.join(home, ".local", "share", "flatpak")
    return find_flatpak_remotes(flatpak_root, method="user", user=user, home=home)


def find_system_flatpaks() -> List[FlatpakInstall]:
    """Return Flatpak refs installed system-wide.

    Prefer `flatpak list --system` because it is Flatpak's own view of
    installed refs and includes layouts the filesystem scanner might miss.
    Fall back to the on-disk app deployment tree when the command is
    unavailable or produces unparsable output.
    """
    listing = _run_flatpak_list("system")
    if listing is not None:
        output, columns = listing
        parsed = _parse_flatpak_list_output(output, method="system", columns=columns)
        if parsed or not output.strip():
            return parsed
    return _find_flatpaks_in_root("/var/lib/flatpak", method="system")


def find_system_flatpak_remotes() -> List[FlatpakRemote]:
    return find_flatpak_remotes("/var/lib/flatpak", method="system")


def _parse_snap_notes(notes: str) -> List[str]:
    if not notes or notes == "-":
        return []
    cleaned = notes.replace(",", " ").replace(";", " ")
    return sorted(
        {n.strip().lower() for n in cleaned.split() if n.strip() and n.strip() != "-"}
    )


def _parse_snap_list_output(output: str) -> List[SnapInstall]:
    out: List[SnapInstall] = []
    for idx, line in enumerate(output.splitlines()):
        line = line.strip()
        if not line:
            continue
        if idx == 0 and line.lower().startswith("name"):
            continue
        parts = line.split(maxsplit=5)
        if len(parts) < 5:
            continue
        name = parts[0]
        revision: Optional[int]
        try:
            revision = int(parts[2])
        except ValueError:
            revision = None
        tracking = parts[3]
        channel = None if tracking in {"-", ""} else tracking
        notes = _parse_snap_notes(parts[5] if len(parts) > 5 else "")
        out.append(
            SnapInstall(
                name=name,
                channel=channel,
                revision=revision,
                classic="classic" in notes,
                devmode="devmode" in notes,
                dangerous="dangerous" in notes,
                notes=notes,
                source="snap-list",
            )
        )
    return sorted(out, key=lambda s: s.name)


def _run_snap_list() -> Optional[str]:
    if shutil.which("snap") is None:
        return None
    try:
        proc = subprocess.run(  # nosec
            ["snap", "list"],
            shell=False,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout or ""


def _find_system_snaps_from_filesystem() -> List[SnapInstall]:
    snapd_snaps = "/var/lib/snapd/snaps"
    if not os.path.isdir(snapd_snaps):
        return []

    current_revisions: Dict[str, int] = {}
    snap_mounts = "/snap"
    if os.path.isdir(snap_mounts):
        try:
            mount_names = os.listdir(snap_mounts)
        except OSError:
            mount_names = []
        for name in mount_names:
            current = os.path.join(snap_mounts, name, "current")
            try:
                target = os.readlink(current)
            except OSError:
                continue
            try:
                current_revisions[name] = int(os.path.basename(target.rstrip("/")))
            except ValueError:
                continue

    candidates: Dict[str, List[int]] = {}
    try:
        entries = os.listdir(snapd_snaps)
    except OSError:
        return []

    for entry in entries:
        if not entry.endswith(".snap") or "_" not in entry:
            continue
        name, rev_text = entry[:-5].rsplit("_", 1)
        try:
            revision = int(rev_text)
        except ValueError:
            continue
        candidates.setdefault(name, []).append(revision)

    out: List[SnapInstall] = []
    for name, revisions in candidates.items():
        revision = current_revisions.get(name)
        if revision is None:
            revision = max(revisions)
        out.append(SnapInstall(name=name, revision=revision, source="filesystem"))
    return sorted(out, key=lambda s: s.name)


def find_system_snaps() -> List[SnapInstall]:
    """Return system-wide snap packages.

    Prefer `snap list` because it exposes channel tracking and confinement notes.
    Fall back to snapd's on-disk snap filenames when the command is unavailable.
    """
    output = _run_snap_list()
    if output is not None:
        parsed = _parse_snap_list_output(output)
        if parsed:
            return parsed
    return _find_system_snaps_from_filesystem()


def collect_non_system_users() -> List[UserRecord]:
    defs = parse_login_defs()
    uid_min = defs.get("UID_MIN", 1000)

    passwd_rows = parse_passwd()
    gid_to_name, _, group_members = parse_group()

    users: List[UserRecord] = []
    for name, uid, gid, gecos, home, shell in passwd_rows:
        if name in {"root", "nobody"}:
            continue
        if not is_human_user(uid, shell, uid_min):
            continue

        primary_group = gid_to_name.get(gid, str(gid))

        supp: List[str] = []
        for gname, mem in group_members.items():
            if name in mem and gname != primary_group:
                supp.append(gname)
        supp = sorted(set(supp))

        ssh_files = find_user_ssh_files(home) if home and home.startswith("/") else []

        flatpaks: List[FlatpakInstall] = []
        if home and home.startswith("/"):
            flatpaks = find_user_flatpaks(home, user=name)

        users.append(
            UserRecord(
                name=name,
                uid=uid,
                gid=gid,
                gecos=gecos,
                home=home,
                shell=shell,  # nosec
                primary_group=primary_group,
                supplementary_groups=supp,
                ssh_files=ssh_files,
                flatpaks=flatpaks,
            )
        )

    return users
