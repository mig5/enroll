from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple


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
    if not os.path.isdir(sshdir):
        return out

    ak = os.path.join(sshdir, "authorized_keys")
    if os.path.isfile(ak) and not os.path.islink(ak):
        out.append(ak)

    return sorted(set(out))


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
            )
        )

    return users
