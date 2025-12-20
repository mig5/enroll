from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess  # nosec
import tarfile
import tempfile
import urllib.request
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .remote import _safe_extract_tar
from .sopsutil import decrypt_file_binary_to, require_sops_cmd


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass
class BundleRef:
    """A prepared harvest bundle.

    `dir` is a directory containing state.json + artifacts/.
    `tempdir` is set when the bundle needed extraction into a temp directory.
    """

    dir: Path
    tempdir: Optional[tempfile.TemporaryDirectory] = None

    @property
    def state_path(self) -> Path:
        return self.dir / "state.json"


def _bundle_from_input(path: str, *, sops_mode: bool) -> BundleRef:
    """Resolve a user-supplied path to a harvest bundle directory.

    Accepts:
      - a bundle directory
      - a path to state.json inside a bundle directory
      - (sops mode or .sops) a SOPS-encrypted tar.gz bundle
      - a plain tar.gz/tgz bundle
    """

    p = Path(path).expanduser()

    # Accept the state.json path directly (harvest often prints this).
    if p.is_file() and p.name == "state.json":
        p = p.parent

    if p.is_dir():
        return BundleRef(dir=p)

    if not p.exists():
        raise RuntimeError(f"Harvest path not found: {p}")

    # Auto-enable sops mode if it looks like an encrypted bundle.
    is_sops = p.name.endswith(".sops")
    if sops_mode or is_sops:
        require_sops_cmd()
        td = tempfile.TemporaryDirectory(prefix="enroll-harvest-")
        td_path = Path(td.name)
        try:
            os.chmod(td_path, 0o700)
        except OSError:
            pass

        tar_path = td_path / "harvest.tar.gz"
        out_dir = td_path / "bundle"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(out_dir, 0o700)
        except OSError:
            pass

        decrypt_file_binary_to(p, tar_path, mode=0o600)
        with tarfile.open(tar_path, mode="r:gz") as tf:
            _safe_extract_tar(tf, out_dir)

        return BundleRef(dir=out_dir, tempdir=td)

    # Plain tarballs (useful for operators who rsync/zip harvests around).
    if p.suffixes[-2:] == [".tar", ".gz"] or p.suffix == ".tgz":
        td = tempfile.TemporaryDirectory(prefix="enroll-harvest-")
        td_path = Path(td.name)
        try:
            os.chmod(td_path, 0o700)
        except OSError:
            pass
        out_dir = td_path / "bundle"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(out_dir, 0o700)
        except OSError:
            pass
        with tarfile.open(p, mode="r:gz") as tf:
            _safe_extract_tar(tf, out_dir)
        return BundleRef(dir=out_dir, tempdir=td)

    raise RuntimeError(
        f"Harvest path is not a directory, state.json, encrypted bundle, or tarball: {p}"
    )


def _load_state(bundle_dir: Path) -> Dict[str, Any]:
    sp = bundle_dir / "state.json"
    with open(sp, "r", encoding="utf-8") as f:
        return json.load(f)


def _all_packages(state: Dict[str, Any]) -> List[str]:
    pkgs = set(state.get("manual_packages", []) or [])
    pkgs |= set(state.get("manual_packages_skipped", []) or [])
    for s in state.get("services", []) or []:
        for p in s.get("packages", []) or []:
            pkgs.add(p)
    return sorted(pkgs)


def _service_units(state: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for s in state.get("services", []) or []:
        unit = s.get("unit")
        if unit:
            out[str(unit)] = s
    return out


def _users_by_name(state: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    users = (state.get("users") or {}).get("users") or []
    out: Dict[str, Dict[str, Any]] = {}
    for u in users:
        name = u.get("name")
        if name:
            out[str(name)] = u
    return out


@dataclass(frozen=True)
class FileRec:
    path: str
    role: str
    src_rel: str
    owner: Optional[str]
    group: Optional[str]
    mode: Optional[str]
    reason: Optional[str]


def _iter_managed_files(state: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    # Services
    for s in state.get("services", []) or []:
        role = s.get("role_name") or "unknown"
        for mf in s.get("managed_files", []) or []:
            yield str(role), mf

    # Package roles
    for p in state.get("package_roles", []) or []:
        role = p.get("role_name") or "unknown"
        for mf in p.get("managed_files", []) or []:
            yield str(role), mf

    # Users
    u = state.get("users") or {}
    u_role = u.get("role_name") or "users"
    for mf in u.get("managed_files", []) or []:
        yield str(u_role), mf

    # etc_custom
    ec = state.get("etc_custom") or {}
    ec_role = ec.get("role_name") or "etc_custom"
    for mf in ec.get("managed_files", []) or []:
        yield str(ec_role), mf

    # usr_local_custom
    ul = state.get("usr_local_custom") or {}
    ul_role = ul.get("role_name") or "usr_local_custom"
    for mf in ul.get("managed_files", []) or []:
        yield str(ul_role), mf

    # extra_paths
    xp = state.get("extra_paths") or {}
    xp_role = xp.get("role_name") or "extra_paths"
    for mf in xp.get("managed_files", []) or []:
        yield str(xp_role), mf


def _file_index(bundle_dir: Path, state: Dict[str, Any]) -> Dict[str, FileRec]:
    """Return mapping of absolute path -> FileRec.

    If duplicates occur, the first one wins (should be rare by design).
    """

    out: Dict[str, FileRec] = {}
    for role, mf in _iter_managed_files(state):
        p = mf.get("path")
        src_rel = mf.get("src_rel")
        if not p or not src_rel:
            continue
        p = str(p)
        if p in out:
            continue
        out[p] = FileRec(
            path=p,
            role=str(role),
            src_rel=str(src_rel),
            owner=mf.get("owner"),
            group=mf.get("group"),
            mode=mf.get("mode"),
            reason=mf.get("reason"),
        )
    return out


def _artifact_path(bundle_dir: Path, rec: FileRec) -> Path:
    return bundle_dir / "artifacts" / rec.role / rec.src_rel


def compare_harvests(
    old_path: str,
    new_path: str,
    *,
    sops_mode: bool = False,
) -> Tuple[Dict[str, Any], bool]:
    """Compare two harvests.

    Returns (report, has_changes).
    """
    with ExitStack() as stack:
        old_b = _bundle_from_input(old_path, sops_mode=sops_mode)
        new_b = _bundle_from_input(new_path, sops_mode=sops_mode)
        if old_b.tempdir:
            stack.callback(old_b.tempdir.cleanup)
        if new_b.tempdir:
            stack.callback(new_b.tempdir.cleanup)

        old_state = _load_state(old_b.dir)
        new_state = _load_state(new_b.dir)

        old_pkgs = set(_all_packages(old_state))
        new_pkgs = set(_all_packages(new_state))

        pkgs_added = sorted(new_pkgs - old_pkgs)
        pkgs_removed = sorted(old_pkgs - new_pkgs)

        old_units = _service_units(old_state)
        new_units = _service_units(new_state)
        units_added = sorted(set(new_units) - set(old_units))
        units_removed = sorted(set(old_units) - set(new_units))

        units_changed: List[Dict[str, Any]] = []
        for unit in sorted(set(old_units) & set(new_units)):
            a = old_units[unit]
            b = new_units[unit]
            ch: Dict[str, Any] = {}
            for k in [
                "active_state",
                "sub_state",
                "unit_file_state",
                "condition_result",
            ]:
                if a.get(k) != b.get(k):
                    ch[k] = {"old": a.get(k), "new": b.get(k)}
            a_pk = set(a.get("packages", []) or [])
            b_pk = set(b.get("packages", []) or [])
            if a_pk != b_pk:
                ch["packages"] = {
                    "added": sorted(b_pk - a_pk),
                    "removed": sorted(a_pk - b_pk),
                }
            if ch:
                units_changed.append({"unit": unit, "changes": ch})

        old_users = _users_by_name(old_state)
        new_users = _users_by_name(new_state)
        users_added = sorted(set(new_users) - set(old_users))
        users_removed = sorted(set(old_users) - set(new_users))

        users_changed: List[Dict[str, Any]] = []
        for name in sorted(set(old_users) & set(new_users)):
            a = old_users[name]
            b = new_users[name]
            ch: Dict[str, Any] = {}
            for k in [
                "uid",
                "gid",
                "gecos",
                "home",
                "shell",
                "primary_group",
            ]:
                if a.get(k) != b.get(k):
                    ch[k] = {"old": a.get(k), "new": b.get(k)}
            a_sg = set(a.get("supplementary_groups", []) or [])
            b_sg = set(b.get("supplementary_groups", []) or [])
            if a_sg != b_sg:
                ch["supplementary_groups"] = {
                    "added": sorted(b_sg - a_sg),
                    "removed": sorted(a_sg - b_sg),
                }
            if ch:
                users_changed.append({"name": name, "changes": ch})

        old_files = _file_index(old_b.dir, old_state)
        new_files = _file_index(new_b.dir, new_state)
        old_paths_set = set(old_files)
        new_paths_set = set(new_files)

        files_added = sorted(new_paths_set - old_paths_set)
        files_removed = sorted(old_paths_set - new_paths_set)

        # Hash cache to avoid reading the same file more than once.
        hash_cache: Dict[str, str] = {}

        def _hash_for(bundle_dir: Path, rec: FileRec) -> Optional[str]:
            ap = _artifact_path(bundle_dir, rec)
            if not ap.exists() or not ap.is_file():
                return None
            key = str(ap)
            if key in hash_cache:
                return hash_cache[key]
            hash_cache[key] = _sha256(ap)
            return hash_cache[key]

        files_changed: List[Dict[str, Any]] = []
        for p in sorted(old_paths_set & new_paths_set):
            a = old_files[p]
            b = new_files[p]
            ch: Dict[str, Any] = {}

            # Role movement is itself interesting (e.g., file ownership attribution changed).
            if a.role != b.role:
                ch["role"] = {"old": a.role, "new": b.role}
            for k in ["owner", "group", "mode", "reason"]:
                av = getattr(a, k)
                bv = getattr(b, k)
                if av != bv:
                    ch[k] = {"old": av, "new": bv}

            ha = _hash_for(old_b.dir, a)
            hb = _hash_for(new_b.dir, b)
            if ha is None or hb is None:
                if ha != hb:
                    ch["content"] = {
                        "old": "missing" if ha is None else "present",
                        "new": "missing" if hb is None else "present",
                    }
            else:
                if ha != hb:
                    ch["content"] = {"old_sha256": ha, "new_sha256": hb}

            if ch:
                files_changed.append({"path": p, "changes": ch})

        has_changes = any(
            [
                pkgs_added,
                pkgs_removed,
                units_added,
                units_removed,
                units_changed,
                users_added,
                users_removed,
                users_changed,
                files_added,
                files_removed,
                files_changed,
            ]
        )

        def _mtime_iso(p: Path) -> Optional[str]:
            try:
                ts = p.stat().st_mtime
            except OSError:
                return None
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

        report: Dict[str, Any] = {
            "generated_at": _utc_now_iso(),
            "old": {
                "input": old_path,
                "bundle_dir": str(old_b.dir),
                "state_mtime": _mtime_iso(old_b.state_path),
                "host": (old_state.get("host") or {}).get("hostname"),
            },
            "new": {
                "input": new_path,
                "bundle_dir": str(new_b.dir),
                "state_mtime": _mtime_iso(new_b.state_path),
                "host": (new_state.get("host") or {}).get("hostname"),
            },
            "packages": {"added": pkgs_added, "removed": pkgs_removed},
            "services": {
                "enabled_added": units_added,
                "enabled_removed": units_removed,
                "changed": units_changed,
            },
            "users": {
                "added": users_added,
                "removed": users_removed,
                "changed": users_changed,
            },
            "files": {
                "added": [
                    {
                        "path": p,
                        "role": new_files[p].role,
                        "reason": new_files[p].reason,
                    }
                    for p in files_added
                ],
                "removed": [
                    {
                        "path": p,
                        "role": old_files[p].role,
                        "reason": old_files[p].reason,
                    }
                    for p in files_removed
                ],
                "changed": files_changed,
            },
        }

        return report, has_changes


def format_report(report: Dict[str, Any], *, fmt: str = "text") -> str:
    fmt = (fmt or "text").lower()
    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=True)
    if fmt == "markdown":
        return _report_markdown(report)
    return _report_text(report)


def _report_text(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    old = report.get("old", {})
    new = report.get("new", {})
    lines.append(
        f"enroll diff report (generated {report.get('generated_at')})\n"
        f"old: {old.get('input')} (host={old.get('host')}, state_mtime={old.get('state_mtime')})\n"
        f"new: {new.get('input')} (host={new.get('host')}, state_mtime={new.get('state_mtime')})"
    )

    pk = report.get("packages", {})
    lines.append("\nPackages")
    lines.append(f"  added:   {len(pk.get('added', []) or [])}")
    lines.append(f"  removed: {len(pk.get('removed', []) or [])}")
    for p in pk.get("added", []) or []:
        lines.append(f"    + {p}")
    for p in pk.get("removed", []) or []:
        lines.append(f"    - {p}")

    sv = report.get("services", {})
    lines.append("\nServices (enabled systemd units)")
    for u in sv.get("enabled_added", []) or []:
        lines.append(f"  + {u}")
    for u in sv.get("enabled_removed", []) or []:
        lines.append(f"  - {u}")
    for ch in sv.get("changed", []) or []:
        unit = ch.get("unit")
        lines.append(f"  * {unit} changed")
        for k, v in (ch.get("changes") or {}).items():
            if k == "packages":
                a = (v or {}).get("added", [])
                r = (v or {}).get("removed", [])
                if a:
                    lines.append(f"      packages +: {', '.join(a)}")
                if r:
                    lines.append(f"      packages -: {', '.join(r)}")
            else:
                lines.append(f"      {k}: {v.get('old')} -> {v.get('new')}")

    us = report.get("users", {})
    lines.append("\nUsers")
    for u in us.get("added", []) or []:
        lines.append(f"  + {u}")
    for u in us.get("removed", []) or []:
        lines.append(f"  - {u}")
    for ch in us.get("changed", []) or []:
        name = ch.get("name")
        lines.append(f"  * {name} changed")
        for k, v in (ch.get("changes") or {}).items():
            if k == "supplementary_groups":
                a = (v or {}).get("added", [])
                r = (v or {}).get("removed", [])
                if a:
                    lines.append(f"      groups +: {', '.join(a)}")
                if r:
                    lines.append(f"      groups -: {', '.join(r)}")
            else:
                lines.append(f"      {k}: {v.get('old')} -> {v.get('new')}")

    fl = report.get("files", {})
    lines.append("\nFiles")
    for e in fl.get("added", []) or []:
        lines.append(
            f"  + {e.get('path')}  (role={e.get('role')}, reason={e.get('reason')})"
        )
    for e in fl.get("removed", []) or []:
        lines.append(
            f"  - {e.get('path')}  (role={e.get('role')}, reason={e.get('reason')})"
        )
    for ch in fl.get("changed", []) or []:
        p = ch.get("path")
        lines.append(f"  * {p} changed")
        for k, v in (ch.get("changes") or {}).items():
            if k == "content":
                if "old_sha256" in (v or {}):
                    lines.append("      content: sha256 changed")
                else:
                    lines.append(f"      content: {v.get('old')} -> {v.get('new')}")
            else:
                lines.append(f"      {k}: {v.get('old')} -> {v.get('new')}")

    if not any(
        [
            (pk.get("added") or []),
            (pk.get("removed") or []),
            (sv.get("enabled_added") or []),
            (sv.get("enabled_removed") or []),
            (sv.get("changed") or []),
            (us.get("added") or []),
            (us.get("removed") or []),
            (us.get("changed") or []),
            (fl.get("added") or []),
            (fl.get("removed") or []),
            (fl.get("changed") or []),
        ]
    ):
        lines.append("\nNo differences detected.")

    return "\n".join(lines) + "\n"


def _report_markdown(report: Dict[str, Any]) -> str:
    old = report.get("old", {})
    new = report.get("new", {})
    out: List[str] = []
    out.append("# enroll diff report\n")
    out.append(f"Generated: `{report.get('generated_at')}`\n")
    out.append(
        f"- **Old**: `{old.get('input')}` (host={old.get('host')}, state_mtime={old.get('state_mtime')})\n"
        f"- **New**: `{new.get('input')}` (host={new.get('host')}, state_mtime={new.get('state_mtime')})\n"
    )

    pk = report.get("packages", {})
    out.append("## Packages\n")
    out.append(f"- Added: {len(pk.get('added', []) or [])}\n")
    for p in pk.get("added", []) or []:
        out.append(f"  - `+ {p}`\n")
    out.append(f"- Removed: {len(pk.get('removed', []) or [])}\n")
    for p in pk.get("removed", []) or []:
        out.append(f"  - `- {p}`\n")

    sv = report.get("services", {})
    out.append("## Services (enabled systemd units)\n")
    if sv.get("enabled_added"):
        out.append("- Enabled added\n")
        for u in sv.get("enabled_added", []) or []:
            out.append(f"  - `+ {u}`\n")
    if sv.get("enabled_removed"):
        out.append("- Enabled removed\n")
        for u in sv.get("enabled_removed", []) or []:
            out.append(f"  - `- {u}`\n")
    if sv.get("changed"):
        out.append("- Changed\n")
        for ch in sv.get("changed", []) or []:
            unit = ch.get("unit")
            out.append(f"  - `{unit}`\n")
            for k, v in (ch.get("changes") or {}).items():
                if k == "packages":
                    a = (v or {}).get("added", [])
                    r = (v or {}).get("removed", [])
                    if a:
                        out.append(
                            f"    - packages added: {', '.join('`'+x+'`' for x in a)}\n"
                        )
                    if r:
                        out.append(
                            f"    - packages removed: {', '.join('`'+x+'`' for x in r)}\n"
                        )
                else:
                    out.append(f"    - {k}: `{v.get('old')}` → `{v.get('new')}`\n")

    us = report.get("users", {})
    out.append("## Users\n")
    if us.get("added"):
        out.append("- Added\n")
        for u in us.get("added", []) or []:
            out.append(f"  - `+ {u}`\n")
    if us.get("removed"):
        out.append("- Removed\n")
        for u in us.get("removed", []) or []:
            out.append(f"  - `- {u}`\n")
    if us.get("changed"):
        out.append("- Changed\n")
        for ch in us.get("changed", []) or []:
            name = ch.get("name")
            out.append(f"  - `{name}`\n")
            for k, v in (ch.get("changes") or {}).items():
                if k == "supplementary_groups":
                    a = (v or {}).get("added", [])
                    r = (v or {}).get("removed", [])
                    if a:
                        out.append(
                            f"    - groups added: {', '.join('`'+x+'`' for x in a)}\n"
                        )
                    if r:
                        out.append(
                            f"    - groups removed: {', '.join('`'+x+'`' for x in r)}\n"
                        )
                else:
                    out.append(f"    - {k}: `{v.get('old')}` → `{v.get('new')}`\n")

    fl = report.get("files", {})
    out.append("## Files\n")
    if fl.get("added"):
        out.append("- Added\n")
        for e in fl.get("added", []) or []:
            out.append(
                f"  - `+ {e.get('path')}` (role={e.get('role')}, reason={e.get('reason')})\n"
            )
    if fl.get("removed"):
        out.append("- Removed\n")
        for e in fl.get("removed", []) or []:
            out.append(
                f"  - `- {e.get('path')}` (role={e.get('role')}, reason={e.get('reason')})\n"
            )
    if fl.get("changed"):
        out.append("- Changed\n")
        for ch in fl.get("changed", []) or []:
            p = ch.get("path")
            out.append(f"  - `{p}`\n")
            for k, v in (ch.get("changes") or {}).items():
                if k == "content":
                    if "old_sha256" in (v or {}):
                        out.append("    - content: sha256 changed\n")
                    else:
                        out.append(
                            f"    - content: `{v.get('old')}` → `{v.get('new')}`\n"
                        )
                else:
                    out.append(f"    - {k}: `{v.get('old')}` → `{v.get('new')}`\n")

    if not any(
        [
            (pk.get("added") or []),
            (pk.get("removed") or []),
            (sv.get("enabled_added") or []),
            (sv.get("enabled_removed") or []),
            (sv.get("changed") or []),
            (us.get("added") or []),
            (us.get("removed") or []),
            (us.get("changed") or []),
            (fl.get("added") or []),
            (fl.get("removed") or []),
            (fl.get("changed") or []),
        ]
    ):
        out.append("\n_No differences detected._\n")

    return "".join(out)


def post_webhook(
    url: str,
    body: bytes,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout_s: int = 10,
) -> Tuple[int, str]:
    req = urllib.request.Request(url=url, data=body, method="POST")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec
            status = int(getattr(resp, "status", 0) or 0)
            text = resp.read().decode("utf-8", errors="replace")
            return status, text
    except Exception as e:
        raise RuntimeError(f"webhook POST failed: {e}") from e


def send_email(
    *,
    to_addrs: List[str],
    subject: str,
    body: str,
    from_addr: Optional[str] = None,
    smtp: Optional[str] = None,
    smtp_user: Optional[str] = None,
    smtp_password: Optional[str] = None,
) -> None:
    if not to_addrs:
        raise RuntimeError("email: no recipients")

    msg = EmailMessage()
    msg["To"] = ", ".join(to_addrs)
    if from_addr:
        msg["From"] = from_addr
    else:
        host = os.uname().nodename
        msg["From"] = f"enroll@{host}"
    msg["Subject"] = subject
    msg.set_content(body)

    # Preferred: use local sendmail if smtp wasn't specified.
    if not smtp:
        sendmail = shutil.which("sendmail")
        if not sendmail:
            raise RuntimeError(
                "email: no --smtp provided and sendmail not found on PATH"
            )
        p = subprocess.run(
            [sendmail, "-t", "-i"],
            input=msg.as_bytes(),
            capture_output=True,
            check=False,
        )  # nosec
        if p.returncode != 0:
            raise RuntimeError(
                "email: sendmail failed:\n"
                f"  rc: {p.returncode}\n"
                f"  stderr: {p.stderr.decode('utf-8', errors='replace').strip()}"
            )
        return

    import smtplib

    host = smtp
    port = 25
    if ":" in smtp:
        host, port_s = smtp.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            raise RuntimeError(f"email: invalid smtp port in {smtp!r}")

    with smtplib.SMTP(host, port, timeout=10) as s:
        s.ehlo()
        try:
            s.starttls()
            s.ehlo()
        except Exception:
            # STARTTLS is optional; ignore if unsupported.
            pass  # nosec
        if smtp_user:
            s.login(smtp_user, smtp_password or "")
        s.send_message(msg)
