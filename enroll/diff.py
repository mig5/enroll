from __future__ import annotations

import hashlib
import json
import os
import re
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
from .pathfilter import PathFilter
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


def _packages_inventory(state: Dict[str, Any]) -> Dict[str, Any]:
    return (state.get("inventory") or {}).get("packages") or {}


def _all_packages(state: Dict[str, Any]) -> List[str]:
    return sorted(_packages_inventory(state).keys())


def _roles(state: Dict[str, Any]) -> Dict[str, Any]:
    return state.get("roles") or {}


def _pkg_version_key(entry: Dict[str, Any]) -> Optional[str]:
    """Return a stable string used for version comparison."""
    installs = entry.get("installations") or []
    if isinstance(installs, list) and installs:
        parts: List[str] = []
        for inst in installs:
            if not isinstance(inst, dict):
                continue
            arch = str(inst.get("arch") or "")
            ver = str(inst.get("version") or "")
            if not ver:
                continue
            parts.append(f"{arch}:{ver}" if arch else ver)
        if parts:
            return "|".join(sorted(parts))
    v = entry.get("version")
    if v:
        return str(v)
    return None


def _pkg_version_display(entry: Dict[str, Any]) -> Optional[str]:
    v = entry.get("version")
    if v:
        return str(v)
    installs = entry.get("installations") or []
    if isinstance(installs, list) and installs:
        parts: List[str] = []
        for inst in installs:
            if not isinstance(inst, dict):
                continue
            arch = str(inst.get("arch") or "")
            ver = str(inst.get("version") or "")
            if not ver:
                continue
            parts.append(f"{ver} ({arch})" if arch else ver)
        if parts:
            return ", ".join(sorted(parts))
    return None


def _service_units(state: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for s in _roles(state).get("services") or []:
        unit = s.get("unit")
        if unit:
            out[str(unit)] = s
    return out


def _users_by_name(state: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    users = (_roles(state).get("users") or {}).get("users") or []
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
    for s in _roles(state).get("services") or []:
        role = s.get("role_name") or "unknown"
        for mf in s.get("managed_files", []) or []:
            yield str(role), mf

    # Package roles
    for p in _roles(state).get("packages") or []:
        role = p.get("role_name") or "unknown"
        for mf in p.get("managed_files", []) or []:
            yield str(role), mf

    # Users
    u = _roles(state).get("users") or {}
    u_role = u.get("role_name") or "users"
    for mf in u.get("managed_files", []) or []:
        yield str(u_role), mf

    # apt_config
    ac = _roles(state).get("apt_config") or {}
    ac_role = ac.get("role_name") or "apt_config"
    for mf in ac.get("managed_files", []) or []:
        yield str(ac_role), mf

    # etc_custom
    ec = _roles(state).get("etc_custom") or {}
    ec_role = ec.get("role_name") or "etc_custom"
    for mf in ec.get("managed_files", []) or []:
        yield str(ec_role), mf

    # usr_local_custom
    ul = _roles(state).get("usr_local_custom") or {}
    ul_role = ul.get("role_name") or "usr_local_custom"
    for mf in ul.get("managed_files", []) or []:
        yield str(ul_role), mf

    # extra_paths
    xp = _roles(state).get("extra_paths") or {}
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
    exclude_paths: Optional[List[str]] = None,
    ignore_package_versions: bool = False,
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

        old_inv = _packages_inventory(old_state)
        new_inv = _packages_inventory(new_state)

        old_pkgs = set(old_inv.keys())
        new_pkgs = set(new_inv.keys())

        pkgs_added = sorted(new_pkgs - old_pkgs)
        pkgs_removed = sorted(old_pkgs - new_pkgs)

        pkgs_version_changed: List[Dict[str, Any]] = []
        pkgs_version_changed_ignored_count = 0
        for pkg in sorted(old_pkgs & new_pkgs):
            a = old_inv.get(pkg) or {}
            b = new_inv.get(pkg) or {}
            if _pkg_version_key(a) != _pkg_version_key(b):
                if ignore_package_versions:
                    pkgs_version_changed_ignored_count += 1
                else:
                    pkgs_version_changed.append(
                        {
                            "package": pkg,
                            "old": _pkg_version_display(a),
                            "new": _pkg_version_display(b),
                        }
                    )

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

        # Optional user-supplied path exclusions (same semantics as harvest --exclude-path),
        # applied only to file drift reporting.
        diff_filter = PathFilter(include=(), exclude=exclude_paths or ())
        if exclude_paths:
            old_files = {
                p: r for p, r in old_files.items() if not diff_filter.is_excluded(p)
            }
            new_files = {
                p: r for p, r in new_files.items() if not diff_filter.is_excluded(p)
            }
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
                pkgs_version_changed,
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
            "filters": {
                "exclude_paths": list(exclude_paths or []),
                "ignore_package_versions": bool(ignore_package_versions),
            },
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
            "packages": {
                "added": pkgs_added,
                "removed": pkgs_removed,
                "version_changed": pkgs_version_changed,
                "version_changed_ignored_count": int(
                    pkgs_version_changed_ignored_count
                ),
            },
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


def has_enforceable_drift(report: Dict[str, Any]) -> bool:
    """Return True if the diff report contains drift that is safe/meaningful to enforce.

    Enforce mode is intended to restore *state* (files/users/services) and to
    reinstall packages that were removed.

    It is deliberately conservative about package drift:
      - Package *version* changes alone are not enforced (no downgrades).
      - Newly installed packages are not removed.

    This helper lets the CLI decide whether `--enforce` should actually run.
    """

    pk = report.get("packages", {}) or {}
    if pk.get("removed"):
        return True

    sv = report.get("services", {}) or {}
    # We do not try to disable newly-enabled services; we only restore units
    # that were enabled in the baseline but are now missing.
    if sv.get("enabled_removed") or []:
        return True

    for ch in sv.get("changed", []) or []:
        changes = ch.get("changes") or {}
        # Ignore package set drift for enforceability decisions; package
        # enforcement is handled via reinstalling removed packages, and we
        # avoid trying to "undo" upgrades/renames.
        for k in changes.keys():
            if k != "packages":
                return True

    us = report.get("users", {}) or {}
    # We restore baseline users (missing/changed). We do not remove newly-added users.
    if (us.get("removed") or []) or (us.get("changed") or []):
        return True

    fl = report.get("files", {}) or {}
    # We restore baseline files (missing/changed). We do not delete newly-managed files.
    if (fl.get("removed") or []) or (fl.get("changed") or []):
        return True

    return False


def _role_tag(role: str) -> str:
    """Return the Ansible tag name for a role (must match manifest generation)."""
    r = str(role or "").strip()
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", r).strip("_")
    if not safe:
        safe = "other"
    return f"role_{safe}"


def _enforcement_plan(
    report: Dict[str, Any],
    old_state: Dict[str, Any],
    old_bundle_dir: Path,
) -> Dict[str, Any]:
    """Return a best-effort enforcement plan (roles/tags) for this diff report.

    We only plan for drift that the baseline manifest can safely restore:
      - packages that were removed (reinstall, no downgrades)
      - baseline users that were removed/changed
      - baseline files that were removed/changed
      - baseline systemd units that were disabled/changed

    We do NOT plan to remove newly-added packages/users/files/services.
    """
    roles: set[str] = set()

    # --- Packages (only removals)
    pk = report.get("packages", {}) or {}
    removed_pkgs = set(pk.get("removed") or [])
    if removed_pkgs:
        pkg_to_roles: Dict[str, set[str]] = {}

        for svc in _roles(old_state).get("services") or []:
            r = str(svc.get("role_name") or "").strip()
            for p in svc.get("packages", []) or []:
                if p:
                    pkg_to_roles.setdefault(str(p), set()).add(r)

        for pr in _roles(old_state).get("packages") or []:
            r = str(pr.get("role_name") or "").strip()
            p = pr.get("package")
            if p:
                pkg_to_roles.setdefault(str(p), set()).add(r)

        for p in removed_pkgs:
            for r in pkg_to_roles.get(str(p), set()):
                if r:
                    roles.add(r)

    # --- Users (removed/changed)
    us = report.get("users", {}) or {}
    if (us.get("removed") or []) or (us.get("changed") or []):
        u = _roles(old_state).get("users") or {}
        u_role = str(u.get("role_name") or "users")
        if u_role:
            roles.add(u_role)

    # --- Files (removed/changed)
    fl = report.get("files", {}) or {}
    file_paths: List[str] = []
    for e in fl.get("removed", []) or []:
        if isinstance(e, dict):
            p = e.get("path")
        else:
            p = e
        if p:
            file_paths.append(str(p))
    for e in fl.get("changed", []) or []:
        if isinstance(e, dict):
            p = e.get("path")
        else:
            p = e
        if p:
            file_paths.append(str(p))

    if file_paths:
        idx = _file_index(old_bundle_dir, old_state)
        for p in file_paths:
            rec = idx.get(p)
            if rec and rec.role:
                roles.add(str(rec.role))

    # --- Services (enabled_removed + meaningful changes)
    sv = report.get("services", {}) or {}
    units: List[str] = []
    for u in sv.get("enabled_removed", []) or []:
        if u:
            units.append(str(u))
    for ch in sv.get("changed", []) or []:
        if not isinstance(ch, dict):
            continue
        unit = ch.get("unit")
        changes = ch.get("changes") or {}
        if unit and any(k != "packages" for k in changes.keys()):
            units.append(str(unit))

    if units:
        old_units = _service_units(old_state)
        for u in units:
            snap = old_units.get(u)
            if snap and snap.get("role_name"):
                roles.add(str(snap.get("role_name")))

    # Drop empty/unknown roles.
    roles = {r for r in roles if r and str(r).strip() and str(r).strip() != "unknown"}

    tags = sorted({_role_tag(r) for r in roles})
    return {
        "roles": sorted(roles),
        "tags": tags,
    }


def enforce_old_harvest(
    old_path: str,
    *,
    sops_mode: bool = False,
    report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Enforce the *old* (baseline) harvest state on the current machine.

    When Ansible is available, this:
      1) renders a temporary manifest from the old harvest, and
      2) runs ansible-playbook locally to apply it.

    Returns a dict suitable for attaching to the diff report under
    report['enforcement'].
    """

    ansible_playbook = shutil.which("ansible-playbook")
    if not ansible_playbook:
        raise RuntimeError(
            "ansible-playbook not found on PATH (cannot enforce; install Ansible)"
        )

    # Import lazily to avoid heavy import cost and potential CLI cycles.
    from .manifest import manifest

    started_at = _utc_now_iso()

    with ExitStack() as stack:
        old_b = _bundle_from_input(old_path, sops_mode=sops_mode)
        if old_b.tempdir:
            stack.callback(old_b.tempdir.cleanup)

        old_state = _load_state(old_b.dir)

        plan: Optional[Dict[str, Any]] = None
        tags: Optional[List[str]] = None
        roles: List[str] = []
        if report is not None:
            plan = _enforcement_plan(report, old_state, old_b.dir)
            roles = list(plan.get("roles") or [])
            t = list(plan.get("tags") or [])
            tags = t if t else None

        with tempfile.TemporaryDirectory(prefix="enroll-enforce-") as td:
            td_path = Path(td)
            try:
                os.chmod(td_path, 0o700)
            except OSError:
                pass

            # 1) Generate a manifest in a temp directory.
            manifest(str(old_b.dir), str(td_path))

            playbook = td_path / "playbook.yml"
            if not playbook.exists():
                raise RuntimeError(
                    f"manifest did not produce expected playbook.yml at {playbook}"
                )

            # 2) Apply it locally.
            env = dict(os.environ)
            cfg = td_path / "ansible.cfg"
            if cfg.exists():
                env["ANSIBLE_CONFIG"] = str(cfg)

            cmd = [
                ansible_playbook,
                "-i",
                "localhost,",
                "-c",
                "local",
                str(playbook),
            ]
            if tags:
                cmd.extend(["--tags", ",".join(tags)])
            p = subprocess.run(
                cmd,
                cwd=str(td_path),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )  # nosec

            finished_at = _utc_now_iso()

            info: Dict[str, Any] = {
                "status": "applied" if p.returncode == 0 else "failed",
                "started_at": started_at,
                "finished_at": finished_at,
                "ansible_playbook": ansible_playbook,
                "command": cmd,
                "returncode": int(p.returncode),
            }

            # Record tag selection (if we could attribute drift to specific roles).
            info["roles"] = roles
            info["tags"] = list(tags or [])
            if not tags:
                info["scope"] = "full_playbook"

            if p.returncode != 0:
                err = (p.stderr or p.stdout or "").strip()
                raise RuntimeError(
                    "ansible-playbook failed"
                    + (f" (rc={p.returncode})" if p.returncode is not None else "")
                    + (f": {err}" if err else "")
                )

            return info


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

    filt = report.get("filters", {}) or {}
    ex_paths = filt.get("exclude_paths", []) or []
    if ex_paths:
        lines.append(f"file exclude patterns: {', '.join(str(p) for p in ex_paths)}")

    if filt.get("ignore_package_versions"):
        ignored = int(
            (report.get("packages", {}) or {}).get("version_changed_ignored_count") or 0
        )
        msg = "package version drift: ignored (--ignore-package-versions)"
        if ignored:
            msg += f" (ignored {ignored} change{'s' if ignored != 1 else ''})"
        lines.append(msg)

    enf = report.get("enforcement") or {}
    if enf:
        lines.append("\nEnforcement")
        status = str(enf.get("status") or "").strip().lower()
        if status == "applied":
            extra = ""
            tags = enf.get("tags") or []
            scope = enf.get("scope")
            if tags:
                extra = f" (tags={','.join(str(t) for t in tags)})"
            elif scope:
                extra = f" ({scope})"
            lines.append(
                f"  applied old harvest via ansible-playbook (rc={enf.get('returncode')})"
                + extra
                + (
                    f" (finished {enf.get('finished_at')})"
                    if enf.get("finished_at")
                    else ""
                )
            )
        elif status == "failed":
            lines.append(
                f"  attempted enforcement but ansible-playbook failed (rc={enf.get('returncode')})"
            )
        elif status == "skipped":
            r = enf.get("reason")
            lines.append("  skipped" + (f": {r}" if r else ""))
        else:
            # Best-effort formatting for future fields.
            lines.append("  " + json.dumps(enf, sort_keys=True))

    pk = report.get("packages", {})
    lines.append("\nPackages")
    lines.append(f"  added:   {len(pk.get('added', []) or [])}")
    lines.append(f"  removed: {len(pk.get('removed', []) or [])}")
    ignored_v = int(pk.get("version_changed_ignored_count") or 0)
    vc = len(pk.get("version_changed", []) or [])
    suffix = f" (ignored {ignored_v})" if ignored_v else ""
    lines.append(f"  version_changed: {vc}{suffix}")
    for p in pk.get("added", []) or []:
        lines.append(f"    + {p}")
    for p in pk.get("removed", []) or []:
        lines.append(f"    - {p}")
    for ch in pk.get("version_changed", []) or []:
        lines.append(f"    ~ {ch.get('package')}: {ch.get('old')} -> {ch.get('new')}")

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
            (pk.get("version_changed") or []),
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

    filt = report.get("filters", {}) or {}
    ex_paths = filt.get("exclude_paths", []) or []
    if ex_paths:
        out.append(
            "- **File exclude patterns**: "
            + ", ".join(f"`{p}`" for p in ex_paths)
            + "\n"
        )

    if filt.get("ignore_package_versions"):
        ignored = int(
            (report.get("packages", {}) or {}).get("version_changed_ignored_count") or 0
        )
        msg = "- **Package version drift**: ignored (`--ignore-package-versions`)"
        if ignored:
            msg += f" (ignored {ignored} change{'s' if ignored != 1 else ''})"
        out.append(msg + "\n")

    enf = report.get("enforcement") or {}
    if enf:
        out.append("\n## Enforcement\n")
        status = str(enf.get("status") or "").strip().lower()
        if status == "applied":
            extra = ""
            tags = enf.get("tags") or []
            scope = enf.get("scope")
            if tags:
                extra = " (tags=" + ",".join(str(t) for t in tags) + ")"
            elif scope:
                extra = f" ({scope})"
            out.append(
                "- ✅ Applied old harvest via ansible-playbook"
                + extra
                + (
                    f" (rc={enf.get('returncode')})"
                    if enf.get("returncode") is not None
                    else ""
                )
                + (
                    f" (finished `{enf.get('finished_at')}`)"
                    if enf.get("finished_at")
                    else ""
                )
                + "\n"
            )
        elif status == "failed":
            out.append(
                "- ⚠️ Attempted enforcement but ansible-playbook failed"
                + (
                    f" (rc={enf.get('returncode')})"
                    if enf.get("returncode") is not None
                    else ""
                )
                + "\n"
            )
        elif status == "skipped":
            r = enf.get("reason")
            out.append("- Skipped" + (f": {r}" if r else "") + "\n")
        else:
            out.append(f"- {json.dumps(enf, sort_keys=True)}\n")

    pk = report.get("packages", {})
    out.append("## Packages\n")
    out.append(f"- Added: {len(pk.get('added', []) or [])}\n")
    for p in pk.get("added", []) or []:
        out.append(f"  - `+ {p}`\n")
    out.append(f"- Removed: {len(pk.get('removed', []) or [])}\n")
    for p in pk.get("removed", []) or []:
        out.append(f"  - `- {p}`\n")

    ignored_v = int(pk.get("version_changed_ignored_count") or 0)
    vc = len(pk.get("version_changed", []) or [])
    suffix = f" (ignored {ignored_v})" if ignored_v else ""
    out.append(f"- Version changed: {vc}{suffix}\n")
    for ch in pk.get("version_changed", []) or []:
        out.append(
            f"  - `~ {ch.get('package')}`: `{ch.get('old')}` → `{ch.get('new')}`\n"
        )

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
            (pk.get("version_changed") or []),
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
