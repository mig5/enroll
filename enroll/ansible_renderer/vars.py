from __future__ import annotations

from typing import Any, Dict, List, Optional, Set


def _normalise_flatpak_item(
    item: Any,
    *,
    method: str,
    user: Optional[str] = None,
    home: Optional[str] = None,
) -> Dict[str, Any]:
    if isinstance(item, str):
        out: Dict[str, Any] = {"name": item, "method": method}
    elif isinstance(item, dict):
        out = dict(item)
        out.setdefault("method", method)
    else:
        out = {"name": str(item), "method": method}
    if user:
        out.setdefault("user", user)
    if home:
        out.setdefault("home", home)
    return out


def _normalise_flatpak_remote(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        out = dict(item)
    else:
        out = {"name": str(item)}
    out.setdefault("method", "system")
    return out


def _normalise_snap_item(item: Any) -> Dict[str, Any]:
    if isinstance(item, str):
        out: Dict[str, Any] = {"name": item}
    elif isinstance(item, dict):
        out = dict(item)
    else:
        out = {"name": str(item)}

    notes = out.get("notes") or []
    if isinstance(notes, str):
        notes = [notes]
    notes_l = {str(n).lower() for n in notes}
    out["classic"] = bool(out.get("classic") or "classic" in notes_l)
    out["devmode"] = bool(out.get("devmode") or "devmode" in notes_l)
    out["dangerous"] = bool(out.get("dangerous") or "dangerous" in notes_l)

    # The Ansible snap module's revision parameter pins/holds the snap. For
    # ordinary store snaps that track a channel, preserve the channel instead
    # of freezing every harvested host at today's revision.
    if out.get("revision") is not None and not out.get("channel"):
        out["install_revision"] = True
    else:
        out["install_revision"] = False
    return out


def _build_managed_dirs_var(
    managed_dirs: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Convert enroll managed_dirs into an Ansible-friendly list of dicts.

    Each dict drives a role task loop and is safe across hosts.
    """
    out: List[Dict[str, Any]] = []
    for d in managed_dirs:
        dest = d.get("path") or ""
        if not dest:
            continue
        out.append(
            {
                "dest": dest,
                "owner": d.get("owner") or "root",
                "group": d.get("group") or "root",
                "mode": d.get("mode") or "0755",
            }
        )
    return out


def _build_managed_files_var(
    managed_files: List[Dict[str, Any]],
    templated_src_rels: Set[str],
    *,
    notify_other: Optional[str] = None,
    notify_systemd: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Convert enroll managed_files into an Ansible-friendly list of dicts.

    Each dict drives a role task loop and is safe across hosts.
    """
    out: List[Dict[str, Any]] = []
    for mf in managed_files:
        dest = mf.get("path") or ""
        src_rel = mf.get("src_rel") or ""
        if not dest or not src_rel:
            continue
        is_unit = str(dest).startswith("/etc/systemd/system/")
        kind = "template" if src_rel in templated_src_rels else "copy"
        notify: List[str] = []
        if is_unit and notify_systemd:
            notify.append(notify_systemd)
        if (not is_unit) and notify_other:
            notify.append(notify_other)
        out.append(
            {
                "dest": dest,
                "src_rel": src_rel,
                "owner": mf.get("owner") or "root",
                "group": mf.get("group") or "root",
                "mode": mf.get("mode") or "0644",
                "kind": kind,
                "is_systemd_unit": bool(is_unit),
                "notify": notify,
            }
        )
    return out


def _build_managed_links_var(
    managed_links: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Convert enroll managed_links into an Ansible-friendly list of dicts."""
    out: List[Dict[str, Any]] = []
    for ml in managed_links or []:
        dest = ml.get("path") or ""
        src = ml.get("target") or ""
        if not dest or not src:
            continue
        out.append({"dest": dest, "src": src})
    return out


def _normalise_container_image_item(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        out = dict(item)
    else:
        out = {"pull_ref": str(item)}
    out.setdefault("engine", "docker")
    out.setdefault("scope", "system")
    out.setdefault("user", None)
    out.setdefault("home", None)
    out.setdefault("repo_tags", [])
    out.setdefault("repo_digests", [])
    out.setdefault("tag_aliases", [])
    out.setdefault("notes", [])
    return out
