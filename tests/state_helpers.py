from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

_VALID_REASON_FALLBACKS = {
    "dangerous_user_dotfile": "user_shell_rc",
    "possible_secret": "sensitive_content",
}

_COMMON_ROLES = {
    "users",
    "apt_config",
    "dnf_config",
    "etc_custom",
    "usr_local_custom",
    "extra_paths",
}


def _common_role(name: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "role_name": name,
        "managed_dirs": [],
        "managed_files": [],
        "excluded": [],
        "notes": [],
    }
    if name == "users":
        out["users"] = []
    if name == "extra_paths":
        out["include_patterns"] = []
        out["exclude_patterns"] = []
        out["managed_links"] = []
    return out


def _normalise_managed_file(mf: dict[str, Any]) -> None:
    reason = mf.get("reason")
    if reason in _VALID_REASON_FALLBACKS:
        mf["reason"] = _VALID_REASON_FALLBACKS[reason]
    mf.setdefault("owner", "root")
    mf.setdefault("group", "root")
    mf.setdefault("mode", "0644")
    mf.setdefault("reason", "modified_conffile")


def _normalise_managed_dir(md: dict[str, Any]) -> None:
    md.setdefault("owner", "root")
    md.setdefault("group", "root")
    md.setdefault("mode", "0755")
    if md.get("reason") in {None, "parent_dir"}:
        md["reason"] = "parent_of_managed_file"


def _normalise_managed_link(ml: dict[str, Any]) -> None:
    ml.setdefault("reason", "enabled_symlink")


def _normalise_common_role(role: dict[str, Any], name: str) -> None:
    role.setdefault("role_name", name)
    role.setdefault("managed_dirs", [])
    role.setdefault("managed_files", [])
    role.setdefault("excluded", [])
    role.setdefault("notes", [])
    for mf in role.get("managed_files") or []:
        if isinstance(mf, dict):
            _normalise_managed_file(mf)
    for md in role.get("managed_dirs") or []:
        if isinstance(md, dict):
            _normalise_managed_dir(md)
    for ml in role.get("managed_links") or []:
        if isinstance(ml, dict):
            _normalise_managed_link(ml)
    for ex in role.get("excluded") or []:
        if isinstance(ex, dict) and ex.get("reason") in _VALID_REASON_FALLBACKS:
            ex["reason"] = _VALID_REASON_FALLBACKS[ex["reason"]]


def make_schema_valid_state(state: dict[str, Any]) -> dict[str, Any]:
    """Return a current-schema harvest state from a compact renderer fixture.

    Many renderer tests intentionally build only the fields needed by the
    renderer under test. Manifest now validates strictly before rendering, so
    those fixtures need current-schema boilerplate too.
    """

    st = copy.deepcopy(state)
    st.pop("schema_version", None)

    enroll = st.setdefault("enroll", {})
    enroll.setdefault("version", "0.0.test")
    enroll.setdefault("harvest_time", 0)

    host = st.setdefault("host", {})
    host.setdefault("hostname", "testhost")
    host.setdefault("os", "unknown")
    host.setdefault("pkg_backend", "dpkg")
    host.setdefault("os_release", {})

    inv = st.setdefault("inventory", {})
    inv.setdefault("packages", {})
    for pkg in (inv.get("packages") or {}).values():
        if not isinstance(pkg, dict):
            continue
        pkg.setdefault("version", None)
        pkg.setdefault("arches", [])
        installations = pkg.setdefault("installations", [])
        for inst in installations:
            if isinstance(inst, dict):
                inst.setdefault("version", str(pkg.get("version") or "1.0"))
                inst.setdefault("arch", "amd64")
        observed = pkg.setdefault("observed_via", [])
        for ov in observed:
            if isinstance(ov, dict) and ov.get("kind") not in {
                "user_installed",
                "systemd_unit",
                "package_role",
                "firewall_runtime",
            }:
                ov["kind"] = "package_role"
                ov.setdefault("ref", "package")
        pkg.setdefault("roles", [])

    roles = st.setdefault("roles", {})
    for name in _COMMON_ROLES:
        cur = roles.get(name)
        if not isinstance(cur, dict):
            roles[name] = _common_role(name)
        else:
            _normalise_common_role(cur, name)

    roles.setdefault("services", [])
    roles.setdefault("packages", [])

    users = roles.get("users") or {}
    users.setdefault("users", [])
    for user in users.get("users") or []:
        if not isinstance(user, dict):
            continue
        user.setdefault("uid", 0)
        user.setdefault("gid", user.get("uid", 0))
        user.setdefault("gecos", "")
        user.setdefault("home", f"/home/{user.get('name', 'user')}")
        user.setdefault("shell", "/bin/sh")
        user.setdefault("primary_group", user.get("name", "users"))
        user.setdefault("supplementary_groups", [])

    extra = roles.get("extra_paths") or {}
    extra.setdefault("include_patterns", [])
    extra.setdefault("exclude_patterns", [])
    extra.setdefault("managed_links", [])

    for svc in roles.get("services") or []:
        if not isinstance(svc, dict):
            continue
        _normalise_common_role(svc, str(svc.get("role_name") or "service_role"))
        svc.setdefault("unit", "example.service")
        svc.setdefault("packages", [])
        svc.setdefault("active_state", None)
        svc.setdefault("sub_state", None)
        svc.setdefault("unit_file_state", None)
        svc.setdefault("condition_result", None)

    for pkg in roles.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        _normalise_common_role(
            pkg, str(pkg.get("role_name") or pkg.get("package") or "package_role")
        )
        pkg.setdefault("package", str(pkg.get("role_name") or "package"))

    if isinstance(roles.get("sysctl"), dict):
        sysctl = roles["sysctl"]
        sysctl.setdefault("role_name", "sysctl")
        sysctl.setdefault("managed_files", [])
        sysctl.setdefault("parameters", {})
        sysctl.setdefault("notes", [])
        sysctl.pop("managed_dirs", None)
        sysctl.pop("managed_links", None)
        for mf in sysctl.get("managed_files") or []:
            if isinstance(mf, dict):
                _normalise_managed_file(mf)

    if isinstance(roles.get("firewall_runtime"), dict):
        fw = roles["firewall_runtime"]
        fw.setdefault("role_name", "firewall_runtime")
        fw.setdefault("packages", [])
        fw.setdefault("ipset_save", None)
        fw.setdefault("ipset_sets", [])
        fw.setdefault("iptables_v4_save", None)
        fw.setdefault("iptables_v6_save", None)
        fw.setdefault("notes", [])

    if isinstance(roles.get("flatpak"), dict):
        roles["flatpak"].setdefault("role_name", "flatpak")
    if isinstance(roles.get("snap"), dict):
        roles["snap"].setdefault("role_name", "snap")
    if isinstance(roles.get("container_images"), dict):
        ci = roles["container_images"]
        ci.setdefault("role_name", "container_images")
        ci.setdefault("images", [])
        ci.setdefault("notes", [])
        for img in ci.get("images") or []:
            if not isinstance(img, dict):
                continue
            img.setdefault("engine", "docker")
            img.setdefault("scope", "system")
            img.setdefault("user", None)
            img.setdefault("home", None)
            img.setdefault("image_id", None)
            img.setdefault("repo_tags", [])
            img.setdefault("repo_digests", [])
            img.setdefault("pull_ref", None)
            img.setdefault("tag_aliases", [])
            img.setdefault("os", None)
            img.setdefault("architecture", None)
            img.setdefault("variant", None)
            img.setdefault("platform", None)
            img.setdefault("size", None)
            img.setdefault("created", None)
            img.setdefault("source", "test")
            img.setdefault("notes", [])

    return st


def write_schema_state(bundle: Path, state: dict[str, Any]) -> None:
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "state.json").write_text(
        json.dumps(make_schema_valid_state(state), indent=2), encoding="utf-8"
    )
