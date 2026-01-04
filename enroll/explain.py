from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

from .diff import _bundle_from_input, _load_state  # reuse existing bundle handling


@dataclass(frozen=True)
class ReasonInfo:
    title: str
    why: str


_MANAGED_FILE_REASONS: Dict[str, ReasonInfo] = {
    # Package manager / repo config
    "apt_config": ReasonInfo(
        "APT configuration",
        "APT configuration affecting package installation and repository behavior.",
    ),
    "apt_source": ReasonInfo(
        "APT repository source",
        "APT source list entries (e.g. sources.list or sources.list.d).",
    ),
    "apt_keyring": ReasonInfo(
        "APT keyring",
        "Repository signing key material used by APT.",
    ),
    "apt_signed_by_keyring": ReasonInfo(
        "APT Signed-By keyring",
        "Keyring referenced via a Signed-By directive in an APT source.",
    ),
    "yum_conf": ReasonInfo(
        "YUM/DNF main config",
        "Primary YUM configuration (often /etc/yum.conf).",
    ),
    "yum_config": ReasonInfo(
        "YUM/DNF config",
        "YUM/DNF configuration files (including conf.d).",
    ),
    "yum_repo": ReasonInfo(
        "YUM/DNF repository",
        "YUM/DNF repository definitions (e.g. yum.repos.d).",
    ),
    "dnf_config": ReasonInfo(
        "DNF configuration",
        "DNF configuration affecting package installation and repositories.",
    ),
    "rpm_gpg_key": ReasonInfo(
        "RPM GPG key",
        "Repository signing keys used by RPM/YUM/DNF.",
    ),
    # SSH
    "authorized_keys": ReasonInfo(
        "SSH authorized keys",
        "User authorized_keys files (controls who can log in with SSH keys).",
    ),
    "ssh_public_key": ReasonInfo(
        "SSH public key",
        "SSH host/user public keys relevant to authentication.",
    ),
    # System config / security
    "system_security": ReasonInfo(
        "Security configuration",
        "Security-sensitive configuration (SSH, sudoers, PAM, auth, etc.).",
    ),
    "system_network": ReasonInfo(
        "Network configuration",
        "Network configuration (interfaces, resolv.conf, network managers, etc.).",
    ),
    "system_firewall": ReasonInfo(
        "Firewall configuration",
        "Firewall rules/configuration (ufw, nftables, iptables, etc.).",
    ),
    "system_sysctl": ReasonInfo(
        "sysctl configuration",
        "Kernel sysctl tuning (sysctl.conf / sysctl.d).",
    ),
    "system_modprobe": ReasonInfo(
        "modprobe configuration",
        "Kernel module configuration (modprobe.d).",
    ),
    "system_mounts": ReasonInfo(
        "Mount configuration",
        "Mount configuration (e.g. /etc/fstab and related).",
    ),
    "system_rc": ReasonInfo(
        "Startup/rc configuration",
        "Startup scripts / rc configuration that can affect boot behavior.",
    ),
    # systemd + timers
    "systemd_dropin": ReasonInfo(
        "systemd drop-in",
        "systemd override/drop-in files that modify a unit's behavior.",
    ),
    "systemd_envfile": ReasonInfo(
        "systemd EnvironmentFile",
        "Files referenced by systemd units via EnvironmentFile.",
    ),
    "related_timer": ReasonInfo(
        "Related systemd timer",
        "A systemd timer captured because it is related to a unit/service.",
    ),
    # cron / logrotate
    "system_cron": ReasonInfo(
        "System cron",
        "System cron configuration (crontab, cron.d, etc.).",
    ),
    "cron_snippet": ReasonInfo(
        "Cron snippet",
        "Cron snippets referenced/used by harvested services or configs.",
    ),
    "system_logrotate": ReasonInfo(
        "System logrotate",
        "System logrotate configuration.",
    ),
    "logrotate_snippet": ReasonInfo(
        "logrotate snippet",
        "logrotate snippets/configs referenced in system configuration.",
    ),
    # Custom paths / drift signals
    "modified_conffile": ReasonInfo(
        "Modified package conffile",
        "A package-managed conffile differs from the packaged/default version.",
    ),
    "modified_packaged_file": ReasonInfo(
        "Modified packaged file",
        "A file owned by a package differs from the packaged version.",
    ),
    "custom_unowned": ReasonInfo(
        "Unowned custom file",
        "A file not owned by any package (often custom/operator-managed).",
    ),
    "custom_specific_path": ReasonInfo(
        "Custom specific path",
        "A specific path included by a custom rule or snapshot.",
    ),
    "usr_local_bin_script": ReasonInfo(
        "/usr/local/bin script",
        "Executable scripts under /usr/local/bin (often operator-installed).",
    ),
    "usr_local_etc_custom": ReasonInfo(
        "/usr/local/etc custom",
        "Custom configuration under /usr/local/etc.",
    ),
    # User includes
    "user_include": ReasonInfo(
        "User-included path",
        "Included because you specified it via --include-path / include patterns.",
    ),
}

_MANAGED_DIR_REASONS: Dict[str, ReasonInfo] = {
    "parent_of_managed_file": ReasonInfo(
        "Parent directory",
        "Included so permissions/ownership can be recreated for managed files.",
    ),
    "user_include_dir": ReasonInfo(
        "User-included directory",
        "Included because you specified it via --include-path / include patterns.",
    ),
}

_EXCLUDED_REASONS: Dict[str, ReasonInfo] = {
    "user_excluded": ReasonInfo(
        "User excluded",
        "Excluded because you explicitly excluded it (e.g. --exclude-path / patterns).",
    ),
    "unreadable": ReasonInfo(
        "Unreadable",
        "Enroll could not read this path with the permissions it had.",
    ),
    "log_file": ReasonInfo(
        "Log file",
        "Excluded because it appears to be a log file (usually noisy/large).",
    ),
    "denied_path": ReasonInfo(
        "Denied path",
        "Excluded because the path is in a denylist for safety.",
    ),
    "too_large": ReasonInfo(
        "Too large",
        "Excluded because it exceeded the size limit for harvested files.",
    ),
    "not_regular_file": ReasonInfo(
        "Not a regular file",
        "Excluded because it was not a regular file (device, socket, etc.).",
    ),
    "binary_like": ReasonInfo(
        "Binary-like",
        "Excluded because it looked like binary content (not useful for config management).",
    ),
    "sensitive_content": ReasonInfo(
        "Sensitive content",
        "Excluded because it likely contains secrets (e.g. shadow, private keys).",
    ),
}

_OBSERVED_VIA: Dict[str, ReasonInfo] = {
    "user_installed": ReasonInfo(
        "User-installed",
        "Package appears explicitly installed (as opposed to only pulled in as a dependency).",
    ),
    "systemd_unit": ReasonInfo(
        "Referenced by systemd unit",
        "Package is associated with a systemd unit that was harvested.",
    ),
    "package_role": ReasonInfo(
        "Referenced by package role",
        "Package was referenced by an enroll packages snapshot/role.",
    ),
}


def _ri(mapping: Dict[str, ReasonInfo], key: str) -> ReasonInfo:
    return mapping.get(key) or ReasonInfo(key, f"Captured with reason '{key}'")


def _role_common_counts(role_obj: Dict[str, Any]) -> Tuple[int, int, int, int]:
    """Return (managed_files, managed_dirs, excluded, notes) counts for a RoleCommon object."""
    mf = len(role_obj.get("managed_files") or [])
    md = len(role_obj.get("managed_dirs") or [])
    ex = len(role_obj.get("excluded") or [])
    nt = len(role_obj.get("notes") or [])
    return mf, md, ex, nt


def _summarize_reasons(
    items: Iterable[Dict[str, Any]],
    reason_key: str,
    *,
    mapping: Dict[str, ReasonInfo],
    max_examples: int,
) -> List[Dict[str, Any]]:
    by_reason: Dict[str, List[str]] = defaultdict(list)
    counts: Counter[str] = Counter()

    for it in items:
        if not isinstance(it, dict):
            continue
        r = it.get(reason_key)
        if not r:
            continue
        r = str(r)
        counts[r] += 1
        p = it.get("path")
        if (
            max_examples > 0
            and isinstance(p, str)
            and p
            and len(by_reason[r]) < max_examples
        ):
            by_reason[r].append(p)

    out: List[Dict[str, Any]] = []
    for reason, count in counts.most_common():
        info = _ri(mapping, reason)
        out.append(
            {
                "reason": reason,
                "count": count,
                "title": info.title,
                "why": info.why,
                "examples": by_reason.get(reason, []),
            }
        )
    return out


def explain_state(
    harvest: str,
    *,
    sops_mode: bool = False,
    fmt: str = "text",
    max_examples: int = 3,
) -> str:
    """Explain a harvest bundle's state.json.

    `harvest` may be:
      - a bundle directory
      - a path to state.json
      - a tarball (.tar.gz/.tgz)
      - a SOPS-encrypted bundle (.sops)
    """
    bundle = _bundle_from_input(harvest, sops_mode=sops_mode)
    state = _load_state(bundle.dir)

    host = state.get("host") or {}
    enroll = state.get("enroll") or {}
    roles = state.get("roles") or {}
    inv = state.get("inventory") or {}
    inv_pkgs = (inv.get("packages") or {}) if isinstance(inv, dict) else {}

    role_summaries: List[Dict[str, Any]] = []

    # Users
    users_obj = roles.get("users") or {}
    user_entries = users_obj.get("users") or []
    mf, md, ex, _nt = (
        _role_common_counts(users_obj) if isinstance(users_obj, dict) else (0, 0, 0, 0)
    )
    role_summaries.append(
        {
            "role": "users",
            "summary": f"{len(user_entries)} user(s), {mf} file(s), {ex} excluded",
            "notes": users_obj.get("notes") or [],
        }
    )

    # Services
    services_list = roles.get("services") or []
    if isinstance(services_list, list):
        total_mf = sum(
            len((s.get("managed_files") or []))
            for s in services_list
            if isinstance(s, dict)
        )
        total_ex = sum(
            len((s.get("excluded") or [])) for s in services_list if isinstance(s, dict)
        )
        role_summaries.append(
            {
                "role": "services",
                "summary": f"{len(services_list)} unit(s), {total_mf} file(s), {total_ex} excluded",
                "units": [
                    {
                        "unit": s.get("unit"),
                        "active_state": s.get("active_state"),
                        "sub_state": s.get("sub_state"),
                        "unit_file_state": s.get("unit_file_state"),
                        "condition_result": s.get("condition_result"),
                    }
                    for s in services_list
                    if isinstance(s, dict)
                ],
            }
        )

    # Package snapshots
    pkgs_list = roles.get("packages") or []
    if isinstance(pkgs_list, list):
        total_mf = sum(
            len((p.get("managed_files") or []))
            for p in pkgs_list
            if isinstance(p, dict)
        )
        total_ex = sum(
            len((p.get("excluded") or [])) for p in pkgs_list if isinstance(p, dict)
        )
        role_summaries.append(
            {
                "role": "packages",
                "summary": f"{len(pkgs_list)} package snapshot(s), {total_mf} file(s), {total_ex} excluded",
                "packages": [
                    p.get("package") for p in pkgs_list if isinstance(p, dict)
                ],
            }
        )

    # Single snapshots
    for rname in [
        "apt_config",
        "dnf_config",
        "etc_custom",
        "usr_local_custom",
        "extra_paths",
    ]:
        robj = roles.get(rname) or {}
        if not isinstance(robj, dict):
            continue
        mf, md, ex, _nt = _role_common_counts(robj)
        extra: Dict[str, Any] = {}
        if rname == "extra_paths":
            extra = {
                "include_patterns": robj.get("include_patterns") or [],
                "exclude_patterns": robj.get("exclude_patterns") or [],
            }
        role_summaries.append(
            {
                "role": rname,
                "summary": f"{mf} file(s), {md} dir(s), {ex} excluded",
                "notes": robj.get("notes") or [],
                **extra,
            }
        )

    # Flatten managed/excluded across roles
    all_managed_files: List[Dict[str, Any]] = []
    all_managed_dirs: List[Dict[str, Any]] = []
    all_excluded: List[Dict[str, Any]] = []

    def _consume_role(role_obj: Dict[str, Any]) -> None:
        for f in role_obj.get("managed_files") or []:
            if isinstance(f, dict):
                all_managed_files.append(f)
        for d in role_obj.get("managed_dirs") or []:
            if isinstance(d, dict):
                all_managed_dirs.append(d)
        for e in role_obj.get("excluded") or []:
            if isinstance(e, dict):
                all_excluded.append(e)

    if isinstance(users_obj, dict):
        _consume_role(users_obj)
    if isinstance(services_list, list):
        for s in services_list:
            if isinstance(s, dict):
                _consume_role(s)
    if isinstance(pkgs_list, list):
        for p in pkgs_list:
            if isinstance(p, dict):
                _consume_role(p)
    for rname in [
        "apt_config",
        "dnf_config",
        "etc_custom",
        "usr_local_custom",
        "extra_paths",
    ]:
        robj = roles.get(rname)
        if isinstance(robj, dict):
            _consume_role(robj)

    managed_file_reasons = _summarize_reasons(
        all_managed_files,
        "reason",
        mapping=_MANAGED_FILE_REASONS,
        max_examples=max_examples,
    )
    managed_dir_reasons = _summarize_reasons(
        all_managed_dirs,
        "reason",
        mapping=_MANAGED_DIR_REASONS,
        max_examples=max_examples,
    )
    excluded_reasons = _summarize_reasons(
        all_excluded,
        "reason",
        mapping=_EXCLUDED_REASONS,
        max_examples=max_examples,
    )

    # Inventory observed_via breakdown (count packages that contain at least one entry for that kind)
    observed_kinds: Counter[str] = Counter()
    observed_refs: Dict[str, Counter[str]] = defaultdict(Counter)
    for _pkg, entry in inv_pkgs.items():
        if not isinstance(entry, dict):
            continue
        seen_kinds = set()
        for ov in entry.get("observed_via") or []:
            if not isinstance(ov, dict):
                continue
            kind = ov.get("kind")
            if not kind:
                continue
            kind = str(kind)
            seen_kinds.add(kind)
            ref = ov.get("ref")
            if isinstance(ref, str) and ref:
                observed_refs[kind][ref] += 1
        for k in seen_kinds:
            observed_kinds[k] += 1

    observed_via_summary: List[Dict[str, Any]] = []
    for kind, cnt in observed_kinds.most_common():
        info = _ri(_OBSERVED_VIA, kind)
        top_refs = [
            r for r, _ in observed_refs.get(kind, Counter()).most_common(max_examples)
        ]
        observed_via_summary.append(
            {
                "kind": kind,
                "count": cnt,
                "title": info.title,
                "why": info.why,
                "top_refs": top_refs,
            }
        )

    report: Dict[str, Any] = {
        "bundle_dir": str(bundle.dir),
        "host": host,
        "enroll": enroll,
        "inventory": {
            "package_count": len(inv_pkgs),
            "observed_via": observed_via_summary,
        },
        "roles": role_summaries,
        "reasons": {
            "managed_files": managed_file_reasons,
            "managed_dirs": managed_dir_reasons,
            "excluded": excluded_reasons,
        },
    }

    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=True)

    # Text rendering
    out: List[str] = []
    out.append(f"Enroll explained: {harvest}")
    hn = host.get("hostname") or "(unknown host)"
    os_family = host.get("os") or "unknown"
    pkg_backend = host.get("pkg_backend") or "?"
    ver = enroll.get("version") or "?"
    out.append(f"Host: {hn} (os: {os_family}, pkg: {pkg_backend})")
    out.append(f"Enroll: {ver}")
    out.append("")

    out.append("Inventory")
    out.append(f"- Packages: {len(inv_pkgs)}")
    if observed_via_summary:
        out.append("- Why packages were included (observed_via):")
        for ov in observed_via_summary:
            extra = ""
            if ov.get("top_refs"):
                extra = f" (e.g. {', '.join(ov['top_refs'])})"
            out.append(f"  - {ov['kind']}: {ov['count']} – {ov['why']}{extra}")
    out.append("")

    out.append("Roles collected")
    for rs in role_summaries:
        out.append(f"- {rs['role']}: {rs['summary']}")
        if rs["role"] == "extra_paths":
            inc = rs.get("include_patterns") or []
            exc = rs.get("exclude_patterns") or []
            if inc:
                suffix = "…" if len(inc) > max_examples else ""
                out.append(
                    f"    include_patterns: {', '.join(map(str, inc[:max_examples]))}{suffix}"
                )
            if exc:
                suffix = "…" if len(exc) > max_examples else ""
                out.append(
                    f"    exclude_patterns: {', '.join(map(str, exc[:max_examples]))}{suffix}"
                )
        notes = rs.get("notes") or []
        if notes:
            for n in notes[:max_examples]:
                out.append(f"    note: {n}")
            if len(notes) > max_examples:
                out.append(
                    f"    note: (+{len(notes) - max_examples} more. Use --format json to see them all)"
                )
    out.append("")

    out.append("Why files were included (managed_files.reason)")
    if managed_file_reasons:
        for r in managed_file_reasons[:15]:
            exs = r.get("examples") or []
            ex_txt = f" Examples: {', '.join(exs)}" if exs else ""
            out.append(f"- {r['reason']} ({r['count']}): {r['why']}.{ex_txt}")
        if len(managed_file_reasons) > 15:
            out.append(
                f"- (+{len(managed_file_reasons) - 15} more reasons. Use --format json to see them all)"
            )
    else:
        out.append("- (no managed files)")

    if managed_dir_reasons:
        out.append("")
        out.append("Why directories were included (managed_dirs.reason)")
        for r in managed_dir_reasons:
            out.append(f"- {r['reason']} ({r['count']}): {r['why']}")

    out.append("")
    out.append("Why paths were excluded")
    if excluded_reasons:
        for r in excluded_reasons:
            exs = r.get("examples") or []
            ex_txt = f" Examples: {', '.join(exs)}" if exs else ""
            out.append(f"- {r['reason']} ({r['count']}): {r['why']}.{ex_txt}")
    else:
        out.append("- (no excluded paths)")

    return "\n".join(out) + "\n"
