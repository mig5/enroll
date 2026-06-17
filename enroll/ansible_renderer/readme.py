from __future__ import annotations

import os
import re
from typing import Any, Callable, Dict, List, Set


def _markdown_list(items: List[str]) -> str:
    values = [str(item) for item in items if str(item)]
    return "\n".join(f"- {item}" for item in values) or "- (none)"


def _managed_file_lines(
    managed_files: List[Dict[str, Any]], *, include_reason: bool
) -> List[str]:
    out: List[str] = []
    for mf in managed_files:
        path = str(mf.get("path") or "")
        if not path:
            continue
        if include_reason:
            out.append(f"{path} ({mf.get('reason')})")
        else:
            out.append(path)
    return out


def _excluded_lines(excluded: List[Dict[str, Any]]) -> List[str]:
    return [f"{e.get('path')} ({e.get('reason')})" for e in excluded if e.get("path")]


def _read_artifact_lines(bundle_dir: str, role: str, src_rel: str) -> List[str]:
    art_path = os.path.join(bundle_dir, "artifacts", role, src_rel)
    try:
        with open(art_path, "r", encoding="utf-8", errors="replace") as f:
            return [line.rstrip("\n") for line in f]
    except OSError:
        return []


def _apt_config_readme(
    *,
    bundle_dir: str,
    role: str,
    snapshot: Dict[str, Any],
    managed_files: List[Dict[str, Any]],
    managed_dirs: List[Dict[str, Any]],
    excluded: List[Dict[str, Any]],
    notes: List[Any],
) -> str:
    source_paths: List[str] = []
    keyring_paths: List[str] = []
    repo_hosts: Set[str] = set()
    url_re = re.compile(r"(?:https?|ftp)://([^/\s]+)", re.IGNORECASE)

    for mf in managed_files:
        path = str(mf.get("path") or "")
        src_rel = str(mf.get("src_rel") or "")
        if not path or not src_rel:
            continue
        if path == "/etc/apt/sources.list" or path.startswith(
            "/etc/apt/sources.list.d/"
        ):
            source_paths.append(path)
            for line in _read_artifact_lines(bundle_dir, role, src_rel):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                for match in url_re.finditer(s):
                    repo_hosts.add(match.group(1))
        if (
            path.startswith("/etc/apt/trusted.gpg")
            or path.startswith("/etc/apt/keyrings/")
            or path.startswith("/usr/share/keyrings/")
        ):
            keyring_paths.append(path)

    return f"""# apt_config

APT configuration harvested from the system (sources, pinning, and keyrings).

## Repository hosts
{_markdown_list(sorted(repo_hosts))}

## Source files
{_markdown_list(sorted(set(source_paths)))}

## Keyrings
{_markdown_list(sorted(set(keyring_paths)))}

## Managed files
{_markdown_list(_managed_file_lines(managed_files, include_reason=True))}

## Excluded
{_markdown_list(_excluded_lines(excluded))}

## Notes
{_markdown_list([str(n) for n in notes])}
"""


def _dnf_config_readme(
    *,
    bundle_dir: str,
    role: str,
    snapshot: Dict[str, Any],
    managed_files: List[Dict[str, Any]],
    managed_dirs: List[Dict[str, Any]],
    excluded: List[Dict[str, Any]],
    notes: List[Any],
) -> str:
    repo_paths: List[str] = []
    key_paths: List[str] = []
    repo_hosts: Set[str] = set()
    url_re = re.compile(r"(?:https?|ftp)://([^/\s]+)", re.IGNORECASE)
    file_url_re = re.compile(r"file://(/[^\s]+)")

    for mf in managed_files:
        path = str(mf.get("path") or "")
        src_rel = str(mf.get("src_rel") or "")
        if not path or not src_rel:
            continue
        if path.startswith("/etc/yum.repos.d/") and path.endswith(".repo"):
            repo_paths.append(path)
            for line in _read_artifact_lines(bundle_dir, role, src_rel):
                s = line.strip()
                if not s or s.startswith("#") or s.startswith(";"):
                    continue
                for match in url_re.finditer(s):
                    repo_hosts.add(match.group(1))
                for match in file_url_re.finditer(s):
                    key_paths.append(match.group(1))
        if path.startswith("/etc/pki/rpm-gpg/"):
            key_paths.append(path)

    return f"""# dnf_config

DNF/YUM configuration harvested from the system (repos, config files, and RPM GPG keys).

## Repository hosts
{_markdown_list(sorted(repo_hosts))}

## Repo files
{_markdown_list(sorted(set(repo_paths)))}

## GPG keys
{_markdown_list(sorted(set(key_paths)))}

## Managed files
{_markdown_list(_managed_file_lines(managed_files, include_reason=True))}

## Excluded
{_markdown_list(_excluded_lines(excluded))}

## Notes
{_markdown_list([str(n) for n in notes])}
"""


def _simple_managed_files_readme(
    title: str,
    description: str,
    *,
    include_reason: bool,
) -> Callable[..., str]:
    def _builder(
        *,
        bundle_dir: str,
        role: str,
        snapshot: Dict[str, Any],
        managed_files: List[Dict[str, Any]],
        managed_dirs: List[Dict[str, Any]],
        excluded: List[Dict[str, Any]],
        notes: List[Any],
    ) -> str:
        return f"""# {title}

{description}

## Managed files
{_markdown_list(_managed_file_lines(managed_files, include_reason=include_reason))}

## Excluded
{_markdown_list(_excluded_lines(excluded))}

## Notes
{_markdown_list([str(n) for n in notes])}
"""

    return _builder


def _extra_paths_readme(
    *,
    bundle_dir: str,
    role: str,
    snapshot: Dict[str, Any],
    managed_files: List[Dict[str, Any]],
    managed_dirs: List[Dict[str, Any]],
    excluded: List[Dict[str, Any]],
    notes: List[Any],
) -> str:
    include_pats = snapshot.get("include_patterns", []) or []
    exclude_pats = snapshot.get("exclude_patterns", []) or []
    return f"""# {role}

User-requested extra file harvesting.

## Include patterns
{_markdown_list([str(p) for p in include_pats])}

## Exclude patterns
{_markdown_list([str(p) for p in exclude_pats])}

## Managed directories
{_markdown_list([str(d.get('path') or '') for d in managed_dirs])}

## Managed files
{_markdown_list(_managed_file_lines(managed_files, include_reason=False))}

## Excluded
{_markdown_list(_excluded_lines(excluded))}

## Notes
{_markdown_list([str(n) for n in notes])}
"""
