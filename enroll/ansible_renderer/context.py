from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Tuple

from ..jinjaturtle import find_jinjaturtle_cmd


@dataclass
class AnsibleManifestContext:
    bundle_dir: str
    out_dir: str
    roles_root: str
    fqdn: Optional[str]
    site_mode: bool
    jt_exe: Optional[str]
    jt_enabled: bool


def _resolve_jinjaturtle_mode(jinjaturtle: str) -> Tuple[Optional[str], bool]:
    jt_exe = find_jinjaturtle_cmd()
    if jinjaturtle not in ("auto", "on", "off"):
        raise ValueError("jinjaturtle must be one of: auto, on, off")
    if jinjaturtle == "on":
        if not jt_exe:
            raise RuntimeError("jinjaturtle requested but not found on PATH")
        return jt_exe, True
    if jinjaturtle == "auto":
        return jt_exe, jt_exe is not None
    return jt_exe, False


def _prepare_ansible_context(
    bundle_dir: str,
    out_dir: str,
    *,
    fqdn: Optional[str],
    jinjaturtle: str,
) -> AnsibleManifestContext:
    site_mode = fqdn is not None and fqdn != ""
    jt_exe, jt_enabled = _resolve_jinjaturtle_mode(jinjaturtle)

    os.makedirs(out_dir, exist_ok=True)
    roles_root = os.path.join(out_dir, "roles")
    os.makedirs(roles_root, exist_ok=True)

    return AnsibleManifestContext(
        bundle_dir=bundle_dir,
        out_dir=out_dir,
        roles_root=roles_root,
        fqdn=fqdn,
        site_mode=site_mode,
        jt_exe=jt_exe,
        jt_enabled=jt_enabled,
    )
