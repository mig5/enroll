from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Set, Tuple

from ..jinjaturtle import can_jinjify_path, infer_other_formats, run_jinjaturtle
from .yamlutil import _merge_mappings_overwrite, _yaml_dump_mapping, _yaml_load_mapping


def _jinjify_managed_files(
    bundle_dir: str,
    role: str,
    role_dir: str,
    managed_files: List[Dict[str, Any]],
    *,
    jt_exe: Optional[str],
    jt_enabled: bool,
    overwrite_templates: bool,
) -> Tuple[Set[str], str]:
    """
    Return (templated_src_rels, combined_vars_text).
    combined_vars_text is a YAML mapping fragment (no leading ---).
    """
    templated: Set[str] = set()
    vars_map: Dict[str, Any] = {}

    if not (jt_enabled and jt_exe):
        return templated, ""

    for mf in managed_files:
        dest_path = mf.get("path", "")
        src_rel = mf.get("src_rel", "")
        if not dest_path or not src_rel:
            continue
        if not can_jinjify_path(dest_path):
            continue

        artifact_path = os.path.join(bundle_dir, "artifacts", role, src_rel)
        if not os.path.isfile(artifact_path):
            continue

        try:
            force_fmt = infer_other_formats(dest_path)
            res = run_jinjaturtle(
                jt_exe, artifact_path, role_name=role, force_format=force_fmt
            )
        except Exception:
            # If jinjaturtle cannot process a file for any reason, skip silently.
            # (Enroll's core promise is to be optimistic and non-interactive.)
            continue  # nosec

        tmpl_rel = src_rel + ".j2"
        tmpl_dst = os.path.join(role_dir, "templates", tmpl_rel)
        if overwrite_templates or not os.path.exists(tmpl_dst):
            os.makedirs(os.path.dirname(tmpl_dst), exist_ok=True)
            with open(tmpl_dst, "w", encoding="utf-8") as f:
                f.write(res.template_text)

        templated.add(src_rel)
        if res.vars_text.strip():
            # merge YAML mappings; last wins (avoids duplicate keys)
            chunk = _yaml_load_mapping(res.vars_text)
            if chunk:
                vars_map = _merge_mappings_overwrite(vars_map, chunk)

    if vars_map:
        combined = _yaml_dump_mapping(vars_map, sort_keys=True)
        return templated, combined
    return templated, ""
