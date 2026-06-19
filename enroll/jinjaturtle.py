from __future__ import annotations

import shutil
import subprocess  # nosec
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .yamlutil import yaml_dump_mapping, yaml_load_mapping


SYSTEMD_SUFFIXES = {
    ".service",
    ".socket",
    ".target",
    ".timer",
    ".path",
    ".mount",
    ".automount",
    ".slice",
    ".swap",
    ".scope",
    ".link",
    ".netdev",
    ".network",
}

SUPPORTED_SUFFIXES = {
    ".ini",
    ".cfg",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".xml",
    ".repo",
} | SYSTEMD_SUFFIXES


def resolve_jinjaturtle_mode(jinjaturtle: str) -> Tuple[Optional[str], bool]:
    """Resolve Enroll's common JinjaTurtle mode flag.

    Renderers accept the same values:
    - ``auto``: use JinjaTurtle when present on PATH
    - ``on``: require it and fail if it is absent
    - ``off``: never use it
    """
    jt_exe = find_jinjaturtle_cmd()
    if jinjaturtle not in {"auto", "on", "off"}:
        raise ValueError("jinjaturtle must be one of: auto, on, off")
    if jinjaturtle == "on":
        if not jt_exe:
            raise RuntimeError("jinjaturtle requested but not found on PATH")
        return jt_exe, True
    if jinjaturtle == "auto":
        return jt_exe, jt_exe is not None
    return jt_exe, False


def _merge_mappings_overwrite(
    existing: Dict[str, Any], incoming: Dict[str, Any]
) -> Dict[str, Any]:
    merged = dict(existing)
    merged.update(incoming)
    return merged


@dataclass(frozen=True)
class JinjifiedArtifact:
    template_rel: str
    template_text: str
    vars_text: str
    context: Dict[str, Any]


def jinjify_artifact(
    bundle_dir: str | Path,
    artifact_role: str,
    src_rel: str,
    dest_path: str,
    template_root: str | Path,
    *,
    jt_exe: Optional[str],
    jt_enabled: bool,
    overwrite_templates: bool = True,
    role_name: Optional[str] = None,
) -> Optional[JinjifiedArtifact]:
    """Best-effort conversion of one harvested artifact into a Jinja2 template.

    Puppet does not use JinjaTurtle, but Salt and Ansible both have the same
    philosophical operation: take ``artifacts/<role>/<src_rel>``, ask
    JinjaTurtle for a template and variable mapping, and write that template
    under the renderer's template directory. Keeping that here prevents Salt
    and Ansible from reimplementing the same probing/format/error handling.
    """
    if not (jt_enabled and jt_exe and can_jinjify_path(dest_path)):
        return None

    artifact_path = Path(bundle_dir) / "artifacts" / artifact_role / src_rel
    if not artifact_path.is_file():
        return None

    try:
        result = run_jinjaturtle(
            jt_exe,
            str(artifact_path),
            role_name=role_name or artifact_role,
            force_format=infer_other_formats(dest_path),
        )
    except Exception:
        return None  # nosec - best-effort template generation

    template_rel = Path(src_rel).as_posix() + ".j2"
    template_dst = Path(template_root) / template_rel
    if overwrite_templates or not template_dst.exists():
        template_dst.parent.mkdir(parents=True, exist_ok=True)
        template_dst.write_text(result.template_text, encoding="utf-8")

    return JinjifiedArtifact(
        template_rel=template_rel,
        template_text=result.template_text,
        vars_text=result.vars_text,
        context=yaml_load_mapping(result.vars_text),
    )


def jinjify_managed_files(
    bundle_dir: str | Path,
    artifact_role: str,
    template_root: str | Path,
    managed_files: List[Dict[str, Any]],
    *,
    jt_exe: Optional[str],
    jt_enabled: bool,
    overwrite_templates: bool,
    role_name: Optional[str] = None,
) -> Tuple[Set[str], str]:
    """Jinjify a list of managed files and return Ansible-style vars text.

    The return shape intentionally matches the historical Ansible helper:
    ``(templated_src_rels, combined_vars_text)``. Salt uses
    :func:`jinjify_artifact` directly because it stores variables as a context
    map per managed file.
    """
    templated: Set[str] = set()
    vars_map: Dict[str, Any] = {}

    for mf in managed_files:
        dest_path = str(mf.get("path") or "")
        src_rel = str(mf.get("src_rel") or "")
        if not dest_path or not src_rel:
            continue

        converted = jinjify_artifact(
            bundle_dir,
            artifact_role,
            src_rel,
            dest_path,
            template_root,
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=overwrite_templates,
            role_name=role_name or artifact_role,
        )
        if converted is None:
            continue

        templated.add(src_rel)
        if converted.context:
            vars_map = _merge_mappings_overwrite(vars_map, converted.context)

    if vars_map:
        return templated, yaml_dump_mapping(vars_map, sort_keys=True)
    return templated, ""


def infer_other_formats(dest_path: str) -> Optional[str]:
    p = Path(dest_path)
    name = p.name.lower()
    suffix = p.suffix.lower()
    # postfix
    if name == "main.cf":
        return "postfix"
    # systemd units
    if suffix in SYSTEMD_SUFFIXES:
        return "systemd"
    # OpenSSH system config files and snippets
    parts = {part.lower() for part in p.parts}
    if name in {"sshd_config", "ssh_config"}:
        return "ssh"
    if suffix == ".conf" and {"sshd_config.d", "ssh_config.d"} & parts:
        return "ssh"
    return None


@dataclass(frozen=True)
class JinjifyResult:
    template_text: str
    vars_text: str  # YAML mapping text (no leading --- expected)


def find_jinjaturtle_cmd() -> Optional[str]:
    """Return the executable path for jinjaturtle if found on PATH."""
    return shutil.which("jinjaturtle")


def can_jinjify_path(dest_path: str) -> bool:
    p = Path(dest_path)
    suffix = p.suffix.lower()
    if infer_other_formats(dest_path):
        return True
    # allow unambiguous structured formats
    if suffix in SUPPORTED_SUFFIXES:
        return True
    return False


def run_jinjaturtle(
    jt_exe: str,
    src_path: str,
    *,
    role_name: str,
    force_format: Optional[str] = None,
) -> JinjifyResult:
    """
    Run jinjaturtle against src_path and return (template, defaults-yaml).
    Uses tempfiles and captures outputs.

    jinjaturtle CLI:
      jinjaturtle <config> -r <role> [-f <format>] [-d <defaults-output>] [-t <template-output>]
    """
    src = Path(src_path)
    if not src.is_file():
        raise FileNotFoundError(src_path)

    with tempfile.TemporaryDirectory(prefix="enroll-jt-") as td:
        td_path = Path(td)
        defaults_out = td_path / "defaults.yml"
        template_out = td_path / "template.j2"

        cmd = [
            jt_exe,
            str(src),
            "-r",
            role_name,
            "-d",
            str(defaults_out),
            "-t",
            str(template_out),
        ]
        if force_format:
            cmd.extend(["-f", force_format])

        p = subprocess.run(cmd, text=True, capture_output=True)  # nosec
        if p.returncode != 0:
            raise RuntimeError(
                "jinjaturtle failed for %s (role=%s)\ncmd=%r\nstdout=%s\nstderr=%s"
                % (src_path, role_name, cmd, p.stdout, p.stderr)
            )

        vars_text = defaults_out.read_text(encoding="utf-8").strip()
        template_text = template_out.read_text(encoding="utf-8")

        # jinjaturtle outputs a YAML mapping; strip leading document marker if present
        if vars_text.startswith("---"):
            vars_text = "\n".join(vars_text.splitlines()[1:]).lstrip()

        return JinjifyResult(
            template_text=template_text, vars_text=vars_text.rstrip() + "\n"
        )
