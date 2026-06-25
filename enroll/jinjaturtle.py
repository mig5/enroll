from __future__ import annotations

import hashlib
import re
import shutil
import subprocess  # nosec
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .manifest_safety import ArtifactSafetyError, safe_artifact_file
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


_JINJA_EXPR_VAR_RE = re.compile(r"{{\s*([A-Za-z_][A-Za-z0-9_]*)\b")
_JINJA_FOR_RE = re.compile(
    r"{%\s*for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
_JINJA_SPECIAL_VARS = {"loop", "true", "false", "none", "True", "False", "None"}


def _find_undeclared_jinja_vars(template_text: str) -> Set[str]:
    try:
        from jinja2 import Environment, meta  # type: ignore

        env = Environment()  # nosec B701 - parsing config templates, not rendering HTML
        ast = env.parse(template_text)
        return set(meta.find_undeclared_variables(ast))
    except Exception:
        locals_from_loops: Set[str] = set()
        collection_vars: Set[str] = set()
        for match in _JINJA_FOR_RE.finditer(template_text):
            locals_from_loops.add(match.group(1))
            collection_vars.add(match.group(2))

        referenced = set(_JINJA_EXPR_VAR_RE.findall(template_text)) | collection_vars
        referenced -= locals_from_loops
        referenced -= _JINJA_SPECIAL_VARS
        return referenced


def missing_jinja_template_vars(
    template_text: str, context: Dict[str, Any]
) -> Set[str]:
    """Return variables referenced by a JinjaTurtle template but absent from vars.

    This is a defensive check for Enroll's best-effort templating path. If
    JinjaTurtle ever emits a placeholder without a matching default variable,
    Enroll should fall back to copying the raw harvested file rather than
    generating an Ansible role that fails at apply time.
    """

    referenced = _find_undeclared_jinja_vars(template_text)
    referenced -= _JINJA_SPECIAL_VARS
    return {name for name in referenced if name not in context}


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
    """Best-effort conversion of one harvested artifact into a Jinja2 template."""
    if not (jt_enabled and jt_exe and can_jinjify_path(dest_path)):
        return None

    try:
        artifact_path = safe_artifact_file(bundle_dir, artifact_role, src_rel)
    except (ArtifactSafetyError, FileNotFoundError):
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

    context = yaml_load_mapping(result.vars_text)
    missing = missing_jinja_template_vars(result.template_text, context)
    if missing:
        # If this role was generated into an existing output directory, avoid
        # leaving an obsolete template behind after falling back to a raw copy.
        if overwrite_templates and template_dst.exists():
            template_dst.unlink()
        return None

    if overwrite_templates or not template_dst.exists():
        template_dst.parent.mkdir(parents=True, exist_ok=True)
        template_dst.write_text(result.template_text, encoding="utf-8")

    return JinjifiedArtifact(
        template_rel=template_rel,
        template_text=result.template_text,
        vars_text=result.vars_text,
        context=context,
    )


def managed_file_var_prefix(role_name: str, src_rel: str) -> str:
    """Return a JinjaTurtle-safe variable prefix for one managed file.

    JinjaTurtle's ``--role-name`` is a variable prefix. Enroll can place many
    unrelated managed files in one generated role, so using only the role name
    can collide for common keys such as ``enabled``, ``ignore``, or ``name``.
    Include the relative artifact path when a role templates multiple files.
    """

    raw = f"{role_name}_{src_rel}"
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_").lower()
    safe = re.sub(r"_+", "_", safe)
    if not safe:
        safe = "managed_file"
    if len(safe) > 96:
        digest = hashlib.sha1(  # nosec B324
            raw.encode("utf-8", errors="replace")
        ).hexdigest()[:8]
        safe = safe[:80].rstrip("_") + "_" + digest
    return safe


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

    The return shape is ``(templated_src_rels, combined_vars_text)``.
    """
    templated: Set[str] = set()
    vars_map: Dict[str, Any] = {}
    base_role_name = role_name or artifact_role
    candidates = [
        mf
        for mf in managed_files
        if str(mf.get("path") or "")
        and str(mf.get("src_rel") or "")
        and can_jinjify_path(str(mf.get("path") or ""))
    ]
    namespace_by_file = len(candidates) > 1

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
            role_name=(
                managed_file_var_prefix(base_role_name, src_rel)
                if namespace_by_file
                else base_role_name
            ),
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
