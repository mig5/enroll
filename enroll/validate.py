from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import jsonschema

from .diff import BundleRef, _bundle_from_input


@dataclass
class ValidationResult:
    errors: List[str]
    warnings: List[str]

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }

    def to_text(self) -> str:
        lines: List[str] = []
        if not self.errors and not self.warnings:
            lines.append("OK: harvest bundle validated")
        elif not self.errors and self.warnings:
            lines.append(f"WARN: {len(self.warnings)} warning(s)")
        else:
            lines.append(f"ERROR: {len(self.errors)} validation error(s)")

        if self.errors:
            lines.append("")
            lines.append("Errors:")
            for e in self.errors:
                lines.append(f"- {e}")
        if self.warnings:
            lines.append("")
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"- {w}")
        return "\n".join(lines) + "\n"


def _default_schema_path() -> Path:
    # Keep the schema vendored with the codebase so enroll can validate offline.
    return Path(__file__).resolve().parent / "schema" / "state.schema.json"


def _load_schema(schema: Optional[str]) -> Dict[str, Any]:
    """Load a JSON schema.

    If schema is None, load the vendored schema.
    If schema begins with http(s)://, fetch it.
    Otherwise, treat it as a local file path.
    """

    if not schema:
        p = _default_schema_path()
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)

    if schema.startswith("http://") or schema.startswith("https://"):
        with urllib.request.urlopen(schema, timeout=10) as resp:  # nosec
            data = resp.read()
        return json.loads(data.decode("utf-8"))

    p = Path(schema).expanduser()
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def _json_pointer(err: jsonschema.ValidationError) -> str:
    # Build a JSON pointer-ish path that is easy to read.
    if err.absolute_path:
        parts = [str(p) for p in err.absolute_path]
        return "/" + "/".join(parts)
    return "/"


def _iter_managed_files(state: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """Return (role_name, managed_file_dict) tuples across all roles."""

    roles = state.get("roles") or {}
    out: List[Tuple[str, Dict[str, Any]]] = []

    # Singleton roles
    for rn in [
        "users",
        "apt_config",
        "dnf_config",
        "etc_custom",
        "usr_local_custom",
        "extra_paths",
    ]:
        snap = roles.get(rn) or {}
        for mf in snap.get("managed_files") or []:
            if isinstance(mf, dict):
                out.append((rn, mf))

    # Array roles
    for s in roles.get("services") or []:
        if not isinstance(s, dict):
            continue
        role_name = str(s.get("role_name") or "unknown")
        for mf in s.get("managed_files") or []:
            if isinstance(mf, dict):
                out.append((role_name, mf))

    for p in roles.get("packages") or []:
        if not isinstance(p, dict):
            continue
        role_name = str(p.get("role_name") or "unknown")
        for mf in p.get("managed_files") or []:
            if isinstance(mf, dict):
                out.append((role_name, mf))

    return out


def validate_harvest(
    harvest_input: str,
    *,
    sops_mode: bool = False,
    schema: Optional[str] = None,
    no_schema: bool = False,
) -> ValidationResult:
    """Validate an enroll harvest bundle.

    Checks:
      - state.json parses
      - state.json validates against the schema (unless no_schema)
      - every managed_file src_rel exists in artifacts/<role>/<src_rel>
    """

    errors: List[str] = []
    warnings: List[str] = []

    bundle: BundleRef = _bundle_from_input(harvest_input, sops_mode=sops_mode)
    try:
        state_path = bundle.state_path
        if not state_path.exists():
            return ValidationResult(
                errors=[f"missing state.json at {state_path}"], warnings=[]
            )

        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            return ValidationResult(
                errors=[f"failed to parse state.json: {e!r}"], warnings=[]
            )

        if not no_schema:
            try:
                sch = _load_schema(schema)
                validator = jsonschema.Draft202012Validator(sch)
                for err in sorted(validator.iter_errors(state), key=str):
                    ptr = _json_pointer(err)
                    msg = err.message
                    errors.append(f"schema {ptr}: {msg}")
            except Exception as e:  # noqa: BLE001
                errors.append(f"failed to load/validate schema: {e!r}")

        # Artifact existence checks
        artifacts_dir = bundle.dir / "artifacts"
        referenced: Set[Tuple[str, str]] = set()
        for role_name, mf in _iter_managed_files(state):
            src_rel = str(mf.get("src_rel") or "")
            if not src_rel:
                errors.append(
                    f"managed_file missing src_rel for role {role_name} (path={mf.get('path')!r})"
                )
                continue
            if src_rel.startswith("/") or ".." in src_rel.split("/"):
                errors.append(
                    f"managed_file has suspicious src_rel for role {role_name}: {src_rel!r}"
                )
                continue

            referenced.add((role_name, src_rel))
            p = artifacts_dir / role_name / src_rel
            if not p.exists():
                errors.append(
                    f"missing artifact for role {role_name}: artifacts/{role_name}/{src_rel}"
                )
                continue
            if not p.is_file():
                errors.append(
                    f"artifact is not a file for role {role_name}: artifacts/{role_name}/{src_rel}"
                )

        # Warn if there are extra files in artifacts not referenced.
        if artifacts_dir.exists() and artifacts_dir.is_dir():
            for fp in artifacts_dir.rglob("*"):
                if not fp.is_file():
                    continue
                try:
                    rel = fp.relative_to(artifacts_dir)
                except ValueError:
                    continue
                parts = rel.parts
                if len(parts) < 2:
                    continue
                role_name = parts[0]
                src_rel = "/".join(parts[1:])
                if (role_name, src_rel) not in referenced:
                    warnings.append(
                        f"unreferenced artifact present: artifacts/{role_name}/{src_rel}"
                    )

        return ValidationResult(errors=errors, warnings=warnings)
    finally:
        # Ensure any temp extraction dirs are cleaned up.
        if bundle.tempdir is not None:
            bundle.tempdir.cleanup()
