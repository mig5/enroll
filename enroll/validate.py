from __future__ import annotations

import json
import os
import stat
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import jsonschema

from .diff import BundleRef, _bundle_from_input
from .manifest_safety import ArtifactSafetyError, safe_artifact_file
from .state import load_state
from .cm import sanitize_report_text


@dataclass
class ValidationResult:
    errors: List[str]
    warnings: List[str]

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> Dict[str, Any]:
        # Error/warning messages embed harvested, attacker-influenceable values
        # (a managed_file src_rel, a role name, artifact paths). A raw newline in
        # such a value could forge an extra message line in the text output, and
        # a control byte could smuggle a terminal escape sequence when the result
        # is printed or piped. Neutralise every message centrally here (and in
        # to_text) so all current and future append sites are covered by one
        # chokepoint, mirroring how the rest of Enroll sanitises harvested values
        # before they reach a report/README/explain surface.
        return {
            "ok": self.ok,
            "errors": [sanitize_report_text(e) for e in self.errors],
            "warnings": [sanitize_report_text(w) for w in self.warnings],
        }

    def to_text(self) -> str:
        errors = [sanitize_report_text(e) for e in self.errors]
        warnings = [sanitize_report_text(w) for w in self.warnings]

        lines: List[str] = []
        if not errors and not warnings:
            lines.append("OK: harvest bundle validated")
        elif not errors and warnings:
            lines.append(f"WARN: {len(warnings)} warning(s)")
        else:
            lines.append(f"ERROR: {len(errors)} validation error(s)")

        if errors:
            lines.append("")
            lines.append("Errors:")
            for e in errors:
                lines.append(f"- {e}")
        if warnings:
            lines.append("")
            lines.append("Warnings:")
            for w in warnings:
                lines.append(f"- {w}")
        return "\n".join(lines) + "\n"


def _default_schema_path() -> Path:
    # Keep the schema vendored with the codebase so enroll can validate offline.
    return Path(__file__).resolve().parent / "schema" / "state.schema.json"


def _load_schema(
    schema: Optional[str], *, allow_remote_schema: bool = False
) -> Dict[str, Any]:
    """Load a JSON schema.

    If schema is None, load the vendored schema.
    If schema begins with http(s)://, fetch it only when remote schema
    loading was explicitly enabled by the caller. Otherwise, treat it as a
    local file path.
    """

    if not schema:
        p = _default_schema_path()
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)

    if schema.startswith("http://") or schema.startswith("https://"):
        if not allow_remote_schema:
            raise ValueError(
                "remote schema URLs are disabled by default; use "
                "--allow-remote-schema only when the schema source is trusted"
            )
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
        "sysctl",
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
    allow_remote_schema: bool = False,
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
            state = load_state(bundle.dir)
        except Exception as e:  # noqa: BLE001
            return ValidationResult(
                errors=[f"failed to parse state.json: {e!r}"], warnings=[]
            )

        if not no_schema:
            try:
                sch = _load_schema(schema, allow_remote_schema=allow_remote_schema)
                validator = jsonschema.Draft202012Validator(sch)
                for err in sorted(validator.iter_errors(state), key=str):
                    ptr = _json_pointer(err)
                    msg = err.message
                    errors.append(f"schema {ptr}: {msg}")
            except Exception as e:  # noqa: BLE001
                errors.append(f"failed to load/validate schema: {e!r}")

        # Artifact existence and safety checks.
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
            try:
                safe_artifact_file(bundle.dir, role_name, src_rel)
            except FileNotFoundError:
                errors.append(
                    f"missing artifact for role {role_name}: artifacts/{role_name}/{src_rel}"
                )
            except ArtifactSafetyError as e:
                errors.append(
                    f"unsafe artifact for role {role_name}: artifacts/{role_name}/{src_rel}: {e}"
                )

        # Runtime firewall snapshots are generated artifacts rather than managed files.
        fw = (state.get("roles") or {}).get("firewall_runtime") or {}
        if isinstance(fw, dict):
            for key in ("ipset_save", "iptables_v4_save", "iptables_v6_save"):
                src_rel = str(fw.get(key) or "")
                if not src_rel:
                    continue
                if src_rel.startswith("/") or ".." in src_rel.split("/"):
                    errors.append(
                        f"firewall_runtime {key} has suspicious src_rel: {src_rel!r}"
                    )
                    continue
                role_name = str(fw.get("role_name") or "firewall_runtime")
                referenced.add((role_name, src_rel))
                try:
                    safe_artifact_file(bundle.dir, role_name, src_rel)
                except FileNotFoundError:
                    errors.append(
                        "missing firewall runtime artifact: "
                        f"artifacts/{role_name}/{src_rel}"
                    )
                except ArtifactSafetyError as e:
                    errors.append(
                        "unsafe firewall runtime artifact: "
                        f"artifacts/{role_name}/{src_rel}: {e}"
                    )

        # Validate the whole artifact tree too, so unreferenced symlinks,
        # hardlinks, special files, and path-shaping tricks do not survive
        # validation simply because no managed_file currently references them.
        if artifacts_dir.exists():
            try:
                artifacts_st = artifacts_dir.lstat()
            except OSError as e:
                errors.append(f"unable to inspect artifacts directory: {e}")
            else:
                if stat.S_ISLNK(artifacts_st.st_mode):
                    errors.append(f"artifacts directory is a symlink: {artifacts_dir}")
                elif not stat.S_ISDIR(artifacts_st.st_mode):
                    errors.append(f"artifacts path is not a directory: {artifacts_dir}")
                else:
                    for root, dirs, files in os.walk(artifacts_dir, followlinks=False):
                        root_p = Path(root)
                        for name in list(dirs):
                            fp = root_p / name
                            try:
                                st = fp.lstat()
                            except FileNotFoundError:
                                continue
                            if stat.S_ISLNK(st.st_mode):
                                errors.append(f"artifact directory is a symlink: {fp}")
                            elif not stat.S_ISDIR(st.st_mode):
                                errors.append(
                                    f"artifact directory is not a directory: {fp}"
                                )

                        for name in files:
                            fp = root_p / name
                            try:
                                st = fp.lstat()
                            except FileNotFoundError:
                                continue
                            try:
                                rel = fp.relative_to(artifacts_dir)
                            except ValueError:
                                errors.append(f"artifact escapes artifact root: {fp}")
                                continue
                            parts = rel.parts
                            if len(parts) < 2:
                                errors.append(
                                    f"artifact is not under a role directory: {fp}"
                                )
                                continue
                            role_name = parts[0]
                            src_rel = "/".join(parts[1:])

                            if stat.S_ISLNK(st.st_mode):
                                errors.append(
                                    f"artifact is a symlink: artifacts/{role_name}/{src_rel}"
                                )
                                continue
                            if not stat.S_ISREG(st.st_mode):
                                errors.append(
                                    f"artifact is not a regular file: artifacts/{role_name}/{src_rel}"
                                )
                                continue
                            if st.st_nlink > 1:
                                errors.append(
                                    f"artifact is hardlinked: artifacts/{role_name}/{src_rel}"
                                )
                                continue
                            try:
                                safe_artifact_file(bundle.dir, role_name, src_rel)
                            except (FileNotFoundError, ArtifactSafetyError) as e:
                                errors.append(
                                    f"unsafe artifact: artifacts/{role_name}/{src_rel}: {e}"
                                )
                                continue

                            if (role_name, src_rel) not in referenced:
                                warnings.append(
                                    f"unreferenced artifact present: artifacts/{role_name}/{src_rel}"
                                )

        return ValidationResult(errors=errors, warnings=warnings)
    finally:
        # Ensure any temp extraction dirs are cleaned up.
        if bundle.tempdir is not None:
            bundle.tempdir.cleanup()
