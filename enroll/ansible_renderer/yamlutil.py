from __future__ import annotations

from typing import Any, Dict, List


def _try_yaml():
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    return yaml


def _yaml_load_mapping(text: str) -> Dict[str, Any]:
    yaml = _try_yaml()
    if yaml is None:
        return {}
    try:
        obj = yaml.safe_load(text)
    except Exception:
        return {}
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    return {}


def _yaml_dump_mapping(obj: Dict[str, Any], *, sort_keys: bool = True) -> str:
    yaml = _try_yaml()
    if yaml is None:
        # fall back to a naive key: value dump (best-effort)
        lines: List[str] = []
        for k, v in sorted(obj.items()) if sort_keys else obj.items():
            lines.append(f"{k}: {v!r}")
        return "\n".join(lines).rstrip() + "\n"

    # ansible-lint/yamllint's indentation rules are stricter than YAML itself.
    # In particular, they expect sequences nested under a mapping key to be
    # indented (e.g. `foo:\n  - a`), whereas PyYAML's default is often
    # `foo:\n- a`.
    class _IndentDumper(yaml.SafeDumper):  # type: ignore
        def increase_indent(self, flow: bool = False, indentless: bool = False):
            return super().increase_indent(flow, False)

    return (
        yaml.dump(
            obj,
            Dumper=_IndentDumper,
            default_flow_style=False,
            sort_keys=sort_keys,
            indent=2,
            allow_unicode=True,
        ).rstrip()
        + "\n"
    )


def _merge_mappings_overwrite(
    existing: Dict[str, Any], incoming: Dict[str, Any]
) -> Dict[str, Any]:
    """Merge incoming into existing with overwrite.

    NOTE: Unlike role defaults merging, host_vars should reflect the current
    harvest for a host. Therefore lists are replaced rather than unioned.
    """
    merged = dict(existing)
    merged.update(incoming)
    return merged
