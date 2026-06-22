from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

import yaml

from .render_safety import AnsibleUnsafeText


class IndentedSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """PyYAML loader that understands Ansible's ``!unsafe`` tag."""


def _construct_ansible_unsafe(
    loader: yaml.Loader, node: yaml.Node
) -> AnsibleUnsafeText:
    return AnsibleUnsafeText(loader.construct_scalar(node))


IndentedSafeLoader.add_constructor("!unsafe", _construct_ansible_unsafe)


class IndentedSafeDumper(yaml.SafeDumper):  # type: ignore[misc]
    """PyYAML dumper that indents sequences under mapping keys."""

    def increase_indent(self, flow: bool = False, indentless: bool = False):
        # PyYAML calls this method with an ``indentless`` keyword, so the
        # parameter name must stay intact even though Enroll deliberately
        # ignores its value to force indented block sequences.
        return super().increase_indent(flow, False)


def yaml_load_mapping(text: str) -> Dict[str, Any]:
    """Load YAML text and return a mapping, or an empty mapping on failure.

    Enroll may re-read Ansible host_vars that contain ``!unsafe`` scalars
    written during the same manifest operation, so the loader accepts that tag
    while remaining otherwise based on PyYAML's SafeLoader.
    """

    try:
        obj = yaml.load(
            text, Loader=IndentedSafeLoader
        )  # nosec B506 - subclasses yaml.SafeLoader; only adds !unsafe scalar support.
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def yaml_load_mapping_file(path: Path) -> Dict[str, Any]:
    """Load a YAML mapping from *path*, returning an empty mapping if absent."""

    if not path.exists():
        return {}
    return yaml_load_mapping(path.read_text(encoding="utf-8"))


def _represent_ansible_unsafe(
    dumper: yaml.Dumper, data: AnsibleUnsafeText
) -> yaml.Node:
    return dumper.represent_scalar("!unsafe", str(data))


IndentedSafeDumper.add_representer(AnsibleUnsafeText, _represent_ansible_unsafe)


def yaml_dump_mapping(
    obj: Mapping[str, Any],
    *,
    sort_keys: bool = True,
    explicit_start: bool = False,
) -> str:
    """Dump a YAML mapping using Enroll's renderer-friendly formatting."""

    return (
        yaml.dump(
            dict(obj),
            Dumper=IndentedSafeDumper,
            default_flow_style=False,
            sort_keys=sort_keys,
            indent=2,
            allow_unicode=True,
            explicit_start=explicit_start,
        ).rstrip()
        + "\n"
    )
