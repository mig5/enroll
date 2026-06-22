from __future__ import annotations

import json
import re
from collections.abc import Mapping, Set as AbstractSet
from typing import Any


ANSIBLE_JINJA_STARTS = ("{{", "{%", "{#")


class AnsibleUnsafeText(str):
    """String subclass dumped as Ansible's ``!unsafe`` YAML scalar.

    Ansible templating can recursively evaluate Jinja delimiters that arrive
    through variables/defaults.  Harvested data is not authored playbook code;
    values containing Jinja starts must be tagged as unsafe data before they are
    written to Ansible variable files.
    """


def is_ansible_template_like(value: str) -> bool:
    """Return true if *value* contains a Jinja start delimiter."""

    return any(marker in value for marker in ANSIBLE_JINJA_STARTS)


def ansible_unsafe_data(value: Any) -> Any:
    """Recursively mark template-looking harvested strings as Ansible data.

    Keep ordinary strings untouched so generated output remains readable and so
    existing tests/tools that use ``yaml.safe_load`` continue to work for normal
    data.  Mapping keys are also strings in Ansible data structures, so protect
    keys as well as values.
    """

    if isinstance(value, AnsibleUnsafeText):
        return value
    if isinstance(value, str):
        return AnsibleUnsafeText(value) if is_ansible_template_like(value) else value
    if isinstance(value, Mapping):
        return {
            ansible_unsafe_data(str(key)): ansible_unsafe_data(inner)
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [ansible_unsafe_data(item) for item in value]
    if isinstance(value, tuple):
        return [ansible_unsafe_data(item) for item in value]
    if isinstance(value, AbstractSet):
        return sorted(ansible_unsafe_data(item) for item in value)
    return value


def escape_puppet_hiera_interpolation(value: str) -> str:
    """Preserve literal ``%{`` text in Puppet Hiera data sources.

    Hiera treats ``%{...}`` in data values as interpolation.  Enroll's Hiera
    data is generated from harvested values, not authored Hiera expressions, so
    any literal interpolation opener is escaped with Hiera's documented
    ``literal('%')`` helper.
    """

    return str(value).replace("%{", "%{literal('%')}{")


def puppet_hiera_safe_data(value: Any) -> Any:
    """Recursively escape Hiera interpolation openers in harvested data."""

    if isinstance(value, Mapping):
        return {
            escape_puppet_hiera_interpolation(str(key)): puppet_hiera_safe_data(inner)
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [puppet_hiera_safe_data(item) for item in value]
    if isinstance(value, tuple):
        return [puppet_hiera_safe_data(item) for item in value]
    if isinstance(value, AbstractSet):
        return sorted(puppet_hiera_safe_data(item) for item in value)
    if isinstance(value, str):
        return escape_puppet_hiera_interpolation(value)
    return value


def _plain_json_data(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain_json_data(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_plain_json_data(item) for item in value]
    if isinstance(value, tuple):
        return [_plain_json_data(item) for item in value]
    if isinstance(value, AbstractSet):
        return sorted(_plain_json_data(item) for item in value)
    return value


def _escape_braces_inside_json_strings(text: str) -> str:
    """Replace literal braces only while scanning JSON string tokens."""

    out: list[str] = []
    in_string = False
    escaped = False
    for ch in text:
        if not in_string:
            out.append(ch)
            if ch == '"':
                in_string = True
            continue

        if escaped:
            out.append(ch)
            escaped = False
        elif ch == "\\":
            out.append(ch)
            escaped = True
        elif ch == '"':
            out.append(ch)
            in_string = False
        elif ch == "{":
            out.append("\\u007b")
        elif ch == "}":
            out.append("\\u007d")
        else:
            out.append(ch)
    return "".join(out)


def salt_sls_json_quote(value: Any) -> str:
    """Return a double-quoted YAML/JSON scalar safe for Salt's Jinja pass.

    Salt state and pillar SLS files normally use the ``jinja|yaml`` renderer
    pipeline.  YAML/JSON quoting alone does not stop ``{{ ... }}``, ``{% ... %}``
    or ``{# ... #}`` inside harvested values from being evaluated before YAML is
    parsed.  JSON/YAML double-quoted scalars decode ``\u007b`` and ``\u007d``
    after Jinja has run, so encode braces inside string tokens as Unicode escapes.
    """

    dumped = json.dumps(str(value), ensure_ascii=False)
    return _escape_braces_inside_json_strings(dumped)


_PLAIN_YAML_KEY_RE = re.compile(r"^[A-Za-z0-9_./:-]+$")


def _salt_yaml_key(value: Any) -> str:
    text = str(value)
    if text and _PLAIN_YAML_KEY_RE.match(text) and not text.startswith(("-", "?", ":")):
        return text
    return salt_sls_json_quote(text)


def _salt_yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return json.dumps(value, allow_nan=False)
    return salt_sls_json_quote(value)


def _salt_yaml_lines(
    value: Any, indent: int = 0, *, sort_keys: bool = True
) -> list[str]:
    prefix = " " * indent
    if isinstance(value, Mapping):
        if not value:
            return [prefix + "{}"]
        keys = sorted(value, key=lambda item: str(item)) if sort_keys else list(value)
        lines: list[str] = []
        for key in keys:
            inner = value[key]
            key_text = _salt_yaml_key(key)
            if isinstance(inner, Mapping):
                if not inner:
                    lines.append(f"{prefix}{key_text}: {{}}")
                else:
                    lines.append(f"{prefix}{key_text}:")
                    lines.extend(
                        _salt_yaml_lines(inner, indent + 2, sort_keys=sort_keys)
                    )
            elif isinstance(inner, (list, tuple, set)):
                seq = list(inner) if not isinstance(inner, set) else sorted(inner)
                if not seq:
                    lines.append(f"{prefix}{key_text}: []")
                else:
                    lines.append(f"{prefix}{key_text}:")
                    lines.extend(_salt_yaml_lines(seq, indent + 2, sort_keys=sort_keys))
            else:
                lines.append(f"{prefix}{key_text}: {_salt_yaml_scalar(inner)}")
        return lines

    if isinstance(value, (list, tuple, set)):
        seq = list(value) if not isinstance(value, set) else sorted(value)
        if not seq:
            return [prefix + "[]"]
        lines = []
        for item in seq:
            if isinstance(item, Mapping):
                if not item:
                    lines.append(prefix + "- {}")
                else:
                    lines.append(prefix + "-")
                    lines.extend(
                        _salt_yaml_lines(item, indent + 2, sort_keys=sort_keys)
                    )
            elif isinstance(item, (list, tuple, set)):
                lines.append(prefix + "-")
                lines.extend(_salt_yaml_lines(item, indent + 2, sort_keys=sort_keys))
            else:
                lines.append(f"{prefix}- {_salt_yaml_scalar(item)}")
        return lines

    return [prefix + _salt_yaml_scalar(value)]


def salt_sls_yaml_dump(
    value: Any,
    *,
    sort_keys: bool = True,
    explicit_start: bool = False,
) -> str:
    """Dump block YAML whose string braces cannot form Salt Jinja delimiters."""

    lines = _salt_yaml_lines(_plain_json_data(value), sort_keys=sort_keys)
    rendered = "\n".join(lines).rstrip() + "\n"
    if explicit_start:
        rendered = "---\n" + rendered
    return rendered
