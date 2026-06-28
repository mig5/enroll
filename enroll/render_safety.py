from __future__ import annotations

import re
from collections.abc import Mapping, Set as AbstractSet
from typing import Any


ANSIBLE_JINJA_STARTS = ("{{", "{%", "{#")


class RenderSafetyError(RuntimeError):
    """Raised when generated configuration-management text is unsafe.

    This is a *generation-time* guardrail. It fires when Enroll would otherwise
    emit raw scaffolding (task/handler YAML) built from a value that is not a
    known-safe Enroll-controlled token, or when a generated task/handler file
    does not round-trip to the structure Enroll intended. Either case means a
    harvested value has leaked into playbook *structure* instead of staying in
    Ansible *data*, so Enroll fails closed rather than writing a poisoned
    manifest.
    """


# The only characters Enroll ever needs inside raw YAML scaffolding are those
# that make up sanitized role/module identifiers and a handful of fixed English
# words in task names. Anything outside this set must travel as Ansible *data*
# (a variable consumed via ``{{ ... }}``), never as scaffolding text.
#
# This is deliberately strict: it matches the charset produced by
# ``ansible._role_id`` / ``package_hints.role_id`` plus spaces (for the fixed
# human-readable portions of task names that Enroll itself authors). It does NOT
# permit quotes, colons, newlines, braces, or any YAML metacharacter, so a value
# that passes this gate cannot alter document structure.
_SCAFFOLD_TOKEN_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_ .-]*$")


def scaffold_token(value: str, *, field: str = "scaffold token") -> str:
    """Return *value* only if it is safe to splice into raw YAML scaffolding.

    Use this for the *only* legitimate reason to interpolate a dynamic value
    into hand-written YAML text: an Enroll-generated, already-sanitized
    identifier such as a role name or module name. Harvested free-text (unit
    names, file paths, package descriptions, user fields, ...) must never be
    passed here -- it belongs in a variable file via :func:`ansible_unsafe_data`
    and must be referenced from tasks through ``{{ ... }}`` indirection.

    Raising rather than escaping is intentional. Escaping invites a long tail of
    "did we cover every YAML metacharacter / Jinja delimiter / indentation
    trick" bugs. A hard allowlist makes structural injection impossible by
    construction: if a caller ever tries to splice harvested data into
    scaffolding, generation aborts loudly instead of silently producing unsafe
    output.
    """

    text = "" if value is None else str(value)
    if not _SCAFFOLD_TOKEN_RE.fullmatch(text):
        raise RenderSafetyError(
            f"refusing to interpolate unsafe {field} into generated YAML "
            f"scaffolding: {text!r}. Harvested values must be passed as Ansible "
            f"data (a variable rendered through ansible_unsafe_data), not spliced "
            f"into task/handler text."
        )
    return text


def assert_generated_yaml_safe(text: str, *, label: str) -> None:
    """Verify a block of Enroll-generated task/handler YAML is well-formed.

    This is the backstop for the scaffold-token rule. Even if a future change
    reintroduces raw interpolation of a harvested value, this check parses the
    generated YAML and confirms it is a list of mappings (Ansible task/handler
    shape) with only string keys -- the structure Enroll intends. A harvested
    value that injects an extra list item, a non-mapping entry, a non-string
    key, or breaks parsing entirely will trip this and abort generation.

    It is intentionally structural, not value-level: it does not try to judge
    whether a *value* is dangerous (that is what ``ansible_unsafe_data`` handles
    for variable files). It ensures harvested data cannot change the *shape* of
    a generated tasks/handlers document.
    """

    import yaml

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:  # pragma: no cover - exercised via tests
        raise RenderSafetyError(
            f"generated {label} is not valid YAML; a harvested value likely "
            f"broke document structure: {e}"
        ) from e

    if doc is None:
        # An empty "---\n" document is a legitimate "no tasks/handlers" result.
        return
    if not isinstance(doc, list):
        raise RenderSafetyError(
            f"generated {label} is not a YAML list of tasks/handlers; a "
            f"harvested value likely altered document structure"
        )
    for entry in doc:
        if not isinstance(entry, Mapping):
            raise RenderSafetyError(
                f"generated {label} contains a non-mapping entry; a harvested "
                f"value likely injected list structure: {entry!r}"
            )
        for key in entry.keys():
            if not isinstance(key, str):
                raise RenderSafetyError(
                    f"generated {label} contains a non-string task key; a "
                    f"harvested value likely injected mapping structure: {key!r}"
                )


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
