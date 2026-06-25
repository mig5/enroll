from __future__ import annotations

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
