from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping, Union

BundlePath = Union[str, Path]
State = Dict[str, Any]


def state_path(bundle_dir: BundlePath) -> Path:
    """Return the canonical state.json path for a harvest bundle."""

    return Path(bundle_dir) / "state.json"


def load_state(bundle_dir: BundlePath) -> State:
    """Load state.json from a harvest bundle directory."""

    with open(state_path(bundle_dir), "r", encoding="utf-8") as f:
        return json.load(f)


def write_state(
    bundle_dir: BundlePath,
    state: Mapping[str, Any],
    *,
    indent: int = 2,
    sort_keys: bool = True,
) -> Path:
    """Write state.json to a harvest bundle directory and return its path."""

    path = state_path(bundle_dir)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=indent, sort_keys=sort_keys)
    return path


def roles_from_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the roles mapping from a harvest state, or an empty mapping."""

    roles = state.get("roles")
    return dict(roles) if isinstance(roles, dict) else {}


def inventory_packages_from_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Return inventory.packages from a harvest state, or an empty mapping."""

    inventory = state.get("inventory")
    if not isinstance(inventory, dict):
        return {}
    packages = inventory.get("packages")
    return dict(packages) if isinstance(packages, dict) else {}
