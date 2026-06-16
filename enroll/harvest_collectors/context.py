from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Set

from ..ignore import IgnorePolicy
from ..pathfilter import PathFilter


@dataclass
class HarvestContext:
    """Shared context passed to feature collectors."""

    bundle_dir: str
    policy: IgnorePolicy
    path_filter: PathFilter
    platform: Dict[str, Any]
    backend: Any
    installed_pkgs: Dict[str, Any]
    installed_names: Set[str]
    owned_etc: Set[str]
    etc_owner_map: Dict[str, str]
    topdir_to_pkgs: Dict[str, Set[str]]
    pkg_to_etc_paths: Dict[str, List[str]]
    captured_global: Set[str]


class HarvestCollector:
    """Base class for harvest feature collectors."""

    def __init__(self, context: HarvestContext) -> None:
        self.context = context
