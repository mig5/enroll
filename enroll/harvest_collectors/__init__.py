"""Harvest collector package exports"""

from __future__ import annotations

from importlib import import_module

from .context import HarvestCollector, HarvestContext

_COLLECTOR_EXPORTS = {
    "CronLogrotateCollection": ".cron_logrotate",
    "CronLogrotateCollector": ".cron_logrotate",
    "ExtraPathsCollector": ".paths",
    "PackageManagerConfigCollection": ".package_manager",
    "PackageManagerConfigCollector": ".package_manager",
    "RuntimeStateCollection": ".runtime",
    "RuntimeStateCollector": ".runtime",
    "ServicePackageCollection": ".services",
    "ServicePackageCollector": ".services",
    "UsersCollection": ".users",
    "UsersCollector": ".users",
    "UsrLocalCustomCollector": ".paths",
}

__all__ = [
    "HarvestCollector",
    "HarvestContext",
    *_COLLECTOR_EXPORTS,
]


def __getattr__(name: str):
    module_name = _COLLECTOR_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(module_name, __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value
