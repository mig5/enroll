"""Conservative installed-package relationships, never a dependency solver."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Dict, List, Set, Tuple

# Rows contain name, source identity, dependency groups and provided capabilities.
Row = Tuple[str, str, List[Set[str]], Set[str]]


def family_links(rows: List[Row]) -> Dict[str, Set[str]]:
    """Only link uniquely installed providers within the same source family."""
    counts = Counter(row[0] for row in rows)
    providers: Dict[str, Set[str]] = defaultdict(set)
    for name, _, _, capabilities in rows:
        for capability in capabilities | {name}:
            providers[capability].add(name)
    sources = {name: source for name, source, _, _ in rows if counts[name] == 1}
    links: Dict[str, Set[str]] = defaultdict(set)
    for name, source, dependencies, _ in rows:
        if counts[name] != 1 or not source:
            continue
        for alternatives in dependencies:
            matches = set().union(*(providers.get(dep, set()) for dep in alternatives))
            if len(matches) != 1:
                continue
            other = next(iter(matches))
            if other != name and sources.get(other) == source:
                links[name].add(other)
                links[other].add(name)
    return dict(links)


def debian_relations(output: str) -> Dict[str, Set[str]]:
    rows: List[Row] = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            continue
        name, status, source, depends, predepends, provides = fields
        if status != "installed":
            continue

        def names(group: str) -> Set[str]:
            result = set()
            for item in group.split("|"):
                # Installed binary metadata has no build profiles/arch restrictions.
                match = re.fullmatch(
                    r"\s*([a-z0-9][a-z0-9+.-]*)(?::(?:any|native))?"
                    r"\s*(?:\([^()]+\))?\s*",
                    item,
                )
                if not match:
                    return set()
                result.add(match[1])
            return result

        deps = [names(group) for group in (depends + "," + predepends).split(",")]
        caps = set().union(*(names(group) for group in provides.split(",")))
        rows.append((name, source, deps, caps))
    return family_links(rows)


def rpm_relations(output: str) -> Dict[str, Set[str]]:
    rows: List[Row] = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            continue
        name, source, requires, provides = fields
        if source in ("", "(none)"):
            source = ""
        # Exact capability names only: rich boolean expressions are not inferred.
        deps = [{cap} for cap in requires.split(",") if cap and not cap.startswith("(")]
        caps = {cap for cap in provides.split(",") if cap and cap != "(none)"}
        rows.append((name, source, deps, caps))
    return family_links(rows)


def associate_services(
    owners: Dict[str, str], links: Dict[str, Set[str]]
) -> Tuple[Dict[str, Set[str]], Dict[str, List[str]]]:
    additions: Dict[str, Set[str]] = defaultdict(set)
    notes: Dict[str, List[str]] = defaultdict(list)
    candidates: Dict[str, Set[str]] = defaultdict(set)
    for unit, owner in owners.items():
        for package in links.get(owner, set()):
            # A package with its own captured service keeps that attribution.
            if package not in owners.values():
                candidates[package].add(unit)
    for package, units in sorted(candidates.items()):
        exact = {unit for unit in units if unit == package + ".service"}
        choices = exact or units
        if len(choices) == 1:
            unit = next(iter(choices))
            additions[unit].add(package)
            notes[unit].append(
                f"Associated package {package}: direct dependency relationship "
                f"and shared source package with unit owner {owners[unit]}."
            )
        else:
            for unit in sorted(units):
                notes[unit].append(
                    f"Ambiguous package family association for {package}: "
                    f"{', '.join(sorted(units))}; no additional attribution made."
                )
    return dict(additions), dict(notes)
