from __future__ import annotations

import sys
import types


def test_get_enroll_version_returns_unknown_when_import_fails(monkeypatch):
    from enroll.version import get_enroll_version

    # Ensure both the module cache and the parent package attribute are redirected.
    import importlib

    dummy = types.ModuleType("importlib.metadata")
    # Missing attributes will cause ImportError when importing names.
    monkeypatch.setitem(sys.modules, "importlib.metadata", dummy)
    monkeypatch.setattr(importlib, "metadata", dummy, raising=False)

    assert get_enroll_version() == "unknown"


def test_get_enroll_version_uses_packages_distributions(monkeypatch):
    # Restore the real module for this test.
    monkeypatch.delitem(sys.modules, "importlib.metadata", raising=False)

    import importlib.metadata

    from enroll.version import get_enroll_version

    monkeypatch.setattr(
        importlib.metadata,
        "packages_distributions",
        lambda: {"enroll": ["enroll-dist"]},
    )
    monkeypatch.setattr(importlib.metadata, "version", lambda dist: "9.9.9")

    assert get_enroll_version() == "9.9.9"
