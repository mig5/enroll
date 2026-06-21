from __future__ import annotations

import importlib.metadata as metadata


def test_get_enroll_version_returns_string():
    from enroll.version import get_enroll_version

    result = get_enroll_version()
    assert isinstance(result, str)
    assert len(result) > 0


def test_get_enroll_version_falls_back_after_bad_mapped_dist(monkeypatch):
    from enroll.version import get_enroll_version

    monkeypatch.setattr(
        metadata,
        "packages_distributions",
        lambda: {"enroll": ["wrong-dist", "enroll"]},
    )

    def fake_version(name):
        if name == "enroll":
            return "0.7.0"
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(metadata, "version", fake_version)

    assert get_enroll_version() == "0.7.0"


def test_get_enroll_version_uses_default_when_mapping_fails(monkeypatch):
    from enroll.version import get_enroll_version

    def broken_mapping():
        raise RuntimeError("metadata unavailable")

    monkeypatch.setattr(metadata, "packages_distributions", broken_mapping)
    monkeypatch.setattr(
        metadata,
        "version",
        lambda name: "0.7.0" if name == "enroll" else "bad",
    )

    assert get_enroll_version() == "0.7.0"


def test_get_enroll_version_returns_unknown_when_all_lookups_fail(monkeypatch):
    from enroll.version import get_enroll_version

    monkeypatch.setattr(metadata, "packages_distributions", lambda: {"enroll": ["bad"]})

    def missing(_name):
        raise metadata.PackageNotFoundError(_name)

    monkeypatch.setattr(metadata, "version", missing)

    assert get_enroll_version() == "unknown"
