from __future__ import annotations

from enroll.cm import CMModule, resolve_catalog_conflicts


def test_resolve_catalog_conflicts_dedupes_before_rendering():
    first = CMModule(role_name="admin", module_name="admin")
    first.packages.add("curl")
    first.dirs["/etc/default"] = {"owner": "root"}
    first.files["/etc/foo.conf"] = {"owner": "root"}

    second = CMModule(role_name="misc", module_name="misc")
    second.packages.add("curl")
    second.dirs["/etc/default"] = {"owner": "root"}
    second.dirs["/etc/foo.conf"] = {"owner": "root"}
    second.files["/etc/foo.conf"] = {"owner": "root"}

    resolve_catalog_conflicts([first, second])

    assert first.packages == {"curl"}
    assert "/etc/default" in first.dirs
    assert "/etc/foo.conf" in first.files

    assert second.packages == set()
    assert second.dirs == {}
    assert second.files == {}
    assert any("duplicate Package[curl]" in note for note in second.notes)
    assert any("duplicate File[/etc/default]" in note for note in second.notes)
    assert any("a file or link with the same path" in note for note in second.notes)


def test_cm_module_uses_shared_state_io(tmp_path):
    state = {"roles": {"packages": []}}

    written = CMModule.write_state(tmp_path, state)

    assert written == tmp_path / "state.json"
    assert CMModule.state_path(tmp_path) == written
    assert CMModule.load_state(tmp_path) == state
    assert CMModule._load_state(tmp_path) == state


def test_active_service_units_for_package_snapshot_is_conservative():
    entries = [
        {
            "kind": "service",
            "snapshot": {
                "unit": "docker.service",
                "role_name": "docker",
                "packages": ["docker.io"],
                "active_state": "active",
            },
        },
        {
            "kind": "service",
            "snapshot": {
                "unit": "docker-cleanup.service",
                "role_name": "docker_cleanup",
                "packages": ["docker.io"],
                "active_state": "inactive",
            },
        },
    ]

    by_package = CMModule.active_service_units_by_package(entries)

    assert by_package == {
        "docker.io": [{"unit": "docker.service", "role_name": "docker"}]
    }
    assert CMModule.active_service_units_for_package_snapshot(
        {"package": "docker.io", "role_name": "docker"}, by_package
    ) == ["docker.service"]


def test_active_service_units_for_package_snapshot_avoids_ambiguous_restarts():
    entries = [
        {
            "kind": "service",
            "snapshot": {
                "unit": "alpha.service",
                "role_name": "alpha",
                "packages": ["shared"],
                "active_state": "active",
            },
        },
        {
            "kind": "service",
            "snapshot": {
                "unit": "beta.service",
                "role_name": "beta",
                "packages": ["shared"],
                "active_state": "active",
            },
        },
    ]

    by_package = CMModule.active_service_units_by_package(entries)

    assert (
        CMModule.active_service_units_for_package_snapshot(
            {"package": "shared", "role_name": "shared"}, by_package
        )
        == []
    )
    assert CMModule.active_service_units_for_package_snapshot(
        {"package": "shared", "role_name": "beta"}, by_package
    ) == ["beta.service"]
