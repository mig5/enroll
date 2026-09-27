from dataclasses import asdict
from pathlib import Path

import pytest

from enroll.harvest_collectors.services import ServicePackageCollector
from enroll.harvest_types import ManagedFile, ServiceSnapshot
from enroll.manifest import manifest
from enroll.package_hints import role_name_from_unit
from state_helpers import write_schema_state
from test_harvest_collectors import _context


class PackageBackend:
    name = "dpkg"

    def __init__(self, config, packages):
        self.config = config
        self.packages = packages

    def list_manual_packages(self):
        return self.packages

    def modified_paths(self, package, paths):
        return {str(self.config): "modified_conffile"}

    def specific_paths_for_hints(self, hints):
        return []

    def is_pkg_config_path(self, path):
        return False


def collector(tmp_path, packages=("console-setup",)):
    context = _context(tmp_path)
    context.bundle_dir = str(tmp_path / "bundle")
    config = tmp_path / "keyboard.conf"
    config.write_text("layout=us\n")
    context.backend = PackageBackend(config, list(packages))
    return ServicePackageCollector(context)


@pytest.mark.parametrize("unit_packages", [[], ["console-setup-linux"]])
@pytest.mark.parametrize("individual", [False, True])
def test_service_and_manual_package_keep_separate_artifacts(
    tmp_path, unit_packages, individual
):
    harvest = collector(tmp_path)
    role = role_name_from_unit("console-setup.service")
    harvest._claim_role(role, "unit console-setup.service")
    bundle = Path(harvest.context.bundle_dir)
    service_file = bundle / "artifacts" / role / "service.conf"
    service_file.parent.mkdir(parents=True)
    service_file.write_text("service_setting=yes\n")
    service = ServiceSnapshot(
        unit="console-setup.service",
        role_name=role,
        packages=unit_packages,
        active_state="inactive",
        sub_state="dead",
        unit_file_state="enabled",
        condition_result=None,
        managed_files=[
            ManagedFile(
                path=str(tmp_path / "service.conf"),
                src_rel="service.conf",
                owner="root",
                group="root",
                mode="0644",
                reason="custom_unowned",
            )
        ],
    )
    packages, manual, _, skipped = harvest._collect_package_snapshots([service], {})
    assert manual == ["console-setup"]
    assert not skipped
    assert len(packages) == 1
    assert packages[0].role_name == "package_console_setup"
    assert packages[0].managed_files
    artifact = (
        bundle
        / "artifacts"
        / packages[0].role_name
        / packages[0].managed_files[0].src_rel
    )
    assert artifact.read_text() == "layout=us\n"
    assert service_file.read_text() == "service_setting=yes\n"
    write_schema_state(
        bundle,
        {
            "roles": {
                "services": [asdict(service)],
                "packages": [asdict(p) for p in packages],
            }
        },
    )
    out = tmp_path / "ansible"
    manifest(str(bundle), str(out), jinjaturtle=False, no_common_roles=individual)
    if individual:
        assert (out / "roles/console_setup/tasks/main.yml").exists()
        assert (out / "roles/package_console_setup/tasks/main.yml").exists()
    rendered_files = [
        p.read_text()
        for p in (out / "roles").rglob("*")
        if p.is_file() and "files" in p.parts
    ]
    assert "layout=us\n" in rendered_files
    assert "service_setting=yes\n" in rendered_files


def test_package_already_attributed_to_service_is_still_deduplicated(tmp_path):
    harvest = collector(tmp_path)
    harvest._claim_role("console_setup", "unit console-setup.service")
    service = ServiceSnapshot(
        "console-setup.service",
        "console_setup",
        ["console-setup"],
        None,
        None,
        None,
        None,
    )
    packages, _, _, skipped = harvest._collect_package_snapshots([service], {})
    assert packages == []
    assert skipped == ["console-setup"]


def test_prefixed_service_names_are_also_avoided(tmp_path):
    harvest = collector(tmp_path)
    harvest._claim_role("console_setup", "unit console-setup.service")
    harvest._claim_role("package_console_setup", "unit package-console-setup.service")
    packages, _, _, _ = harvest._collect_package_snapshots([], {})
    assert packages[0].role_name == "package_package_console_setup"


@pytest.mark.parametrize("service_collision", [False, True])
def test_distinct_packages_with_same_normalized_name_still_fail(
    tmp_path, service_collision
):
    harvest = collector(tmp_path, ["foo-bar", "foo_bar"])
    if service_collision:
        harvest._claim_role("foo_bar", "unit foo-bar.service")
    with pytest.raises(ValueError, match="Role name collision"):
        harvest._collect_package_snapshots([], {})
