import subprocess
from dataclasses import asdict
from pathlib import Path

import pytest

from enroll.package_relations import associate_services, debian_relations, rpm_relations
from enroll.harvest_collectors.services import ServicePackageCollector
from enroll.manifest import manifest
from enroll.systemd import UnitInfo
from state_helpers import write_schema_state
from test_harvest_collectors import _context

DEB = (
    "console-setup\tinstalled\tconsole-setup\tconsole-setup-linux | hurd, libc6\t\t\n"
    "console-setup-linux\tinstalled\tconsole-setup\t\t\t\n"
    "libc6\tinstalled\tglibc\t\t\t\n"
    "unused\tconfig-files\tconsole-setup\tconsole-setup-linux\t\t\n"
)
RPM = (
    "console-setup\tconsole-1-1.src.rpm\tconsole-core(x86-64),libc.so.6,\t\n"
    "console-setup-linux\tconsole-1-1.src.rpm\t\tconsole-core(x86-64),\n"
    "glibc\tglibc-1-1.src.rpm\t\tlibc.so.6,\n"
)


@pytest.mark.parametrize(
    "parser,output", [(debian_relations, DEB), (rpm_relations, RPM)]
)
def test_family_relationships(parser, output):
    assert parser(output) == {
        "console-setup": {"console-setup-linux"},
        "console-setup-linux": {"console-setup"},
    }


def test_debian_ambiguous_alternatives_multiarch_and_uninstalled():
    output = (
        "a\tinstalled\tsrc\tb | c\t\t\n"
        "b\tinstalled\tsrc\t\t\t\n"
        "c\tinstalled\tsrc\t\t\t\n"
    )
    assert debian_relations(output) == {}
    assert (
        debian_relations(DEB + "console-setup-linux\tinstalled\tconsole-setup\t\t\t\n")
        == {}
    )
    assert debian_relations(DEB.replace("installed", "config-files")) == {}


def test_debian_predepends_and_virtual_providers():
    assert debian_relations(
        "a\tinstalled\tsrc\t\tcap:any (>= 1)\t\n" "b\tinstalled\tsrc\t\t\tcap (= 1)\n"
    ) == {"a": {"b"}, "b": {"a"}}


def test_rpm_ambiguous_providers_missing_sources_and_rich_dependencies():
    assert (
        rpm_relations(RPM + "alternative\tother.src.rpm\t\tconsole-core(x86-64),\n")
        == {}
    )
    assert rpm_relations(RPM.replace("console-1-1.src.rpm", "(none)")) == {}
    assert rpm_relations("a\ts.src.rpm\t(b if c),\t\nb\ts.src.rpm\t\t\n") == {}
    assert (
        rpm_relations(
            RPM + "console-setup-linux\tconsole-1-1.src.rpm\t\tconsole-core(x86-64),\n"
        )
        == {}
    )


def test_multiple_services_require_unique_choice_or_exact_name():
    links = debian_relations(DEB)
    owners = {
        "keyboard-setup.service": "console-setup-linux",
        "console-setup.service": "console-setup-linux",
    }
    added, notes = associate_services(owners, links)
    assert added == {"console-setup.service": {"console-setup"}}
    assert "shared source" in notes["console-setup.service"][0]
    owners["other.service"] = owners.pop("console-setup.service")
    added, notes = associate_services(owners, links)
    assert added == {}
    assert all("Ambiguous" in values[0] for values in notes.values())
    assert associate_services(dict(reversed(list(owners.items()))), links) == (
        added,
        notes,
    )


def test_no_transitive_expansion_or_reassignment_of_service_owners():
    links = {"a": {"b"}, "b": {"a", "c"}, "c": {"b"}}
    assert associate_services({"a.service": "a"}, links)[0] == {"a.service": {"b"}}
    assert associate_services({"a.service": "a", "b.service": "b"}, links)[0] == {
        "b.service": {"c"}
    }


@pytest.mark.parametrize(
    "backend_name,parser,output",
    [("dpkg", debian_relations, DEB), ("rpm", rpm_relations, RPM)],
)
@pytest.mark.parametrize("individual", [False, True])
def test_collector_captures_related_config_in_service_role(
    tmp_path, monkeypatch, backend_name, parser, output, individual
):
    from enroll import harvest as h

    config = tmp_path / "console.conf"
    config.write_text("layout=us\n")

    class Backend:
        name = backend_name

        def related_packages(self):
            return parser(output)

        def owner_of_path(self, path):
            return "console-setup-linux"

        def list_manual_packages(self):
            return ["console-setup"]

        def modified_paths(self, package, paths):
            return (
                {str(config): "modified_conffile"} if package == "console-setup" else {}
            )

        def is_pkg_config_path(self, path):
            return False

        def specific_paths_for_hints(self, hints):
            return []

    context = _context(tmp_path)
    context.backend = Backend()
    monkeypatch.setattr(h, "list_enabled_services", lambda: ["console-setup.service"])
    monkeypatch.setattr(
        h,
        "get_unit_info",
        lambda unit: UnitInfo(
            unit,
            "/usr/lib/systemd/system/" + unit,
            [],
            [],
            [],
            "inactive",
            "dead",
            "enabled",
            None,
        ),
    )
    monkeypatch.setattr(h, "list_enabled_timers", lambda: [])
    monkeypatch.setattr(
        "enroll.harvest_collectors.services.scan_unowned_under_roots",
        lambda *a, **kw: [],
    )
    collector = ServicePackageCollector(context)
    monkeypatch.setattr(collector, "_capture_common_enabled_symlinks", lambda *a: None)
    result = collector.collect()
    assert result.pkg_snaps == []
    service = result.service_snaps[0]
    assert service.packages == ["console-setup", "console-setup-linux"]
    assert service.managed_files[0].path == str(config)
    bundle = Path(context.bundle_dir)
    assert (
        bundle / "artifacts/console_setup" / service.managed_files[0].src_rel
    ).read_text() == "layout=us\n"
    write_schema_state(
        bundle, {"roles": {"services": [asdict(service)], "packages": []}}
    )
    out = tmp_path / "ansible"
    manifest(str(bundle), str(out), jinjaturtle=False, no_common_roles=individual)
    assert not (out / "roles/package_console_setup").exists()
    assert any(
        p.read_text() == "layout=us\n"
        for p in (out / "roles").rglob("*")
        if p.is_file()
    )


@pytest.mark.parametrize("module", ["debian", "rpm"])
def test_backend_query_failure_is_best_effort(monkeypatch, module):
    from enroll import debian, rpm

    target = {"debian": debian, "rpm": rpm}[module]
    monkeypatch.setattr(
        target.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a, 1, DEB, "failed"),
    )
    assert target.package_family_relations() == {}


@pytest.mark.parametrize("backend_name,output", [("dpkg", DEB), ("rpm", RPM)])
def test_backends_query_installed_database(monkeypatch, backend_name, output):
    from enroll import debian, rpm
    from enroll.platform import DpkgBackend, RpmBackend

    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, output, "")

    module = debian if backend_name == "dpkg" else rpm
    monkeypatch.setattr(module.subprocess, "run", run)
    backend = object.__new__(DpkgBackend if backend_name == "dpkg" else RpmBackend)
    assert backend.related_packages()["console-setup"] == {"console-setup-linux"}
    assert len(calls) == 1
    assert calls[0][:2] == (
        ["dpkg-query", "-W"] if backend_name == "dpkg" else ["rpm", "-qa"]
    )
