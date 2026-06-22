from __future__ import annotations

from enroll.package_hints import (
    add_pkgs_from_etc_topdirs,
    hint_names,
    maybe_add_specific_paths,
    package_section_from_installations,
    role_id,
    role_name_from_pkg,
    role_name_from_unit,
    safe_name,
)


class _Backend:
    def __init__(self, *, fail: bool = False):
        self.fail = fail

    def specific_paths_for_hints(self, hints):
        if self.fail:
            raise RuntimeError("backend unavailable")
        return [f"/backend/{h}" for h in sorted(hints)]


def test_role_name_helpers_sanitise_reserved_and_odd_names():
    assert safe_name("pkg.name+with-dash") == "pkg_name_with_dash"
    assert role_id("123 Camel-Case!!") == "r_123_camel_case"
    assert role_name_from_unit("class.service") == "class"
    assert role_name_from_pkg("flatpak") == "package_flatpak"


def test_package_section_from_installations_filters_empty_and_unspecified():
    assert package_section_from_installations([]) is None
    assert (
        package_section_from_installations([{"section": "none"}, {"group": ""}]) is None
    )
    assert (
        package_section_from_installations([{"section": "z-utils"}, {"group": "admin"}])
        == "admin"
    )


def test_hint_names_expands_templates_packages_and_dot_prefixes():
    assert hint_names("postgresql@14-main.service", {"postgresql.14"}) == {
        "postgresql@14-main",
        "postgresql",
        "postgresql.14",
    }


def test_add_pkgs_from_etc_topdirs_skips_shared_dirs():
    pkgs: set[str] = set()
    add_pkgs_from_etc_topdirs(
        {"ssh", "nginx"},
        {"ssh": {"openssh-server"}, "nginx": {"nginx"}, "nginx.d": {"nginx-extra"}},
        pkgs,
    )
    assert pkgs == {"nginx", "nginx-extra"}


def test_maybe_add_specific_paths_uses_backend_and_fallback():
    assert maybe_add_specific_paths({"a", "b"}, _Backend()) == [
        "/backend/a",
        "/backend/b",
    ]
    assert maybe_add_specific_paths({"svc"}, _Backend(fail=True)) == [
        "/etc/default/svc",
        "/etc/init.d/svc",
        "/etc/sysctl.d/svc.conf",
    ]
