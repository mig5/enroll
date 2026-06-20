from __future__ import annotations

from enroll.cm import CMModule
from enroll.ansible import AnsibleRole


def test_ansible_role_extends_cm_module_and_normalises_service_snapshot():
    role = AnsibleRole("network")

    role.add_service_snapshot(
        {
            "role_name": "networking",
            "unit": "networking.service",
            "packages": ["ifupdown"],
            "active_state": "active",
            "unit_file_state": "enabled",
            "managed_dirs": [
                {
                    "path": "/etc/network",
                    "owner": "root",
                    "group": "root",
                    "mode": "0755",
                }
            ],
            "managed_files": [
                {
                    "path": "/etc/network/interfaces",
                    "src_rel": "etc/network/interfaces",
                    "owner": "root",
                    "group": "root",
                    "mode": "0644",
                    "reason": "service_config",
                }
            ],
            "managed_links": [
                {
                    "path": "/etc/systemd/system/multi-user.target.wants/networking.service",
                    "target": "/usr/lib/systemd/system/networking.service",
                }
            ],
            "excluded": [{"path": "/etc/network/secrets", "reason": "secret"}],
            "notes": ["captured for test"],
        }
    )

    assert isinstance(role, CMModule)
    assert role.sorted_packages == ["ifupdown"]
    assert role.dirs["/etc/network"]["mode"] == "0755"
    assert role.files["/etc/network/interfaces"]["src_rel"] == "etc/network/interfaces"
    assert (
        role.links["/etc/systemd/system/multi-user.target.wants/networking.service"][
            "src"
        ]
        == "/usr/lib/systemd/system/networking.service"
    )
    assert role.systemd_units_var == [
        {
            "name": "networking.service",
            "manage": True,
            "enabled": True,
            "state": "started",
        }
    ]
    assert role.excluded == [{"path": "/etc/network/secrets", "reason": "secret"}]
    assert role.notes == ["captured for test"]
    assert "service `networking.service` from role `networking`" in role.origin_lines


def test_ansible_role_normalises_package_snapshot():
    role = AnsibleRole("admin")
    role.add_package_snapshot(
        {
            "role_name": "curl",
            "package": "curl",
            "managed_files": [
                {
                    "path": "/etc/curlrc",
                    "src_rel": "etc/curlrc",
                    "owner": "root",
                    "group": "root",
                    "mode": "0644",
                }
            ],
        }
    )

    assert isinstance(role, CMModule)
    assert role.sorted_packages == ["curl"]
    assert role.files["/etc/curlrc"]["dest"] == "/etc/curlrc"
    assert role.services == {}
    assert role.origin_lines == ["package `curl` from role `curl`"]
