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


from pathlib import Path

from state_helpers import write_schema_state

from enroll import manifest, yamlutil as yaml_helpers


def _ansible_jinja_payload_state(payload: str) -> dict:
    return {
        "schema_version": 3,
        "host": {"hostname": "test", "os": "debian", "pkg_backend": "dpkg"},
        "inventory": {"packages": {}},
        "roles": {
            "users": {
                "role_name": "users",
                "users": [
                    {
                        "name": "alice",
                        "uid": 1000,
                        "gid": 1000,
                        "gecos": payload,
                        "home": "/home/alice",
                        "shell": "/bin/bash",
                        "primary_group": "alice",
                        "supplementary_groups": [],
                    }
                ],
                "managed_dirs": [],
                "managed_files": [],
                "managed_links": [],
                "excluded": [],
                "notes": [],
            },
            "services": [],
            "packages": [],
        },
    }


def test_ansible_static_marks_harvested_jinja_values_unsafe(tmp_path: Path):
    bundle = tmp_path / "bundle"
    out = tmp_path / "out"
    payload = "{{ lookup('pipe','touch /tmp/PWNED_BY_ENROLL_ANSIBLE') }}"
    write_schema_state(bundle, _ansible_jinja_payload_state(payload))

    manifest.manifest(str(bundle), str(out))

    defaults = out / "roles" / "users" / "defaults" / "main.yml"
    text = defaults.read_text(encoding="utf-8")
    assert "gecos: !unsafe" in text
    assert "lookup(''pipe'',''touch /tmp/PWNED_BY_ENROLL_ANSIBLE'')" in text
    loaded = yaml_helpers.yaml_load_mapping(text)
    assert loaded["users_users"][0]["gecos"] == payload


def test_individual_service_handlers_are_unique():
    from enroll.ansible import _single_service_restart_handler_body
    import yaml

    handlers = [
        yaml.safe_load(_single_service_restart_handler_body(r))[0]
        for r in ("alpha", "beta")
    ]
    assert handlers[0]["name"] != handlers[1]["name"]
    assert "alpha_unit_name" in handlers[0]["ansible.builtin.systemd_service"]["name"]
    assert "beta_unit_name" in handlers[1]["ansible.builtin.systemd_service"]["name"]


def test_grouped_notifications_select_only_associated_service():
    from enroll.ansible import (
        AnsibleRole,
        _grouped_service_restart_handlers_body,
        _service_restart_listen_topic,
        _build_managed_links_var,
        _build_managed_files_var,
    )
    import yaml

    role = AnsibleRole("apps")
    role.services = {
        name: {"name": name, "state": "started"}
        for name in ("alpha.service", "beta.service")
    }
    handlers = yaml.safe_load(_grouped_service_restart_handlers_body(role))
    assert len({h["listen"] for h in handlers}) == 2
    topic = _service_restart_listen_topic("apps", "alpha.service")
    assert [h["name"] for h in handlers if h["listen"] == topic] == [
        "Restart managed service apps 0"
    ]
    links = _build_managed_links_var(
        [
            {
                "path": "/etc/nginx/sites-enabled/site",
                "target": "../sites-available/site",
            }
        ],
        notify_other=[topic],
    )
    assert links[0]["notify"] == [topic]
    files = _build_managed_files_var(
        [
            {
                "path": "/etc/systemd/system/alpha.service.d/override.conf",
                "src_rel": "override",
            }
        ],
        set(),
        notify_other=[topic],
        notify_systemd="Run systemd daemon-reload",
    )
    assert files[0]["notify"] == ["Run systemd daemon-reload", topic]


def test_role_phases_defer_activation_and_keep_failed_probes(tmp_path):
    from enroll.ansible import (
        _write_role_phases,
        _render_single_systemd_tasks,
        _render_install_packages_tasks,
    )
    import yaml

    (tmp_path / "tasks").mkdir()
    main = _write_role_phases(
        str(tmp_path),
        _render_install_packages_tasks("app", "app")
        + _render_single_systemd_tasks("app"),
    )
    assert (tmp_path / "tasks" / "packages.yml").exists()
    activate = yaml.safe_load((tmp_path / "tasks" / "activate.yml").read_text())
    assert "failed_when" not in activate[0]
    assert "enroll_defer_activation" not in str(activate)
    for task in yaml.safe_load(main):
        if "ansible.builtin.systemd" in task:
            assert "enroll_defer_activation" in str(task["when"])
