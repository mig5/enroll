"""Opt-in execution regressions using an isolated ansible-core installation.

Set ENROLL_TEST_ANSIBLE_PYTHONPATH to its site-packages directory. Service
operations are replaced with debug actions; no system services are modified.
"""

import os
import subprocess
import sys

import pytest
import yaml

from enroll.manifest import manifest
from state_helpers import write_schema_state


@pytest.mark.parametrize("individual", [False, True])
def test_only_changed_service_restarts_and_second_apply_is_clean(tmp_path, individual):
    ansible_path = os.environ.get("ENROLL_TEST_ANSIBLE_PYTHONPATH")
    if not ansible_path:
        pytest.skip("set ENROLL_TEST_ANSIBLE_PYTHONPATH for Ansible execution tests")
    bundle = tmp_path / "bundle"
    services = []
    for name in ("alpha", "beta"):
        artifact = bundle / "artifacts" / name / "config"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("managed\n")
        destination = tmp_path / (name + ".conf")
        if name == "beta":
            destination.write_text("managed\n")
        services.append(
            {
                "unit": name + ".service",
                "role_name": name,
                "packages": [],
                "active_state": "active",
                "unit_file_state": "enabled",
                "managed_files": [
                    {
                        "path": str(destination),
                        "src_rel": "config",
                        "owner": str(os.getuid()),
                        "group": str(os.getgid()),
                        "mode": "0644",
                        "reason": "custom_unowned",
                    }
                ],
            }
        )
    write_schema_state(bundle, {"roles": {"services": services}})
    out = tmp_path / "ansible"
    manifest(str(bundle), str(out), jinjaturtle=False, no_common_roles=individual)
    # Retain generated names, notifications, loops and conditions exactly.
    for file in (out / "roles").glob("*/handlers/main.yml"):
        tasks = yaml.safe_load(file.read_text()) or []
        for task in tasks:
            for module in (
                "ansible.builtin.service",
                "ansible.builtin.systemd_service",
                "ansible.builtin.systemd",
            ):
                if module in task:
                    action = task.pop(module)
                    task["ansible.builtin.debug"] = {
                        "msg": "RESTART " + action.get("name", "daemon")
                    }
        file.write_text(yaml.safe_dump(tasks, sort_keys=False))
    for file in (out / "roles").glob("*/tasks/*.yml"):
        tasks = yaml.safe_load(file.read_text()) or []
        for task in tasks:
            if "ansible.builtin.systemd" in task:
                task.pop("ansible.builtin.systemd")
                task["ansible.builtin.debug"] = {"msg": "Simulated service lifecycle"}
        file.write_text(yaml.safe_dump(tasks, sort_keys=False))
    env = dict(
        os.environ,
        PYTHONPATH=ansible_path,
        ANSIBLE_STDOUT_CALLBACK="default",
        ANSIBLE_NOCOLOR="1",
    )
    command = [
        sys.executable,
        "-m",
        "ansible.cli.playbook",
        "-i",
        "localhost,",
        "-c",
        "local",
        str(out / "playbook.yml"),
    ]
    first = subprocess.run(
        command, env=env, cwd=out, capture_output=True, text=True, timeout=60
    )
    assert first.returncode == 0, first.stdout + first.stderr
    assert "RESTART alpha.service" in first.stdout
    assert "RESTART beta.service" not in first.stdout
    second = subprocess.run(
        command, env=env, cwd=out, capture_output=True, text=True, timeout=60
    )
    assert second.returncode == 0, second.stdout + second.stderr
    assert "RESTART " not in second.stdout
    assert "changed=0" in second.stdout
