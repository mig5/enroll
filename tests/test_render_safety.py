"""Tests for the generation-time render-safety guardrails.

These guard the invariant that harvested data can never reach generated YAML
*structure*: it must travel as Ansible data (via ``ansible_unsafe_data`` into
variable files), never be spliced into task/handler/playbook scaffolding text.
"""

import pytest

from enroll.render_safety import (
    AnsibleUnsafeText,
    RenderSafetyError,
    ansible_unsafe_data,
    assert_generated_yaml_safe,
    is_ansible_template_like,
    scaffold_token,
)


@pytest.mark.parametrize(
    "value",
    [
        "net",
        "admin",
        "section_misc_2",
        "docker_service",
        "enroll_restart_grouped_services_net",
        "host.example.com",  # fqdn-like, dots/hyphens allowed
        "a-b_c.d",
    ],
)
def test_scaffold_token_accepts_safe_identifiers(value):
    assert scaffold_token(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "evil.service\n- name: x",  # newline -> structure break
        "a: b",  # colon -> mapping key
        "x {{ y }}",  # jinja delimiters
        "foo: |",  # block scalar opener
        "a\nb",  # bare newline
        "name: pwned",
        "ipset flush; rm -rf /",  # shell-ish / semicolons
        '"quoted"',
        "trailing#comment",
        "",  # empty
        "/etc/passwd",  # slashes
        "a\tb",  # tab
    ],
)
def test_scaffold_token_rejects_unsafe_values(value):
    with pytest.raises(RenderSafetyError):
        scaffold_token(value)


def test_scaffold_token_rejects_harvested_unit_payload():
    # The exact class of payload from the original handler-injection finding.
    payload = (
        "evil.service\n"
        "  ansible.builtin.command: touch /tmp/pwned\n"
        "- name: INJECTED\n"
    )
    with pytest.raises(RenderSafetyError):
        scaffold_token(payload, field="unit name")


def test_assert_generated_yaml_safe_accepts_task_lists():
    text = (
        "---\n"
        "- name: Restart managed services for net\n"
        "  ansible.builtin.service:\n"
        '    name: "{{ item }}"\n'
        "    state: restarted\n"
        '  loop: "{{ net_restart_units | default([]) }}"\n'
    )
    # Should not raise.
    assert_generated_yaml_safe(text, label="handlers")


def test_assert_generated_yaml_safe_accepts_empty_document():
    assert_generated_yaml_safe("---\n", label="handlers")


def test_assert_generated_yaml_safe_rejects_broken_yaml():
    # A harvested value that breaks document structure must fail closed.
    broken = "---\n- name: a\n  x: : :\n"
    with pytest.raises(RenderSafetyError):
        assert_generated_yaml_safe(broken, label="handlers")


def test_assert_generated_yaml_safe_rejects_non_list_document():
    with pytest.raises(RenderSafetyError):
        assert_generated_yaml_safe("---\nkey: value\n", label="handlers")


def test_assert_generated_yaml_safe_rejects_non_mapping_entry():
    with pytest.raises(RenderSafetyError):
        assert_generated_yaml_safe("---\n- just_a_string\n", label="handlers")


def test_ansible_unsafe_data_still_tags_jinja_values():
    out = ansible_unsafe_data({"k": "{{ danger }}", "safe": "plain"})
    assert isinstance(out["k"], AnsibleUnsafeText)
    assert not isinstance(out["safe"], AnsibleUnsafeText)
    assert is_ansible_template_like("{{ x }}")
    assert not is_ansible_template_like("plain")


def test_write_generated_task_yaml_uses_safety_gate(tmp_path):
    from enroll.ansible import _write_generated_task_yaml

    path = tmp_path / "tasks.yml"

    with pytest.raises(RenderSafetyError):
        _write_generated_task_yaml(
            str(path), "---\nkey: value\n", label="test tasks/main.yml"
        )

    assert not path.exists()
