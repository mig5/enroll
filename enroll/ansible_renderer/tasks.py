from __future__ import annotations


def _render_generic_files_tasks(
    var_prefix: str, *, include_restart_notify: bool
) -> str:
    """Render generic tasks to deploy <var_prefix>_managed_files safely."""
    # Using first_found makes roles work in both modes:
    # - site-mode: inventory/host_vars/<host>/<role>/.files/...
    # - non-site: roles/<role>/files/...
    return f"""- name: Ensure managed directories exist (preserve owner/group/mode)
  ansible.builtin.file:
    path: "{{{{ item.dest }}}}"
    state: directory
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: "{{{{ {var_prefix}_managed_dirs | default([]) }}}}"

- name: Deploy any systemd unit files (templates)
  ansible.builtin.template:
    src: "{{{{ item.src_rel }}}}.j2"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', true)
      | selectattr('kind', 'equalto', 'template')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Deploy any systemd unit files (raw files)
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ item.src_rel }}}}"
        - "{{{{ role_path }}}}/files/{{{{ item.src_rel }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', true)
      | selectattr('kind', 'equalto', 'copy')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Reload systemd to pick up unit changes
  ansible.builtin.meta: flush_handlers
  when: >-
    ({var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', true)
      | list
      | length) > 0

- name: Deploy any other managed files (templates)
  ansible.builtin.template:
    src: "{{{{ item.src_rel }}}}.j2"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', false)
      | selectattr('kind', 'equalto', 'template')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Deploy any other managed files (raw files)
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ item.src_rel }}}}"
        - "{{{{ role_path }}}}/files/{{{{ item.src_rel }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', false)
      | selectattr('kind', 'equalto', 'copy')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Ensure managed symlinks exist
  ansible.builtin.file:
    src: "{{{{ item.src }}}}"
    dest: "{{{{ item.dest }}}}"
    state: link
    force: true
  loop: "{{{{ {var_prefix}_managed_links | default([]) }}}}"
"""


def _render_install_packages_tasks(role: str, var_prefix: str) -> str:
    """Render package installation through Ansible's generic package provider.

    Puppet and Salt use provider-backed package resources instead of selecting
    apt/dnf/yum in the generated manifest.  Ansible's package module is the
    equivalent abstraction: it proxies to the target host's detected package
    manager and keeps generated roles provider-neutral.
    """

    return f"""- name: Install packages for {role}
  ansible.builtin.package:
    name: "{{{{ {var_prefix}_packages | default([]) }}}}"
    state: present
  when: ({var_prefix}_packages | default([])) | length > 0

"""


def _render_grouped_systemd_tasks(var_prefix: str) -> str:
    """Render tasks to manage multiple systemd units in a common role."""

    return f"""- name: Probe whether grouped systemd units exist and are manageable
  ansible.builtin.systemd:
    name: "{{{{ item.name }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  check_mode: true
  loop: "{{{{ {var_prefix}_systemd_units | default([]) }}}}"
  register: _enroll_unit_probes
  failed_when: false
  changed_when: false
  when: item.manage | default(false)

- name: Ensure grouped unit enablement matches harvest
  ansible.builtin.systemd:
    name: "{{{{ item.item.name }}}}"
    enabled: "{{{{ item.item.enabled | bool }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  loop: "{{{{ _enroll_unit_probes.results | default([]) }}}}"
  when:
    - item.item.manage | default(false)
    - not (item.failed | default(false))

- name: Ensure grouped unit running state matches harvest
  ansible.builtin.systemd:
    name: "{{{{ item.item.name }}}}"
    state: "{{{{ item.item.state }}}}"
  no_log: "{{{{ enroll_hide_systemd_status | default(true) | bool }}}}"
  loop: "{{{{ _enroll_unit_probes.results | default([]) }}}}"
  when:
    - item.item.manage | default(false)
    - not (item.failed | default(false))
"""


def _render_sysctl_tasks(var_prefix: str) -> str:
    return f"""- name: Ensure sysctl.d exists
  ansible.builtin.file:
    path: /etc/sysctl.d
    state: directory
    owner: root
    group: root
    mode: "0755"

- name: Deploy captured sysctl configuration
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ {var_prefix}_conf_src_rel }}}}"
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_conf_src_rel }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: /etc/sysctl.d/99-enroll.conf
    owner: root
    group: root
    mode: "0644"
  when: ({var_prefix}_conf_src_rel | default('') | length) > 0
  notify: Apply captured sysctl configuration
"""


def _render_sysctl_handlers(var_prefix: str) -> str:
    return f"""---
- name: Apply captured sysctl configuration
  ansible.builtin.command:
    argv:
      - sysctl
      - -e
      - -p
      - /etc/sysctl.d/99-enroll.conf
  register: _enroll_sysctl_apply
  changed_when: false
  failed_when:
    - not ({var_prefix}_ignore_apply_errors | default(true) | bool)
    - _enroll_sysctl_apply.rc != 0
  when: {var_prefix}_apply | default(true) | bool
"""


def _render_firewall_runtime_tasks(var_prefix: str) -> str:
    """Render tasks for live ipset/iptables snapshots."""
    return f"""- name: Ensure firewall runtime snapshot directory exists
  ansible.builtin.file:
    path: /etc/enroll/firewall
    state: directory
    owner: root
    group: root
    mode: "0750"

- name: Deploy captured ipset snapshot
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ {var_prefix}_ipset_save }}}}"
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_ipset_save }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: /etc/enroll/firewall/ipset.save
    owner: root
    group: root
    mode: "0600"
  when: ({var_prefix}_ipset_save | default('') | length) > 0

- name: Flush captured ipsets before restoring members
  ansible.builtin.command:
    cmd: "ipset flush {{{{ item }}}}"
  loop: "{{{{ {var_prefix}_ipset_sets | default([]) }}}}"
  register: _enroll_ipset_flush
  failed_when: false
  changed_when: false
  when:
    - ({var_prefix}_ipset_save | default('') | length) > 0
    - {var_prefix}_sync_ipsets_exact | default(true) | bool

- name: Restore captured ipsets
  ansible.builtin.shell: "ipset restore -exist < /etc/enroll/firewall/ipset.save"
  args:
    executable: /bin/sh
  register: _enroll_ipset_restore
  changed_when: _enroll_ipset_restore.rc == 0
  when: ({var_prefix}_ipset_save | default('') | length) > 0

- name: Deploy captured IPv4 iptables snapshot
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ {var_prefix}_iptables_v4_save }}}}"
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_iptables_v4_save }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: /etc/enroll/firewall/iptables.v4
    owner: root
    group: root
    mode: "0600"
  when: ({var_prefix}_iptables_v4_save | default('') | length) > 0

- name: Restore captured IPv4 iptables rules
  ansible.builtin.command:
    cmd: iptables-restore /etc/enroll/firewall/iptables.v4
  register: _enroll_iptables_v4_restore
  changed_when: _enroll_iptables_v4_restore.rc == 0
  when:
    - ({var_prefix}_iptables_v4_save | default('') | length) > 0
    - {var_prefix}_restore_iptables | default(true) | bool

- name: Deploy captured IPv6 iptables snapshot
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ {var_prefix}_iptables_v6_save }}}}"
        - "{{{{ role_path }}}}/files/{{{{ {var_prefix}_iptables_v6_save }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: /etc/enroll/firewall/iptables.v6
    owner: root
    group: root
    mode: "0600"
  when: ({var_prefix}_iptables_v6_save | default('') | length) > 0

- name: Restore captured IPv6 iptables rules
  ansible.builtin.command:
    cmd: ip6tables-restore /etc/enroll/firewall/iptables.v6
  register: _enroll_iptables_v6_restore
  changed_when: _enroll_iptables_v6_restore.rc == 0
  when:
    - ({var_prefix}_iptables_v6_save | default('') | length) > 0
    - {var_prefix}_restore_iptables | default(true) | bool
"""
