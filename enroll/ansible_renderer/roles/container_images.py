from __future__ import annotations

import os
from typing import Any, Dict, List

from ..context import AnsibleManifestContext
from ..layout import (
    _ensure_requirements_yaml,
    _write_hostvars,
    _write_role_defaults,
    _write_role_scaffold,
)
from ..model import AnsibleManifestPlan
from ..vars import _normalise_container_image_item

_CONTAINER_COLLECTIONS = [
    {"name": "community.docker", "version": ">=4.0.0"},
    {"name": "containers.podman", "version": ">=1.0.0"},
]


def _render_container_images_role(
    ctx: AnsibleManifestContext,
    manifest_plan: AnsibleManifestPlan,
    container_images_snapshot: Dict[str, Any],
) -> None:
    raw_images = container_images_snapshot.get("images", []) or []
    if not container_images_snapshot and not raw_images:
        return

    images = [_normalise_container_image_item(img) for img in raw_images]
    if not images and not (container_images_snapshot.get("notes") or []):
        return

    role = container_images_snapshot.get("role_name", "container_images")
    role_dir = os.path.join(ctx.roles_root, role)
    _write_role_scaffold(role_dir)
    _ensure_requirements_yaml(
        os.path.join(ctx.out_dir, "requirements.yml"), _CONTAINER_COLLECTIONS
    )

    vars_map = {"container_images": images}
    if ctx.site_mode:
        _write_role_defaults(role_dir, {"container_images": []})
        _write_hostvars(ctx.out_dir, ctx.fqdn or "", role, vars_map)
    else:
        _write_role_defaults(role_dir, vars_map)

    with open(os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8") as f:
        f.write(
            "---\n"
            "dependencies: []\n"
            "collections:\n"
            "  - community.docker\n"
            "  - containers.podman\n"
        )

    tasks = """---

- name: Pull Docker images by immutable registry digest
  community.docker.docker_image_pull:
    name: "{{ item.pull_ref }}"
    pull: not_present
    platform: "{{ item.platform | default(omit, true) }}"
  loop: "{{ container_images | default([]) | selectattr('engine', 'equalto', 'docker') | selectattr('pull_ref', 'defined') | list }}"
  when:
    - item.pull_ref | default('') | length > 0
  become: true

- name: Tag Docker images with harvested tag aliases
  community.docker.docker_image_tag:
    name: "{{ item.0.pull_ref }}"
    repository:
      - "{{ item.1.ref }}"
  loop: "{{ query('subelements', container_images | default([]) | selectattr('engine', 'equalto', 'docker') | selectattr('pull_ref', 'defined') | list, 'tag_aliases', {'skip_missing': True}) }}"
  when:
    - item.0.pull_ref | default('') | length > 0
    - item.1.repository | default('') | length > 0
    - item.1.tag | default('') | length > 0
  become: true

- name: Pull system Podman images by immutable registry digest
  containers.podman.podman_image:
    name: "{{ item.pull_ref }}"
    state: present
    force: false
    platform: "{{ item.platform | default(omit, true) }}"
  loop: "{{ container_images | default([]) | selectattr('engine', 'equalto', 'podman') | rejectattr('scope', 'equalto', 'user') | selectattr('pull_ref', 'defined') | list }}"
  when:
    - item.pull_ref | default('') | length > 0
  become: true

- name: Tag system Podman images with harvested tag aliases
  containers.podman.podman_tag:
    image: "{{ item.0.pull_ref }}"
    target_names:
      - "{{ item.1.ref }}"
  loop: "{{ query('subelements', container_images | default([]) | selectattr('engine', 'equalto', 'podman') | rejectattr('scope', 'equalto', 'user') | selectattr('pull_ref', 'defined') | list, 'tag_aliases', {'skip_missing': True}) }}"
  when:
    - item.0.pull_ref | default('') | length > 0
    - item.1.ref | default('') | length > 0
  become: true

- name: Pull user Podman images by immutable registry digest
  containers.podman.podman_image:
    name: "{{ item.pull_ref }}"
    state: present
    force: false
    platform: "{{ item.platform | default(omit, true) }}"
  loop: "{{ container_images | default([]) | selectattr('engine', 'equalto', 'podman') | selectattr('scope', 'equalto', 'user') | selectattr('pull_ref', 'defined') | list }}"
  when:
    - item.pull_ref | default('') | length > 0
    - item.user | default('') | length > 0
  become: true
  become_user: "{{ item.user }}"

- name: Tag user Podman images with harvested tag aliases
  containers.podman.podman_tag:
    image: "{{ item.0.pull_ref }}"
    target_names:
      - "{{ item.1.ref }}"
  loop: "{{ query('subelements', container_images | default([]) | selectattr('engine', 'equalto', 'podman') | selectattr('scope', 'equalto', 'user') | selectattr('pull_ref', 'defined') | list, 'tag_aliases', {'skip_missing': True}) }}"
  when:
    - item.0.pull_ref | default('') | length > 0
    - item.0.user | default('') | length > 0
    - item.1.ref | default('') | length > 0
  become: true
  become_user: "{{ item.0.user }}"
"""
    with open(os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8") as f:
        f.write(tasks)

    with open(
        os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
    ) as f:
        f.write("---\n")

    def _fmt_image(img: Dict[str, Any]) -> str:
        pull_ref = (
            img.get("pull_ref") or "(no registry digest; not rendered as an exact pull)"
        )
        tags = img.get("repo_tags") or []
        tag_part = f" tags={', '.join(tags)}" if tags else ""
        platform = img.get("platform")
        platform_part = f" platform={platform}" if platform else ""
        return f"- {img.get('engine', 'unknown')}: {pull_ref}{tag_part}{platform_part}"

    notes = list(container_images_snapshot.get("notes", []) or [])
    unpinned_notes: List[str] = []
    for img in images:
        if img.get("pull_ref"):
            continue
        label = (
            ", ".join(img.get("repo_tags") or [])
            or img.get("image_id")
            or "unknown image"
        )
        unpinned_notes.append(
            f"{label}: no RepoDigest was available, so no exact pull task is emitted."
        )

    readme = (
        """# container_images

Generated Docker and Podman image-cache restoration role.

Images are pulled by immutable registry digest, such as
`registry.example.net/app@sha256:...`, when the harvest found a usable
`RepoDigest`. Local image IDs are recorded in `state.json` for evidence but are
not registry pull references.

**Note:** This role requires the `community.docker` and `containers.podman`
Ansible collections. Install them with:
`ansible-galaxy collection install -r requirements.yml`.

Registry credentials are not harvested. Private-registry authentication must be
managed separately before this role runs.

## Container images
"""
        + "\n".join(_fmt_image(img) for img in images)
        + """

## Notes
"""
        + ("\n".join([f"- {n}" for n in notes + unpinned_notes]) or "- (none)")
        + "\n"
    )
    with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)

    manifest_plan.add("container_images", role)
