from __future__ import annotations

from typing import Optional

from .ansible_renderer.context import _prepare_ansible_context
from .ansible_renderer.layout import _write_manifest_playbook, _write_site_scaffold
from .ansible_renderer.model import (
    AnsibleManifestPlan,
    AnsibleRole,
    _collect_ansible_roles,
)
from .ansible_renderer.roles.container_images import _render_container_images_role
from .ansible_renderer.roles.desktop import _render_flatpak_role, _render_snap_role
from .ansible_renderer.roles.managed_files import _render_managed_file_roles
from .ansible_renderer.roles.packages import (
    _render_common_ansible_roles,
    _render_package_roles,
    _render_service_roles,
)
from .ansible_renderer.roles.runtime import (
    _render_firewall_runtime_role,
    _render_sysctl_role,
)
from .ansible_renderer.roles.users import _render_users_role
from .state import inventory_packages_from_state, roles_from_state


class AnsibleManifestRenderer:
    """Render Ansible roles and playbook from a harvest bundle."""

    def __init__(
        self,
        bundle_dir: str,
        out_dir: str,
        *,
        fqdn: Optional[str] = None,
        jinjaturtle: str = "auto",
        no_common_roles: bool = False,
    ) -> None:
        self.bundle_dir = bundle_dir
        self.out_dir = out_dir
        self.fqdn = fqdn
        self.jinjaturtle = jinjaturtle
        self.no_common_roles = no_common_roles

    def render(self) -> None:
        state = AnsibleRole.load_state(self.bundle_dir)
        roles = roles_from_state(state)
        inventory_packages = inventory_packages_from_state(state)

        ctx = _prepare_ansible_context(
            self.bundle_dir,
            self.out_dir,
            fqdn=self.fqdn,
            jinjaturtle=self.jinjaturtle,
        )
        _write_site_scaffold(ctx)

        use_common_roles = (not ctx.site_mode) and (not self.no_common_roles)
        collection = _collect_ansible_roles(
            roles,
            inventory_packages,
            use_common_roles=use_common_roles,
        )

        manifest_plan = AnsibleManifestPlan()

        _render_users_role(ctx, manifest_plan, roles.get("users", {}))
        _render_flatpak_role(ctx, manifest_plan, roles.get("flatpak", {}))
        _render_snap_role(ctx, manifest_plan, roles.get("snap", {}))
        _render_container_images_role(
            ctx, manifest_plan, roles.get("container_images", {})
        )
        _render_managed_file_roles(ctx, manifest_plan, roles)
        _render_sysctl_role(ctx, manifest_plan, roles.get("sysctl", {}))
        _render_firewall_runtime_role(
            ctx, manifest_plan, roles.get("firewall_runtime", {})
        )
        _render_service_roles(ctx, manifest_plan, collection.services)

        common_tail_roles = _render_common_ansible_roles(
            ctx, manifest_plan, collection.common_role_groups, collection.packages
        )
        _render_package_roles(ctx, manifest_plan, collection.packages)

        # Place cron/logrotate at the end of the playbook so users exist before
        # per-user crontabs are restored and core packages/services are in place.
        for role in ("cron", "logrotate"):
            manifest_plan.mark_tail_package(role)
        for role in common_tail_roles:
            manifest_plan.mark_tail_package(role)

        _write_manifest_playbook(ctx, manifest_plan.ordered_roles())


def manifest_from_bundle_dir(
    bundle_dir: str,
    out_dir: str,
    *,
    fqdn: Optional[str] = None,
    jinjaturtle: str = "auto",
    no_common_roles: bool = False,
) -> None:
    AnsibleManifestRenderer(
        bundle_dir,
        out_dir,
        fqdn=fqdn,
        jinjaturtle=jinjaturtle,
        no_common_roles=no_common_roles,
    ).render()
