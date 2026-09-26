from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Set

from .. import harvest as h
from ..capture import capture_file, capture_user_shell_dotfiles
from ..harvest_types import (
    ExcludedFile,
    FlatpakSnapshot,
    ManagedFile,
    SnapSnapshot,
    UsersSnapshot,
)
from .context import HarvestCollector, HarvestContext


@dataclass
class UsersCollection:
    users_snapshot: UsersSnapshot
    flatpak_snapshot: FlatpakSnapshot
    snap_snapshot: SnapSnapshot


class UsersCollector(HarvestCollector):
    """Collect non-system users plus system/user Flatpak and Snap facts."""

    def __init__(
        self, context: HarvestContext, seen_by_role: Dict[str, Set[str]]
    ) -> None:
        super().__init__(context)
        self.seen_by_role = seen_by_role

    def collect(self) -> UsersCollection:
        users_notes: List[str] = []
        users_excluded: List[ExcludedFile] = []
        users_managed: List[ManagedFile] = []
        users_list: List[dict] = []

        try:
            user_records = h.collect_non_system_users()
        except Exception as e:
            user_records = []
            users_notes.append(f"Failed to enumerate users: {e!r}")

        # Detect system-wide Flatpaks/Snaps and configured Flatpak remotes.
        from ..accounts import (
            find_system_flatpak_remotes,
            find_system_flatpaks,
            find_system_snaps,
            find_user_flatpak_remotes,
        )

        system_flatpaks = [asdict(f) for f in find_system_flatpaks()]
        system_snaps = [asdict(s) for s in find_system_snaps()]
        flatpak_notes: List[str] = []
        snap_notes: List[str] = []

        def safe_remotes(remotes, notes):
            accepted = []
            for remote in remotes:
                record = asdict(remote)
                reason = self.context.policy.metadata_deny_reason(record)
                if reason:
                    notes.append(f"Flatpak remote omitted: {reason} (metadata policy).")
                else:
                    accepted.append(record)
            return accepted

        system_flatpak_remotes = safe_remotes(
            find_system_flatpak_remotes(), flatpak_notes
        )
        if system_flatpaks:
            flatpak_notes.append(
                "System-wide flatpaks detected: "
                + ", ".join(str(f.get("name")) for f in system_flatpaks)
            )
        if system_snaps:
            snap_notes.append(
                "System-wide snaps detected: "
                + ", ".join(str(s.get("name")) for s in system_snaps)
            )

        users_role_name = "users"
        users_role_seen = self.seen_by_role.setdefault(users_role_name, set())

        skel_dir = "/etc/skel"
        auto_capture_user_dotfiles = bool(
            getattr(self.context.policy, "dangerous", False)
        )
        if user_records and not auto_capture_user_dotfiles:
            users_notes.append(
                "User shell dotfiles were not auto-harvested because --dangerous was not set; "
                "use --dangerous for automatic shell-dotfile capture, or targeted "
                "--include-path patterns for safe-mode review."
            )

        user_flatpaks_map: Dict[str, List[Dict[str, Any]]] = {}
        user_flatpak_remotes: List[Dict[str, Any]] = []

        for user in user_records:
            users_list.append(
                {
                    "name": user.name,
                    "uid": user.uid,
                    "gid": user.gid,
                    "gecos": user.gecos,
                    "home": user.home,
                    "shell": user.shell,
                    "primary_group": user.primary_group,
                    "supplementary_groups": user.supplementary_groups,
                }
            )

            # Copy only safe SSH public material: authorized_keys + *.pub
            for ssh_file in user.ssh_files:
                reason = (
                    "authorized_keys"
                    if ssh_file.endswith("/authorized_keys")
                    else "ssh_public_key"
                )
                capture_file(
                    bundle_dir=self.context.bundle_dir,
                    role_name=users_role_name,
                    abs_path=ssh_file,
                    reason=reason,
                    policy=self.context.policy,
                    path_filter=self.context.path_filter,
                    managed_out=users_managed,
                    excluded_out=users_excluded,
                    seen_role=users_role_seen,
                    seen_global=self.context.captured_global,
                )

            # Capture common per-user shell dotfiles only in dangerous mode. They
            # often contain exported tokens or aliases/functions with embedded secrets.
            home = (user.home or "").rstrip("/")
            if home and home.startswith("/"):
                capture_user_shell_dotfiles(
                    bundle_dir=self.context.bundle_dir,
                    role_name=users_role_name,
                    home=home,
                    skel_dir=skel_dir,
                    enabled=auto_capture_user_dotfiles,
                    policy=self.context.policy,
                    path_filter=self.context.path_filter,
                    managed_out=users_managed,
                    excluded_out=users_excluded,
                    seen_role=users_role_seen,
                    seen_global=self.context.captured_global,
                )

                # Collect per-user Flatpak applications and remotes. Snap packages are
                # system-wide; ~/snap/* is user data, not an install source.
                if user.flatpaks:
                    user_flatpaks_map[user.name] = [asdict(fp) for fp in user.flatpaks]
                user_flatpak_remotes.extend(
                    safe_remotes(
                        find_user_flatpak_remotes(home, user=user.name), users_notes
                    )
                )

        return UsersCollection(
            users_snapshot=UsersSnapshot(
                role_name="users",
                users=users_list,
                managed_files=users_managed,
                excluded=users_excluded,
                notes=users_notes,
                user_flatpaks=user_flatpaks_map,
                user_flatpak_remotes=user_flatpak_remotes,
            ),
            flatpak_snapshot=FlatpakSnapshot(
                role_name="flatpak",
                system_flatpaks=system_flatpaks,
                remotes=system_flatpak_remotes,
                notes=flatpak_notes,
            ),
            snap_snapshot=SnapSnapshot(
                role_name="snap",
                system_snaps=system_snaps,
                notes=snap_notes,
            ),
        )
