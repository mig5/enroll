from __future__ import annotations

import glob
import os
from typing import Dict, List, Optional, Set

from .. import harvest as h
from ..capture import capture_file
from ..harvest_types import (
    ExcludedFile,
    ExtraPathsSnapshot,
    ManagedDir,
    ManagedFile,
    UsrLocalCustomSnapshot,
)
from ..system_paths import MAX_FILES_CAP
from ..pathfilter import expand_includes
from .context import HarvestCollector, HarvestContext


class UsrLocalCustomCollector(HarvestCollector):
    """Collect selected /usr/local state into the usr_local_custom role."""

    role_name = "usr_local_custom"

    def __init__(
        self,
        context: HarvestContext,
        seen_by_role: Dict[str, Set[str]],
        already_all: Set[str],
    ) -> None:
        super().__init__(context)
        self.seen_by_role = seen_by_role
        self.already_all = already_all
        self.notes: List[str] = []
        self.excluded: List[ExcludedFile] = []
        self.managed: List[ManagedFile] = []

    def collect(self) -> UsrLocalCustomSnapshot:
        self._scan_tree(
            "/usr/local/etc",
            require_executable=False,
            cap=MAX_FILES_CAP,
            reason="usr_local_etc_custom",
        )
        self._scan_tree(
            "/usr/local/bin",
            require_executable=True,
            cap=MAX_FILES_CAP,
            reason="usr_local_bin_script",
        )
        return UsrLocalCustomSnapshot(
            role_name=self.role_name,
            managed_files=self.managed,
            excluded=self.excluded,
            notes=self.notes,
        )

    def _scan_tree(
        self,
        root: str,
        *,
        require_executable: bool,
        cap: int,
        reason: str,
    ) -> None:
        scanned = 0
        if not os.path.isdir(root):
            return
        role_seen = self.seen_by_role.setdefault(self.role_name, set())
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                if path in self.already_all:
                    continue
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                try:
                    owner, group, mode = h.stat_triplet(path)
                except OSError:
                    self.excluded.append(ExcludedFile(path=path, reason="unreadable"))
                    continue

                if require_executable:
                    try:
                        if (int(mode, 8) & 0o111) == 0:
                            continue
                    except ValueError:
                        continue

                if capture_file(
                    bundle_dir=self.context.bundle_dir,
                    role_name=self.role_name,
                    abs_path=path,
                    reason=reason,
                    policy=self.context.policy,
                    path_filter=self.context.path_filter,
                    managed_out=self.managed,
                    excluded_out=self.excluded,
                    seen_role=role_seen,
                    seen_global=self.context.captured_global,
                    metadata=(owner, group, mode),
                ):
                    self.already_all.add(path)
                    scanned += 1
                if scanned >= cap:
                    self.notes.append(
                        f"Reached file cap ({cap}) while scanning {root}."
                    )
                    return


class ExtraPathsCollector(HarvestCollector):
    """Collect user-requested include/exclude paths into extra_paths."""

    role_name = "extra_paths"

    def __init__(
        self,
        context: HarvestContext,
        seen_by_role: Dict[str, Set[str]],
        already_all: Set[str],
        *,
        include_paths: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
    ) -> None:
        super().__init__(context)
        self.seen_by_role = seen_by_role
        self.already_all = already_all
        self.include_specs = list(include_paths or [])
        self.exclude_specs = list(exclude_paths or [])
        self.notes: List[str] = []
        self.excluded: List[ExcludedFile] = []
        self.managed: List[ManagedFile] = []
        self.managed_dirs: List[ManagedDir] = []
        self.dir_seen: Set[str] = set()

    def collect(self) -> ExtraPathsSnapshot:
        self._collect_included_dirs()
        if self.include_specs:
            self.notes.append("User include patterns:")
            self.notes.extend([f"- {p}" for p in self.include_specs])
        if self.exclude_specs:
            self.notes.append("User exclude patterns:")
            self.notes.extend([f"- {p}" for p in self.exclude_specs])

        included_files: List[str] = []
        if self.include_specs:
            files, inc_notes = expand_includes(
                self.context.path_filter.iter_include_patterns(),
                exclude=self.context.path_filter,
                max_files=MAX_FILES_CAP,
            )
            included_files = files
            self.notes.extend(inc_notes)

        role_seen = self.seen_by_role.setdefault(self.role_name, set())
        for path in included_files:
            if path in self.already_all:
                continue
            if capture_file(
                bundle_dir=self.context.bundle_dir,
                role_name=self.role_name,
                abs_path=path,
                reason="user_include",
                policy=self.context.policy,
                path_filter=self.context.path_filter,
                managed_out=self.managed,
                excluded_out=self.excluded,
                seen_role=role_seen,
                seen_global=self.context.captured_global,
            ):
                self.already_all.add(path)

        return ExtraPathsSnapshot(
            role_name=self.role_name,
            include_patterns=self.include_specs,
            exclude_patterns=self.exclude_specs,
            managed_dirs=self.managed_dirs,
            managed_files=self.managed,
            excluded=self.excluded,
            notes=self.notes,
        )

    def _collect_included_dirs(self) -> None:
        for pat in self.context.path_filter.iter_include_patterns():
            if pat.kind == "prefix":
                path = pat.value
                if os.path.isdir(path) and not os.path.islink(path):
                    self._walk_and_capture_dirs(path)
            elif pat.kind == "glob":
                for hit in glob.glob(pat.value, recursive=True):
                    if os.path.isdir(hit) and not os.path.islink(hit):
                        self._walk_and_capture_dirs(hit)

    def _walk_and_capture_dirs(self, root: str) -> None:
        root = os.path.normpath(root)
        if not root.startswith("/"):
            root = "/" + root
        if not os.path.isdir(root) or os.path.islink(root):
            return
        for dirpath, dirnames, _ in os.walk(root, followlinks=False):
            if len(self.managed_dirs) >= MAX_FILES_CAP:
                self.notes.append(
                    f"Reached directory cap ({MAX_FILES_CAP}) while scanning {root}."
                )
                return
            dirpath = os.path.normpath(dirpath)
            if not dirpath.startswith("/"):
                dirpath = "/" + dirpath
            if self.context.path_filter.is_excluded(dirpath):
                dirnames[:] = []
                continue
            if os.path.islink(dirpath) or not os.path.isdir(dirpath):
                dirnames[:] = []
                continue

            if dirpath not in self.dir_seen:
                deny = None
                deny_dir = getattr(self.context.policy, "deny_reason_dir", None)
                if callable(deny_dir):
                    deny = deny_dir(dirpath)
                else:
                    deny = self.context.policy.deny_reason(dirpath)
                    if deny in ("not_regular_file", "not_file", "not_regular"):
                        deny = None
                if not deny:
                    try:
                        owner, group, mode = h.stat_triplet(dirpath)
                        self.managed_dirs.append(
                            ManagedDir(
                                path=dirpath,
                                owner=owner,
                                group=group,
                                mode=mode,
                                reason="user_include_dir",
                            )
                        )
                    except OSError:
                        pass
                self.dir_seen.add(dirpath)

            pruned: List[str] = []
            for dirname in dirnames:
                path = os.path.join(dirpath, dirname)
                if os.path.islink(path) or self.context.path_filter.is_excluded(path):
                    continue
                pruned.append(dirname)
            dirnames[:] = pruned
