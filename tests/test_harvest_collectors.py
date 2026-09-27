from __future__ import annotations

from pathlib import Path

from enroll.harvest_collectors.context import HarvestContext
from enroll.harvest_collectors.paths import ExtraPathsCollector, UsrLocalCustomCollector
from enroll.harvest_collectors.runtime import RuntimeStateCollector
from enroll.harvest_types import FirewallRuntimeSnapshot, ManagedFile, SysctlSnapshot
from enroll.ignore import IgnorePolicy
from enroll.pathfilter import PathFilter


class _Backend:
    name = "dpkg"


def _context(tmp_path: Path, *, include=(), exclude=(), policy=None) -> HarvestContext:
    return HarvestContext(
        bundle_dir=str(tmp_path / "bundle"),
        policy=policy or IgnorePolicy(),
        path_filter=PathFilter(include=include, exclude=exclude),
        platform={},
        backend=_Backend(),
        installed_pkgs={},
        installed_names=set(),
        owned_etc=set(),
        etc_owner_map={},
        topdir_to_pkgs={},
        pkg_to_etc_paths={},
        captured_global=set(),
    )


def test_runtime_state_collector_preserves_non_root_skip_schema(monkeypatch, tmp_path):
    monkeypatch.setattr("enroll.harvest.os.geteuid", lambda: 1000)

    result = RuntimeStateCollector(_context(tmp_path)).collect()

    assert isinstance(result.firewall_runtime_snapshot, FirewallRuntimeSnapshot)
    assert isinstance(result.sysctl_snapshot, SysctlSnapshot)
    assert result.firewall_runtime_snapshot.role_name == "firewall_runtime"
    assert result.sysctl_snapshot.role_name == "sysctl"
    assert "not running as root" in result.firewall_runtime_snapshot.notes[0]
    assert "not running as root" in result.sysctl_snapshot.notes[0]


def test_container_images_collector_records_digest_pinned_docker_images(
    monkeypatch, tmp_path
):
    import json
    import subprocess

    from enroll.harvest_collectors import container_images as ci
    from enroll.harvest_collectors.container_images import ContainerImagesCollector

    def fake_which(cmd):
        return f"/usr/bin/{cmd}" if cmd == "docker" else None

    def fake_run(argv, check=False, stdout=None, stderr=None, text=False, timeout=None):
        if argv[:4] == ["/usr/bin/docker", "image", "ls", "-q"]:
            return subprocess.CompletedProcess(argv, 0, "sha256:" + "a" * 64 + "\n", "")
        if argv[:3] == ["/usr/bin/docker", "image", "inspect"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    [
                        {
                            "Id": "sha256:" + "a" * 64,
                            "RepoTags": ["docker.io/library/nginx:1.27"],
                            "RepoDigests": [
                                "docker.io/library/nginx@sha256:" + "b" * 64
                            ],
                            "Os": "linux",
                            "Architecture": "amd64",
                            "Size": 123,
                            "Created": "2026-01-01T00:00:00Z",
                        }
                    ]
                ),
                "",
            )
        raise AssertionError(argv)

    monkeypatch.setattr(ci.shutil, "which", fake_which)
    monkeypatch.setattr(ci.subprocess, "run", fake_run)

    result = ContainerImagesCollector(_context(tmp_path)).collect()

    assert result.role_name == "container_images"
    assert len(result.images) == 1
    image = result.images[0]
    assert image["engine"] == "docker"
    assert image["pull_ref"] == "docker.io/library/nginx@sha256:" + "b" * 64
    assert image["platform"] == "linux/amd64"
    assert image["tag_aliases"] == [
        {
            "ref": "docker.io/library/nginx:1.27",
            "repository": "docker.io/library/nginx",
            "tag": "1.27",
        }
    ]


def test_container_images_collector_records_unpullable_tagged_images(
    monkeypatch, tmp_path
):
    import json
    import subprocess

    from enroll.harvest_collectors import container_images as ci
    from enroll.harvest_collectors.container_images import ContainerImagesCollector

    def fake_which(cmd):
        return "/usr/bin/podman" if cmd == "podman" else None

    monkeypatch.setattr(ci.shutil, "which", fake_which)

    def fake_run(argv, check=False, stdout=None, stderr=None, text=False, timeout=None):
        if argv[:4] == ["/usr/bin/podman", "image", "ls", "-q"]:
            return subprocess.CompletedProcess(argv, 0, "c" * 64 + "\n", "")
        if argv[:3] == ["/usr/bin/podman", "image", "inspect"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    [
                        {
                            "Id": "c" * 64,
                            "RepoTags": ["localhost/demo:latest"],
                            "RepoDigests": [],
                            "Os": "linux",
                            "Architecture": "amd64",
                        }
                    ]
                ),
                "",
            )
        raise AssertionError(argv)

    monkeypatch.setattr(ci.subprocess, "run", fake_run)

    result = ContainerImagesCollector(_context(tmp_path)).collect()

    assert result.images[0]["pull_ref"] is None
    assert "exact digest-pinned pull cannot be rendered" in result.images[0]["notes"][0]


def test_container_images_collector_notes_list_exceptions(monkeypatch, tmp_path):
    from enroll.harvest_collectors import container_images as ci
    from enroll.harvest_collectors.container_images import ContainerImagesCollector

    monkeypatch.setattr(
        ci.shutil,
        "which",
        lambda cmd: f"/usr/bin/{cmd}" if cmd == "docker" else None,
    )

    def boom(_argv, *, timeout=20):
        raise RuntimeError("socket unavailable")

    monkeypatch.setattr(ci, "_run_command", boom)

    result = ContainerImagesCollector(_context(tmp_path)).collect()

    assert result.images == []
    assert "Failed to list docker images" in result.notes[0]


def test_container_images_collector_notes_list_nonzero_without_detail(
    monkeypatch, tmp_path
):
    import subprocess

    from enroll.harvest_collectors import container_images as ci
    from enroll.harvest_collectors.container_images import ContainerImagesCollector

    monkeypatch.setattr(
        ci.shutil,
        "which",
        lambda cmd: f"/usr/bin/{cmd}" if cmd == "podman" else None,
    )
    monkeypatch.setattr(
        ci,
        "_run_command",
        lambda argv, *, timeout=20: subprocess.CompletedProcess(argv, 42, "", ""),
    )

    result = ContainerImagesCollector(_context(tmp_path)).collect()

    assert result.images == []
    assert "exit 42" in result.notes[0]


def test_container_images_collector_notes_bad_inspect_json(monkeypatch, tmp_path):
    import subprocess

    from enroll.harvest_collectors import container_images as ci
    from enroll.harvest_collectors.container_images import ContainerImagesCollector

    image_id = "sha256:" + "d" * 64
    monkeypatch.setattr(
        ci.shutil,
        "which",
        lambda cmd: f"/usr/bin/{cmd}" if cmd == "docker" else None,
    )

    def fake_run(argv, *, timeout=20):
        if argv[:4] == ["/usr/bin/docker", "image", "ls", "-q"]:
            return subprocess.CompletedProcess(argv, 0, image_id + "\n", "")
        if argv[:3] == ["/usr/bin/docker", "image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "not json", "")
        raise AssertionError(argv)

    monkeypatch.setattr(ci, "_run_command", fake_run)

    result = ContainerImagesCollector(_context(tmp_path)).collect()

    assert result.images == []
    assert "Failed to parse docker image inspect JSON" in result.notes[0]


def test_container_images_collector_notes_unexpected_inspect_shape(
    monkeypatch, tmp_path
):
    import subprocess

    from enroll.harvest_collectors import container_images as ci
    from enroll.harvest_collectors.container_images import ContainerImagesCollector

    image_id = "sha256:" + "e" * 64
    monkeypatch.setattr(
        ci.shutil,
        "which",
        lambda cmd: f"/usr/bin/{cmd}" if cmd == "docker" else None,
    )

    def fake_run(argv, *, timeout=20):
        if argv[:4] == ["/usr/bin/docker", "image", "ls", "-q"]:
            return subprocess.CompletedProcess(argv, 0, image_id + "\n", "")
        if argv[:3] == ["/usr/bin/docker", "image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, '{"not":"a-list"}', "")
        raise AssertionError(argv)

    monkeypatch.setattr(ci, "_run_command", fake_run)

    result = ContainerImagesCollector(_context(tmp_path)).collect()

    assert result.images == []
    assert "Unexpected docker image inspect JSON shape" in result.notes[0]


def test_extra_paths_collector_records_dirs_files_notes_and_excludes(
    monkeypatch, tmp_path
):
    from enroll.harvest_collectors import paths

    root = tmp_path / "include"
    sub = root / "sub"
    skip = root / "skip"
    sub.mkdir(parents=True)
    skip.mkdir()
    keep_file = sub / "keep.conf"
    keep_file.write_text("ok", encoding="utf-8")
    skip_file = skip / "skip.conf"
    skip_file.write_text("no", encoding="utf-8")

    class Policy(IgnorePolicy):
        def deny_reason_dir(self, path: str):
            return "denied_dir" if path == str(sub) else None

    def fake_stat_triplet(path: str):
        return ("root", "root", "0755")

    def fake_capture_file(**kwargs):
        kwargs["managed_out"].append(
            ManagedFile(
                path=kwargs["abs_path"],
                src_rel=kwargs["abs_path"].lstrip("/"),
                owner="root",
                group="root",
                mode="0644",
                reason=kwargs["reason"],
            )
        )
        return True

    monkeypatch.setattr(paths, "stat_dir_triplet", fake_stat_triplet)
    monkeypatch.setattr(paths, "capture_file", lambda *a, **kw: fake_capture_file(**kw))

    ctx = _context(
        tmp_path,
        include=[str(root)],
        exclude=[str(skip)],
        policy=Policy(),
    )
    result = ExtraPathsCollector(
        ctx,
        seen_by_role={},
        already_all=set(),
        include_paths=[str(root)],
        exclude_paths=[str(skip)],
    ).collect()

    managed_dirs = {d.path for d in result.managed_dirs}
    assert str(root) in managed_dirs
    assert str(sub) not in managed_dirs  # denied by policy
    assert str(skip) not in managed_dirs  # pruned by exclude filter
    assert [m.path for m in result.managed_files] == [str(keep_file)]
    assert "User include patterns:" in result.notes
    assert f"- {root}" in result.notes
    assert f"- {skip}" in result.notes


def test_extra_paths_collector_skips_already_captured_files(monkeypatch, tmp_path):
    from enroll.harvest_collectors import paths

    root = tmp_path / "include"
    root.mkdir()
    file_path = root / "keep.conf"
    file_path.write_text("ok", encoding="utf-8")
    calls: list[str] = []

    monkeypatch.setattr(paths, "stat_dir_triplet", lambda p: ("root", "root", "0755"))
    monkeypatch.setattr(
        paths, "capture_file", lambda *a, **kw: calls.append(kw["abs_path"]) or True
    )

    ctx = _context(tmp_path, include=[str(root)])
    result = ExtraPathsCollector(
        ctx,
        seen_by_role={},
        already_all={str(file_path)},
        include_paths=[str(root)],
    ).collect()

    assert result.managed_files == []
    assert calls == []


def test_usr_local_custom_collector_scans_executable_bin_and_notes_cap(
    monkeypatch, tmp_path
):
    from enroll.harvest_collectors import paths

    captured: list[str] = []

    def fake_isdir(path: str) -> bool:
        return path in {"/usr/local/etc", "/usr/local/bin"}

    def fake_walk(root: str):
        if root == "/usr/local/etc":
            yield root, [], ["app.conf"]
        elif root == "/usr/local/bin":
            yield root, [], ["tool", "not-exec"]

    def fake_isfile(path: str) -> bool:
        return path in {
            "/usr/local/etc/app.conf",
            "/usr/local/bin/tool",
            "/usr/local/bin/not-exec",
        }

    def fake_stat_triplet(path: str):
        mode = "0755" if path == "/usr/local/bin/tool" else "0644"
        return ("root", "root", mode)

    def fake_capture_file(**kwargs):
        captured.append(kwargs["abs_path"])
        kwargs["managed_out"].append(
            ManagedFile(
                path=kwargs["abs_path"],
                src_rel=kwargs["abs_path"].lstrip("/"),
                owner="root",
                group="root",
                mode="0644",
                reason=kwargs["reason"],
            )
        )
        return True

    monkeypatch.setattr(paths.os.path, "isdir", fake_isdir)
    monkeypatch.setattr(paths.os, "walk", fake_walk)
    monkeypatch.setattr(paths.os.path, "isfile", fake_isfile)
    monkeypatch.setattr(paths.os.path, "islink", lambda p: False)
    monkeypatch.setattr(paths, "stat_triplet", fake_stat_triplet)
    monkeypatch.setattr(paths, "capture_file", lambda *a, **kw: fake_capture_file(**kw))

    ctx = _context(tmp_path)
    result = UsrLocalCustomCollector(ctx, seen_by_role={}, already_all=set()).collect()

    assert captured == ["/usr/local/etc/app.conf", "/usr/local/bin/tool"]
    assert [m.reason for m in result.managed_files] == [
        "usr_local_etc_custom",
        "usr_local_bin_script",
    ]


def test_extra_paths_collector_records_symlinks_without_following(tmp_path):
    root = tmp_path / "include"
    root.mkdir()
    real_file = root / "real.conf"
    real_file.write_text("ok", encoding="utf-8")
    (root / "link.conf").symlink_to("real.conf")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "outside.conf").write_text("do-not-follow", encoding="utf-8")
    (root / "shared").symlink_to(outside, target_is_directory=True)

    ctx = _context(tmp_path, include=[str(root)])
    result = ExtraPathsCollector(
        ctx,
        seen_by_role={},
        already_all=set(),
        include_paths=[str(root)],
    ).collect()

    links = {(link.path, link.target, link.reason) for link in result.managed_links}
    assert (str(root / "link.conf"), "real.conf", "user_include_link") in links
    assert (str(root / "shared"), str(outside), "user_include_link") in links

    managed_files = {mf.path for mf in result.managed_files}
    assert str(real_file) in managed_files
    assert str(outside / "outside.conf") not in managed_files


def test_extra_paths_collector_records_include_path_that_is_symlink(tmp_path):
    real_root = tmp_path / "real"
    real_root.mkdir()
    (real_root / "inside.conf").write_text("do-not-follow", encoding="utf-8")
    link_root = tmp_path / "linked-root"
    link_root.symlink_to(real_root, target_is_directory=True)

    ctx = _context(tmp_path, include=[str(link_root)])
    result = ExtraPathsCollector(
        ctx,
        seen_by_role={},
        already_all=set(),
        include_paths=[str(link_root)],
    ).collect()

    assert [(link.path, link.target, link.reason) for link in result.managed_links] == [
        (str(link_root), str(real_root), "user_include_link")
    ]
    assert result.managed_files == []


def test_extra_paths_collector_skips_directory_through_symlinked_parent(tmp_path):
    real_root = tmp_path / "real"
    child = real_root / "child"
    child.mkdir(parents=True)
    (child / "inside.conf").write_text("do-not-follow", encoding="utf-8")
    link_root = tmp_path / "linked-root"
    link_root.symlink_to(real_root, target_is_directory=True)

    include_path = str(link_root / "child")
    ctx = _context(tmp_path, include=[include_path])
    result = ExtraPathsCollector(
        ctx,
        seen_by_role={},
        already_all=set(),
        include_paths=[include_path],
    ).collect()

    assert result.managed_dirs == []
    assert result.managed_files == []
    assert result.managed_links == []


def test_users_collector_filters_flatpak_credentials(monkeypatch, tmp_path):
    from enroll import accounts, harvest
    from enroll.harvest_collectors.users import UsersCollector
    from types import SimpleNamespace

    remote = accounts.FlatpakRemote(
        name="private",
        method="system",
        url="https://user:FAKE_SECRET@repo.example/repo",
    )
    user = SimpleNamespace(
        name="alice",
        uid=1000,
        gid=1000,
        gecos="",
        home="/home/alice",
        shell="/bin/bash",
        primary_group="alice",
        supplementary_groups=[],
        ssh_files=[],
        flatpaks=[],
    )
    monkeypatch.setattr(harvest, "collect_non_system_users", lambda: [user])
    monkeypatch.setattr(accounts, "find_system_flatpaks", lambda: [])
    monkeypatch.setattr(accounts, "find_system_snaps", lambda: [])
    monkeypatch.setattr(accounts, "find_system_flatpak_remotes", lambda: [remote])
    monkeypatch.setattr(
        accounts, "find_user_flatpak_remotes", lambda *a, **kw: [remote]
    )
    for dangerous in (False, True):
        result = UsersCollector(
            _context(tmp_path, policy=IgnorePolicy(dangerous=dangerous)), {}
        ).collect()
        assert bool(result.flatpak_snapshot.remotes) == dangerous
        assert bool(result.users_snapshot.user_flatpak_remotes) == dangerous
        assert "FAKE_SECRET" not in str(result.flatpak_snapshot.notes)
        assert "FAKE_SECRET" not in str(result.users_snapshot.notes)


def test_runtime_exclusions_apply_before_capture(monkeypatch, tmp_path):
    from enroll import harvest

    monkeypatch.setattr(harvest.os, "geteuid", lambda: 0)

    def unexpected_capture(*args, **kwargs):
        raise AssertionError("excluded runtime resource was read")

    monkeypatch.setattr(harvest, "_run_capture_command", unexpected_capture)
    result = RuntimeStateCollector(
        _context(
            tmp_path,
            exclude=(
                "/etc/sysctl.d/99-enroll.conf",
                "/etc/enroll/firewall/*",
            ),
        )
    ).collect()
    assert result.sysctl_snapshot.managed_files == []
    assert result.sysctl_snapshot.parameters == {}
    assert result.firewall_runtime_snapshot.ipset_save is None
    assert not (tmp_path / "bundle" / "artifacts").exists()


def test_service_collector_rejects_normalized_role_collisions(tmp_path):
    import pytest
    from enroll.harvest_collectors.services import ServicePackageCollector
    from enroll.package_hints import role_name_from_unit

    collector = ServicePackageCollector(_context(tmp_path))
    collector._claim_role(role_name_from_unit("foo-bar.service"), "foo-bar.service")
    with pytest.raises(ValueError, match="collision"):
        collector._claim_role(role_name_from_unit("foo_bar.service"), "foo_bar.service")
