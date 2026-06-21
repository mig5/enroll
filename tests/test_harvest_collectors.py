from __future__ import annotations

from enroll.harvest_collectors.context import HarvestContext
from enroll.harvest_collectors.runtime import RuntimeStateCollector
from enroll.harvest_types import FirewallRuntimeSnapshot, SysctlSnapshot
from enroll.ignore import IgnorePolicy
from enroll.pathfilter import PathFilter


class _Backend:
    name = "dpkg"


def _context(tmp_path):
    return HarvestContext(
        bundle_dir=str(tmp_path),
        policy=IgnorePolicy(),
        path_filter=PathFilter(include=(), exclude=()),
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
