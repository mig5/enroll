import json
from pathlib import Path

import enroll.harvest as h
from enroll.platform import PlatformInfo
from enroll.systemd import UnitInfo


class AllowAllPolicy:
    def deny_reason(self, path: str):
        return None

    def deny_reason_link(self, path: str):
        return None


class FakeBackend:
    """Minimal backend stub for harvest tests.

    Keep harvest deterministic and avoid enumerating the real system.
    """

    name = "dpkg"

    def build_etc_index(self):
        return (set(), {}, {}, {})

    def owner_of_path(self, path: str):
        return None

    def list_manual_packages(self):
        return []

    def installed_packages(self):
        return {}

    def specific_paths_for_hints(self, hints: set[str]):
        return []

    def is_pkg_config_path(self, path: str) -> bool:
        return False

    def modified_paths(self, pkg: str, etc_paths: list[str]):
        return {}


def _base_monkeypatches(monkeypatch, *, unit: str):
    """Patch harvest to avoid live system access."""

    monkeypatch.setattr(
        h, "detect_platform", lambda: PlatformInfo("debian", "dpkg", {})
    )
    monkeypatch.setattr(h, "get_backend", lambda info=None: FakeBackend())

    monkeypatch.setattr(h, "list_enabled_timers", lambda: [])
    monkeypatch.setattr(
        h,
        "get_unit_info",
        lambda u: UnitInfo(
            name=u,
            fragment_path=None,
            dropin_paths=[],
            env_files=[],
            exec_paths=[],
            active_state="inactive",
            sub_state="dead",
            unit_file_state="enabled",
            condition_result=None,
        ),
    )

    # Keep users empty and avoid touching /etc/skel.
    monkeypatch.setattr(h, "collect_non_system_users", lambda: [])

    # Avoid warning spam from non-root test runs.
    if hasattr(h.os, "geteuid"):
        monkeypatch.setattr(h.os, "geteuid", lambda: 0)

    # Avoid walking the real filesystem.
    monkeypatch.setattr(h.os, "walk", lambda root: iter(()))
    monkeypatch.setattr(h, "_copy_into_bundle", lambda *a, **k: None)

    # Default to a "no files exist" view of the world unless a test overrides.
    monkeypatch.setattr(h.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(h.os.path, "exists", lambda p: False)

    # Minimal enabled services list.
    monkeypatch.setattr(h, "list_enabled_services", lambda: [unit] if unit else [])


def test_harvest_captures_nginx_enabled_symlinks(monkeypatch, tmp_path: Path):
    bundle = tmp_path / "bundle"
    unit = "nginx.service"
    _base_monkeypatches(monkeypatch, unit=unit)

    # Fake filesystem for nginx enabled dirs.
    dirs = {
        "/etc",
        "/etc/nginx",
        "/etc/nginx/sites-enabled",
        "/etc/nginx/modules-enabled",
    }
    links = {
        "/etc/nginx/sites-enabled/default": "../sites-available/default",
        "/etc/nginx/modules-enabled/mod-http": "../modules-available/mod-http",
    }

    monkeypatch.setattr(h.os.path, "isdir", lambda p: p in dirs)
    monkeypatch.setattr(h.os.path, "islink", lambda p: p in links)
    monkeypatch.setattr(h.os, "readlink", lambda p: links[p])

    def fake_glob(pat: str):
        if pat == "/etc/nginx/sites-enabled/*":
            return [
                "/etc/nginx/sites-enabled/default",
                "/etc/nginx/sites-enabled/README",
            ]
        if pat == "/etc/nginx/modules-enabled/*":
            return ["/etc/nginx/modules-enabled/mod-http"]
        return []

    monkeypatch.setattr(h.glob, "glob", fake_glob)

    state_path = h.harvest(str(bundle), policy=AllowAllPolicy())
    st = json.loads(Path(state_path).read_text(encoding="utf-8"))

    svc = next(s for s in st["roles"]["services"] if s["role_name"] == "nginx")
    managed_links = svc.get("managed_links") or []
    assert {(ml["path"], ml["target"], ml["reason"]) for ml in managed_links} == {
        (
            "/etc/nginx/sites-enabled/default",
            "../sites-available/default",
            "enabled_symlink",
        ),
        (
            "/etc/nginx/modules-enabled/mod-http",
            "../modules-available/mod-http",
            "enabled_symlink",
        ),
    }


def test_harvest_does_not_capture_enabled_symlinks_without_role(
    monkeypatch, tmp_path: Path
):
    bundle = tmp_path / "bundle"
    _base_monkeypatches(monkeypatch, unit="")

    # Dirs exist but nginx isn't detected, so nothing should be captured.
    monkeypatch.setattr(
        h.os.path,
        "isdir",
        lambda p: p
        in {
            "/etc",
            "/etc/nginx/sites-enabled",
            "/etc/nginx/modules-enabled",
        },
    )
    monkeypatch.setattr(
        h.glob, "glob", lambda pat: ["/etc/nginx/sites-enabled/default"]
    )
    monkeypatch.setattr(h.os.path, "islink", lambda p: True)
    monkeypatch.setattr(h.os, "readlink", lambda p: "../sites-available/default")

    state_path = h.harvest(str(bundle), policy=AllowAllPolicy())
    st = json.loads(Path(state_path).read_text(encoding="utf-8"))

    # No services => no place to attach nginx links.
    assert st["roles"]["services"] == []
    # And no package snapshots either.
    assert st["roles"]["packages"] == []


def test_harvest_symlink_capture_respects_ignore_policy(monkeypatch, tmp_path: Path):
    bundle = tmp_path / "bundle"
    _base_monkeypatches(monkeypatch, unit="nginx.service")

    dirs = {"/etc", "/etc/nginx/sites-enabled", "/etc/nginx/modules-enabled"}
    links = {
        "/etc/nginx/sites-enabled/default": "../sites-available/default",
        "/etc/nginx/sites-enabled/ok": "../sites-available/ok",
    }

    monkeypatch.setattr(h.os.path, "isdir", lambda p: p in dirs)
    monkeypatch.setattr(h.os.path, "islink", lambda p: p in links)
    monkeypatch.setattr(h.os, "readlink", lambda p: links[p])
    monkeypatch.setattr(
        h.glob,
        "glob",
        lambda pat: (
            sorted(list(links.keys())) if pat == "/etc/nginx/sites-enabled/*" else []
        ),
    )

    calls: list[str] = []

    class Policy:
        def deny_reason(self, path: str):
            return None

        def deny_reason_link(self, path: str):
            calls.append(path)
            if path.endswith("/default"):
                return "denied_path"
            return None

    state_path = h.harvest(str(bundle), policy=Policy())
    st = json.loads(Path(state_path).read_text(encoding="utf-8"))

    svc = next(s for s in st["roles"]["services"] if s["role_name"] == "nginx")
    managed_links = svc.get("managed_links") or []
    excluded = svc.get("excluded") or []

    assert any(p.endswith("/default") for p in calls)
    assert any(p.endswith("/ok") for p in calls)
    assert {ml["path"] for ml in managed_links} == {"/etc/nginx/sites-enabled/ok"}
    assert {ex["path"] for ex in excluded} == {"/etc/nginx/sites-enabled/default"}
    assert (
        next(ex["reason"] for ex in excluded if ex["path"].endswith("/default"))
        == "denied_path"
    )


def test_harvest_captures_apache2_enabled_symlinks(monkeypatch, tmp_path: Path):
    bundle = tmp_path / "bundle"
    _base_monkeypatches(monkeypatch, unit="apache2.service")

    dirs = {
        "/etc",
        "/etc/apache2/conf-enabled",
        "/etc/apache2/mods-enabled",
        "/etc/apache2/sites-enabled",
    }
    links = {
        "/etc/apache2/sites-enabled/000-default.conf": "../sites-available/000-default.conf",
        "/etc/apache2/mods-enabled/rewrite.load": "../mods-available/rewrite.load",
        "/etc/apache2/conf-enabled/security.conf": "../conf-available/security.conf",
    }

    monkeypatch.setattr(h.os.path, "isdir", lambda p: p in dirs)
    monkeypatch.setattr(h.os.path, "islink", lambda p: p in links)
    monkeypatch.setattr(h.os, "readlink", lambda p: links[p])

    def fake_glob(pat: str):
        if pat == "/etc/apache2/sites-enabled/*":
            return ["/etc/apache2/sites-enabled/000-default.conf"]
        if pat == "/etc/apache2/mods-enabled/*":
            return ["/etc/apache2/mods-enabled/rewrite.load"]
        if pat == "/etc/apache2/conf-enabled/*":
            return ["/etc/apache2/conf-enabled/security.conf"]
        return []

    monkeypatch.setattr(h.glob, "glob", fake_glob)

    state_path = h.harvest(str(bundle), policy=AllowAllPolicy())
    st = json.loads(Path(state_path).read_text(encoding="utf-8"))

    svc = next(s for s in st["roles"]["services"] if s["role_name"] == "apache2")
    managed_links = svc.get("managed_links") or []
    assert {ml["path"] for ml in managed_links} == set(links.keys())
    assert {ml["target"] for ml in managed_links} == set(links.values())
    assert all(ml["reason"] == "enabled_symlink" for ml in managed_links)
