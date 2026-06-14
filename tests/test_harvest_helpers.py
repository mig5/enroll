from __future__ import annotations

import os
from pathlib import Path

import enroll.harvest as h


def test_iter_matching_files_skips_symlinks_and_walks_dirs(monkeypatch, tmp_path: Path):
    # Layout:
    #   root/real.txt (file)
    #   root/sub/nested.txt
    #   root/link -> ... (ignored)
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "real.txt").write_text("a", encoding="utf-8")
    (root / "sub" / "nested.txt").write_text("b", encoding="utf-8")

    paths = {
        str(root): "dir",
        str(root / "real.txt"): "file",
        str(root / "sub"): "dir",
        str(root / "sub" / "nested.txt"): "file",
        str(root / "link"): "link",
    }

    monkeypatch.setattr(h.glob, "glob", lambda spec: [str(root), str(root / "link")])
    monkeypatch.setattr(h.os.path, "islink", lambda p: paths.get(p) == "link")
    monkeypatch.setattr(h.os.path, "isfile", lambda p: paths.get(p) == "file")
    monkeypatch.setattr(h.os.path, "isdir", lambda p: paths.get(p) == "dir")
    monkeypatch.setattr(
        h.os,
        "walk",
        lambda p: [
            (str(root), ["sub"], ["real.txt", "link"]),
            (str(root / "sub"), [], ["nested.txt"]),
        ],
    )

    out = h._iter_matching_files("/whatever/*", cap=100)
    assert str(root / "real.txt") in out
    assert str(root / "sub" / "nested.txt") in out
    assert str(root / "link") not in out


def test_parse_apt_signed_by_extracts_keyrings(tmp_path: Path):
    f1 = tmp_path / "a.list"
    f1.write_text(
        "deb [signed-by=/usr/share/keyrings/foo.gpg] https://example.invalid stable main\n",
        encoding="utf-8",
    )
    f2 = tmp_path / "b.sources"
    f2.write_text(
        "Types: deb\nSigned-By: /etc/apt/keyrings/bar.gpg, /usr/share/keyrings/baz.gpg\n",
        encoding="utf-8",
    )
    f3 = tmp_path / "c.sources"
    f3.write_text("Signed-By: | /bin/echo nope\n", encoding="utf-8")

    out = h._parse_apt_signed_by([str(f1), str(f2), str(f3)])
    assert "/usr/share/keyrings/foo.gpg" in out
    assert "/etc/apt/keyrings/bar.gpg" in out
    assert "/usr/share/keyrings/baz.gpg" in out


def test_iter_apt_capture_paths_includes_signed_by_keyring(monkeypatch):
    # Simulate:
    #   /etc/apt/apt.conf.d/00test
    #   /etc/apt/sources.list.d/test.list (signed-by outside /etc/apt)
    #   /usr/share/keyrings/ext.gpg
    files = {
        "/etc/apt/apt.conf.d/00test": "file",
        "/etc/apt/sources.list.d/test.list": "file",
        "/usr/share/keyrings/ext.gpg": "file",
    }

    monkeypatch.setattr(h.os.path, "isdir", lambda p: p in {"/etc/apt"})
    monkeypatch.setattr(
        h.os,
        "walk",
        lambda root: [
            ("/etc/apt", ["apt.conf.d", "sources.list.d"], []),
            ("/etc/apt/apt.conf.d", [], ["00test"]),
            ("/etc/apt/sources.list.d", [], ["test.list"]),
        ],
    )
    monkeypatch.setattr(h.os.path, "islink", lambda p: False)
    monkeypatch.setattr(h.os.path, "isfile", lambda p: files.get(p) == "file")

    # Only treat the sources glob as having a hit.
    def fake_iter_matching(spec: str, cap: int = 10000):
        if spec == "/etc/apt/sources.list.d/*.list":
            return ["/etc/apt/sources.list.d/test.list"]
        return []

    monkeypatch.setattr(h, "_iter_matching_files", fake_iter_matching)

    # Provide file contents for the sources file.
    real_open = open

    def fake_open(path, *a, **k):
        if path == "/etc/apt/sources.list.d/test.list":
            return real_open(os.devnull, "r", encoding="utf-8")  # placeholder
        return real_open(path, *a, **k)

    # Easier: patch _parse_apt_signed_by directly to avoid filesystem reads.
    monkeypatch.setattr(
        h, "_parse_apt_signed_by", lambda sfs: {"/usr/share/keyrings/ext.gpg"}
    )

    out = h._iter_apt_capture_paths()
    paths = {p for p, _r in out}
    reasons = {p: r for p, r in out}
    assert "/etc/apt/apt.conf.d/00test" in paths
    assert "/etc/apt/sources.list.d/test.list" in paths
    assert "/usr/share/keyrings/ext.gpg" in paths
    assert reasons["/usr/share/keyrings/ext.gpg"] == "apt_signed_by_keyring"


def test_iter_dnf_capture_paths(monkeypatch):
    files = {
        "/etc/dnf/dnf.conf": "file",
        "/etc/yum/yum.conf": "file",
        "/etc/yum.conf": "file",
        "/etc/yum.repos.d/test.repo": "file",
        "/etc/pki/rpm-gpg/RPM-GPG-KEY": "file",
    }

    def isdir(p):
        return p in {"/etc/dnf", "/etc/yum", "/etc/yum.repos.d", "/etc/pki/rpm-gpg"}

    def walk(root):
        if root == "/etc/dnf":
            return [("/etc/dnf", [], ["dnf.conf"])]
        if root == "/etc/yum":
            return [("/etc/yum", [], ["yum.conf"])]
        if root == "/etc/pki/rpm-gpg":
            return [("/etc/pki/rpm-gpg", [], ["RPM-GPG-KEY"])]
        return []

    monkeypatch.setattr(h.os.path, "isdir", isdir)
    monkeypatch.setattr(h.os, "walk", walk)
    monkeypatch.setattr(h.os.path, "islink", lambda p: False)
    monkeypatch.setattr(h.os.path, "isfile", lambda p: files.get(p) == "file")
    monkeypatch.setattr(
        h,
        "_iter_matching_files",
        lambda spec, cap=10000: (
            ["/etc/yum.repos.d/test.repo"] if spec.endswith("*.repo") else []
        ),
    )

    out = h._iter_dnf_capture_paths()
    paths = {p for p, _r in out}
    assert "/etc/dnf/dnf.conf" in paths
    assert "/etc/yum/yum.conf" in paths
    assert "/etc/yum.conf" in paths
    assert "/etc/yum.repos.d/test.repo" in paths
    assert "/etc/pki/rpm-gpg/RPM-GPG-KEY" in paths


def test_iter_system_capture_paths_dedupes_first_reason(monkeypatch):
    monkeypatch.setattr(h, "_SYSTEM_CAPTURE_GLOBS", [("/a", "r1"), ("/b", "r2")])
    monkeypatch.setattr(
        h,
        "_iter_matching_files",
        lambda spec, cap=10000: ["/dup"] if spec in {"/a", "/b"} else [],
    )
    out = h._iter_system_capture_paths()
    assert out == [("/dup", "r1")]


def test_ipset_and_iptables_state_helpers(tmp_path: Path):
    ipset_save = """create blocklist hash:ip family inet hashsize 1024 maxelem 65536
add blocklist 203.0.113.10
create nets hash:net family inet
"""
    assert h._ipset_save_has_state(ipset_save)
    assert h._parse_ipset_set_names(ipset_save) == ["blocklist", "nets"]
    assert not h._ipset_save_has_state("# empty\n")

    empty_iptables = """*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
"""
    assert not h._iptables_save_has_state(empty_iptables)

    native_rule = empty_iptables.replace(
        "COMMIT", "-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT"
    )
    assert h._iptables_save_has_state(native_rule)

    changed_policy = empty_iptables.replace(":INPUT ACCEPT", ":INPUT DROP")
    assert h._iptables_save_has_state(changed_policy)


def test_collect_firewall_runtime_snapshot_writes_generated_artifacts(
    monkeypatch, tmp_path: Path
):
    outputs = {
        "ipset_save": (
            "create blocklist hash:ip family inet\nadd blocklist 203.0.113.10\n",
            None,
        ),
        "iptables_v4_save": (
            "*filter\n:INPUT DROP [0:0]\n-A INPUT -m set --match-set blocklist src -j DROP\nCOMMIT\n",
            None,
        ),
        "iptables_v6_save": ("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n", None),
    }

    def fake_run(command_key, *, timeout=10):
        return outputs[command_key]

    monkeypatch.setattr(h, "_run_capture_command", fake_run)

    snap = h._collect_firewall_runtime_snapshot(str(tmp_path))
    assert snap.role_name == "firewall_runtime"
    assert snap.packages == ["ipset", "iptables"]
    assert snap.ipset_save == "firewall/ipset.save"
    assert snap.ipset_sets == ["blocklist"]
    assert snap.iptables_v4_save == "firewall/iptables.v4"
    assert snap.iptables_v6_save is None

    assert (
        (tmp_path / "artifacts" / "firewall_runtime" / "firewall" / "ipset.save")
        .read_text(encoding="utf-8")
        .startswith("create blocklist")
    )
    assert (
        (tmp_path / "artifacts" / "firewall_runtime" / "firewall" / "iptables.v4")
        .read_text(encoding="utf-8")
        .startswith("*filter")
    )


def test_collect_firewall_runtime_snapshot_is_per_family_fallback(
    monkeypatch, tmp_path: Path
):
    calls = []
    outputs = {
        "ipset_save": (
            "create blocklist hash:ip family inet\nadd blocklist 203.0.113.10\n",
            None,
        ),
        "iptables_v4_save": (
            "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n",
            None,
        ),
        "iptables_v6_save": (
            "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n",
            None,
        ),
    }

    def fake_run(command_key, *, timeout=10):
        calls.append(command_key)
        return outputs[command_key]

    monkeypatch.setattr(h, "_run_capture_command", fake_run)

    snap = h._collect_firewall_runtime_snapshot(
        str(tmp_path),
        persistent_ipset_files=["/etc/ipset.conf"],
        persistent_iptables_v4_files=["/etc/iptables/rules.v4"],
        persistent_iptables_v6_files=[],
    )

    assert "ipset_save" not in calls
    assert "iptables_v4_save" not in calls
    assert "iptables_v6_save" in calls
    assert snap.ipset_save is None
    assert snap.iptables_v4_save is None
    assert snap.iptables_v6_save == "firewall/iptables.v6"
    assert snap.packages == ["iptables"]
    assert any("persistent ipset configuration" in note for note in snap.notes)
    assert any("persistent IPv4 iptables configuration" in note for note in snap.notes)
    assert not (
        tmp_path / "artifacts" / "firewall_runtime" / "firewall" / "ipset.save"
    ).exists()
    assert not (
        tmp_path / "artifacts" / "firewall_runtime" / "firewall" / "iptables.v4"
    ).exists()
    assert (
        tmp_path / "artifacts" / "firewall_runtime" / "firewall" / "iptables.v6"
    ).exists()


def test_package_role_names_do_not_collide_with_singleton_roles():
    from enroll.harvest import _role_name_from_pkg

    assert _role_name_from_pkg("flatpak") == "package_flatpak"
    assert _role_name_from_pkg("snap") == "package_snap"
    assert _role_name_from_pkg("users") == "package_users"
    assert _role_name_from_pkg("nginx") == "nginx"


def test_service_role_names_do_not_collide_with_singleton_roles():
    from enroll.harvest import _role_name_from_unit

    assert _role_name_from_unit("flatpak.service") == "service_flatpak"
    assert _role_name_from_unit("users.service") == "service_users"
    assert _role_name_from_unit("nginx.service") == "nginx"
