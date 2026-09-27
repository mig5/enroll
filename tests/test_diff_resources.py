import json

import pytest

from enroll.diff import compare_harvests, format_report


@pytest.mark.parametrize(
    "kind",
    [
        "dnf_config",
        "firewall_runtime",
        "managed_links",
        "managed_dirs",
        "flatpak",
        "snap",
        "container_images",
    ],
)
def test_diff_reports_previously_omitted_resources(tmp_path, kind):
    for number, label in enumerate(("old", "new")):
        root = tmp_path / label
        root.mkdir()
        snapshot = {}
        role = kind
        if kind in ("dnf_config", "firewall_runtime"):
            if kind == "dnf_config":
                snapshot["managed_files"] = [
                    {"path": "/etc/dnf/dnf.conf", "src_rel": "config"}
                ]
            else:
                snapshot["iptables_v4_save"] = "config"
            artifact = root / "artifacts" / role / "config"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(str(number))
        elif kind in ("managed_links", "managed_dirs"):
            role = "etc_custom"
            snapshot[kind] = (
                [{"path": "/etc/example", "target": str(number)}]
                if kind == "managed_links"
                else [{"path": "/etc/example", "mode": ["0700", "0777"][number]}]
            )
        else:
            field = {
                "flatpak": "system_flatpaks",
                "snap": "system_snaps",
                "container_images": "images",
            }[kind]
            snapshot[field] = [{"name": str(number)}]
        (root / "state.json").write_text(json.dumps({"roles": {role: snapshot}}))
    report, changed = compare_harvests(str(tmp_path / "old"), str(tmp_path / "new"))
    assert changed
    for fmt in ("text", "markdown", "json"):
        assert "No differences detected" not in format_report(report, fmt=fmt)
    if kind in ("dnf_config", "firewall_runtime", "managed_links", "managed_dirs"):
        _, changed = compare_harvests(
            str(tmp_path / "old"), str(tmp_path / "new"), exclude_paths=["re:^/etc/"]
        )
        assert not changed
