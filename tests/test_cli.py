import sys

import enroll.cli as cli


def test_cli_harvest_subcommand_calls_harvest(monkeypatch, capsys, tmp_path):
    called = {}

    def fake_harvest(out: str):
        called["out"] = out
        return str(tmp_path / "state.json")

    monkeypatch.setattr(cli, "harvest", fake_harvest)
    monkeypatch.setattr(sys, "argv", ["enroll", "harvest", "--out", str(tmp_path)])

    cli.main()
    assert called["out"] == str(tmp_path)
    captured = capsys.readouterr()
    assert str(tmp_path / "state.json") in captured.out


def test_cli_manifest_subcommand_calls_manifest(monkeypatch, tmp_path):
    called = {}

    def fake_manifest(harvest_dir: str, out_dir: str):
        called["harvest"] = harvest_dir
        called["out"] = out_dir

    monkeypatch.setattr(cli, "manifest", fake_manifest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "manifest",
            "--harvest",
            str(tmp_path / "bundle"),
            "--out",
            str(tmp_path / "ansible"),
        ],
    )

    cli.main()
    assert called["harvest"] == str(tmp_path / "bundle")
    assert called["out"] == str(tmp_path / "ansible")


def test_cli_enroll_subcommand_runs_harvest_then_manifest(monkeypatch, tmp_path):
    calls = []

    def fake_harvest(bundle_dir: str):
        calls.append(("harvest", bundle_dir))
        return str(tmp_path / "bundle" / "state.json")

    def fake_manifest(bundle_dir: str, out_dir: str):
        calls.append(("manifest", bundle_dir, out_dir))

    monkeypatch.setattr(cli, "harvest", fake_harvest)
    monkeypatch.setattr(cli, "manifest", fake_manifest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "enroll",
            "--harvest",
            str(tmp_path / "bundle"),
            "--out",
            str(tmp_path / "ansible"),
        ],
    )

    cli.main()
    assert calls == [
        ("harvest", str(tmp_path / "bundle")),
        ("manifest", str(tmp_path / "bundle"), str(tmp_path / "ansible")),
    ]
