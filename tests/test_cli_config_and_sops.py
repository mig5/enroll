from __future__ import annotations

import argparse
import configparser
import tarfile
from pathlib import Path


def test_discover_config_path_precedence(monkeypatch, tmp_path: Path):
    from enroll.cli import _discover_config_path

    cfg = tmp_path / "cfg.ini"
    cfg.write_text("[enroll]\n", encoding="utf-8")

    # --no-config always wins
    monkeypatch.setenv("ENROLL_CONFIG", str(cfg))
    assert _discover_config_path(["--no-config", "harvest"]) is None

    # explicit --config wins
    assert _discover_config_path(["--config", str(cfg), "harvest"]) == cfg

    # env var used when present
    assert _discover_config_path(["harvest"]) == cfg


def test_discover_config_path_ignores_local_and_finds_xdg(monkeypatch, tmp_path: Path):
    from enroll.cli import _discover_config_path

    # local files in cwd are deliberately ignored unless passed via --config
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    local = cwd / "enroll.ini"
    local.write_text("[enroll]\n", encoding="utf-8")

    monkeypatch.chdir(cwd)
    monkeypatch.delenv("ENROLL_CONFIG", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    assert _discover_config_path(["harvest"]) is None
    assert _discover_config_path(["--config", str(local), "harvest"]) == local

    # xdg config fallback
    monkeypatch.chdir(tmp_path)
    xdg = tmp_path / "xdg"
    (xdg / "enroll").mkdir(parents=True)
    xcfg = xdg / "enroll" / "enroll.ini"
    xcfg.write_text("[enroll]\n", encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    assert _discover_config_path(["harvest"]) == xcfg


def test_section_to_argv_supports_bool_append_count_and_unknown(monkeypatch, capsys):
    from enroll.cli import _section_to_argv

    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--flag", action="store_true")
    ap.add_argument("--no-flag", action="store_false", dest="flag2")
    ap.add_argument("--item", action="append", default=[])
    ap.add_argument("-v", action="count", default=0)

    cfg = configparser.ConfigParser()
    cfg.read_dict(
        {
            "enroll": {
                "flag": "true",
                "no_flag": "false",
                "item": "a,b",
                "v": "2",
                "unknown_key": "zzz",
            }
        }
    )

    argv = _section_to_argv(ap, cfg, "enroll")

    # bools set
    assert "--flag" in argv
    assert "--no-flag" in argv

    # append expanded
    assert argv.count("--item") == 2
    assert "a" in argv and "b" in argv

    # count flag expanded
    assert argv.count("-v") == 2

    # unknown key prints warning
    err = capsys.readouterr().err
    assert "unknown option" in err


def test_inject_config_argv_inserts_global_and_command_tokens(tmp_path: Path):
    from enroll.cli import _inject_config_argv

    root = argparse.ArgumentParser(add_help=False)
    root.add_argument("--root-flag", action="store_true")
    sub = root.add_subparsers(dest="cmd", required=True)
    p_h = sub.add_parser("harvest", add_help=False)
    p_h.add_argument("--dangerous", action="store_true")
    p_h.add_argument("--include-path", action="append", default=[])

    cfg_path = tmp_path / "enroll.ini"
    cfg_path.write_text(
        """[enroll]
root-flag = true

[harvest]
dangerous = true
include-path = /etc/one,/etc/two
""",
        encoding="utf-8",
    )

    argv = ["harvest", "--include-path", "/etc/cli"]
    injected = _inject_config_argv(
        argv,
        cfg_path=cfg_path,
        root_parser=root,
        subparsers={"harvest": p_h},
    )

    # global inserted before cmd, subcommand tokens right after cmd
    assert injected[:2] == ["--root-flag", "harvest"]
    # include-path from config inserted before CLI include-path (CLI wins later if duplicates)
    joined = " ".join(injected)
    assert "--include-path /etc/one" in joined
    assert "--include-path /etc/cli" in joined


def test_resolve_sops_out_file_and_encrypt_path(monkeypatch, tmp_path: Path):
    from enroll import cli

    # directory output should yield harvest.tar.gz.sops inside
    out_dir = tmp_path / "o"
    out_dir.mkdir()
    assert (
        cli._resolve_sops_out_file(str(out_dir), hint="h").name == "harvest.tar.gz.sops"
    )

    # file-like output retained
    out_file = tmp_path / "x.sops"
    assert cli._resolve_sops_out_file(str(out_file), hint="h") == out_file

    # None uses cache dir
    class HC:
        def __init__(self, d: Path):
            self.dir = d

    monkeypatch.setattr(
        cli, "new_harvest_cache_dir", lambda hint: HC(tmp_path / "cache")
    )
    p = cli._resolve_sops_out_file(None, hint="h")
    assert str(p).endswith("harvest.tar.gz.sops")

    # Cover _tar_dir_to quickly (writes a tarball)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "state.json").write_text("{}", encoding="utf-8")
    tar_path = tmp_path / "b.tar.gz"
    cli._tar_dir_to(bundle, tar_path)
    assert tar_path.exists()
    with tarfile.open(tar_path, "r:gz") as tf:
        names = tf.getnames()
    assert "state.json" in names or "./state.json" in names


def test_encrypt_harvest_dir_to_sops_cleans_up_tmp_tgz(monkeypatch, tmp_path: Path):
    from enroll.cli import _encrypt_harvest_dir_to_sops

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "state.json").write_text("{}", encoding="utf-8")
    out_file = tmp_path / "out.sops"

    seen = {}

    def fake_encrypt(src: Path, dst: Path, pgp_fingerprints, mode):  # noqa: ARG001
        # write something so we can see output created
        seen["src"] = src
        dst.write_bytes(b"enc")

    monkeypatch.setattr("enroll.cli.encrypt_file_binary", fake_encrypt)

    # Make os.unlink raise FileNotFoundError to hit the except branch in finally.
    monkeypatch.setattr(
        "enroll.cli.os.unlink", lambda p: (_ for _ in ()).throw(FileNotFoundError())
    )

    res = _encrypt_harvest_dir_to_sops(bundle, out_file, fps=["ABC"])
    assert res == out_file
    assert out_file.read_bytes() == b"enc"
