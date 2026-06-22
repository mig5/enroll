from __future__ import annotations

import argparse
import configparser
import os
import types
import textwrap
from pathlib import Path


def test_discover_config_path_precedence(tmp_path: Path, monkeypatch):
    """_discover_config_path: --config > ENROLL_CONFIG > XDG."""
    from enroll.cli import _discover_config_path

    cfg1 = tmp_path / "one.ini"
    cfg1.write_text("[enroll]\n", encoding="utf-8")

    # Explicit --config should win.
    assert _discover_config_path(["--config", str(cfg1)]) == cfg1

    # --no-config disables config loading.
    assert _discover_config_path(["--no-config", "--config", str(cfg1)]) is None

    monkeypatch.chdir(tmp_path)

    cfg2 = tmp_path / "two.ini"
    cfg2.write_text("[enroll]\n", encoding="utf-8")
    monkeypatch.setenv("ENROLL_CONFIG", str(cfg2))
    assert _discover_config_path([]) == cfg2

    # Local ./enroll.ini is ignored unless passed explicitly.
    monkeypatch.delenv("ENROLL_CONFIG", raising=False)
    local = tmp_path / "enroll.ini"
    local.write_text("[enroll]\n", encoding="utf-8")
    assert _discover_config_path([]) is None
    assert _discover_config_path(["--config", str(local)]) == local

    # XDG fallback.
    xdg = tmp_path / "xdg"
    cfg3 = xdg / "enroll" / "enroll.ini"
    cfg3.parent.mkdir(parents=True)
    cfg3.write_text("[enroll]\n", encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    assert _discover_config_path([]) == cfg3


def test_config_value_parsing_and_list_splitting():
    from enroll.cli import _parse_bool, _split_list_value

    assert _parse_bool("1") is True
    assert _parse_bool("yes") is True
    assert _parse_bool("false") is False

    assert _parse_bool("maybe") is None

    assert _split_list_value("a,b , c") == ["a", "b", "c"]
    # When newlines are present, we split on lines (not commas within a line).
    assert _split_list_value("a,b\nc") == ["a,b", "c"]
    assert _split_list_value("a\n\n b\n") == ["a", "b"]
    assert _split_list_value("   ") == []


def test_section_to_argv_handles_types_and_unknown_keys(capsys):
    from enroll.cli import _section_to_argv

    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--dangerous", action="store_true")
    p.add_argument("--no-color", dest="color", action="store_false")
    p.add_argument("--include-path", dest="include_path", action="append")
    p.add_argument("-v", action="count", default=0)
    p.add_argument("--out")

    cfg = configparser.ConfigParser()
    cfg.read_dict(
        {
            "harvest": {
                "dangerous": "true",
                # Keys are matched by argparse dest; store_false actions still use dest.
                "color": "false",
                "include-path": "a,b,c",
                "v": "2",
                "out": "/tmp/bundle",
                "unknown": "ignored",
            }
        }
    )

    argv = _section_to_argv(p, cfg, "harvest")

    # Boolean store_true.
    assert "--dangerous" in argv

    # Boolean store_false: include the flag only when config wants False.
    assert "--no-color" in argv

    # Append: split lists and add one flag per item.
    assert argv.count("--include-path") == 3
    assert "a" in argv and "b" in argv and "c" in argv

    # Count: repeats.
    assert argv.count("-v") == 2

    # Scalar.
    assert "--out" in argv and "/tmp/bundle" in argv

    err = capsys.readouterr().err
    assert "unknown option" in err


def test_inject_config_argv_inserts_global_and_subcommand(tmp_path: Path, capsys):
    from enroll.cli import _inject_config_argv

    cfg = tmp_path / "enroll.ini"
    cfg.write_text(
        textwrap.dedent(
            """
            [enroll]
            dangerous = true

            [harvest]
            include-path = /etc/foo
            unknown = 1
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    root = argparse.ArgumentParser(add_help=False)
    root.add_argument("--dangerous", action="store_true")

    harvest_p = argparse.ArgumentParser(add_help=False)
    harvest_p.add_argument("--include-path", dest="include_path", action="append")

    argv = _inject_config_argv(
        ["harvest", "--out", "x"],
        cfg_path=cfg,
        root_parser=root,
        subparsers={"harvest": harvest_p},
    )

    # Global tokens should appear before the subcommand.
    assert argv[0] == "--dangerous"
    assert argv[1] == "harvest"

    # Subcommand tokens should appear right after the subcommand.
    assert argv[2:4] == ["--include-path", "/etc/foo"]

    # Unknown option should have produced a warning.
    assert "unknown option" in capsys.readouterr().err


def test_resolve_sops_out_file(tmp_path: Path, monkeypatch):
    from enroll import cli

    # Make a predictable cache dir for the default case.
    fake_cache = types.SimpleNamespace(dir=tmp_path / "cache")
    fake_cache.dir.mkdir(parents=True)
    monkeypatch.setattr(cli, "new_harvest_cache_dir", lambda hint=None: fake_cache)

    # If out is a directory, use it directly.
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    # The output filename is fixed; hint is only used when creating a cache dir.
    assert (
        cli._resolve_sops_out_file(out=out_dir, hint="bundle.tar.gz")
        == out_dir / "harvest.tar.gz.sops"
    )

    # If out is a file path, keep it.
    out_file = tmp_path / "x.sops"
    assert cli._resolve_sops_out_file(out=out_file, hint="bundle.tar.gz") == out_file

    # None uses the cache dir, and the name is fixed.
    assert (
        cli._resolve_sops_out_file(out=None, hint="bundle.tar.gz")
        == fake_cache.dir / "harvest.tar.gz.sops"
    )


def test_unsafe_root_path_reasons_flags_current_and_writable_dirs(tmp_path: Path):
    from enroll.cli import _unsafe_root_path_reasons

    group_writable = tmp_path / "group-writable"
    world_writable = tmp_path / "world-writable"
    safe = tmp_path / "safe"
    group_writable.mkdir()
    world_writable.mkdir()
    safe.mkdir()
    group_writable.chmod(0o775)
    world_writable.chmod(0o777)
    safe.chmod(0o755)

    reasons = _unsafe_root_path_reasons(
        os.pathsep.join(
            [
                "",
                ".",
                "relative-bin",
                str(group_writable),
                str(world_writable),
                str(safe),
            ]
        )
    )

    text = "\n".join(reasons)
    assert "<empty>: empty PATH entry" in text
    assert "'.' resolves" in text
    assert "relative-bin: relative PATH entry" in text
    assert f"{group_writable}: directory is group-writable" in text
    assert f"{world_writable}: directory is world-writable" in text
    assert str(safe) not in text


def test_confirm_root_path_safety_refuses_noninteractive(monkeypatch):
    from enroll import cli

    monkeypatch.setattr(cli, "_is_effective_root", lambda: True)
    monkeypatch.setattr(
        cli,
        "_unsafe_root_path_reasons",
        lambda path_value=None: [".: '.' resolves to the current directory"],
    )
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)

    try:
        cli._confirm_root_path_safety(force=False)
    except SystemExit as e:
        assert "--assume-safe-path" in str(e)
    else:  # pragma: no cover - defensive assertion path
        raise AssertionError("expected SystemExit")


def test_confirm_root_path_safety_force_skips_prompt(monkeypatch):
    from enroll import cli

    monkeypatch.setattr(cli, "_is_effective_root", lambda: True)
    monkeypatch.setattr(
        cli,
        "_unsafe_root_path_reasons",
        lambda path_value=None: [".: '.' resolves to the current directory"],
    )

    cli._confirm_root_path_safety(force=True)
