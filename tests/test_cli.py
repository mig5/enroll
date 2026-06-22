from __future__ import annotations
import sys

import pytest
import enroll.cli as cli

from pathlib import Path

from enroll.remote import RemoteSudoPasswordRequired
from enroll.sopsutil import SopsError


def test_cli_harvest_subcommand_calls_harvest(monkeypatch, capsys, tmp_path):
    called = {}

    def fake_harvest(
        out: str,
        dangerous: bool = False,
        include_paths=None,
        exclude_paths=None,
        **_kwargs,
    ):
        called["out"] = out
        called["dangerous"] = dangerous
        called["include_paths"] = include_paths or []
        called["exclude_paths"] = exclude_paths or []
        return str(tmp_path / "state.json")

    monkeypatch.setattr(cli, "harvest", fake_harvest)
    monkeypatch.setattr(sys, "argv", ["enroll", "harvest", "--out", str(tmp_path)])

    cli.main()
    assert called["out"] == str(tmp_path)
    assert called["dangerous"] is False
    assert called["include_paths"] == []
    assert called["exclude_paths"] == []
    captured = capsys.readouterr()
    assert str(tmp_path / "state.json") in captured.out


def test_cli_manifest_subcommand_calls_manifest(monkeypatch, tmp_path):
    called = {}

    def fake_manifest(harvest_dir: str, out_dir: str, **kwargs):
        called["harvest"] = harvest_dir
        called["out"] = out_dir
        # Common manifest args should be passed through by the CLI.
        called["fqdn"] = kwargs.get("fqdn")
        called["jinjaturtle"] = kwargs.get("jinjaturtle")
        called["no_common_roles"] = kwargs.get("no_common_roles")
        called["target"] = kwargs.get("target")

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
    assert called["fqdn"] is None
    assert called["jinjaturtle"] == "auto"
    assert called["no_common_roles"] is False
    assert called["target"] == "ansible"


def test_cli_force_unsafe_path_before_subcommand_reaches_guard(monkeypatch, tmp_path):
    seen = {}

    def fake_confirm(*, force: bool = False) -> None:
        seen["force"] = force

    def fake_manifest(_harvest_dir: str, _out_dir: str, **_kwargs):
        return None

    monkeypatch.setattr(cli, "_confirm_root_path_safety", fake_confirm)
    monkeypatch.setattr(cli, "manifest", fake_manifest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "--assume-safe-path",
            "manifest",
            "--harvest",
            str(tmp_path / "bundle"),
            "--out",
            str(tmp_path / "ansible"),
        ],
    )

    cli.main()
    assert seen["force"] is True


def test_cli_force_unsafe_path_after_subcommand_reaches_guard(monkeypatch, tmp_path):
    seen = {}

    def fake_confirm(*, force: bool = False) -> None:
        seen["force"] = force

    def fake_manifest(_harvest_dir: str, _out_dir: str, **_kwargs):
        return None

    monkeypatch.setattr(cli, "_confirm_root_path_safety", fake_confirm)
    monkeypatch.setattr(cli, "manifest", fake_manifest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "manifest",
            "--assume-safe-path",
            "--harvest",
            str(tmp_path / "bundle"),
            "--out",
            str(tmp_path / "ansible"),
        ],
    )

    cli.main()
    assert seen["force"] is True


def test_cli_manifest_target_puppet_is_forwarded(monkeypatch, tmp_path):
    called = {}

    def fake_manifest(harvest_dir: str, out_dir: str, **kwargs):
        called["harvest"] = harvest_dir
        called["out"] = out_dir
        called["target"] = kwargs.get("target")

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
            str(tmp_path / "puppet"),
            "--target",
            "puppet",
        ],
    )

    cli.main()
    assert called["harvest"] == str(tmp_path / "bundle")
    assert called["out"] == str(tmp_path / "puppet")
    assert called["target"] == "puppet"


def test_cli_manifest_no_common_roles_is_forwarded(monkeypatch, tmp_path):
    called = {}

    def fake_manifest(harvest_dir: str, out_dir: str, **kwargs):
        called["harvest"] = harvest_dir
        called["out"] = out_dir
        called["no_common_roles"] = kwargs.get("no_common_roles")

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
            "--no-common-roles",
        ],
    )

    cli.main()
    assert called["harvest"] == str(tmp_path / "bundle")
    assert called["out"] == str(tmp_path / "ansible")
    assert called["no_common_roles"] is True


def test_cli_enroll_subcommand_runs_harvest_then_manifest(monkeypatch, tmp_path):
    calls = []

    def fake_harvest(
        bundle_dir: str,
        dangerous: bool = False,
        include_paths=None,
        exclude_paths=None,
        **_kwargs,
    ):
        calls.append(
            ("harvest", bundle_dir, dangerous, include_paths or [], exclude_paths or [])
        )
        return str(tmp_path / "bundle" / "state.json")

    def fake_manifest(bundle_dir: str, out_dir: str, **kwargs):
        calls.append(
            (
                "manifest",
                bundle_dir,
                out_dir,
                kwargs.get("fqdn"),
                kwargs.get("jinjaturtle"),
            )
        )

    monkeypatch.setattr(cli, "harvest", fake_harvest)
    monkeypatch.setattr(cli, "manifest", fake_manifest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "single-shot",
            "--harvest",
            str(tmp_path / "bundle"),
            "--out",
            str(tmp_path / "ansible"),
        ],
    )

    cli.main()
    assert calls == [
        ("harvest", str(tmp_path / "bundle"), False, [], []),
        ("manifest", str(tmp_path / "bundle"), str(tmp_path / "ansible"), None, "auto"),
    ]


def test_cli_harvest_dangerous_flag_is_forwarded(monkeypatch, tmp_path):
    called = {}

    def fake_harvest(
        out: str,
        dangerous: bool = False,
        include_paths=None,
        exclude_paths=None,
        **_kwargs,
    ):
        called["out"] = out
        called["dangerous"] = dangerous
        called["include_paths"] = include_paths or []
        called["exclude_paths"] = exclude_paths or []
        return str(tmp_path / "state.json")

    monkeypatch.setattr(cli, "harvest", fake_harvest)
    monkeypatch.setattr(
        sys, "argv", ["enroll", "harvest", "--out", str(tmp_path), "--dangerous"]
    )

    cli.main()
    assert called["dangerous"] is True
    assert called["include_paths"] == []
    assert called["exclude_paths"] == []


def test_cli_harvest_remote_calls_remote_harvest_and_uses_cache_dir(
    monkeypatch, capsys, tmp_path
):
    from enroll.cache import HarvestCache

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    called = {}

    def fake_cache_dir(*, hint=None):
        called["hint"] = hint
        return HarvestCache(dir=cache_dir)

    def fake_remote_harvest(
        *,
        local_out_dir,
        remote_host,
        remote_port,
        remote_user,
        dangerous,
        no_sudo,
        include_paths=None,
        exclude_paths=None,
        **_kwargs,
    ):
        called.update(
            {
                "local_out_dir": local_out_dir,
                "remote_host": remote_host,
                "remote_port": remote_port,
                "remote_user": remote_user,
                "dangerous": dangerous,
                "no_sudo": no_sudo,
                "include_paths": include_paths or [],
                "exclude_paths": exclude_paths or [],
            }
        )
        return cache_dir / "state.json"

    monkeypatch.setattr(cli, "new_harvest_cache_dir", fake_cache_dir)
    monkeypatch.setattr(cli, "remote_harvest", fake_remote_harvest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "harvest",
            "--remote-host",
            "example.test",
            "--remote-user",
            "alice",
        ],
    )

    cli.main()
    out = capsys.readouterr().out
    assert str(cache_dir / "state.json") in out
    assert called["hint"] == "example.test"
    assert called["local_out_dir"] == cache_dir
    assert called["remote_host"] == "example.test"
    assert called["remote_port"] == 22
    assert called["remote_user"] == "alice"
    assert called["dangerous"] is False
    assert called["no_sudo"] is False
    assert called["include_paths"] == []
    assert called["exclude_paths"] == []


def test_cli_single_shot_remote_without_harvest_prints_state_path(
    monkeypatch, capsys, tmp_path
):
    from enroll.cache import HarvestCache

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    ansible_dir = tmp_path / "ansible"

    calls = []

    def fake_cache_dir(*, hint=None):
        return HarvestCache(dir=cache_dir)

    def fake_remote_harvest(**kwargs):
        calls.append(("remote_harvest", kwargs))
        return cache_dir / "state.json"

    def fake_manifest(harvest_dir: str, out_dir: str, **kwargs):
        calls.append(("manifest", harvest_dir, out_dir, kwargs.get("fqdn")))

    monkeypatch.setattr(cli, "new_harvest_cache_dir", fake_cache_dir)
    monkeypatch.setattr(cli, "remote_harvest", fake_remote_harvest)
    monkeypatch.setattr(cli, "manifest", fake_manifest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "single-shot",
            "--remote-host",
            "example.test",
            "--remote-user",
            "alice",
            "--out",
            str(ansible_dir),
            "--fqdn",
            "example.test",
        ],
    )

    cli.main()
    out = capsys.readouterr().out

    # It should print the derived state.json path for usability when --harvest
    # wasn't provided.
    assert str(cache_dir / "state.json") in out

    # And it should manifest using the cache dir.
    assert ("manifest", str(cache_dir), str(ansible_dir), "example.test") in calls


def test_cli_harvest_remote_ask_become_pass_prompts_and_passes_password(
    monkeypatch, tmp_path
):
    from enroll.cache import HarvestCache
    import enroll.remote as r

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    called = {}

    def fake_cache_dir(*, hint=None):
        return HarvestCache(dir=cache_dir)

    def fake__remote_harvest(*, sudo_password=None, **kwargs):
        called["sudo_password"] = sudo_password
        return cache_dir / "state.json"

    monkeypatch.setattr(cli, "new_harvest_cache_dir", fake_cache_dir)
    monkeypatch.setattr(r, "_remote_harvest", fake__remote_harvest)
    monkeypatch.setattr(r.getpass, "getpass", lambda _prompt="": "pw123")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "harvest",
            "--remote-host",
            "example.test",
            "--ask-become-pass",
        ],
    )

    cli.main()
    assert called["sudo_password"] == "pw123"


def test_cli_harvest_remote_password_required_fallback_prompts_and_retries(
    monkeypatch, tmp_path
):
    from enroll.cache import HarvestCache
    import enroll.remote as r

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    def fake_cache_dir(*, hint=None):
        return HarvestCache(dir=cache_dir)

    calls = []

    def fake__remote_harvest(*, sudo_password=None, **kwargs):
        calls.append(sudo_password)
        if sudo_password is None:
            raise r.RemoteSudoPasswordRequired("pw required")
        return cache_dir / "state.json"

    class _TTYStdin:
        def isatty(self):
            return True

    monkeypatch.setattr(cli, "new_harvest_cache_dir", fake_cache_dir)
    monkeypatch.setattr(r, "_remote_harvest", fake__remote_harvest)
    monkeypatch.setattr(r.getpass, "getpass", lambda _prompt="": "pw456")
    monkeypatch.setattr(sys, "stdin", _TTYStdin())

    monkeypatch.setattr(
        sys, "argv", ["enroll", "harvest", "--remote-host", "example.test"]
    )

    cli.main()
    assert calls == [None, "pw456"]


def test_cli_harvest_remote_password_required_noninteractive_errors(
    monkeypatch, tmp_path
):
    from enroll.cache import HarvestCache
    import enroll.remote as r

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    def fake_cache_dir(*, hint=None):
        return HarvestCache(dir=cache_dir)

    def fake__remote_harvest(*, sudo_password=None, **kwargs):
        raise r.RemoteSudoPasswordRequired("pw required")

    class _NoTTYStdin:
        def isatty(self):
            return False

    monkeypatch.setattr(cli, "new_harvest_cache_dir", fake_cache_dir)
    monkeypatch.setattr(r, "_remote_harvest", fake__remote_harvest)
    monkeypatch.setattr(sys, "stdin", _NoTTYStdin())

    monkeypatch.setattr(
        sys, "argv", ["enroll", "harvest", "--remote-host", "example.test"]
    )

    with pytest.raises(SystemExit) as e:
        cli.main()
    assert "--ask-become-pass" in str(e.value)


def test_cli_manifest_common_args(monkeypatch, tmp_path):
    """Ensure --fqdn and jinjaturtle mode flags are forwarded correctly."""

    called = {}

    def fake_manifest(harvest_dir: str, out_dir: str, **kwargs):
        called["harvest"] = harvest_dir
        called["out"] = out_dir
        called["fqdn"] = kwargs.get("fqdn")
        called["jinjaturtle"] = kwargs.get("jinjaturtle")

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
            "--fqdn",
            "example.test",
            "--no-jinjaturtle",
        ],
    )

    cli.main()
    assert called["fqdn"] == "example.test"
    assert called["jinjaturtle"] == "off"


def test_cli_explain_passes_args_and_writes_stdout(monkeypatch, capsys, tmp_path):
    called = {}

    def fake_explain_state(
        harvest: str,
        *,
        sops_mode: bool = False,
        fmt: str = "text",
        max_examples: int = 3,
    ):
        called["harvest"] = harvest
        called["sops_mode"] = sops_mode
        called["fmt"] = fmt
        called["max_examples"] = max_examples
        return "EXPLAINED\n"

    monkeypatch.setattr(cli, "explain_state", fake_explain_state)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "explain",
            "--sops",
            "--format",
            "json",
            "--max-examples",
            "7",
            str(tmp_path / "bundle" / "state.json"),
        ],
    )

    cli.main()
    out = capsys.readouterr().out
    assert out == "EXPLAINED\n"
    assert called["sops_mode"] is True
    assert called["fmt"] == "json"
    assert called["max_examples"] == 7


def test_discover_config_path_missing_config_value_returns_none(monkeypatch):
    # Covers the "--config" flag present with no value.
    monkeypatch.delenv("ENROLL_CONFIG", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    assert cli._discover_config_path(["--config"]) is None


def test_discover_config_path_defaults_to_home_config(monkeypatch, tmp_path: Path):
    # Covers the Path.home() / ".config" fallback.
    monkeypatch.delenv("ENROLL_CONFIG", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(cli.Path, "cwd", lambda: tmp_path)

    cp = tmp_path / ".config" / "enroll" / "enroll.ini"
    cp.parent.mkdir(parents=True)
    cp.write_text("[enroll]\n", encoding="utf-8")

    assert cli._discover_config_path(["harvest"]) == cp


def test_cli_harvest_local_sops_encrypts_and_prints_path(
    monkeypatch, tmp_path: Path, capsys
):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    calls: dict[str, object] = {}

    def fake_harvest(bundle_dir: str, **kwargs):
        calls["bundle"] = bundle_dir
        # Create a minimal state.json so tooling that expects it won't break.
        Path(bundle_dir).mkdir(parents=True, exist_ok=True)
        (Path(bundle_dir) / "state.json").write_text("{}", encoding="utf-8")
        return str(Path(bundle_dir) / "state.json")

    def fake_encrypt(bundle_dir: Path, out_file: Path, fps: list[str]):
        calls["encrypt"] = (bundle_dir, out_file, fps)
        out_file.write_text("encrypted", encoding="utf-8")
        return out_file

    monkeypatch.setattr(cli, "harvest", fake_harvest)
    monkeypatch.setattr(cli, "_encrypt_harvest_dir_to_sops", fake_encrypt)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "harvest",
            "--sops",
            "ABCDEF",
            "--out",
            str(out_dir),
        ],
    )
    cli.main()

    printed = capsys.readouterr().out.strip()
    assert printed.endswith("harvest.tar.gz.sops")
    assert Path(printed).exists()
    assert calls.get("encrypt")


def test_cli_harvest_remote_sops_encrypts_and_prints_path(
    monkeypatch, tmp_path: Path, capsys
):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    calls: dict[str, object] = {}

    def fake_remote_harvest(**kwargs):
        calls["remote"] = kwargs
        # Create a minimal state.json in the temp bundle.
        out = Path(kwargs["local_out_dir"]) / "state.json"
        out.write_text("{}", encoding="utf-8")
        return out

    def fake_encrypt(bundle_dir: Path, out_file: Path, fps: list[str]):
        calls["encrypt"] = (bundle_dir, out_file, fps)
        out_file.write_text("encrypted", encoding="utf-8")
        return out_file

    monkeypatch.setattr(cli, "remote_harvest", fake_remote_harvest)
    monkeypatch.setattr(cli, "_encrypt_harvest_dir_to_sops", fake_encrypt)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "harvest",
            "--remote-host",
            "example.com",
            "--remote-user",
            "root",
            "--sops",
            "ABCDEF",
            "--out",
            str(out_dir),
        ],
    )
    cli.main()

    printed = capsys.readouterr().out.strip()
    assert printed.endswith("harvest.tar.gz.sops")
    assert Path(printed).exists()
    assert calls.get("remote")
    assert calls.get("encrypt")


def test_cli_harvest_remote_password_required_exits_cleanly(monkeypatch):
    def boom(**kwargs):
        raise RemoteSudoPasswordRequired("pw required")

    monkeypatch.setattr(cli, "remote_harvest", boom)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "harvest",
            "--remote-host",
            "example.com",
            "--remote-user",
            "root",
        ],
    )
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert "--ask-become-pass" in str(e.value)


def test_cli_runtime_error_is_wrapped_as_user_friendly_system_exit(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("nope")

    monkeypatch.setattr(cli, "harvest", boom)
    monkeypatch.setattr(sys, "argv", ["enroll", "harvest", "--out", "/tmp/x"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert str(e.value) == "error: nope"


def test_cli_sops_error_is_wrapped_as_user_friendly_system_exit(monkeypatch):
    def boom(*args, **kwargs):
        raise SopsError("sops broke")

    monkeypatch.setattr(cli, "manifest", boom)
    monkeypatch.setattr(
        sys, "argv", ["enroll", "manifest", "--harvest", "/tmp/x", "--out", "/tmp/y"]
    )
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert str(e.value) == "error: sops broke"


def test_cli_diff_notifies_webhook_and_email_and_respects_exit_code(
    monkeypatch, capsys
):
    calls: dict[str, object] = {}

    def fake_compare(old, new, sops_mode=False, **kwargs):
        calls["compare"] = (old, new, sops_mode)
        return {"dummy": True}, True

    def fake_format(report, fmt="text"):
        calls.setdefault("format", []).append((report, fmt))
        return "REPORT\n"

    def fake_post(url, body, headers=None):
        calls["webhook"] = (url, body, headers)
        return 200, b"ok"

    def fake_email(**kwargs):
        calls["email"] = kwargs

    monkeypatch.setattr(cli, "compare_harvests", fake_compare)
    monkeypatch.setattr(cli, "format_report", fake_format)
    monkeypatch.setattr(cli, "post_webhook", fake_post)
    monkeypatch.setattr(cli, "send_email", fake_email)
    monkeypatch.setenv("SMTPPW", "secret")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "diff",
            "--old",
            "/tmp/old",
            "--new",
            "/tmp/new",
            "--webhook",
            "https://example.invalid/h",
            "--webhook-header",
            "X-Test: ok",
            "--email-to",
            "a@example.com",
            "--smtp-password-env",
            "SMTPPW",
            "--exit-code",
        ],
    )

    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2

    assert calls.get("compare")
    assert calls.get("webhook")
    assert calls.get("email")
    # No report printed when exiting via --exit-code? (we still render and print).
    _ = capsys.readouterr()


def test_cli_diff_webhook_http_error_raises_system_exit(monkeypatch):
    def fake_compare(old, new, sops_mode=False, **kwargs):
        return {"dummy": True}, True

    monkeypatch.setattr(cli, "compare_harvests", fake_compare)
    monkeypatch.setattr(cli, "format_report", lambda report, fmt="text": "R\n")
    monkeypatch.setattr(cli, "post_webhook", lambda url, body, headers=None: (500, b""))

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enroll",
            "diff",
            "--old",
            "/tmp/old",
            "--new",
            "/tmp/new",
            "--webhook",
            "https://example.invalid/h",
        ],
    )
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert "HTTP 500" in str(e.value)
