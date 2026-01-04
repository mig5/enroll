import sys

import pytest

import enroll.cli as cli


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
