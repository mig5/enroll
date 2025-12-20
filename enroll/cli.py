from __future__ import annotations

import argparse
import configparser
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

from .cache import new_harvest_cache_dir
from .diff import compare_harvests, format_report, post_webhook, send_email
from .harvest import harvest
from .manifest import manifest
from .remote import remote_harvest
from .sopsutil import SopsError, encrypt_file_binary


def _discover_config_path(argv: list[str]) -> Optional[Path]:
    """Return the config path to use, if any.

    Precedence:
      1) --no-config disables loading.
      2) --config PATH (or -c PATH)
      3) $ENROLL_CONFIG
      4) ./enroll.ini, ./.enroll.ini
      5) $XDG_CONFIG_HOME/enroll/enroll.ini (or ~/.config/enroll/enroll.ini)

    The config file is optional; if no file is found, returns None.
    """

    # Quick scan for explicit flags without needing to build the full parser.
    if "--no-config" in argv:
        return None

    def _value_after(flag: str) -> Optional[str]:
        try:
            i = argv.index(flag)
        except ValueError:
            return None
        if i + 1 >= len(argv):
            return None
        return argv[i + 1]

    p = _value_after("--config") or _value_after("-c")
    if p:
        return Path(p).expanduser()

    envp = os.environ.get("ENROLL_CONFIG")
    if envp:
        return Path(envp).expanduser()

    cwd = Path.cwd()
    for name in ("enroll.ini", ".enroll.ini"):
        cp = cwd / name
        if cp.exists() and cp.is_file():
            return cp

    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        base = Path(xdg).expanduser()
    else:
        base = Path.home() / ".config"
    cp = base / "enroll" / "enroll.ini"
    if cp.exists() and cp.is_file():
        return cp

    return None


def _parse_bool(s: str) -> Optional[bool]:
    v = str(s).strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return None


def _action_lookup(p: argparse.ArgumentParser) -> dict[str, argparse.Action]:
    """Map config keys -> argparse actions for a parser.

    Accepts both dest names and long option names without leading dashes,
    normalized with '-' -> '_'.
    """

    m: dict[str, argparse.Action] = {}
    for a in p._actions:  # noqa: SLF001 (argparse internal)
        if not getattr(a, "dest", None):
            continue
        dest = str(a.dest).strip().lower()
        if dest:
            m[dest] = a
        for opt in getattr(a, "option_strings", []) or []:
            k = opt.lstrip("-").strip().lower()
            if k:
                m[k.replace("-", "_")] = a
                m[k] = a
    return m


def _choose_flag(a: argparse.Action) -> Optional[str]:
    # Prefer a long flag if available (e.g. --dangerous over -d)
    for s in getattr(a, "option_strings", []) or []:
        if s.startswith("--"):
            return s
    for s in getattr(a, "option_strings", []) or []:
        return s
    return None


def _split_list_value(v: str) -> list[str]:
    # Support comma-separated and/or multi-line lists.
    raw = str(v)
    if "\n" in raw:
        parts = [p.strip() for p in raw.splitlines()]
        return [p for p in parts if p]
    if "," in raw:
        parts = [p.strip() for p in raw.split(",")]
        return [p for p in parts if p]
    raw = raw.strip()
    return [raw] if raw else []


def _section_to_argv(
    p: argparse.ArgumentParser, cfg: configparser.ConfigParser, section: str
) -> list[str]:
    """Translate an INI section into argv tokens for this parser."""
    if not cfg.has_section(section):
        return []

    lookup = _action_lookup(p)
    out: list[str] = []

    for k, v in cfg.items(section):
        key = str(k).strip().lower().replace("-", "_")
        # Avoid recursion / confusing self-configuration.
        if key in {"config", "no_config"}:
            continue

        a = lookup.get(key)
        if not a:
            # Unknown keys are ignored (but we try to be helpful).
            print(
                f"warning: config [{section}] contains unknown option '{k}' (ignored)",
                file=sys.stderr,
            )
            continue

        flag = _choose_flag(a)
        if not flag:
            continue

        # Boolean flags
        if isinstance(a, argparse._StoreTrueAction):  # noqa: SLF001
            b = _parse_bool(v)
            if b is True:
                out.append(flag)
            continue
        if isinstance(a, argparse._StoreFalseAction):  # noqa: SLF001
            b = _parse_bool(v)
            if b is False:
                out.append(flag)
            continue

        # Repeated options
        if isinstance(a, argparse._AppendAction):  # noqa: SLF001
            for item in _split_list_value(v):
                out.extend([flag, item])
            continue

        # Count flags (rare, but easy to support)
        if isinstance(a, argparse._CountAction):  # noqa: SLF001
            b = _parse_bool(v)
            if b is True:
                out.append(flag)
            else:
                try:
                    n = int(str(v).strip())
                except ValueError:
                    n = 0
                out.extend([flag] * max(0, n))
            continue

        # Standard scalar options
        sval = str(v).strip()
        if sval:
            out.extend([flag, sval])

    return out


def _inject_config_argv(
    argv: list[str],
    *,
    cfg_path: Optional[Path],
    root_parser: argparse.ArgumentParser,
    subparsers: dict[str, argparse.ArgumentParser],
) -> list[str]:
    """Return argv with config-derived tokens inserted.

    We insert:
      - [enroll] options before the subcommand
      - [<subcommand>] options immediately after the subcommand token

    CLI flags always win because they come later in argv.
    """

    if not cfg_path:
        return argv
    cfg_path = Path(cfg_path).expanduser()
    if not (cfg_path.exists() and cfg_path.is_file()):
        return argv

    cfg = configparser.ConfigParser()
    try:
        cfg.read(cfg_path, encoding="utf-8")
    except (OSError, configparser.Error) as e:
        raise SystemExit(f"error: failed to read config file {cfg_path}: {e}")

    global_tokens = _section_to_argv(root_parser, cfg, "enroll")

    # Find the subcommand token position.
    cmd_pos: Optional[int] = None
    cmd_name: Optional[str] = None
    for i, tok in enumerate(argv):
        if tok in subparsers:
            cmd_pos = i
            cmd_name = tok
            break
    if cmd_pos is None or cmd_name is None:
        # No subcommand found (argparse will handle the error); only apply global.
        return global_tokens + argv

    cmd_tokens = _section_to_argv(subparsers[cmd_name], cfg, cmd_name)
    # Also accept section names with '_' in place of '-' (e.g. [single_shot])
    if "-" in cmd_name:
        alt = cmd_name.replace("-", "_")
        if alt != cmd_name:
            cmd_tokens += _section_to_argv(subparsers[cmd_name], cfg, alt)

    return global_tokens + argv[: cmd_pos + 1] + cmd_tokens + argv[cmd_pos + 1 :]


def _resolve_sops_out_file(out: Optional[str], *, hint: str) -> Path:
    """Resolve an output *file* path for --sops mode.

    If `out` looks like a directory (or points to an existing directory), we
    place the encrypted harvest inside it as harvest.tar.gz.sops.
    """
    if out:
        p = Path(out).expanduser()
        if p.exists() and p.is_dir():
            return p / "harvest.tar.gz.sops"
        # Heuristic: treat paths with a suffix as files; otherwise directories.
        if p.suffix:
            return p
        return p / "harvest.tar.gz.sops"

    # Default: use a secure cache directory.
    d = new_harvest_cache_dir(hint=hint).dir
    return d / "harvest.tar.gz.sops"


def _tar_dir_to(path_dir: Path, tar_path: Path) -> None:
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, mode="w:gz") as tf:
        # Keep a stable on-disk layout when extracted: state.json + artifacts/
        tf.add(str(path_dir), arcname=".")


def _encrypt_harvest_dir_to_sops(
    bundle_dir: Path, out_file: Path, fps: list[str]
) -> Path:
    out_file = Path(out_file)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    # Create the tarball alongside the output file (keeps filesystem permissions/locality sane).
    fd, tmp_tgz = tempfile.mkstemp(
        prefix=".enroll-harvest-", suffix=".tar.gz", dir=str(out_file.parent)
    )
    os.close(fd)
    try:
        _tar_dir_to(bundle_dir, Path(tmp_tgz))
        encrypt_file_binary(Path(tmp_tgz), out_file, pgp_fingerprints=fps, mode=0o600)
    finally:
        try:
            os.unlink(tmp_tgz)
        except FileNotFoundError:
            pass
    return out_file


def _add_common_manifest_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--fqdn",
        help="Host FQDN/name for site-mode output (creates inventory/, inventory/host_vars/, playbooks/).",
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument(
        "--jinjaturtle",
        action="store_true",
        help="Attempt jinjaturtle template integration (it will error if jinjaturtle is not found on PATH).",
    )
    g.add_argument(
        "--no-jinjaturtle",
        action="store_true",
        help="Do not use jinjaturtle integration, even if it is installed.",
    )


def _jt_mode(args: argparse.Namespace) -> str:
    if getattr(args, "jinjaturtle", False):
        return "on"
    if getattr(args, "no_jinjaturtle", False):
        return "off"
    return "auto"


def _add_remote_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--remote-host",
        help="SSH host to run harvesting on (if set, harvest runs remotely and is pulled locally).",
    )


def _add_config_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "-c",
        "--config",
        help=(
            "Path to an INI config file for default options. If omitted, enroll will look for "
            "./enroll.ini, ./.enroll.ini, or ~/.config/enroll/enroll.ini (or $XDG_CONFIG_HOME/enroll/enroll.ini)."
        ),
    )
    p.add_argument(
        "--no-config",
        action="store_true",
        help="Do not load any INI config file (even if one would be auto-discovered).",
    )
    p.add_argument(
        "--remote-port",
        type=int,
        default=22,
        help="SSH port for --remote-host (default: 22).",
    )
    p.add_argument(
        "--remote-user",
        default=os.environ.get("USER") or None,
        help="SSH username for --remote-host (default: local $USER).",
    )


def main() -> None:
    ap = argparse.ArgumentParser(prog="enroll")
    _add_config_args(ap)
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("harvest", help="Harvest service/package/config state")
    _add_config_args(h)
    h.add_argument(
        "--out",
        help=(
            "Harvest output directory. If --sops is set, this may be either a directory "
            "(an encrypted file named harvest.tar.gz.sops will be created inside) or a file path."
        ),
    )
    h.add_argument(
        "--dangerous",
        action="store_true",
        help="Collect files more aggressively (may include secrets). Disables secret-avoidance checks.",
    )
    h.add_argument(
        "--include-path",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "Include extra file paths to harvest (repeatable). Supports globs (including '**') and regex via 're:<regex>'. "
            "Included files are still filtered by IgnorePolicy unless --dangerous is used."
        ),
    )
    h.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "Exclude file paths from harvesting (repeatable). Supports globs (including '**') and regex via 're:<regex>'. "
            "Excludes apply to all harvesting, including defaults."
        ),
    )

    h.add_argument(
        "--sops",
        nargs="+",
        metavar="GPG_FINGERPRINT",
        help=(
            "Encrypt the harvest output as a SOPS-encrypted tarball using the given GPG fingerprint(s). "
            "Requires `sops` on PATH."
        ),
    )
    h.add_argument(
        "--no-sudo",
        action="store_true",
        help="Don't use sudo on the remote host (when using --remote options). This may result in a limited harvest due to permission restrictions.",
    )
    _add_remote_args(h)

    m = sub.add_parser("manifest", help="Render Ansible roles from a harvest")
    _add_config_args(m)
    m.add_argument(
        "--harvest",
        required=True,
        help=(
            "Path to the directory created by the harvest command, or (with --sops) "
            "a SOPS-encrypted harvest tarball."
        ),
    )
    m.add_argument(
        "--out",
        required=True,
        help=(
            "Output location for the generated manifest. In plain mode this is a directory. "
            "In --sops mode this may be either a directory (an encrypted file named manifest.tar.gz.sops will be created inside) "
            "or a file path."
        ),
    )
    m.add_argument(
        "--sops",
        nargs="+",
        metavar="GPG_FINGERPRINT",
        help=(
            "In --sops mode, decrypt the harvest using `sops -d` (if the harvest is an encrypted file) "
            "and then bundle+encrypt the entire generated manifest output into a single SOPS-encrypted tarball "
            "(binary) using the given GPG fingerprint(s). Requires `sops` on PATH."
        ),
    )
    _add_common_manifest_args(m)

    s = sub.add_parser(
        "single-shot", help="Harvest state, then manifest Ansible code, in one shot"
    )
    _add_config_args(s)
    s.add_argument(
        "--harvest",
        help=(
            "Where to place the harvest. In plain mode this is a directory; in --sops mode this may be "
            "a directory or a file path (an encrypted file is produced)."
        ),
    )
    s.add_argument(
        "--dangerous",
        action="store_true",
        help="Collect files more aggressively (may include secrets). Disables secret-avoidance checks.",
    )
    s.add_argument(
        "--include-path",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "Include extra file paths to harvest (repeatable). Supports globs (including '**') and regex via 're:<regex>'. "
            "Included files are still filtered by IgnorePolicy unless --dangerous is used."
        ),
    )
    s.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "Exclude file paths from harvesting (repeatable). Supports globs (including '**') and regex via 're:<regex>'. "
            "Excludes apply to all harvesting, including defaults."
        ),
    )

    s.add_argument(
        "--sops",
        nargs="+",
        metavar="GPG_FINGERPRINT",
        help=(
            "Encrypt the harvest as a SOPS-encrypted tarball, and bundle+encrypt the manifest output in --out "
            "(same behavior as `harvest --sops` and `manifest --sops`)."
        ),
    )
    s.add_argument(
        "--no-sudo",
        action="store_true",
        help="Don't use sudo on the remote host (when using --remote options). This may result in a limited harvest due to permission restrictions.",
    )
    s.add_argument(
        "--out",
        required=True,
        help=(
            "Output location for the generated manifest. In plain mode this is a directory. "
            "In --sops mode this may be either a directory (an encrypted file named manifest.tar.gz.sops will be created inside) "
            "or a file path."
        ),
    )
    _add_common_manifest_args(s)
    _add_remote_args(s)

    d = sub.add_parser("diff", help="Compare two harvests and report differences")
    _add_config_args(d)
    d.add_argument(
        "--old",
        required=True,
        help=(
            "Old/baseline harvest (directory, a path to state.json, a tarball, or a SOPS-encrypted bundle)."
        ),
    )
    d.add_argument(
        "--new",
        required=True,
        help=(
            "New/current harvest (directory, a path to state.json, a tarball, or a SOPS-encrypted bundle)."
        ),
    )
    d.add_argument(
        "--sops",
        action="store_true",
        help="Allow SOPS-encrypted harvest bundle inputs (requires `sops` on PATH).",
    )
    d.add_argument(
        "--format",
        choices=["text", "markdown", "json"],
        default="text",
        help="Report output format (default: text).",
    )
    d.add_argument(
        "--out",
        help="Write the report to this file instead of stdout.",
    )
    d.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with status 2 if differences are detected.",
    )
    d.add_argument(
        "--notify-always",
        action="store_true",
        help="Send webhook/email even when there are no differences.",
    )
    d.add_argument(
        "--webhook",
        help="POST the report to this URL (only when differences are detected, unless --notify-always).",
    )
    d.add_argument(
        "--webhook-format",
        choices=["json", "text", "markdown"],
        default="json",
        help="Payload format for --webhook (default: json).",
    )
    d.add_argument(
        "--webhook-header",
        action="append",
        default=[],
        metavar="K:V",
        help="Extra HTTP header for --webhook (repeatable), e.g. 'Authorization: Bearer ...'.",
    )
    d.add_argument(
        "--email-to",
        action="append",
        default=[],
        help="Email the report to this address (repeatable; only when differences are detected unless --notify-always).",
    )
    d.add_argument(
        "--email-from",
        help="From address for --email-to (default: enroll@<hostname>).",
    )
    d.add_argument(
        "--email-subject",
        help="Subject for --email-to (default: 'enroll diff report').",
    )
    d.add_argument(
        "--smtp",
        help="SMTP server host[:port] for --email-to. If omitted, uses local sendmail.",
    )
    d.add_argument(
        "--smtp-user",
        help="SMTP username (optional).",
    )
    d.add_argument(
        "--smtp-password-env",
        help="Environment variable containing SMTP password (optional).",
    )

    argv = sys.argv[1:]
    cfg_path = _discover_config_path(argv)
    argv = _inject_config_argv(
        argv,
        cfg_path=cfg_path,
        root_parser=ap,
        subparsers={
            "harvest": h,
            "manifest": m,
            "single-shot": s,
            "diff": d,
        },
    )
    args = ap.parse_args(argv)

    remote_host: Optional[str] = getattr(args, "remote_host", None)

    try:
        if args.cmd == "harvest":
            sops_fps = getattr(args, "sops", None)
            if remote_host:
                if sops_fps:
                    out_file = _resolve_sops_out_file(args.out, hint=remote_host)
                    with tempfile.TemporaryDirectory(prefix="enroll-harvest-") as td:
                        tmp_bundle = Path(td) / "bundle"
                        tmp_bundle.mkdir(parents=True, exist_ok=True)
                        try:
                            os.chmod(tmp_bundle, 0o700)
                        except OSError:
                            pass
                        remote_harvest(
                            local_out_dir=tmp_bundle,
                            remote_host=remote_host,
                            remote_port=int(args.remote_port),
                            remote_user=args.remote_user,
                            dangerous=bool(args.dangerous),
                            no_sudo=bool(args.no_sudo),
                            include_paths=list(getattr(args, "include_path", []) or []),
                            exclude_paths=list(getattr(args, "exclude_path", []) or []),
                        )
                        _encrypt_harvest_dir_to_sops(
                            tmp_bundle, out_file, list(sops_fps)
                        )
                    print(str(out_file))
                else:
                    out_dir = (
                        Path(args.out)
                        if args.out
                        else new_harvest_cache_dir(hint=remote_host).dir
                    )
                    state = remote_harvest(
                        local_out_dir=out_dir,
                        remote_host=remote_host,
                        remote_port=int(args.remote_port),
                        remote_user=args.remote_user,
                        dangerous=bool(args.dangerous),
                        no_sudo=bool(args.no_sudo),
                        include_paths=list(getattr(args, "include_path", []) or []),
                        exclude_paths=list(getattr(args, "exclude_path", []) or []),
                    )
                    print(str(state))
            else:
                if sops_fps:
                    out_file = _resolve_sops_out_file(args.out, hint="local")
                    with tempfile.TemporaryDirectory(prefix="enroll-harvest-") as td:
                        tmp_bundle = Path(td) / "bundle"
                        tmp_bundle.mkdir(parents=True, exist_ok=True)
                        try:
                            os.chmod(tmp_bundle, 0o700)
                        except OSError:
                            pass
                        harvest(
                            str(tmp_bundle),
                            dangerous=bool(args.dangerous),
                            include_paths=list(getattr(args, "include_path", []) or []),
                            exclude_paths=list(getattr(args, "exclude_path", []) or []),
                        )
                        _encrypt_harvest_dir_to_sops(
                            tmp_bundle, out_file, list(sops_fps)
                        )
                    print(str(out_file))
                else:
                    if not args.out:
                        raise SystemExit(
                            "error: --out is required unless --remote-host is set"
                        )
                    path = harvest(
                        args.out,
                        dangerous=bool(args.dangerous),
                        include_paths=list(getattr(args, "include_path", []) or []),
                        exclude_paths=list(getattr(args, "exclude_path", []) or []),
                    )
                    print(path)
        elif args.cmd == "manifest":
            out_enc = manifest(
                args.harvest,
                args.out,
                fqdn=args.fqdn,
                jinjaturtle=_jt_mode(args),
                sops_fingerprints=getattr(args, "sops", None),
            )
            if getattr(args, "sops", None) and out_enc:
                print(str(out_enc))
        elif args.cmd == "diff":
            report, has_changes = compare_harvests(
                args.old,
                args.new,
                sops_mode=bool(getattr(args, "sops", False)),
            )

            txt = format_report(report, fmt=str(getattr(args, "format", "text")))
            out_path = getattr(args, "out", None)
            if out_path:
                p = Path(out_path).expanduser()
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(txt, encoding="utf-8")
            else:
                print(txt, end="" if txt.endswith("\n") else "\n")

            should_notify = has_changes or bool(getattr(args, "notify_always", False))

            webhook = getattr(args, "webhook", None)
            if webhook and should_notify:
                wf = str(getattr(args, "webhook_format", "json"))
                payload = format_report(report, fmt=wf)
                body = payload.encode("utf-8")
                headers = {}
                if wf == "json":
                    headers["Content-Type"] = "application/json"
                else:
                    headers["Content-Type"] = "text/plain; charset=utf-8"
                for hv in getattr(args, "webhook_header", []) or []:
                    if ":" in hv:
                        k, v = hv.split(":", 1)
                        headers[k.strip()] = v.strip()
                status, _resp = post_webhook(webhook, body, headers=headers)
                if status and status >= 400:
                    raise SystemExit(f"error: webhook returned HTTP {status}")

            to_addrs = getattr(args, "email_to", []) or []
            if to_addrs and should_notify:
                subject = getattr(args, "email_subject", None) or "enroll diff report"
                smtp_pw = None
                pw_env = getattr(args, "smtp_password_env", None)
                if pw_env:
                    smtp_pw = os.environ.get(str(pw_env))
                send_email(
                    to_addrs=list(to_addrs),
                    subject=str(subject),
                    body=txt,
                    from_addr=getattr(args, "email_from", None),
                    smtp=getattr(args, "smtp", None),
                    smtp_user=getattr(args, "smtp_user", None),
                    smtp_password=smtp_pw,
                )

            if getattr(args, "exit_code", False) and has_changes:
                raise SystemExit(2)
        elif args.cmd == "single-shot":
            sops_fps = getattr(args, "sops", None)
            if remote_host:
                if sops_fps:
                    out_file = _resolve_sops_out_file(args.harvest, hint=remote_host)
                    with tempfile.TemporaryDirectory(prefix="enroll-harvest-") as td:
                        tmp_bundle = Path(td) / "bundle"
                        tmp_bundle.mkdir(parents=True, exist_ok=True)
                        try:
                            os.chmod(tmp_bundle, 0o700)
                        except OSError:
                            pass
                        remote_harvest(
                            local_out_dir=tmp_bundle,
                            remote_host=remote_host,
                            remote_port=int(args.remote_port),
                            remote_user=args.remote_user,
                            dangerous=bool(args.dangerous),
                            no_sudo=bool(args.no_sudo),
                            include_paths=list(getattr(args, "include_path", []) or []),
                            exclude_paths=list(getattr(args, "exclude_path", []) or []),
                        )
                        _encrypt_harvest_dir_to_sops(
                            tmp_bundle, out_file, list(sops_fps)
                        )

                    manifest(
                        str(out_file),
                        args.out,
                        fqdn=args.fqdn,
                        jinjaturtle=_jt_mode(args),
                        sops_fingerprints=list(sops_fps),
                    )
                    if not args.harvest:
                        print(str(out_file))
                else:
                    harvest_dir = (
                        Path(args.harvest)
                        if args.harvest
                        else new_harvest_cache_dir(hint=remote_host).dir
                    )
                    remote_harvest(
                        local_out_dir=harvest_dir,
                        remote_host=remote_host,
                        remote_port=int(args.remote_port),
                        remote_user=args.remote_user,
                        dangerous=bool(args.dangerous),
                        no_sudo=bool(args.no_sudo),
                        include_paths=list(getattr(args, "include_path", []) or []),
                        exclude_paths=list(getattr(args, "exclude_path", []) or []),
                    )
                    manifest(
                        str(harvest_dir),
                        args.out,
                        fqdn=args.fqdn,
                        jinjaturtle=_jt_mode(args),
                    )
                    # For usability (when --harvest wasn't provided), print the harvest path.
                    if not args.harvest:
                        print(str(harvest_dir / "state.json"))
            else:
                if sops_fps:
                    out_file = _resolve_sops_out_file(args.harvest, hint="local")
                    with tempfile.TemporaryDirectory(prefix="enroll-harvest-") as td:
                        tmp_bundle = Path(td) / "bundle"
                        tmp_bundle.mkdir(parents=True, exist_ok=True)
                        try:
                            os.chmod(tmp_bundle, 0o700)
                        except OSError:
                            pass
                        harvest(
                            str(tmp_bundle),
                            dangerous=bool(args.dangerous),
                            include_paths=list(getattr(args, "include_path", []) or []),
                            exclude_paths=list(getattr(args, "exclude_path", []) or []),
                        )
                        _encrypt_harvest_dir_to_sops(
                            tmp_bundle, out_file, list(sops_fps)
                        )

                    manifest(
                        str(out_file),
                        args.out,
                        fqdn=args.fqdn,
                        jinjaturtle=_jt_mode(args),
                        sops_fingerprints=list(sops_fps),
                    )
                    if not args.harvest:
                        print(str(out_file))
                else:
                    if not args.harvest:
                        raise SystemExit(
                            "error: --harvest is required unless --remote-host is set"
                        )
                    harvest(
                        args.harvest,
                        dangerous=bool(args.dangerous),
                        include_paths=list(getattr(args, "include_path", []) or []),
                        exclude_paths=list(getattr(args, "exclude_path", []) or []),
                    )
                    manifest(
                        args.harvest,
                        args.out,
                        fqdn=args.fqdn,
                        jinjaturtle=_jt_mode(args),
                    )
        elif args.cmd == "diff":
            report, has_changes = compare_harvests(
                args.old, args.new, sops_mode=bool(getattr(args, "sops", False))
            )

            rendered = format_report(report, fmt=str(args.format))
            if args.out:
                Path(args.out).expanduser().write_text(rendered, encoding="utf-8")
            else:
                print(rendered, end="")

            do_notify = bool(has_changes or getattr(args, "notify_always", False))

            if do_notify and getattr(args, "webhook", None):
                wf = str(getattr(args, "webhook_format", "json"))
                body = format_report(report, fmt=wf).encode("utf-8")
                headers = {"User-Agent": "enroll"}
                if wf == "json":
                    headers["Content-Type"] = "application/json"
                else:
                    headers["Content-Type"] = "text/plain; charset=utf-8"
                for hv in getattr(args, "webhook_header", []) or []:
                    if ":" not in hv:
                        raise SystemExit(
                            "error: --webhook-header must be in the form 'K:V'"
                        )
                    k, v = hv.split(":", 1)
                    headers[k.strip()] = v.strip()
                status, _ = post_webhook(str(args.webhook), body, headers=headers)
                if status and status >= 400:
                    raise SystemExit(f"error: webhook returned HTTP {status}")

            if do_notify and (getattr(args, "email_to", []) or []):
                subject = getattr(args, "email_subject", None) or "enroll diff report"
                smtp_password = None
                pw_env = getattr(args, "smtp_password_env", None)
                if pw_env:
                    smtp_password = os.environ.get(str(pw_env))
                send_email(
                    to_addrs=list(getattr(args, "email_to", []) or []),
                    subject=str(subject),
                    body=rendered,
                    from_addr=getattr(args, "email_from", None),
                    smtp=getattr(args, "smtp", None),
                    smtp_user=getattr(args, "smtp_user", None),
                    smtp_password=smtp_password,
                )

            if getattr(args, "exit_code", False) and has_changes:
                raise SystemExit(2)
    except SopsError as e:
        raise SystemExit(f"error: {e}")
