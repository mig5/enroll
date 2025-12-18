from __future__ import annotations

import argparse
import os
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
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("harvest", help="Harvest service/package/config state")
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

    args = ap.parse_args()

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
                        harvest(str(tmp_bundle), dangerous=bool(args.dangerous))
                        _encrypt_harvest_dir_to_sops(
                            tmp_bundle, out_file, list(sops_fps)
                        )
                    print(str(out_file))
                else:
                    if not args.out:
                        raise SystemExit(
                            "error: --out is required unless --remote-host is set"
                        )
                    path = harvest(args.out, dangerous=bool(args.dangerous))
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
                        harvest(str(tmp_bundle), dangerous=bool(args.dangerous))
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
                    harvest(args.harvest, dangerous=bool(args.dangerous))
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
