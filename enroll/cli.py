from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Optional

from .cache import new_harvest_cache_dir
from .harvest import harvest
from .manifest import manifest
from .remote import remote_harvest


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
    h.add_argument("--out", help="Harvest output directory")
    h.add_argument(
        "--dangerous",
        action="store_true",
        help="Collect files more aggressively (may include secrets). Disables secret-avoidance checks.",
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
        help="Path to the directory created by the harvest command",
    )
    m.add_argument(
        "--out",
        required=True,
        help="Output directory for generated roles/playbook Ansible manifest",
    )
    _add_common_manifest_args(m)

    s = sub.add_parser(
        "single-shot", help="Harvest state, then manifest Ansible code, in one shot"
    )
    s.add_argument("--harvest", help="Path to the directory to place the harvest in")
    s.add_argument(
        "--dangerous",
        action="store_true",
        help="Collect files more aggressively (may include secrets). Disables secret-avoidance checks.",
    )
    s.add_argument(
        "--no-sudo",
        action="store_true",
        help="Don't use sudo on the remote host (when using --remote options). This may result in a limited harvest due to permission restrictions.",
    )
    s.add_argument(
        "--out",
        required=True,
        help="Output directory for generated roles/playbook Ansible manifest",
    )
    _add_common_manifest_args(s)
    _add_remote_args(s)

    args = ap.parse_args()

    remote_host: Optional[str] = getattr(args, "remote_host", None)

    if args.cmd == "harvest":
        if remote_host:
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
            if not args.out:
                raise SystemExit("error: --out is required unless --remote-host is set")
            path = harvest(args.out, dangerous=bool(args.dangerous))
            print(path)
    elif args.cmd == "manifest":
        manifest(args.harvest, args.out, fqdn=args.fqdn, jinjaturtle=_jt_mode(args))
    elif args.cmd == "single-shot":
        if remote_host:
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
                str(harvest_dir), args.out, fqdn=args.fqdn, jinjaturtle=_jt_mode(args)
            )
            # For usability (when --harvest wasn't provided), print the harvest path.
            if not args.harvest:
                print(str(harvest_dir / "state.json"))
        else:
            if not args.harvest:
                raise SystemExit(
                    "error: --harvest is required unless --remote-host is set"
                )
            harvest(args.harvest, dangerous=bool(args.dangerous))
            manifest(args.harvest, args.out, fqdn=args.fqdn, jinjaturtle=_jt_mode(args))
