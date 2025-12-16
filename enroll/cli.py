from __future__ import annotations

import argparse

from .harvest import harvest
from .manifest import manifest


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


def main() -> None:
    ap = argparse.ArgumentParser(prog="enroll")
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("harvest", help="Harvest service/package/config state")
    h.add_argument("--out", required=True, help="Harvest output directory")

    r = sub.add_parser("manifest", help="Render Ansible roles from a harvest")
    r.add_argument(
        "--harvest",
        required=True,
        help="Path to the directory created by the harvest command",
    )
    r.add_argument(
        "--out",
        required=True,
        help="Output directory for generated roles/playbook Ansible manifest",
    )
    _add_common_manifest_args(r)

    e = sub.add_parser(
        "single-shot", help="Harvest state, then manifest Ansible code, in one shot"
    )
    e.add_argument(
        "--harvest", required=True, help="Path to the directory to place the harvest in"
    )
    e.add_argument(
        "--out",
        required=True,
        help="Output directory for generated roles/playbook Ansible manifest",
    )
    _add_common_manifest_args(e)

    args = ap.parse_args()

    if args.cmd == "harvest":
        path = harvest(args.out)
        print(path)
    elif args.cmd == "manifest":
        manifest(args.harvest, args.out, fqdn=args.fqdn, jinjaturtle=_jt_mode(args))
    elif args.cmd == "single-shot":
        harvest(args.harvest)
        manifest(args.harvest, args.out, fqdn=args.fqdn, jinjaturtle=_jt_mode(args))
