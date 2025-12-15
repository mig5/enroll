from __future__ import annotations

import argparse
from .harvest import harvest
from .manifest import manifest


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

    e = sub.add_parser(
        "enroll", help="Harvest state, then manifest Ansible code, in one shot"
    )
    e.add_argument(
        "--harvest", required=True, help="Path to the directory to place the harvest in"
    )
    e.add_argument(
        "--out",
        required=True,
        help="Output directory for generated roles/playbook Ansible manifest",
    )

    args = ap.parse_args()

    if args.cmd == "harvest":
        path = harvest(args.out)
        print(path)
    elif args.cmd == "manifest":
        manifest(args.harvest, args.out)
    elif args.cmd == "enroll":
        harvest(args.harvest)
        manifest(args.harvest, args.out)
