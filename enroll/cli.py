from __future__ import annotations

import argparse
from .harvest import harvest
from .manifest import manifest


def main() -> None:
    ap = argparse.ArgumentParser(prog="enroll")
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("harvest", help="Harvest service/package/config state into a bundle")
    h.add_argument("--out", required=True, help="Bundle output directory")

    r = sub.add_parser("manifest", help="Render Ansible roles from a harvested bundle")
    r.add_argument("--bundle", required=True, help="Path to the bundle directory created by the harvest command")
    r.add_argument("--out", required=True, help="Output directory for generated roles/playbook Ansible manifest")

    e = sub.add_parser("export", help="Harvest then manifest in one shot")
    e.add_argument("--bundle", required=True, help="Path to the directory to place the bundle in")
    e.add_argument("--out", required=True, help="Output directory for generated roles/playbook Ansible manifest")

    args = ap.parse_args()

    if args.cmd == "harvest":
        path = harvest(args.out)
        print(path)
    elif args.cmd == "manifest":
        manifest(args.bundle, args.out)
    elif args.cmd == "export":
        harvest(args.bundle)
        manifest(args.bundle, args.out)
