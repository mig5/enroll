"""Strict, transactional extension of Enroll-owned multi-host projects."""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

import yaml

from .fsutil import open_no_follow_path
from .harvest_safety import ensure_safe_output_parent
from .manifest_safety import (
    ManifestOutputError,
    _read_all_no_follow,
    freeze_directory_bundle,
    staged_manifest_output,
)
from .yamlutil import IndentedSafeLoader, yaml_dump_mapping

META = ".enroll/project.json"
FORMAT = 1


def validate_host(host: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", host or "") or host in {
        "all",
        "ungrouped",
    }:
        raise ManifestOutputError(
            "--host must be a simple inventory name (letters, digits, dot, underscore or hyphen); all/ungrouped are reserved"
        )
    return host


def tree_index(root: Path) -> dict:
    """Fingerprint bytes, relative paths and modes; refuse links/special files."""
    result = {}

    def walk_error(error):
        raise ManifestOutputError(f"Cannot inspect project tree: {error}")

    for current, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        ensure_safe_output_parent(Path(current) / "entry", label="manifest project")
        for name in sorted(dirs + files):
            path = Path(current) / name
            st = path.lstat()
            rel = path.relative_to(root).as_posix()
            if stat.S_ISDIR(st.st_mode):
                result[rel] = {"mode": stat.S_IMODE(st.st_mode), "directory": True}
            elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                data, _ = _read_all_no_follow(str(path.absolute()))
                result[rel] = {
                    "mode": stat.S_IMODE(st.st_mode),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            else:
                raise ManifestOutputError(
                    f"Unsafe project entry (link or special file): {rel}"
                )
    return result


def role_index(root: Path) -> dict:
    return tree_index(root)


def read_metadata(root: Path) -> dict:
    try:
        data = json.loads((root / META).read_text())
        if (
            data["format"] != FORMAT
            or not isinstance(data["hosts"], dict)
            or not isinstance(data["roles"], dict)
        ):
            raise ValueError("unsupported format")
        for host in data["hosts"]:
            validate_host(host)
        return data
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ManifestOutputError(
            "--extend requires a project created by this Enroll version with --host"
        ) from exc


def write_metadata(root: Path, data: dict) -> None:
    (root / META).parent.mkdir(mode=0o700, exist_ok=True)
    (root / META).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    (root / META).chmod(0o600)


def prepare_host(root: Path, host: str, options: dict) -> dict:
    """Extract known generated settings, retaining complete per-host values."""
    validate_host(host)
    roles, owners, values = {}, {}, {}
    for role_dir in sorted((root / "roles").iterdir()):
        if not role_dir.is_dir():
            raise ManifestOutputError("Unexpected entry in generated roles")
        defaults = role_dir / "defaults/main.yml"
        # SafeLoader subclass only adds Ansible's inert !unsafe text tag.
        content = yaml.load(
            defaults.read_text(), Loader=IndentedSafeLoader
        )  # nosec B506
        content = content or {}
        if not isinstance(content, dict):
            raise ManifestOutputError(f"Invalid generated defaults for {role_dir.name}")
        for key, value in content.items():
            if key in owners:
                raise ManifestOutputError(f"Variable namespace collision: {key}")
            owners[key] = role_dir.name
            values[key] = value
        defaults.write_text("---\n{}\n")
        roles[role_dir.name] = role_index(role_dir)
    host_dir = root / "inventory/host_vars" / host
    host_dir.mkdir(parents=True)
    (host_dir / "main.yml").write_text(yaml_dump_mapping(values, explicit_start=True))
    play = yaml.safe_load((root / "playbook.yml").read_text())
    for entry in play:
        entry["hosts"] = host
    (root / "playbooks").mkdir()
    (root / "playbooks" / f"{host}.yml").write_text(
        yaml.safe_dump(play, sort_keys=False)
    )
    (root / "host_notes").mkdir()
    (root / "README.md").rename(root / "host_notes" / f"{host}.md")
    cfg = root / "ansible.cfg"
    cfg.write_text(
        cfg.read_text().replace(
            "# Supply inventory with ansible-playbook -i",
            "inventory = inventory/hosts.yml",
        )
    )
    data = {
        "format": FORMAT,
        "generator_version": "0.9.0",
        "options": options,
        "hosts": {
            host: {
                "roles": [
                    role["role"] for entry in play for role in entry.get("roles", [])
                ],
                "variables": list(values),
            }
        },
        "roles": roles,
        "variable_owners": owners,
    }
    write_project_files(root, data)
    return data


def write_project_files(root: Path, data: dict) -> None:
    hosts = sorted(data["hosts"])
    (root / "inventory/hosts.yml").write_text(
        yaml_dump_mapping({"all": {"hosts": {h: {} for h in hosts}}})
    )
    (root / "playbook.yml").write_text(
        yaml.safe_dump(
            [{"import_playbook": f"playbooks/{h}.yml"} for h in hosts], sort_keys=False
        )
    )
    (root / "README.md").write_text(
        "# Enroll multi-host project\n\n"
        "Install collections: `ansible-galaxy collection install -r requirements.yml`.\n"
        "Apply: `ansible-playbook -i inventory/hosts.yml playbook.yml` (optionally `--limit HOST`).\n\n"
        "Edit connection details and complete host settings in `inventory/host_vars/HOST/main.yml`.\n"
        "Review capture exclusions and caveats in `host_notes/HOST.md`.\n\n"
        "From the parent directory, add a host: `enroll manifest --harvest HARVEST --host HOST --out PROJECT --extend`.\n"
        "Shared roles must match exactly, including tasks, handlers, files, templates, defaults, metadata and modes.\n"
        "Role edits are preserved but prevent sharing that role with incoming generated output.\n"
        "Do not edit generated inventory membership, playbooks, requirements or Enroll metadata.\n"
        "Extensions are staged and published atomically; duplicate hosts and incompatible roles are refused.\n"
    )
    data["controls"] = control_index(tree_index(root))
    write_metadata(root, data)


def control_index(index: dict) -> dict:
    return {
        p: rec
        for p, rec in index.items()
        if not rec.get("directory")
        and (
            p
            in {
                "playbook.yml",
                "inventory/hosts.yml",
                "ansible.cfg",
                "requirements.yml",
                "README.md",
            }
            or p.startswith("playbooks/")
        )
    }


def merge_project(existing: Path, incoming: Path, host: str) -> None:
    old, new = read_metadata(existing), read_metadata(incoming)
    if host in old["hosts"]:
        raise ManifestOutputError(
            f"Host already exists: {host}; replacement is not supported"
        )
    if old["options"] != new["options"]:
        raise ManifestOutputError(
            "Manifest renderer options differ from the existing project"
        )
    current = tree_index(existing)
    actual_controls = control_index(current)
    for path in old["controls"].keys() | actual_controls.keys():
        if actual_controls.get(path) != old["controls"].get(path):
            raise ManifestOutputError(f"Generated project control was edited: {path}")
    for role, expected in new["roles"].items():
        dest = existing / "roles" / role
        if dest.exists() or role in old["roles"]:
            actual = role_index(dest) if dest.exists() else {}
            if role not in old["roles"] or actual != old["roles"][role]:
                raise ManifestOutputError(
                    f"Existing role was edited: {role}; refusing automatic sharing"
                )
            if actual != expected:
                differences = sorted(
                    p
                    for p in actual.keys() | expected.keys()
                    if actual.get(p) != expected.get(p)
                )
                raise ManifestOutputError(
                    f"Incompatible shared role {role}: " + ", ".join(differences[:12])
                )
    for key, owner in new["variable_owners"].items():
        if key in old["variable_owners"] and old["variable_owners"][key] != owner:
            raise ManifestOutputError(f"Variable namespace collision: {key}")
    # Collection requirements are constraints, not arbitrary YAML to merge.
    old_req = yaml.safe_load((existing / "requirements.yml").read_text())
    new_req = yaml.safe_load((incoming / "requirements.yml").read_text())
    collections = {c["name"]: c for c in old_req.get("collections", [])}
    for collection in new_req.get("collections", []):
        name = collection["name"]
        if name in collections and collections[name] != collection:
            raise ManifestOutputError(f"Conflicting collection requirements: {name}")
        collections[name] = collection
    for role in new["roles"]:
        if role not in old["roles"]:
            shutil.copytree(incoming / "roles" / role, existing / "roles" / role)
    for relative in (
        f"inventory/host_vars/{host}",
        f"playbooks/{host}.yml",
        f"host_notes/{host}.md",
    ):
        src, dst = incoming / relative, existing / relative
        if dst.exists():
            raise ManifestOutputError(f"Incoming host path already exists: {relative}")
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    (existing / "requirements.yml").write_text(
        yaml_dump_mapping(
            {"collections": [collections[k] for k in sorted(collections)]}
        )
    )
    old["hosts"].update(new["hosts"])
    old["roles"].update(new["roles"])
    old["variable_owners"].update(new["variable_owners"])
    write_project_files(existing, old)


def atomic_exchange(left: Path, right: Path) -> None:
    """Linux atomic directory exchange; refuse unsupported filesystems."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise ManifestOutputError("Atomic extension requires Linux renameat2 support")
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(left), -100, os.fsencode(right), 2) != 0:
        raise ManifestOutputError(
            f"Atomic extension unavailable: {os.strerror(ctypes.get_errno())}"
        )


def render_project(renderer, out: str, host: str, extend: bool, options: dict) -> None:
    validate_host(host)
    destination = Path(out).expanduser().absolute()
    if not extend:
        with staged_manifest_output(destination) as stage:
            renderer(str(stage))
            prepare_host(stage, host, options)
        return
    if Path.cwd() == destination or destination in Path.cwd().parents:
        raise ManifestOutputError(
            "Run --extend from outside the project directory so atomic publication does not invalidate the working directory"
        )
    ensure_safe_output_parent(destination / "entry", label="manifest project")
    anchor = open_no_follow_path(str(destination), directory=True)
    try:
        fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=anchor)
    finally:
        os.close(anchor)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        locked = os.fstat(fd)
        current = destination.lstat()
        if (locked.st_dev, locked.st_ino) != (current.st_dev, current.st_ino):
            raise ManifestOutputError(
                "Project changed while waiting for extension lock; retry"
            )
        before = tree_index(destination)
        with tempfile.TemporaryDirectory(
            prefix=".enroll-extend-", dir=destination.parent, ignore_cleanup_errors=True
        ) as tmp:
            stage, incoming = Path(tmp) / "project", Path(tmp) / "incoming"
            frozen, cleanup = freeze_directory_bundle(
                destination, label="manifest project"
            )
            try:
                shutil.copytree(frozen, stage)
            finally:
                cleanup.cleanup()
            # Freezing makes content private; retain the existing project's modes.
            for rel, record in before.items():
                (stage / rel).chmod(record["mode"])
            stage.chmod(stat.S_IMODE(locked.st_mode))
            if tree_index(stage) != before:
                raise ManifestOutputError("Project changed during snapshot; retry")
            renderer(str(incoming))
            prepare_host(incoming, host, options)
            merge_project(stage, incoming, host)
            if (
                tree_index(destination) != before
                or destination.stat().st_ino != locked.st_ino
            ):
                raise ManifestOutputError("Project changed during extension; retry")
            atomic_exchange(stage, destination)
    finally:
        os.close(fd)
