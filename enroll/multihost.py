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
from .render_safety import assert_generated_yaml_safe
from .yamlutil import IndentedSafeLoader, yaml_dump_mapping

META = ".enroll/project.json"
FORMAT = 2


def artifact_index(root: Path) -> dict:
    """Fingerprint generated role assets separately from reusable logic."""
    return {
        path: record
        for path, record in tree_index(root).items()
        if path.startswith(("files/", "templates/")) and not record.get("directory")
    }


def host_asset(root: Path, host: str, role: str, relative: str) -> Path:
    return root / "inventory" / "host_files" / host / role / relative


def make_role_lookups_host_aware(role_dir: Path) -> None:
    """Prefer a host override, then the role's common artifact."""
    host_prefix = "{{ inventory_dir }}/host_files/{{ inventory_hostname }}/{{ role_path | basename }}"
    for path in (role_dir / "tasks").glob("*.yml"):
        body = path.read_text()
        lines = []
        for line in body.splitlines(keepends=True):
            if '        - "{{ role_path }}/files/' in line:
                lines.append(line.replace("{{ role_path }}", host_prefix))
            lines.append(line)
        body = "".join(lines)
        for name in (
            "Deploy any systemd unit files (templates)",
            "Deploy any other managed files (templates)",
        ):
            marker = "- name: " + name + "\n"
            if marker in body:
                body = body.replace(
                    marker,
                    marker
                    + "  vars:\n    _enroll_ff:\n      files:\n"
                    + '        - "'
                    + host_prefix
                    + '/templates/{{ item.src_rel }}.j2"\n'
                    + '        - "{{ role_path }}/templates/{{ item.src_rel }}.j2"\n',
                    1,
                )
        body = body.replace(
            'src: "{{ item.src_rel }}.j2"',
            "src: \"{{ lookup('ansible.builtin.first_found', _enroll_ff) }}\"",
        )
        assert_generated_yaml_safe(body, label=f"multi-host role task {path.name}")
        path.write_text(body)


def validate_host(host: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", host or "") or host in {
        "all",
        "ungrouped",
    }:
        raise ManifestOutputError(
            "--host must be a simple inventory name (letters, digits, dot, underscore or hyphen); all/ungrouped are reserved"
        )
    return host


def host_role_alias(role: str, host: str) -> str:
    """Name a distinct role after its host, retaining a collision-resistant ID."""
    readable = re.sub(r"[^A-Za-z0-9]+", "_", host).strip("_")[:64].rstrip("_")
    digest = hashlib.sha256(host.encode()).hexdigest()[:12]
    # A role name is a single filesystem component (255 bytes on common filesystems).
    prefix = role[: 255 - len("__host_") - len(readable) - len(digest) - 1]
    return f"{prefix}__host_{readable}_{digest}"


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
    return {
        path: record
        for path, record in tree_index(root).items()
        if path not in ("files", "templates")
        and not path.startswith(("files/", "templates/"))
    }


def read_metadata(root: Path) -> dict:
    try:
        data = json.loads((root / META).read_text())
        if (
            data["format"] != FORMAT
            or not isinstance(data["hosts"], dict)
            or not isinstance(data["roles"], dict)
            or not isinstance(data.get("artifacts"), dict)
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


def check_host_artifacts(root: Path, data: dict, host: str) -> None:
    """Ensure every generated managed-file reference has a file in its selected role."""
    host_file = root / "inventory/host_vars" / host / "main.yml"
    host_vars_text = host_file.read_text()
    values = yaml.load(host_vars_text, Loader=IndentedSafeLoader) or {}  # nosec B506
    if not isinstance(values, dict):
        raise ManifestOutputError(f"Invalid host variables for {host}")
    play = yaml.safe_load((root / "playbooks" / f"{host}.yml").read_text())
    selected = set(data["hosts"][host]["roles"])
    for entry in play:
        for phase in ("pre_tasks", "post_tasks"):
            for task in entry.get(phase, []):
                imported = task.get("ansible.builtin.import_role")
                if imported and imported.get("name") not in selected:
                    raise ManifestOutputError(
                        f"Phase task for {host} imports an unselected role: {imported.get('name')}"
                    )
    for role in data["hosts"][host]["roles"]:
        role_dir = root / "roles" / role
        # The variable owner is the original role name when a generated role
        # has been assigned a host-specific directory.
        for key, items in values.items():
            if not key.endswith("_managed_files") or data["variable_owners"].get(
                key
            ) not in {role, role.split("__host_", 1)[0]}:
                continue
            if not isinstance(items, list):
                raise ManifestOutputError(f"Invalid managed files for {host}: {key}")
            for item in items:
                if not isinstance(item, dict) or not isinstance(
                    item.get("src_rel"), str
                ):
                    raise ManifestOutputError(
                        f"Invalid managed file reference for {host}: {key}"
                    )
                rel = Path(item["src_rel"])
                if rel.is_absolute() or any(part in (".", "..") for part in rel.parts):
                    raise ManifestOutputError(
                        f"Unsafe managed file reference for {host}: {key}"
                    )
                kind = item.get("kind")
                if kind not in ("copy", "template"):
                    raise ManifestOutputError(
                        f"Invalid managed file kind for {host}: {key}"
                    )
                relative = (
                    ("files" if kind == "copy" else "templates")
                    + "/"
                    + (str(rel) + (".j2" if kind == "template" else ""))
                )
                if not (
                    host_asset(root, host, role, relative).is_file()
                    or (role_dir / relative).is_file()
                ):
                    raise ManifestOutputError(
                        f"Missing generated role artifact for {host}: {role}/{kind}/{rel}"
                    )
        for key, value in values.items():
            if not key.endswith(
                (
                    "_ipset_save",
                    "_iptables_v4_save",
                    "_iptables_v6_save",
                    "_conf_src_rel",
                )
            ):
                continue
            if (
                data["variable_owners"].get(key)
                not in {role, role.split("__host_", 1)[0]}
                or not value
            ):
                continue
            rel = Path(str(value))
            if rel.is_absolute() or any(part in (".", "..") for part in rel.parts):
                raise ManifestOutputError(f"Unsafe runtime artifact for {host}: {key}")
            relative = "files/" + str(rel)
            if not (
                host_asset(root, host, role, relative).is_file()
                or (role_dir / relative).is_file()
            ):
                raise ManifestOutputError(
                    f"Missing runtime artifact for {host}: {role}/{relative}"
                )


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
        make_role_lookups_host_aware(role_dir)
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
        "artifacts": {name: artifact_index(root / "roles" / name) for name in roles},
        "variable_owners": owners,
    }
    write_project_files(root, data)
    check_host_artifacts(root, data, host)
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
        "Matching role logic is shared. Identical files stay in roles; differing files are stored per host under inventory/host_files/.\n"
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
    aliases = {}
    for role, expected in new["roles"].items():
        dest = existing / "roles" / role
        if dest.exists() or role in old["roles"]:
            actual = role_index(dest) if dest.exists() else {}
            if role not in old["roles"] or actual != old["roles"][role]:
                raise ManifestOutputError(
                    f"Existing role was edited: {role}; refusing automatic sharing"
                )
            if artifact_index(dest) != old["artifacts"][role]:
                raise ManifestOutputError(
                    f"Existing shared role artifacts were edited: {role}"
                )
            if actual != expected:
                alias = host_role_alias(role, host)
                if (
                    alias in old["roles"]
                    or alias in new["roles"]
                    or (existing / "roles" / alias).exists()
                ):
                    raise ManifestOutputError(f"Host role namespace collision: {alias}")
                aliases[role] = alias
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
        target = aliases.get(role, role)
        if target not in old["roles"]:
            shutil.copytree(incoming / "roles" / role, existing / "roles" / target)
            old["artifacts"][target] = new["artifacts"][role]
            continue
        # Compare each asset independently. A differing asset is moved from the
        # shared role into every existing host's inventory before adding the new
        # host's copy. Further hosts always receive their own copy of an asset
        # once it has been promoted, even when its bytes match an earlier host.
        shared = old["artifacts"][target]
        incoming_assets = new["artifacts"][role]
        for relative in sorted(shared.keys() | incoming_assets.keys()):
            common = existing / "roles" / target / relative
            candidate = incoming / "roles" / role / relative
            if relative in shared and shared[relative] == incoming_assets.get(relative):
                continue
            if relative in shared:
                for previous_host, record in old["hosts"].items():
                    if target in record["roles"]:
                        override = host_asset(existing, previous_host, target, relative)
                        override.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(common, override)
                common.unlink()
                del shared[relative]
            if relative in incoming_assets:
                override = host_asset(existing, host, target, relative)
                override.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(candidate, override)
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
    if aliases:
        play_path = existing / "playbooks" / f"{host}.yml"
        play = yaml.safe_load(play_path.read_text())
        for entry in play:
            for item in entry.get("roles", []):
                item["role"] = aliases.get(item["role"], item["role"])
            for phase in ("pre_tasks", "post_tasks"):
                for task in entry.get(phase, []):
                    imported = task.get("ansible.builtin.import_role")
                    if imported:
                        imported["name"] = aliases.get(
                            imported["name"], imported["name"]
                        )
        play_path.write_text(yaml.safe_dump(play, sort_keys=False))
        new["hosts"][host]["roles"] = [
            aliases.get(r, r) for r in new["hosts"][host]["roles"]
        ]
        new["roles"] = {aliases.get(r, r): index for r, index in new["roles"].items()}
    (existing / "requirements.yml").write_text(
        yaml_dump_mapping(
            {"collections": [collections[k] for k in sorted(collections)]}
        )
    )
    old["hosts"].update(new["hosts"])
    old["roles"].update(new["roles"])
    old["variable_owners"].update(new["variable_owners"])
    write_project_files(existing, old)
    for existing_host in old["hosts"]:
        check_host_artifacts(existing, old, existing_host)


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
