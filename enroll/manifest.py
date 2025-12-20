from __future__ import annotations

import json
import os
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .jinjaturtle import (
    find_jinjaturtle_cmd,
    can_jinjify_path,
    run_jinjaturtle,
)

from .remote import _safe_extract_tar
from .sopsutil import (
    decrypt_file_binary_to,
    encrypt_file_binary,
    require_sops_cmd,
)


def _try_yaml():
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    return yaml


def _yaml_load_mapping(text: str) -> Dict[str, Any]:
    yaml = _try_yaml()
    if yaml is None:
        return {}
    try:
        obj = yaml.safe_load(text)
    except Exception:
        return {}
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    return {}


def _yaml_dump_mapping(obj: Dict[str, Any], *, sort_keys: bool = True) -> str:
    yaml = _try_yaml()
    if yaml is None:
        # fall back to a naive key: value dump (best-effort)
        lines: List[str] = []
        for k, v in sorted(obj.items()) if sort_keys else obj.items():
            lines.append(f"{k}: {v!r}")
        return "\n".join(lines).rstrip() + "\n"

    # ansible-lint/yamllint's indentation rules are stricter than YAML itself.
    # In particular, they expect sequences nested under a mapping key to be
    # indented (e.g. `foo:\n  - a`), whereas PyYAML's default is often
    # `foo:\n- a`.
    class _IndentDumper(yaml.SafeDumper):  # type: ignore
        def increase_indent(self, flow: bool = False, indentless: bool = False):
            return super().increase_indent(flow, False)

    return (
        yaml.dump(
            obj,
            Dumper=_IndentDumper,
            default_flow_style=False,
            sort_keys=sort_keys,
            indent=2,
            allow_unicode=True,
        ).rstrip()
        + "\n"
    )


def _merge_mappings_overwrite(
    existing: Dict[str, Any], incoming: Dict[str, Any]
) -> Dict[str, Any]:
    """Merge incoming into existing with overwrite.

    NOTE: Unlike role defaults merging, host_vars should reflect the current
    harvest for a host. Therefore lists are replaced rather than unioned.
    """
    merged = dict(existing)
    merged.update(incoming)
    return merged


def _copy2_replace(src: str, dst: str) -> None:
    dst_dir = os.path.dirname(dst)
    os.makedirs(dst_dir, exist_ok=True)

    # Copy to a temp file in the same directory, then atomically replace.
    fd, tmp = tempfile.mkstemp(prefix=".enroll-tmp-", dir=dst_dir)
    os.close(fd)
    try:
        shutil.copy2(src, tmp)

        # Ensure the working tree stays mergeable: make the file user-writable.
        st = os.stat(tmp, follow_symlinks=False)
        mode = stat.S_IMODE(st.st_mode)
        if not (mode & stat.S_IWUSR):
            os.chmod(tmp, mode | stat.S_IWUSR)

        os.replace(tmp, dst)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _copy_artifacts(
    bundle_dir: str,
    role: str,
    dst_files_dir: str,
    *,
    preserve_existing: bool = False,
    exclude_rels: Optional[Set[str]] = None,
) -> None:
    """Copy harvested artifacts for a role into a destination *files* directory.

    In non --fqdn mode, this is usually <role_dir>/files.
    In --fqdn site mode, this is usually:
      inventory/host_vars/<fqdn>/<role>/.files
    """
    artifacts_dir = os.path.join(bundle_dir, "artifacts", role)
    if not os.path.isdir(artifacts_dir):
        return
    for root, _, files in os.walk(artifacts_dir):
        for fn in files:
            src = os.path.join(root, fn)
            rel = os.path.relpath(src, artifacts_dir)
            dst = os.path.join(dst_files_dir, rel)

            # If a file was successfully templatised by JinjaTurtle, do NOT
            # also materialise the raw copy in the destination files dir.
            # (This keeps the output minimal and avoids redundant "raw" files.)
            if exclude_rels and rel in exclude_rels:
                try:
                    if os.path.isfile(dst):
                        os.remove(dst)
                except Exception:
                    pass  # nosec
                continue

            if preserve_existing and os.path.exists(dst):
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            _copy2_replace(src, dst)


def _write_role_scaffold(role_dir: str) -> None:
    os.makedirs(os.path.join(role_dir, "tasks"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "handlers"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "defaults"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "meta"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "files"), exist_ok=True)
    os.makedirs(os.path.join(role_dir, "templates"), exist_ok=True)


def _write_playbook_all(path: str, roles: List[str]) -> None:
    pb_lines = [
        "---",
        "- name: Apply all roles on host",
        "  hosts: all",
        "  become: true",
        "  roles:",
    ]
    for r in roles:
        pb_lines.append(f"    - {r}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(pb_lines) + "\n")


def _write_playbook_host(path: str, fqdn: str, roles: List[str]) -> None:
    pb_lines = [
        "---",
        f"- name: Apply enroll roles on {fqdn}",
        f"  hosts: {fqdn}",
        "  become: true",
        "  roles:",
    ]
    for r in roles:
        pb_lines.append(f"    - {r}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(pb_lines) + "\n")


def _ensure_ansible_cfg(cfg_path: str) -> None:
    if not os.path.exists(cfg_path):
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("[defaults]\n")
            f.write("roles_path = roles\n")
            f.write("interpreter_python=/usr/bin/python3\n")
            f.write("inventory = inventory\n")
            f.write("stdout_callback = unixy\n")
            f.write("force_color = 1\n")
            f.write("vars_plugins_enabled = host_group_vars\n")
            f.write("fact_caching = jsonfile\n")
            f.write("fact_caching_connection = .enroll_cached_facts\n")
            f.write("forks = 30\n")
            f.write("remote_tmp = /tmp/ansible-${USER}\n")
            f.write("timeout = 12\n")
            f.write("[ssh_connection]\n")
            f.write("pipelining = True\n")
            f.write("scp_if_ssh = True\n")
        return


def _ensure_inventory_host(inv_path: str, fqdn: str) -> None:
    os.makedirs(os.path.dirname(inv_path), exist_ok=True)
    if not os.path.exists(inv_path):
        with open(inv_path, "w", encoding="utf-8") as f:
            f.write("[all]\n")
            f.write(fqdn + "\n")
        return

    with open(inv_path, "r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f.readlines()]

    # ensure there is an [all] group; if not, create it at top
    if not any(ln.strip() == "[all]" for ln in lines):
        lines = ["[all]"] + lines

    # check if fqdn already present (exact match, ignoring whitespace)
    if any(ln.strip() == fqdn for ln in lines):
        return

    # append at end
    lines.append(fqdn)
    with open(inv_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _hostvars_path(site_root: str, fqdn: str, role: str) -> str:
    return os.path.join(site_root, "inventory", "host_vars", fqdn, f"{role}.yml")


def _host_role_files_dir(site_root: str, fqdn: str, role: str) -> str:
    """Host-specific files dir for a given role.

    Layout:
      inventory/host_vars/<fqdn>/<role>/.files/
    """
    return os.path.join(site_root, "inventory", "host_vars", fqdn, role, ".files")


def _write_hostvars(site_root: str, fqdn: str, role: str, data: Dict[str, Any]) -> None:
    """Write host_vars YAML for a role for a specific host.

    This is host-specific state and should track the current harvest output.
    Existing keys not mentioned in `data` are preserved, but keys in `data`
    are overwritten (including list values).
    """
    path = _hostvars_path(site_root, fqdn, role)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    existing_map: Dict[str, Any] = {}
    if os.path.exists(path):
        try:
            existing_text = Path(path).read_text(encoding="utf-8")
            existing_map = _yaml_load_mapping(existing_text)
        except Exception:
            existing_map = {}

    merged = _merge_mappings_overwrite(existing_map, data)

    out = "# Generated by enroll (host-specific vars)\n---\n" + _yaml_dump_mapping(
        merged, sort_keys=True
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)


def _jinjify_managed_files(
    bundle_dir: str,
    role: str,
    role_dir: str,
    managed_files: List[Dict[str, Any]],
    *,
    jt_exe: Optional[str],
    jt_enabled: bool,
    overwrite_templates: bool,
) -> Tuple[Set[str], str]:
    """
    Return (templated_src_rels, combined_vars_text).
    combined_vars_text is a YAML mapping fragment (no leading ---).
    """
    templated: Set[str] = set()
    vars_map: Dict[str, Any] = {}

    if not (jt_enabled and jt_exe):
        return templated, ""

    for mf in managed_files:
        dest_path = mf.get("path", "")
        src_rel = mf.get("src_rel", "")
        if not dest_path or not src_rel:
            continue
        if not can_jinjify_path(dest_path):
            continue

        artifact_path = os.path.join(bundle_dir, "artifacts", role, src_rel)
        if not os.path.isfile(artifact_path):
            continue

        try:
            res = run_jinjaturtle(jt_exe, artifact_path, role_name=role)
        except Exception:
            # If jinjaturtle cannot process a file for any reason, skip silently.
            # (Enroll's core promise is to be optimistic and non-interactive.)
            continue  # nosec

        tmpl_rel = src_rel + ".j2"
        tmpl_dst = os.path.join(role_dir, "templates", tmpl_rel)
        if overwrite_templates or not os.path.exists(tmpl_dst):
            os.makedirs(os.path.dirname(tmpl_dst), exist_ok=True)
            with open(tmpl_dst, "w", encoding="utf-8") as f:
                f.write(res.template_text)

        templated.add(src_rel)
        if res.vars_text.strip():
            # merge YAML mappings; last wins (avoids duplicate keys)
            chunk = _yaml_load_mapping(res.vars_text)
            if chunk:
                vars_map = _merge_mappings_overwrite(vars_map, chunk)

    if vars_map:
        combined = _yaml_dump_mapping(vars_map, sort_keys=True)
        return templated, combined
    return templated, ""


def _write_role_defaults(role_dir: str, mapping: Dict[str, Any]) -> None:
    """Overwrite role defaults/main.yml with the provided mapping."""
    defaults_path = os.path.join(role_dir, "defaults", "main.yml")
    os.makedirs(os.path.dirname(defaults_path), exist_ok=True)
    out = "---\n" + _yaml_dump_mapping(mapping, sort_keys=True)
    with open(defaults_path, "w", encoding="utf-8") as f:
        f.write(out)


def _build_managed_files_var(
    managed_files: List[Dict[str, Any]],
    templated_src_rels: Set[str],
    *,
    notify_other: Optional[str] = None,
    notify_systemd: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Convert enroll managed_files into an Ansible-friendly list of dicts.

    Each dict drives a role task loop and is safe across hosts.
    """
    out: List[Dict[str, Any]] = []
    for mf in managed_files:
        dest = mf.get("path") or ""
        src_rel = mf.get("src_rel") or ""
        if not dest or not src_rel:
            continue
        is_unit = str(dest).startswith("/etc/systemd/system/")
        kind = "template" if src_rel in templated_src_rels else "copy"
        notify: List[str] = []
        if is_unit and notify_systemd:
            notify.append(notify_systemd)
        if (not is_unit) and notify_other:
            notify.append(notify_other)
        out.append(
            {
                "dest": dest,
                "src_rel": src_rel,
                "owner": mf.get("owner") or "root",
                "group": mf.get("group") or "root",
                "mode": mf.get("mode") or "0644",
                "kind": kind,
                "is_systemd_unit": bool(is_unit),
                "notify": notify,
            }
        )
    return out


def _render_generic_files_tasks(
    var_prefix: str, *, include_restart_notify: bool
) -> str:
    """Render generic tasks to deploy <var_prefix>_managed_files safely."""
    # Using first_found makes roles work in both modes:
    # - site-mode: inventory/host_vars/<host>/<role>/.files/...
    # - non-site: roles/<role>/files/...
    return f"""# Generated by enroll (data-driven tasks)

- name: Deploy systemd unit files (templates)
  ansible.builtin.template:
    src: "{{{{ item.src_rel }}}}.j2"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', true)
      | selectattr('kind', 'equalto', 'template')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Deploy systemd unit files (copies)
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ item.src_rel }}}}"
        - "{{{{ role_path }}}}/files/{{{{ item.src_rel }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', true)
      | selectattr('kind', 'equalto', 'copy')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Reload systemd to pick up unit changes
  ansible.builtin.meta: flush_handlers
  when: >-
    ({var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', true)
      | list
      | length) > 0

- name: Deploy other managed files (templates)
  ansible.builtin.template:
    src: "{{{{ item.src_rel }}}}.j2"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', false)
      | selectattr('kind', 'equalto', 'template')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"

- name: Deploy other managed files (copies)
  vars:
    _enroll_ff:
      files:
        - "{{{{ inventory_dir }}}}/host_vars/{{{{ inventory_hostname }}}}/{{{{ role_name }}}}/.files/{{{{ item.src_rel }}}}"
        - "{{{{ role_path }}}}/files/{{{{ item.src_rel }}}}"
  ansible.builtin.copy:
    src: "{{{{ lookup('ansible.builtin.first_found', _enroll_ff) }}}}"
    dest: "{{{{ item.dest }}}}"
    owner: "{{{{ item.owner }}}}"
    group: "{{{{ item.group }}}}"
    mode: "{{{{ item.mode }}}}"
  loop: >-
    {{{{ {var_prefix}_managed_files | default([])
      | selectattr('is_systemd_unit', 'equalto', false)
      | selectattr('kind', 'equalto', 'copy')
      | list }}}}
  notify: "{{{{ item.notify | default([]) }}}}"
"""


def _prepare_bundle_dir(
    bundle: str,
    *,
    sops_mode: bool,
) -> tuple[str, Optional[tempfile.TemporaryDirectory]]:
    """Return (bundle_dir, tempdir).

    - In non-sops mode, `bundle` must be a directory.
    - In sops mode, `bundle` may be a directory (already-decrypted) *or*
      a SOPS-encrypted tarball. In the tarball case we decrypt+extract into
      a secure temp directory.
    """
    p = Path(bundle).expanduser()

    if p.is_dir():
        return str(p), None

    if not sops_mode:
        raise RuntimeError(f"Harvest path is not a directory: {p}")

    if not p.exists():
        raise RuntimeError(f"Harvest path not found: {p}")

    # Ensure sops is available early for clear error messages.
    require_sops_cmd()

    td = tempfile.TemporaryDirectory(prefix="enroll-harvest-")
    td_path = Path(td.name)
    try:
        os.chmod(td_path, 0o700)
    except OSError:
        pass

    tar_path = td_path / "harvest.tar.gz"
    out_dir = td_path / "bundle"
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out_dir, 0o700)
    except OSError:
        pass

    decrypt_file_binary_to(p, tar_path, mode=0o600)

    # Extract using the same safe extraction rules as remote harvesting.
    with tarfile.open(tar_path, mode="r:gz") as tf:
        _safe_extract_tar(tf, out_dir)

    return str(out_dir), td


def _resolve_sops_manifest_out_file(out: str) -> Path:
    """Resolve an output *file* path for manifest --sops mode.

    If `out` looks like a directory (or points to an existing directory), we
    place the encrypted manifest bundle inside it as manifest.tar.gz.sops.
    """
    p = Path(out).expanduser()
    if p.exists() and p.is_dir():
        return p / "manifest.tar.gz.sops"
    # Heuristic: treat paths with a suffix as files; otherwise directories.
    if p.suffix:
        return p
    return p / "manifest.tar.gz.sops"


def _tar_dir_to_with_progress(
    src_dir: Path, tar_path: Path, *, desc: str = "tarring"
) -> None:
    """Create a tar.gz of src_dir at tar_path, with a simple per-entry progress display."""
    src_dir = Path(src_dir)
    tar_path = Path(tar_path)
    tar_path.parent.mkdir(parents=True, exist_ok=True)

    # Collect paths (dirs + files)
    paths: list[Path] = [src_dir]
    for root, dirs, files in os.walk(str(src_dir)):
        root_p = Path(root)
        for d in sorted(dirs):
            paths.append(root_p / d)
        for f in sorted(files):
            paths.append(root_p / f)

    total = len(paths)
    is_tty = hasattr(os, "isatty") and os.isatty(2)

    def _print_progress(i: int, p: Path) -> None:
        if not is_tty:
            return
        pct = (i / total * 100.0) if total else 100.0
        rel = "."
        try:
            rel = str(p.relative_to(src_dir))
        except Exception:
            rel = str(p)
        msg = f"{desc}: {i}/{total} ({pct:5.1f}%) {rel}"
        try:
            cols = shutil.get_terminal_size((80, 20)).columns
            msg = msg[: cols - 1]
        except Exception:
            pass  # nosec
        os.write(2, ("\r" + msg).encode("utf-8", errors="replace"))

    with tarfile.open(tar_path, mode="w:gz") as tf:
        prefix = Path("manifest")

        for i, p in enumerate(paths, start=1):
            if p == src_dir:
                arcname = str(prefix)
            else:
                rel = p.relative_to(src_dir)
                arcname = str(prefix / rel)
            tf.add(str(p), arcname=arcname, recursive=False)
            _print_progress(i, p)

    if is_tty:
        os.write(2, b"\n")


def _encrypt_manifest_out_dir_to_sops(
    out_dir: Path, out_file: Path, fps: list[str]
) -> Path:
    """Tar+encrypt the generated manifest output directory into a single .sops file."""
    require_sops_cmd()
    out_file = Path(out_file)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_tgz = tempfile.mkstemp(
        prefix=".enroll-manifest-",
        suffix=".tar.gz",
        dir=str(out_file.parent),
    )
    os.close(fd)
    try:
        _tar_dir_to_with_progress(
            Path(out_dir), Path(tmp_tgz), desc="Bundling manifest"
        )
        encrypt_file_binary(Path(tmp_tgz), out_file, pgp_fingerprints=fps, mode=0o600)
    finally:
        try:
            os.unlink(tmp_tgz)
        except FileNotFoundError:
            pass

    return out_file


def _manifest_from_bundle_dir(
    bundle_dir: str,
    out_dir: str,
    *,
    fqdn: Optional[str] = None,
    jinjaturtle: str = "auto",  # auto|on|off
) -> None:
    state_path = os.path.join(bundle_dir, "state.json")
    with open(state_path, "r", encoding="utf-8") as f:
        state = json.load(f)

    services: List[Dict[str, Any]] = state.get("services", [])
    package_roles: List[Dict[str, Any]] = state.get("package_roles", [])
    users_snapshot: Dict[str, Any] = state.get("users", {})
    etc_custom_snapshot: Dict[str, Any] = state.get("etc_custom", {})
    usr_local_custom_snapshot: Dict[str, Any] = state.get("usr_local_custom", {})
    extra_paths_snapshot: Dict[str, Any] = state.get("extra_paths", {})

    site_mode = fqdn is not None and fqdn != ""

    jt_exe = find_jinjaturtle_cmd()
    jt_enabled = False
    if jinjaturtle not in ("auto", "on", "off"):
        raise ValueError("jinjaturtle must be one of: auto, on, off")
    if jinjaturtle == "on":
        if not jt_exe:
            raise RuntimeError("jinjaturtle requested but not found on PATH")
        jt_enabled = True
    elif jinjaturtle == "auto":
        jt_enabled = jt_exe is not None
    else:
        jt_enabled = False

    os.makedirs(out_dir, exist_ok=True)
    roles_root = os.path.join(out_dir, "roles")
    os.makedirs(roles_root, exist_ok=True)

    # Site-mode scaffolding
    if site_mode:
        os.makedirs(os.path.join(out_dir, "inventory"), exist_ok=True)
        os.makedirs(os.path.join(out_dir, "inventory", "host_vars"), exist_ok=True)
        os.makedirs(os.path.join(out_dir, "playbooks"), exist_ok=True)
        _ensure_inventory_host(
            os.path.join(out_dir, "inventory", "hosts.ini"), fqdn or ""
        )
        _ensure_ansible_cfg(os.path.join(out_dir, "ansible.cfg"))

    manifested_users_roles: List[str] = []
    manifested_etc_custom_roles: List[str] = []
    manifested_usr_local_custom_roles: List[str] = []
    manifested_extra_paths_roles: List[str] = []
    manifested_service_roles: List[str] = []
    manifested_pkg_roles: List[str] = []

    # In site_mode, raw harvested files are stored under host-specific inventory
    # to avoid cross-host clobber while still sharing a role definition.

    # -------------------------

    # -------------------------
    # Users role (non-system users)
    # -------------------------
    if users_snapshot and users_snapshot.get("users"):
        role = users_snapshot.get("role_name", "users")
        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)

        # Users role includes harvested SSH-related files; in site mode keep them
        # host-specific to avoid cross-host clobber.
        if site_mode:
            _copy_artifacts(
                bundle_dir, role, _host_role_files_dir(out_dir, fqdn or "", role)
            )
        else:
            _copy_artifacts(bundle_dir, role, os.path.join(role_dir, "files"))

        users = users_snapshot.get("users", [])
        managed_files = users_snapshot.get("managed_files", [])
        excluded = users_snapshot.get("excluded", [])
        notes = users_snapshot.get("notes", [])

        # Build groups list and a simplified user dict list suitable for loops
        group_names: List[str] = []
        group_set = set()
        users_data: List[Dict[str, Any]] = []
        for u in users:
            name = u.get("name")
            if not name:
                continue
            pg = u.get("primary_group") or name
            home = u.get("home") or f"/home/{name}"
            sshdir = home.rstrip("/") + "/.ssh"
            supp = u.get("supplementary_groups") or []
            if pg:
                group_set.add(pg)
            for g in supp:
                if g:
                    group_set.add(g)

            users_data.append(
                {
                    "name": name,
                    "uid": u.get("uid"),
                    "primary_group": pg,
                    "home": home,
                    "ssh_dir": sshdir,
                    "shell": u.get("shell"),
                    "gecos": u.get("gecos"),
                    "supplementary_groups": sorted(set(supp)),
                }
            )

        group_names = sorted(group_set)

        # SSH-related files (authorized_keys, known_hosts, config, etc.)
        ssh_files: List[Dict[str, Any]] = []
        for mf in managed_files:
            dest = mf.get("path") or ""
            src_rel = mf.get("src_rel") or ""
            if not dest or not src_rel:
                continue

            owner = "root"
            group = "root"
            for u in users_data:
                home_prefix = (u.get("home") or "").rstrip("/") + "/"
                if home_prefix and dest.startswith(home_prefix):
                    owner = str(u.get("name") or "root")
                    group = str(u.get("primary_group") or owner)
                    break

            mode = "0600" if mf.get("reason") == "authorized_keys" else "0644"
            ssh_files.append(
                {
                    "dest": dest,
                    "src_rel": src_rel,
                    "owner": owner,
                    "group": group,
                    "mode": mode,
                }
            )

        # Variables are host-specific in site mode; in non-site mode they live in role defaults.
        if site_mode:
            _write_role_defaults(
                role_dir,
                {
                    "users_groups": [],
                    "users_users": [],
                    "users_ssh_files": [],
                },
            )
            _write_hostvars(
                out_dir,
                fqdn or "",
                role,
                {
                    "users_groups": group_names,
                    "users_users": users_data,
                    "users_ssh_files": ssh_files,
                },
            )
        else:
            _write_role_defaults(
                role_dir,
                {
                    "users_groups": group_names,
                    "users_users": users_data,
                    "users_ssh_files": ssh_files,
                },
            )

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\ndependencies: []\n")

        # tasks (data-driven)
        users_tasks = """---
# Generated by enroll (data-driven tasks)

- name: Ensure groups exist
  ansible.builtin.group:
    name: "{{ item }}"
    state: present
  loop: "{{ users_groups | default([]) }}"

- name: Ensure users exist
  ansible.builtin.user:
    name: "{{ item.name }}"
    uid: "{{ item.uid | default(omit) }}"
    group: "{{ item.primary_group }}"
    home: "{{ item.home }}"
    create_home: true
    shell: "{{ item.shell | default(omit) }}"
    comment: "{{ item.gecos | default(omit) }}"
    state: present
  loop: "{{ users_users | default([]) }}"

- name: Ensure users supplementary groups
  ansible.builtin.user:
    name: "{{ item.name }}"
    groups: "{{ item.supplementary_groups | default([]) | join(',') }}"
    append: true
  loop: "{{ users_users | default([]) }}"
  when: (item.supplementary_groups | default([])) | length > 0

- name: Ensure .ssh directories exist
  ansible.builtin.file:
    path: "{{ item.ssh_dir }}"
    state: directory
    owner: "{{ item.name }}"
    group: "{{ item.primary_group }}"
    mode: "0700"
  loop: "{{ users_users | default([]) }}"

- name: Deploy SSH-related files
  vars:
    _enroll_ff:
      files:
        - "{{ inventory_dir }}/host_vars/{{ inventory_hostname }}/{{ role_name }}/.files/{{ item.src_rel }}"
        - "{{ role_path }}/files/{{ item.src_rel }}"
  ansible.builtin.copy:
    src: "{{ lookup('ansible.builtin.first_found', _enroll_ff) }}"
    dest: "{{ item.dest }}"
    owner: "{{ item.owner }}"
    group: "{{ item.group }}"
    mode: "{{ item.mode }}"
  loop: "{{ users_ssh_files | default([]) }}"
"""

        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(users_tasks)

        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\n")

        readme = (
            """# users

Generated non-system user accounts and SSH public material.

## Users
"""
            + (
                "\n".join([f"- {u.get('name')} (uid {u.get('uid')})" for u in users])
                or "- (none)"
            )
            + """\n
## Included SSH files
"""
            + (
                "\n".join(
                    [f"- {mf.get('path')} ({mf.get('reason')})" for mf in managed_files]
                )
                or "- (none)"
            )
            + """\n
## Excluded
"""
            + (
                "\n".join([f"- {e.get('path')} ({e.get('reason')})" for e in excluded])
                or "- (none)"
            )
            + """\n
## Notes
"""
            + ("\n".join([f"- {n}" for n in notes]) or "- (none)")
            + """\n"""
        )
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        manifested_users_roles.append(role)

    # -------------------------

    # -------------------------
    # etc_custom role (unowned /etc not already attributed)
    # -------------------------
    if etc_custom_snapshot and etc_custom_snapshot.get("managed_files"):
        role = etc_custom_snapshot.get("role_name", "etc_custom")
        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)

        var_prefix = role

        managed_files = etc_custom_snapshot.get("managed_files", [])
        excluded = etc_custom_snapshot.get("excluded", [])
        notes = etc_custom_snapshot.get("notes", [])

        templated, jt_vars = _jinjify_managed_files(
            bundle_dir,
            role,
            role_dir,
            managed_files,
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=not site_mode,
        )

        # Copy only the non-templated artifacts (templates live in the role).
        if site_mode:
            _copy_artifacts(
                bundle_dir,
                role,
                _host_role_files_dir(out_dir, fqdn or "", role),
                exclude_rels=templated,
            )
        else:
            _copy_artifacts(
                bundle_dir,
                role,
                os.path.join(role_dir, "files"),
                exclude_rels=templated,
            )

        files_var = _build_managed_files_var(
            managed_files,
            templated,
            notify_other=None,
            notify_systemd="Run systemd daemon-reload",
        )

        jt_map = _yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
        vars_map: Dict[str, Any] = {f"{var_prefix}_managed_files": files_var}
        vars_map = _merge_mappings_overwrite(vars_map, jt_map)

        if site_mode:
            _write_role_defaults(role_dir, {f"{var_prefix}_managed_files": []})
            _write_hostvars(out_dir, fqdn or "", role, vars_map)
        else:
            _write_role_defaults(role_dir, vars_map)

        tasks = """---\n""" + _render_generic_files_tasks(
            var_prefix, include_restart_notify=False
        )
        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(tasks.rstrip() + "\n")

        handlers = """---
- name: Run systemd daemon-reload
  ansible.builtin.systemd:
    daemon_reload: true
"""
        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(handlers)

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\ndependencies: []\n")

        readme = (
            """# etc_custom

Unowned /etc config files not attributed to packages or services.

## Managed files
"""
            + ("\n".join([f"- {mf.get('path')}" for mf in managed_files]) or "- (none)")
            + """\n
## Excluded
"""
            + (
                "\n".join([f"- {e.get('path')} ({e.get('reason')})" for e in excluded])
                or "- (none)"
            )
            + """\n
## Notes
"""
            + ("\n".join([f"- {n}" for n in notes]) or "- (none)")
            + """\n"""
        )
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        manifested_etc_custom_roles.append(role)

    # -------------------------

    # -------------------------

    # -------------------------
    # usr_local_custom role (/usr/local/etc + /usr/local/bin scripts)
    # -------------------------
    if usr_local_custom_snapshot and usr_local_custom_snapshot.get("managed_files"):
        role = usr_local_custom_snapshot.get("role_name", "usr_local_custom")
        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)

        var_prefix = role

        managed_files = usr_local_custom_snapshot.get("managed_files", [])
        excluded = usr_local_custom_snapshot.get("excluded", [])
        notes = usr_local_custom_snapshot.get("notes", [])

        templated, jt_vars = _jinjify_managed_files(
            bundle_dir,
            role,
            role_dir,
            managed_files,
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=not site_mode,
        )

        # Copy only the non-templated artifacts (templates live in the role).
        if site_mode:
            _copy_artifacts(
                bundle_dir,
                role,
                _host_role_files_dir(out_dir, fqdn or "", role),
                exclude_rels=templated,
            )
        else:
            _copy_artifacts(
                bundle_dir,
                role,
                os.path.join(role_dir, "files"),
                exclude_rels=templated,
            )

        files_var = _build_managed_files_var(
            managed_files,
            templated,
            notify_other=None,
            notify_systemd=None,
        )

        jt_map = _yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
        vars_map: Dict[str, Any] = {f"{var_prefix}_managed_files": files_var}
        vars_map = _merge_mappings_overwrite(vars_map, jt_map)

        if site_mode:
            _write_role_defaults(role_dir, {f"{var_prefix}_managed_files": []})
            _write_hostvars(out_dir, fqdn or "", role, vars_map)
        else:
            _write_role_defaults(role_dir, vars_map)

        tasks = "---\n" + _render_generic_files_tasks(
            var_prefix, include_restart_notify=False
        )
        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(tasks.rstrip() + "\n")

        # No handlers needed for this role, but keep a valid YAML document.
        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\n")

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\ndependencies: []\n")

        readme = (
            """# usr_local_custom\n\n"""
            "Unowned /usr/local files (scripts in /usr/local/bin and config under /usr/local/etc).\n\n"
            "## Managed files\n"
            + ("\n".join([f"- {mf.get('path')}" for mf in managed_files]) or "- (none)")
            + "\n\n## Excluded\n"
            + (
                "\n".join([f"- {e.get('path')} ({e.get('reason')})" for e in excluded])
                or "- (none)"
            )
            + "\n\n## Notes\n"
            + ("\n".join([f"- {n}" for n in notes]) or "- (none)")
            + "\n"
        )
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        manifested_usr_local_custom_roles.append(role)

    # -------------------------
    # extra_paths role (user-requested includes)
    # -------------------------
    if extra_paths_snapshot and extra_paths_snapshot.get("managed_files"):
        role = extra_paths_snapshot.get("role_name", "extra_paths")
        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)

        var_prefix = role

        managed_files = extra_paths_snapshot.get("managed_files", [])
        excluded = extra_paths_snapshot.get("excluded", [])
        notes = extra_paths_snapshot.get("notes", [])
        include_pats = extra_paths_snapshot.get("include_patterns", []) or []
        exclude_pats = extra_paths_snapshot.get("exclude_patterns", []) or []

        templated, jt_vars = _jinjify_managed_files(
            bundle_dir,
            role,
            role_dir,
            managed_files,
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=not site_mode,
        )

        if site_mode:
            _copy_artifacts(
                bundle_dir,
                role,
                _host_role_files_dir(out_dir, fqdn or "", role),
                exclude_rels=templated,
            )
        else:
            _copy_artifacts(
                bundle_dir,
                role,
                os.path.join(role_dir, "files"),
                exclude_rels=templated,
            )

        files_var = _build_managed_files_var(
            managed_files,
            templated,
            notify_other=None,
            notify_systemd=None,
        )

        jt_map = _yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
        vars_map: Dict[str, Any] = {f"{var_prefix}_managed_files": files_var}
        vars_map = _merge_mappings_overwrite(vars_map, jt_map)

        if site_mode:
            _write_role_defaults(role_dir, {f"{var_prefix}_managed_files": []})
            _write_hostvars(out_dir, fqdn or "", role, vars_map)
        else:
            _write_role_defaults(role_dir, vars_map)

        tasks = "---\n" + _render_generic_files_tasks(
            var_prefix, include_restart_notify=False
        )
        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(tasks.rstrip() + "\n")

        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\n")

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\ndependencies: []\n")

        readme = (
            f"""# {role}

User-requested extra file harvesting.

## Include patterns
"""
            + ("\n".join([f"- {p}" for p in include_pats]) or "- (none)")
            + """\n
## Exclude patterns
"""
            + ("\n".join([f"- {p}" for p in exclude_pats]) or "- (none)")
            + """\n
## Managed files
"""
            + ("\n".join([f"- {mf.get('path')}" for mf in managed_files]) or "- (none)")
            + """\n
## Excluded
"""
            + (
                "\n".join([f"- {e.get('path')} ({e.get('reason')})" for e in excluded])
                or "- (none)"
            )
            + """\n
## Notes
"""
            + ("\n".join([f"- {n}" for n in notes]) or "- (none)")
            + """\n"""
        )
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        manifested_extra_paths_roles.append(role)

        manifested_usr_local_custom_roles.append(role)

    # -------------------------

    # -------------------------
    # Service roles
    # -------------------------
    for svc in services:
        role = svc["role_name"]
        unit = svc["unit"]
        pkgs = svc.get("packages", []) or []
        managed_files = svc.get("managed_files", []) or []

        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)

        var_prefix = role

        was_active = svc.get("active_state") == "active"
        unit_file_state = str(svc.get("unit_file_state") or "")
        enabled_at_harvest = unit_file_state in ("enabled", "enabled-runtime")
        desired_state = "started" if was_active else "stopped"

        templated, jt_vars = _jinjify_managed_files(
            bundle_dir,
            role,
            role_dir,
            managed_files,
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=not site_mode,
        )

        # Copy only the non-templated artifacts.
        if site_mode:
            _copy_artifacts(
                bundle_dir,
                role,
                _host_role_files_dir(out_dir, fqdn or "", role),
                exclude_rels=templated,
            )
        else:
            _copy_artifacts(
                bundle_dir,
                role,
                os.path.join(role_dir, "files"),
                exclude_rels=templated,
            )

        files_var = _build_managed_files_var(
            managed_files,
            templated,
            notify_other="Restart service",
            notify_systemd="Run systemd daemon-reload",
        )

        jt_map = _yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
        base_vars: Dict[str, Any] = {
            f"{var_prefix}_unit_name": unit,
            f"{var_prefix}_packages": pkgs,
            f"{var_prefix}_managed_files": files_var,
            f"{var_prefix}_manage_unit": True,
            f"{var_prefix}_systemd_enabled": bool(enabled_at_harvest),
            f"{var_prefix}_systemd_state": desired_state,
        }
        base_vars = _merge_mappings_overwrite(base_vars, jt_map)

        if site_mode:
            # Role defaults are host-agnostic/safe; all harvested state is in host_vars.
            _write_role_defaults(
                role_dir,
                {
                    f"{var_prefix}_unit_name": unit,
                    f"{var_prefix}_packages": [],
                    f"{var_prefix}_managed_files": [],
                    f"{var_prefix}_manage_unit": False,
                    f"{var_prefix}_systemd_enabled": False,
                    f"{var_prefix}_systemd_state": "stopped",
                },
            )
            _write_hostvars(out_dir, fqdn or "", role, base_vars)
        else:
            _write_role_defaults(role_dir, base_vars)

        handlers = f"""---
- name: Run systemd daemon-reload
  ansible.builtin.systemd:
    daemon_reload: true

- name: Restart service
  ansible.builtin.service:
    name: "{{{{ {var_prefix}_unit_name }}}}"
    state: restarted
  when:
    - {var_prefix}_manage_unit | default(false)
    - ({var_prefix}_systemd_state | default('stopped')) == 'started'
"""
        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(handlers)

        task_parts: List[str] = []
        task_parts.append(
            f"""---
# Generated by enroll (data-driven tasks)

- name: Install packages for {role}
  ansible.builtin.apt:
    name: "{{{{ {var_prefix}_packages | default([]) }}}}"
    state: present
    update_cache: true
  when: ({var_prefix}_packages | default([])) | length > 0

"""
        )

        task_parts.append(
            _render_generic_files_tasks(var_prefix, include_restart_notify=True)
        )

        task_parts.append(
            f"""
- name: Probe whether systemd unit exists and is manageable
  ansible.builtin.systemd:
    name: "{{{{ {var_prefix}_unit_name }}}}"
  check_mode: true
  register: _unit_probe
  failed_when: false
  changed_when: false
  when: {var_prefix}_manage_unit | default(false)

- name: Ensure unit enablement matches harvest
  ansible.builtin.systemd:
    name: "{{{{ {var_prefix}_unit_name }}}}"
    enabled: "{{{{ {var_prefix}_systemd_enabled | bool }}}}"
  when:
    - {var_prefix}_manage_unit | default(false)
    - _unit_probe is succeeded

- name: Ensure unit running state matches harvest
  ansible.builtin.systemd:
    name: "{{{{ {var_prefix}_unit_name }}}}"
    state: "{{{{ {var_prefix}_systemd_state }}}}"
  when:
    - {var_prefix}_manage_unit | default(false)
    - _unit_probe is succeeded
"""
        )

        tasks = "\n".join(task_parts).rstrip() + "\n"
        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(tasks)

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\ndependencies: []\n")

        excluded = svc.get("excluded", [])
        notes = svc.get("notes", [])
        readme = f"""# {role}

Generated from `{unit}`.

## Packages
{os.linesep.join("- " + p for p in pkgs) or "- (none detected)"}

## Managed files
{os.linesep.join("- " + mf["path"] + " (" + mf["reason"] + ")" for mf in managed_files) or "- (none)"}

## Excluded (possible secrets / unsafe)
{os.linesep.join("- " + e["path"] + " (" + e["reason"] + ")" for e in excluded) or "- (none)"}

## Notes
{os.linesep.join("- " + n for n in notes) or "- (none)"}
"""
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        manifested_service_roles.append(role)

    # -------------------------
    # Manually installed package roles
    # -------------------------
    for pr in package_roles:
        role = pr["role_name"]
        pkg = pr.get("package") or ""
        managed_files = pr.get("managed_files", []) or []

        role_dir = os.path.join(roles_root, role)
        _write_role_scaffold(role_dir)

        var_prefix = role

        templated, jt_vars = _jinjify_managed_files(
            bundle_dir,
            role,
            role_dir,
            managed_files,
            jt_exe=jt_exe,
            jt_enabled=jt_enabled,
            overwrite_templates=not site_mode,
        )

        # Copy only the non-templated artifacts.
        if site_mode:
            _copy_artifacts(
                bundle_dir,
                role,
                _host_role_files_dir(out_dir, fqdn or "", role),
                exclude_rels=templated,
            )
        else:
            _copy_artifacts(
                bundle_dir,
                role,
                os.path.join(role_dir, "files"),
                exclude_rels=templated,
            )

        pkgs = [pkg] if pkg else []

        files_var = _build_managed_files_var(
            managed_files,
            templated,
            notify_other=None,
            notify_systemd="Run systemd daemon-reload",
        )

        jt_map = _yaml_load_mapping(jt_vars) if jt_vars.strip() else {}
        base_vars: Dict[str, Any] = {
            f"{var_prefix}_packages": pkgs,
            f"{var_prefix}_managed_files": files_var,
        }
        base_vars = _merge_mappings_overwrite(base_vars, jt_map)

        if site_mode:
            _write_role_defaults(
                role_dir,
                {
                    f"{var_prefix}_packages": [],
                    f"{var_prefix}_managed_files": [],
                },
            )
            _write_hostvars(out_dir, fqdn or "", role, base_vars)
        else:
            _write_role_defaults(role_dir, base_vars)

        handlers = """---
- name: Run systemd daemon-reload
  ansible.builtin.systemd:
    daemon_reload: true
"""
        with open(
            os.path.join(role_dir, "handlers", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(handlers)

        task_parts: List[str] = []
        task_parts.append(
            f"""---
# Generated by enroll (data-driven tasks)

- name: Install packages for {role}
  ansible.builtin.apt:
    name: "{{{{ {var_prefix}_packages | default([]) }}}}"
    state: present
    update_cache: true
  when: ({var_prefix}_packages | default([])) | length > 0

"""
        )
        task_parts.append(
            _render_generic_files_tasks(var_prefix, include_restart_notify=False)
        )

        tasks = "\n".join(task_parts).rstrip() + "\n"
        with open(
            os.path.join(role_dir, "tasks", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write(tasks)

        with open(
            os.path.join(role_dir, "meta", "main.yml"), "w", encoding="utf-8"
        ) as f:
            f.write("---\ndependencies: []\n")

        excluded = pr.get("excluded", [])
        notes = pr.get("notes", [])
        readme = f"""# {role}

Generated for package `{pkg}`.

## Managed files
{os.linesep.join("- " + mf["path"] + " (" + mf["reason"] + ")" for mf in managed_files) or "- (none)"}

## Excluded (possible secrets / unsafe)
{os.linesep.join("- " + e["path"] + " (" + e["reason"] + ")" for e in excluded) or "- (none)"}

## Notes
{os.linesep.join("- " + n for n in notes) or "- (none)"}

> Note: package roles (those not discovered via a systemd service) do not attempt to restart or enable services automatically.
"""
        with open(os.path.join(role_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write(readme)

        manifested_pkg_roles.append(role)
    all_roles = (
        manifested_pkg_roles
        + manifested_service_roles
        + manifested_etc_custom_roles
        + manifested_usr_local_custom_roles
        + manifested_extra_paths_roles
        + manifested_users_roles
    )

    if site_mode:
        _write_playbook_host(
            os.path.join(out_dir, "playbooks", f"{fqdn}.yml"), fqdn or "", all_roles
        )
    else:
        _write_playbook_all(os.path.join(out_dir, "playbook.yml"), all_roles)


def manifest(
    bundle_dir: str,
    out: str,
    *,
    fqdn: Optional[str] = None,
    jinjaturtle: str = "auto",  # auto|on|off
    sops_fingerprints: Optional[List[str]] = None,
) -> Optional[str]:
    """Render an Ansible manifest from a harvest.

    Plain mode:
      - `bundle_dir` must be a directory
      - `out` is a directory written in-place

    SOPS mode (when `sops_fingerprints` is provided):
      - `bundle_dir` may be either a directory (already decrypted) or a SOPS
        encrypted tarball (binary) produced by `harvest --sops`
      - the manifest output is bundled (tar.gz) and encrypted into a single
        SOPS file (binary) at the resolved output path.

    Returns:
      - In SOPS mode: the path to the encrypted manifest bundle (.sops)
      - In plain mode: None
    """
    sops_mode = bool(sops_fingerprints)

    # Decrypt/extract the harvest bundle if needed.
    resolved_bundle_dir, td_bundle = _prepare_bundle_dir(
        bundle_dir, sops_mode=sops_mode
    )

    td_out: Optional[tempfile.TemporaryDirectory] = None
    try:
        if not sops_mode:
            _manifest_from_bundle_dir(
                resolved_bundle_dir, out, fqdn=fqdn, jinjaturtle=jinjaturtle
            )
            return None

        # SOPS mode: generate into a secure temp dir, then tar+encrypt into a single file.
        out_file = _resolve_sops_manifest_out_file(out)

        td_out = tempfile.TemporaryDirectory(prefix="enroll-manifest-")
        tmp_out = Path(td_out.name) / "out"
        tmp_out.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(tmp_out, 0o700)
        except OSError:
            pass

        _manifest_from_bundle_dir(
            resolved_bundle_dir, str(tmp_out), fqdn=fqdn, jinjaturtle=jinjaturtle
        )

        enc = _encrypt_manifest_out_dir_to_sops(
            tmp_out, out_file, list(sops_fingerprints or [])
        )
        return str(enc)

    finally:
        if td_out is not None:
            td_out.cleanup()
        if td_bundle is not None:
            td_bundle.cleanup()
