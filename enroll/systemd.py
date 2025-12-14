from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class UnitInfo:
    name: str
    fragment_path: Optional[str]
    dropin_paths: List[str]
    env_files: List[str]
    exec_paths: List[str]  # binaries from ExecStart "path=" parts


class UnitQueryError(RuntimeError):
    def __init__(self, unit: str, stderr: str):
        self.unit = unit
        self.stderr = (stderr or "").strip()
        super().__init__(f"systemctl show failed for {unit}: {self.stderr}")


def _run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, check=False, text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{p.stderr}")
    return p.stdout


def list_enabled_services() -> List[str]:
    out = _run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend"])
    units: List[str] = []
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        unit = parts[0].strip()
        if not unit.endswith(".service"):
            continue
        # Skip template units like "getty@.service" which are enabled but not valid for systemctl show
        if unit.endswith("@.service") or "@.service" in unit:
            continue
        units.append(unit)
    return sorted(set(units))


def get_unit_info(unit: str) -> UnitInfo:
    p = subprocess.run(
        [
            "systemctl", "show", unit,
            "-p", "FragmentPath",
            "-p", "DropInPaths",
            "-p", "EnvironmentFiles",
            "-p", "ExecStart",
            "--no-page",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if p.returncode != 0:
        raise UnitQueryError(unit, p.stderr)

    kv: dict[str, str] = {}
    for line in (p.stdout or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k] = v.strip()

    fragment = kv.get("FragmentPath") or None

    dropins = [pp for pp in (kv.get("DropInPaths", "") or "").split() if pp]

    env_files: List[str] = []
    for token in (kv.get("EnvironmentFiles", "") or "").split():
        token = token.lstrip("-")
        if token:
            env_files.append(token)

    exec_paths = re.findall(r"path=([^ ;}]+)", kv.get("ExecStart", "") or "")

    return UnitInfo(
        name=unit,
        fragment_path=fragment,
        dropin_paths=sorted(set(dropins)),
        env_files=sorted(set(env_files)),
        exec_paths=sorted(set(exec_paths)),
    )
