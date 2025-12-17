from __future__ import annotations

import shutil
import subprocess  # nosec
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


SUPPORTED_EXTS = {".ini", ".json", ".toml", ".yaml", ".yml", ".xml"}


@dataclass(frozen=True)
class JinjifyResult:
    template_text: str
    vars_text: str  # YAML mapping text (no leading --- expected)


def find_jinjaturtle_cmd() -> Optional[str]:
    """Return the executable path for jinjaturtle if found on PATH."""
    return shutil.which("jinjaturtle")


def can_jinjify_path(path: str) -> bool:
    p = Path(path)
    return p.suffix.lower() in SUPPORTED_EXTS


def run_jinjaturtle(
    jt_exe: str,
    src_path: str,
    *,
    role_name: str,
    force_format: Optional[str] = None,
) -> JinjifyResult:
    """
    Run jinjaturtle against src_path and return (template, defaults-yaml).
    Uses tempfiles and captures outputs.

    jinjaturtle CLI:
      jinjaturtle <config> -r <role> [-f <format>] [-d <defaults-output>] [-t <template-output>]
    """
    src = Path(src_path)
    if not src.is_file():
        raise FileNotFoundError(src_path)

    with tempfile.TemporaryDirectory(prefix="enroll-jt-") as td:
        td_path = Path(td)
        defaults_out = td_path / "defaults.yml"
        template_out = td_path / "template.j2"

        cmd = [
            jt_exe,
            str(src),
            "-r",
            role_name,
            "-d",
            str(defaults_out),
            "-t",
            str(template_out),
        ]
        if force_format:
            cmd.extend(["-f", force_format])

        p = subprocess.run(cmd, text=True, capture_output=True)  # nosec
        if p.returncode != 0:
            raise RuntimeError(
                "jinjaturtle failed for %s (role=%s)\ncmd=%r\nstdout=%s\nstderr=%s"
                % (src_path, role_name, cmd, p.stdout, p.stderr)
            )

        vars_text = defaults_out.read_text(encoding="utf-8").strip()
        template_text = template_out.read_text(encoding="utf-8")

        # jinjaturtle outputs a YAML mapping; strip leading document marker if present
        if vars_text.startswith("---"):
            vars_text = "\n".join(vars_text.splitlines()[1:]).lstrip()

        return JinjifyResult(
            template_text=template_text, vars_text=vars_text.rstrip() + "\n"
        )
