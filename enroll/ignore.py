from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from typing import Optional


DEFAULT_DENY_GLOBS = [
    # Common backup copies created by passwd tools (can contain sensitive data)
    "/etc/passwd-",
    "/etc/group-",
    "/etc/shadow-",
    "/etc/gshadow-",
    "/etc/subuid-",
    "/etc/subgid-",
    "/etc/*shadow-",
    "/etc/*gshadow-",
    "/etc/ssl/private/*",
    "/etc/ssh/ssh_host_*",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/*shadow",
    "/etc/letsencrypt/*",
    "/usr/local/etc/ssl/private/*",
    "/usr/local/etc/ssh/ssh_host_*",
    "/usr/local/etc/*shadow",
    "/usr/local/etc/*gshadow",
    "/usr/local/etc/letsencrypt/*",
]

SENSITIVE_CONTENT_PATTERNS = [
    re.compile(rb"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    re.compile(rb"(?i)\bpassword\s*="),
    re.compile(rb"(?i)\b(pass|passwd|token|secret|api[_-]?key)\b"),
]

COMMENT_PREFIXES = (b"#", b";", b"//")
BLOCK_START = b"/*"
BLOCK_END = b"*/"


@dataclass
class IgnorePolicy:
    deny_globs: Optional[list[str]] = None
    max_file_bytes: int = 256_000
    sample_bytes: int = 64_000
    # If True, be much less conservative about collecting potentially
    # sensitive files. This disables deny globs (e.g. /etc/shadow,
    # /etc/ssl/private/*) and skips heuristic content scanning.
    dangerous: bool = False

    def __post_init__(self) -> None:
        if self.deny_globs is None:
            self.deny_globs = list(DEFAULT_DENY_GLOBS)

    def iter_effective_lines(self, content: bytes):
        in_block = False
        for raw in content.splitlines():
            line = raw.lstrip()

            if in_block:
                if BLOCK_END in line:
                    in_block = False
                continue

            if not line:
                continue

            if line.startswith(BLOCK_START):
                in_block = True
                continue

            if line.startswith(COMMENT_PREFIXES) or line.startswith(b"*"):
                continue

            yield raw

    def deny_reason(self, path: str) -> Optional[str]:
        # Always ignore plain *.log files (rarely useful as config, often noisy).
        if path.endswith(".log"):
            return "log_file"

        if not self.dangerous:
            for g in self.deny_globs or []:
                if fnmatch.fnmatch(path, g):
                    return "denied_path"

        try:
            st = os.stat(path, follow_symlinks=True)
        except OSError:
            return "unreadable"

        if st.st_size > self.max_file_bytes:
            return "too_large"

        if not os.path.isfile(path) or os.path.islink(path):
            return "not_regular_file"

        try:
            with open(path, "rb") as f:
                data = f.read(min(self.sample_bytes, st.st_size))
        except OSError:
            return "unreadable"

        if b"\x00" in data:
            return "binary_like"

        if not self.dangerous:
            for line in self.iter_effective_lines(data):
                for pat in SENSITIVE_CONTENT_PATTERNS:
                    if pat.search(line):
                        return "sensitive_content"

        return None
