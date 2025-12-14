from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from typing import Optional


DEFAULT_DENY_GLOBS = [
    "/etc/ssl/private/*",
    "/etc/ssh/ssh_host_*",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/*shadow",
    "/etc/letsencrypt/*",
]

SENSITIVE_CONTENT_PATTERNS = [
    re.compile(br"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    re.compile(br"(?i)\bpassword\s*="),
    re.compile(br"(?i)\b(pass|passwd|token|secret|api[_-]?key)\b"),
]


@dataclass
class SecretPolicy:
    deny_globs: list[str] = None
    max_file_bytes: int = 256_000
    sample_bytes: int = 64_000

    def __post_init__(self) -> None:
        if self.deny_globs is None:
            self.deny_globs = list(DEFAULT_DENY_GLOBS)

    def deny_reason(self, path: str) -> Optional[str]:
        for g in self.deny_globs:
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

        for pat in SENSITIVE_CONTENT_PATTERNS:
            if pat.search(data):
                return "sensitive_content"

        return None
