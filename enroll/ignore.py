from __future__ import annotations

import fnmatch
import errno
import os
import re
import stat
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


# Allow a small set of binary config artifacts that are commonly required to
# reproduce system configuration (notably APT keyrings). These are still subject
# to size and readability limits, but are exempt from the "binary_like" denial.
DEFAULT_ALLOW_BINARY_GLOBS = [
    "/etc/apt/trusted.gpg",
    "/etc/apt/trusted.gpg.d/*.gpg",
    "/etc/apt/keyrings/*.gpg",
    "/etc/apt/keyrings/*.pgp",
    "/etc/apt/keyrings/*.asc",
    "/usr/share/keyrings/*.gpg",
    "/usr/share/keyrings/*.pgp",
    "/usr/share/keyrings/*.asc",
    "/etc/pki/rpm-gpg/*",
]

# Conservative secret patterns for default/safe harvesting.  These are
# intentionally biased towards false positives: operators can opt in with
# --dangerous or targeted include/exclude review when a file is genuinely
# needed.
#
# The assignment pattern catches INI/YAML/JSON/TOML-ish keys such as:
#   password: hunter2
#   "client_secret": "..."
#   aws_secret_access_key = ...
#   GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
SENSITIVE_CONTENT_PATTERNS = [
    re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    ),
    re.compile(rb"(?i)-----BEGIN OPENSSH PRIVATE KEY-----"),
    re.compile(rb"(?i)AGE-SECRET-KEY-[A-Z0-9]+"),
    re.compile(rb"(?i)OPENSSH PRIVATE KEY"),
    re.compile(rb"(?i)PGP PRIVATE KEY BLOCK"),
    re.compile(
        rb"""(?ix)
        (^|[^A-Za-z0-9])
        [\"']?
        (
            [A-Za-z0-9_.-]*
            (
                password|passwd|passphrase|
                token|auth[_-]?token|access[_-]?token|refresh[_-]?token|
                secret|client[_-]?secret|secret[_-]?key|
                api[_-]?key|access[_-]?key|private[_-]?key|
                credential|credentials|
                aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key|
                azure[_-]?client[_-]?secret|azure[_-]?tenant[_-]?id|azure[_-]?client[_-]?id|
                google[_-]?application[_-]?credentials|gcp[_-]?service[_-]?account|
                service[_-]?account[_-]?key
            )
            [A-Za-z0-9_.-]*
        )
        [\"']?
        \s*[:=]
        """
    ),
    re.compile(rb"(?i)\b(pass|passwd|token|secret|api[_-]?key)\b"),
]

COMMENT_PREFIXES = (b"#", b";", b"//")
BLOCK_START = b"/*"
BLOCK_END = b"*/"


@dataclass(frozen=True)
class FileInspection:
    """Bytes and metadata captured from one safely-opened source file."""

    data: bytes
    stat_result: os.stat_result


@dataclass
class IgnorePolicy:
    deny_globs: Optional[list[str]] = None
    allow_binary_globs: Optional[list[str]] = None
    max_file_bytes: int = 256_000
    sample_bytes: int = 64_000
    # If True, be much less conservative about collecting potentially
    # sensitive files. This disables deny globs (e.g. /etc/shadow,
    # /etc/ssl/private/*) and skips heuristic content scanning.
    dangerous: bool = False

    def __post_init__(self) -> None:
        if self.deny_globs is None:
            self.deny_globs = list(DEFAULT_DENY_GLOBS)
        if self.allow_binary_globs is None:
            self.allow_binary_globs = list(DEFAULT_ALLOW_BINARY_GLOBS)

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

    def _path_deny_reason(self, path: str) -> Optional[str]:
        # Always ignore plain *.log files (rarely useful as config, often noisy).
        if path.endswith(".log"):
            return "log_file"
        # Ignore editor/backup files that end with a trailing tilde.
        if path.endswith("~"):
            return "backup_file"
        # Ignore backup shadow files
        if path.startswith("/etc/") and path.endswith("-"):
            return "backup_file"

        if not self.dangerous:
            for g in self.deny_globs or []:
                if fnmatch.fnmatch(path, g):
                    return "denied_path"
        return None

    def _content_deny_reason(self, path: str, data: bytes) -> Optional[str]:
        if b"\x00" in data:
            for g in self.allow_binary_globs or []:
                if fnmatch.fnmatch(path, g):
                    # Binary is acceptable for explicitly-allowed paths.
                    return None
            return "binary_like"

        if not self.dangerous:
            for line in self.iter_effective_lines(data):
                for pat in SENSITIVE_CONTENT_PATTERNS:
                    if pat.search(line):
                        return "sensitive_content"

        return None

    def inspect_file(self, path: str) -> tuple[Optional[str], Optional[FileInspection]]:
        """Safely inspect a regular file and return the exact bytes to copy.

        The source is opened with O_NOFOLLOW where available, fstat() is taken
        from that file descriptor, and the whole file is read only after the
        size cap passes.  With the default 256 KiB cap this avoids a memory DoS
        while ensuring secret scanning covers every byte that may be copied.
        """

        deny = self._path_deny_reason(path)
        if deny:
            return deny, None

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd: Optional[int] = None
        try:
            try:
                fd = os.open(path, flags)
            except OSError as e:
                if e.errno in {errno.ELOOP, errno.ENOTDIR}:
                    return "not_regular_file", None
                return "unreadable", None

            try:
                st = os.fstat(fd)
            except OSError:
                return "unreadable", None

            if not stat.S_ISREG(st.st_mode):
                return "not_regular_file", None
            if st.st_size > self.max_file_bytes:
                return "too_large", None

            chunks: list[bytes] = []
            remaining = int(st.st_size)
            while remaining > 0:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)

            deny = self._content_deny_reason(path, data)
            if deny:
                return deny, None
            return None, FileInspection(data=data, stat_result=st)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def deny_reason(self, path: str) -> Optional[str]:
        deny, _inspection = self.inspect_file(path)
        return deny

    def deny_reason_dir(self, path: str) -> Optional[str]:
        """Directory-specific deny logic.

        deny_reason() is file-oriented (it rejects directories as "not_regular_file").
        For directory metadata capture (so roles can recreate directory trees), we need
        a lighter-weight check:
          - apply deny_globs (unless dangerous)
          - require the path to be a real directory (no symlink)
          - ensure it's stat'able/readable

        No size checks or content scanning are performed for directories.
        """
        if not self.dangerous:
            for g in self.deny_globs or []:
                if fnmatch.fnmatch(path, g):
                    return "denied_path"

        try:
            os.stat(path, follow_symlinks=True)
        except OSError:
            return "unreadable"

        if os.path.islink(path):
            return "symlink"

        if not os.path.isdir(path):
            return "not_directory"

        return None

    def deny_reason_link(self, path: str) -> Optional[str]:
        """Symlink-specific deny logic.

        Symlinks are meaningful configuration state (e.g. Debian-style
        *-enabled directories). deny_reason() is file-oriented and rejects
        symlinks as "not_regular_file".

        For symlinks we:
          - apply the usual deny_globs (unless dangerous)
          - ensure the path is a symlink and we can readlink() it

        No size checks or content scanning are performed for symlinks.
        """

        # Keep the same fast-path filename ignores as deny_reason().
        if path.endswith(".log"):
            return "log_file"
        if path.endswith("~"):
            return "backup_file"
        if path.startswith("/etc/") and path.endswith("-"):
            return "backup_file"

        if not self.dangerous:
            for g in self.deny_globs or []:
                if fnmatch.fnmatch(path, g):
                    return "denied_path"

        try:
            os.lstat(path)
        except OSError:
            return "unreadable"

        if not os.path.islink(path):
            return "not_symlink"

        try:
            os.readlink(path)
        except OSError:
            return "unreadable"

        return None
