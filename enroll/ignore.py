from __future__ import annotations

import fnmatch
import errno
import os
import re
import stat
from dataclasses import dataclass
from typing import Optional

from .fsutil import open_no_follow_path


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
    "/etc/ppp/chap-secrets",
    "/etc/ppp/pap-secrets",
    "/etc/ppp/*-secrets",
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
# Patterns are split into two tiers:
#
#   HIGH_CONFIDENCE_SECRET_PATTERNS
#       Unambiguous secret *material* (private-key blocks, age secret keys).
#       A file containing one of these should never be harvested in safe mode
#       regardless of how it is framed.  These are scanned against the raw bytes
#       and are deliberately NOT subject to comment stripping: a private key is
#       a private key whether or not the surrounding format treats some line as
#       a comment, and (critically) an attacker must not be able to hide key
#       material from the scanner by opening a block comment (e.g. a leading
#       "/*" line) that the line-oriented scanner would otherwise honour.
#
#   SENSITIVE_CONTENT_PATTERNS
#       The single remaining *soft* heuristic: a bare mention of a credential
#       word (e.g. the literal token "password" with no assigned value). This is
#       the only pattern prone to false positives on stock config files that
#       ship commented-out examples, so it -- and only it -- stays comment-aware
#       via iter_effective_lines().
#
# IMPORTANT (conservative-by-default): anything that looks like an actual
# credential *value* -- a populated "key = value" assignment, a URI with
# embedded credentials, or an Authorization header -- is treated as
# high-confidence and is scanned against the RAW bytes, including inside
# comments. A "commented out" secret is very often a real secret that someone
# disabled, so Enroll deliberately refuses such a file in safe mode and requires
# --dangerous (ideally with --sops) to collect it. Only genuinely value-less
# keyword mentions remain tolerated in comments, which is what keeps Enroll
# useful for ordinary config files without risking a real disabled credential.
HIGH_CONFIDENCE_SECRET_PATTERNS = [
    re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    ),
    re.compile(rb"(?i)-----BEGIN OPENSSH PRIVATE KEY-----"),
    re.compile(rb"(?i)AGE-SECRET-KEY-[A-Z0-9]+"),
    re.compile(rb"(?i)OPENSSH PRIVATE KEY"),
    re.compile(rb"(?i)PGP PRIVATE KEY BLOCK"),
    # Assignment-style credential keys with a value, e.g.
    #   password: hunter2
    #   "client_secret": "..."
    #   aws_secret_access_key = ...
    #   GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
    # A populated assignment is a real (if disabled) secret regardless of comment
    # framing, so it is scanned on raw bytes.
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
    # Credentials embedded in connection-string URIs, e.g.
    #   postgres://user:pass@host, redis://:pass@host, amqp://u:p@host
    re.compile(rb"(?i)[a-z][a-z0-9+.-]*://[^/\s:@]*:[^/\s@]+@[^/\s]"),
    # HTTP(S) Authorization / Proxy-Authorization header values carrying a
    # bearer/basic/digest credential.
    re.compile(
        rb"(?im)^\s*(?:proxy-)?authorization\s*:\s*"
        rb"(?:bearer|basic|token|digest)\s+\S"
    ),
]

SENSITIVE_CONTENT_PATTERNS = [
    # Bare credential-word mention with no assigned value. This is the only soft
    # heuristic and the only one tolerated inside comments, because stock config
    # files legitimately ship value-less commented hints (e.g. "# token").
    re.compile(
        rb"(?i)\b(pass|passwd|password|passphrase|token|secret|"
        rb"credentials?|api[_-]?key)\b"
    ),
]

COMMENT_PREFIXES = (b"#", b";", b"//")
BLOCK_START = b"/*"
BLOCK_END = b"*/"


def normalize_for_match(path: str) -> str:
    """Lexically normalize a path string for deny/allow glob matching.

    This collapses redundant separators ("//"), resolves "." and ".."
    segments, and strips trailing slashes using ``os.path.normpath`` -- a
    pure string operation that never touches the filesystem.

    It is deliberately NOT ``os.path.realpath``/``Path.resolve``: resolving
    symlinks would stat the filesystem and reintroduce a time-of-check /
    time-of-use window before the later ``O_NOFOLLOW`` open in
    ``inspect_file``. The goal here is only to stop a non-canonical *string*
    (e.g. "/etc//shadow" or "/etc/foo/../shadow") from slipping past a deny
    glob like "/etc/shadow". It is defense-in-depth on top of the no-follow
    open, not a load-bearing control by itself.

    ``normpath`` preserves a leading "//" because POSIX treats it as
    implementation-defined; for glob matching we collapse it to a single
    leading slash so patterns anchored at "/" still match.
    """

    if not path:
        return path
    normalized = os.path.normpath(path)
    if normalized.startswith("//") and not normalized.startswith("///"):
        normalized = normalized[1:]
    return normalized


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

    def _strip_balanced_block_comments(self, content: bytes) -> bytes:
        """Remove only *properly closed* ``/* ... */`` regions from *content*.

        The previous line-oriented scanner entered "block comment mode" the moment
        a line began with ``/*`` and then skipped every subsequent line until it
        saw ``*/``.  That had two problems an attacker (or just an unusual config)
        could exploit to hide secrets from the content scan:

          * an *unterminated* ``/*`` (no closing ``*/`` anywhere after it) masked
            the entire remainder of the file, including real key material; and
          * content appearing *after* a ``*/`` on the same line, or a one-line
            ``/* ... */ secret``, was dropped.

        Operating on the whole byte stream and removing only *balanced* comment
        regions fixes both: an opening ``/*`` with no matching ``*/`` is left in
        place (so its contents are still scanned), and bytes after a closing
        ``*/`` are preserved.  Each removed region is replaced with a single
        space so tokens on either side cannot be accidentally joined.
        """

        out = bytearray()
        i = 0
        n = len(content)
        while i < n:
            start = content.find(BLOCK_START, i)
            if start == -1:
                out += content[i:]
                break
            end = content.find(BLOCK_END, start + len(BLOCK_START))
            if end == -1:
                # Unterminated block comment: do NOT treat the rest of the file as
                # commented out. Keep it verbatim so secret scanning still runs.
                out += content[i:]
                break
            out += content[i:start]
            out += b" "
            i = end + len(BLOCK_END)
        return bytes(out)

    def iter_effective_lines(self, content: bytes):
        """Yield non-comment lines for the soft content heuristics.

        Block comments are removed first (only when properly closed), then
        single-line comment prefixes are skipped. Genuinely commented-out
        secrets remain ignored -- that is deliberate, documented behaviour -- but
        a block-comment open can no longer suppress scanning of later, real
        content.
        """

        for raw in self._strip_balanced_block_comments(content).splitlines():
            line = raw.lstrip()

            if not line:
                continue

            if line.startswith(COMMENT_PREFIXES) or line.startswith(b"*"):
                continue

            yield raw

    def _path_deny_reason(self, path: str) -> Optional[str]:
        # Match against a lexically-normalized path so non-canonical spellings
        # (e.g. "/etc//shadow", "/etc/foo/../shadow") cannot slip past a deny
        # glob. The original path is still what gets opened/recorded.
        match_path = normalize_for_match(path)
        # Always ignore plain *.log files (rarely useful as config, often noisy).
        if match_path.endswith(".log"):
            return "log_file"
        # Ignore editor/backup files that end with a trailing tilde.
        if match_path.endswith("~"):
            return "backup_file"
        # Ignore backup shadow files
        if match_path.startswith("/etc/") and match_path.endswith("-"):
            return "backup_file"

        if not self.dangerous:
            for g in self.deny_globs or []:
                if fnmatch.fnmatch(match_path, g):
                    return "denied_path"
        return None

    def _content_deny_reason(self, path: str, data: bytes) -> Optional[str]:
        if b"\x00" in data:
            match_path = normalize_for_match(path)
            for g in self.allow_binary_globs or []:
                if fnmatch.fnmatch(match_path, g):
                    # Binary is acceptable for explicitly-allowed paths.
                    return None
            return "binary_like"

        if not self.dangerous:
            # High-confidence secret *material* (private keys, age secret keys)
            # is scanned against the raw bytes and is NOT subject to comment
            # stripping. A private key embedded in a file is sensitive regardless
            # of comment framing, and this closes the bypass where opening a block
            # comment (e.g. a leading "/*" line) hid key material from the
            # line-oriented scanner.
            for pat in HIGH_CONFIDENCE_SECRET_PATTERNS:
                if pat.search(data):
                    return "sensitive_content"

            # Softer assignment/keyword/URI heuristics stay comment-aware so a
            # genuinely commented-out example does not make Enroll useless for
            # ordinary config files. iter_effective_lines() is hardened so an
            # unterminated/inline block comment cannot mask later real content.
            for line in self.iter_effective_lines(data):
                for pat in SENSITIVE_CONTENT_PATTERNS:
                    if pat.search(line):
                        return "sensitive_content"

        return None

    def inspect_file(self, path: str) -> tuple[Optional[str], Optional[FileInspection]]:
        """Safely inspect a regular file and return the exact bytes to copy.

        The source is opened with O_NOFOLLOW on every path component (see
        ``fsutil.open_no_follow_path``), fstat() is taken from that file
        descriptor, and the whole file is read only after the size cap passes.
        With the default 256 KiB cap this avoids a memory DoS while ensuring
        secret scanning covers every byte that may be copied.

        Opening every component without following symlinks means a regular
        file reached through a symlinked *parent* directory is refused with
        ``symlink_component`` rather than silently captured -- its logical
        path would not have matched the deny globs.
        """

        deny = self._path_deny_reason(path)
        if deny:
            return deny, None

        fd: Optional[int] = None
        try:
            try:
                fd = open_no_follow_path(path)
            except OSError as e:
                if e.errno == errno.ELOOP:
                    # A symlink (or unsafe '..') somewhere in the path. This is
                    # distinct from "not a regular file" so operators can see
                    # why a path under a symlinked parent was skipped.
                    return "symlink_component", None
                if e.errno == errno.ENOTDIR:
                    return "not_regular_file", None
                return "unreadable", None

            try:
                st = os.fstat(fd)
            except OSError:
                return "unreadable", None

            if not stat.S_ISREG(st.st_mode):
                return "not_regular_file", None
            if st.st_nlink > 1:
                # A hardlink gives a file another safe-looking pathname. When
                # Enroll is run as root, path-based deny rules such as
                # /etc/shadow must not be bypassed by copying the same inode via
                # an attacker-controlled alias under an otherwise allowed tree.
                return "hardlink_source", None
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
            match_path = normalize_for_match(path)
            for g in self.deny_globs or []:
                if fnmatch.fnmatch(match_path, g):
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
        match_path = normalize_for_match(path)
        if match_path.endswith(".log"):
            return "log_file"
        if match_path.endswith("~"):
            return "backup_file"
        if match_path.startswith("/etc/") and match_path.endswith("-"):
            return "backup_file"

        if not self.dangerous:
            for g in self.deny_globs or []:
                if fnmatch.fnmatch(match_path, g):
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
