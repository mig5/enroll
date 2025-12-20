from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import List, Optional, Sequence, Set, Tuple


_REGEX_PREFIXES = ("re:", "regex:")


def _has_glob_chars(s: str) -> bool:
    return any(ch in s for ch in "*?[")


def _norm_abs(p: str) -> str:
    """Normalise a path-ish string to an absolute POSIX path.

    We treat inputs that don't start with '/' as being relative to '/'.
    """

    p = p.strip()
    if not p:
        return "/"
    if not p.startswith("/"):
        p = "/" + p
    # `normpath` keeps a leading '/' for absolute paths.
    return os.path.normpath(p)


def _posix_match(path: str, pattern: str) -> bool:
    """Path matching with glob semantics.

    Uses PurePosixPath.match which:
      - treats '/' as a segment separator
      - supports '**' for recursive matching

    Both `path` and `pattern` are treated as absolute paths.
    """

    # PurePosixPath.match is anchored and works best on relative strings.
    p = path.lstrip("/")
    pat = pattern.lstrip("/")
    try:
        return PurePosixPath(p).match(pat)
    except Exception:
        # If the pattern is somehow invalid, fail closed.
        return False


def _regex_literal_prefix(regex: str) -> str:
    """Best-effort literal prefix extraction for a regex.

    This lets us pick a starting directory to walk when expanding regex-based
    include patterns.
    """

    s = regex
    if s.startswith("^"):
        s = s[1:]
    out: List[str] = []
    escaped = False
    meta = set(".^$*+?{}[]\\|()")
    for ch in s:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch in meta:
            break
        out.append(ch)
    return "".join(out)


@dataclass(frozen=True)
class CompiledPathPattern:
    raw: str
    kind: str  # 'prefix' | 'glob' | 'regex'
    value: str
    regex: Optional[re.Pattern[str]] = None

    def matches(self, path: str) -> bool:
        p = _norm_abs(path)

        if self.kind == "regex":
            if not self.regex:
                return False
            # Search (not match) so users can write unanchored patterns.
            return self.regex.search(p) is not None

        if self.kind == "glob":
            return _posix_match(p, self.value)

        # prefix
        pref = self.value.rstrip("/")
        return p == pref or p.startswith(pref + "/")


def compile_path_pattern(raw: str) -> CompiledPathPattern:
    s = raw.strip()
    for pre in _REGEX_PREFIXES:
        if s.startswith(pre):
            rex = s[len(pre) :].strip()
            try:
                return CompiledPathPattern(
                    raw=raw, kind="regex", value=rex, regex=re.compile(rex)
                )
            except re.error:
                # Treat invalid regexes as non-matching.
                return CompiledPathPattern(raw=raw, kind="regex", value=rex, regex=None)

    # If the user explicitly says glob:, honour it.
    if s.startswith("glob:"):
        pat = s[len("glob:") :].strip()
        return CompiledPathPattern(raw=raw, kind="glob", value=_norm_abs(pat))

    # Heuristic: if it contains glob metacharacters, treat as a glob.
    if _has_glob_chars(s) or "**" in s:
        return CompiledPathPattern(raw=raw, kind="glob", value=_norm_abs(s))

    # Otherwise treat as an exact path-or-prefix (dir subtree).
    return CompiledPathPattern(raw=raw, kind="prefix", value=_norm_abs(s))


@dataclass
class PathFilter:
    """User-provided path filters.

    Semantics:
      - exclude patterns always win
      - include patterns are used only to expand *additional* files to harvest
        (they do not restrict the default harvest set)

    Patterns:
      - By default: glob-like (supports '**')
      - Regex: prefix with 're:' or 'regex:'
      - Force glob: prefix with 'glob:'
      - A plain path without wildcards matches that path and everything under it
        (directory-prefix behavior).

    Examples:
      --exclude-path /usr/local/bin/docker-*
      --include-path /home/*/.bashrc
      --include-path 're:^/home/[^/]+/.config/myapp/.*$'
    """

    include: Sequence[str] = ()
    exclude: Sequence[str] = ()

    def __post_init__(self) -> None:
        self._include = [
            compile_path_pattern(p) for p in self.include if str(p).strip()
        ]
        self._exclude = [
            compile_path_pattern(p) for p in self.exclude if str(p).strip()
        ]

    def is_excluded(self, path: str) -> bool:
        for pat in self._exclude:
            if pat.matches(path):
                return True
        return False

    def iter_include_patterns(self) -> List[CompiledPathPattern]:
        return list(self._include)


def expand_includes(
    patterns: Sequence[CompiledPathPattern],
    *,
    exclude: Optional[PathFilter] = None,
    max_files: int = 4000,
) -> Tuple[List[str], List[str]]:
    """Expand include patterns into concrete file paths.

    Returns (paths, notes). The returned paths are absolute paths.

    This function is intentionally conservative:
      - symlinks are ignored (both dirs and files)
      - the number of collected files is capped

    Regex patterns are expanded by walking a best-effort inferred root.
    """

    out: List[str] = []
    notes: List[str] = []
    seen: Set[str] = set()

    def _maybe_add_file(p: str) -> None:
        if len(out) >= max_files:
            return
        p = _norm_abs(p)
        if exclude and exclude.is_excluded(p):
            return
        if p in seen:
            return
        if not os.path.isfile(p) or os.path.islink(p):
            return
        seen.add(p)
        out.append(p)

    def _walk_dir(root: str, match: Optional[CompiledPathPattern] = None) -> None:
        root = _norm_abs(root)
        if not os.path.isdir(root) or os.path.islink(root):
            return
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Prune excluded directories early.
            if exclude:
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not exclude.is_excluded(os.path.join(dirpath, d))
                    and not os.path.islink(os.path.join(dirpath, d))
                ]
            for fn in filenames:
                if len(out) >= max_files:
                    return
                p = os.path.join(dirpath, fn)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                if exclude and exclude.is_excluded(p):
                    continue
                if match is not None and not match.matches(p):
                    continue
                if p in seen:
                    continue
                seen.add(p)
                out.append(_norm_abs(p))

    for pat in patterns:
        if len(out) >= max_files:
            notes.append(
                f"Include cap reached ({max_files}); some includes were not expanded."
            )
            break

        matched_any = False

        if pat.kind == "prefix":
            p = pat.value
            if os.path.isfile(p) and not os.path.islink(p):
                _maybe_add_file(p)
                matched_any = True
            elif os.path.isdir(p) and not os.path.islink(p):
                before = len(out)
                _walk_dir(p)
                matched_any = len(out) > before
            else:
                # Still allow prefix patterns that don't exist now (e.g. remote different)
                # by matching nothing rather than erroring.
                matched_any = False

        elif pat.kind == "glob":
            # Use glob for expansion; also walk directories that match.
            gpat = pat.value
            hits = glob.glob(gpat, recursive=True)
            for h in hits:
                if len(out) >= max_files:
                    break
                h = _norm_abs(h)
                if exclude and exclude.is_excluded(h):
                    continue
                if os.path.isdir(h) and not os.path.islink(h):
                    before = len(out)
                    _walk_dir(h)
                    if len(out) > before:
                        matched_any = True
                elif os.path.isfile(h) and not os.path.islink(h):
                    _maybe_add_file(h)
                    matched_any = True

        else:  # regex
            rex = pat.value
            prefix = _regex_literal_prefix(rex)
            # Determine a walk root. If we can infer an absolute prefix, use its
            # directory; otherwise fall back to '/'.
            if prefix.startswith("/"):
                root = os.path.dirname(prefix) or "/"
            else:
                root = "/"
            before = len(out)
            _walk_dir(root, match=pat)
            matched_any = len(out) > before

        if not matched_any:
            notes.append(f"Include pattern matched no files: {pat.raw!r}")

    return out, notes
