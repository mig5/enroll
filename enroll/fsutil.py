from __future__ import annotations

import hashlib
import os
from typing import Tuple


def file_md5(path: str) -> str:
    """Return hex MD5 of a file.

    Used for Debian dpkg baseline comparisons.
    """
    h = hashlib.md5()  # nosec
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stat_triplet(path: str) -> Tuple[str, str, str]:
    """Return (owner, group, mode) for a path.

    owner/group are usernames/group names when resolvable, otherwise numeric ids.
    mode is a zero-padded octal string (e.g. "0644").
    """
    st = os.stat(path, follow_symlinks=True)
    mode = oct(st.st_mode & 0o777)[2:].zfill(4)

    import grp
    import pwd

    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return owner, group, mode
