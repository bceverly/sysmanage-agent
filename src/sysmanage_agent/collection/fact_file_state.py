# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Watched-file state — ROADMAP Phase 21.1, slice S7.

WHAT THIS COLLECTS, AND WHAT IT DELIBERATELY DOES NOT
-----------------------------------------------------
A sha256 and the stat metadata for each path in a watch list. **Never the file
contents.** That single decision is what lets an operator watch
``/etc/shadow``, a private key or a licence file without those bytes landing in
the server's database, its API responses, its backups or its logs. The cost is
real and was accepted knowingly: drift can say THAT a file changed, not WHAT
changed inside it.

WHY NOT osquery's ``file`` AND ``hash`` TABLES
----------------------------------------------
osquery returns NO ROW for a path that does not exist -- and no row for one it
could not read, and no row for one nobody asked about. Three very different
facts, one identical observation. Feeding that into a differ produces the
exact failure this phase exists to prevent: a file deleted from a host reads
the same as a file nobody watched, so it silently is not drift.

This table emits ONE ROW PER WATCHED PATH, always, carrying an explicit
``state``. Nothing downstream has to infer meaning from a row's absence.

THE FIVE STATES ARE FIVE DIFFERENT OPERATOR ACTIONS
----------------------------------------------------
* ``present``    -- stat'd and hashed. The only state with a sha256.
* ``absent``     -- the path does not exist. Real drift, not a gap.
* ``unreadable`` -- it exists and we were not allowed to look. A FIXABLE gap,
                    and emphatically not "unchanged": an agent that loses
                    permission would otherwise report every watched file as
                    stable forever.
* ``not_a_file`` -- a directory, socket or device. Metadata, no hash.
* ``too_large``  -- a regular file above the hash cap. Metadata, no hash.
                    A distinct state rather than a NULL sha256, because
                    "we chose not to hash this" and "we could not" are
                    different answers to the same question.
"""

import errno
import hashlib
import logging
import os
import stat as stat_module
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

STATE_PRESENT = "present"
STATE_ABSENT = "absent"
STATE_UNREADABLE = "unreadable"
STATE_NOT_A_FILE = "not_a_file"
STATE_TOO_LARGE = "too_large"

TYPE_REGULAR = "regular"
TYPE_DIRECTORY = "directory"
TYPE_SYMLINK = "symlink"
TYPE_OTHER = "other"

# Above this, report metadata and skip the hash. A watch list is meant for
# config files; someone who points one at a 40GB image should get a clear
# "too_large" rather than an agent that pins a core for a minute every tick.
MAX_HASH_BYTES = 64 * 1024 * 1024

# Streamed, so peak memory does not track file size.
_CHUNK = 1024 * 1024


def _owner_names(uid: int, gid: int) -> Dict[str, Optional[str]]:
    """Resolve uid/gid to names where the platform can.

    Windows has no pwd/grd, and a uid from a directory service that is down
    will not resolve either. Both leave the NAME null and keep the NUMBER,
    rather than inventing a plausible string -- a watch comparing owners across
    hosts must not match on a guess.
    """
    owner = group = None
    try:
        import pwd  # noqa: PLC0415  pylint: disable=import-outside-toplevel

        owner = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError, OverflowError, TypeError):
        pass
    try:
        import grp  # noqa: PLC0415  pylint: disable=import-outside-toplevel

        group = grp.getgrgid(gid).gr_name
    except (ImportError, KeyError, OverflowError, TypeError):
        pass
    return {"owner": owner, "group_name": group}


def _sha256(path: str) -> Optional[str]:
    """Stream a sha256, or None if the file became unreadable mid-pass."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                digest.update(chunk)
    except (OSError, PermissionError):
        return None
    return digest.hexdigest()


def _empty_row(path: str, state: str) -> Dict[str, Any]:
    """A row carrying no measurement. Every column present, all null.

    The columns are spelled out rather than left missing so a consumer reading
    row["sha256"] gets None, not a KeyError, whatever the state.
    """
    return {
        "path": path,
        "state": state,
        "sha256": None,
        "size": None,
        "mode": None,
        "uid": None,
        "gid": None,
        "owner": None,
        "group_name": None,
        "mtime": None,
        "type": None,
        "target": None,
    }


# Windows ``os.readlink`` hands back the EXTENDED-LENGTH form of an absolute
# target -- "\\?\\C:\\..." -- which is a Win32 API artifact, not part of the
# link's identity. Three reasons it must not reach the fact table:
#
#   * It is inconsistent. A link created with a RELATIVE target comes back
#     without the prefix, so two hosts holding the same configuration differ
#     only in how their link happened to be created -- and get reported as
#     drift, which is exactly the false positive this table exists to avoid.
#   * It puts ``target`` in a different namespace from ``path`` in the SAME
#     row. ``path`` arrives from the server's watch list unprefixed, so
#     comparing or displaying the two together is otherwise nonsense.
#   * An operator reading "points at \\?\\C:\\ProgramData\\..." learns nothing
#     from the prefix; it is noise in the one field meant to say where a
#     replaced config file now points.
#
# Only these two exact forms are rewritten; anything else is returned
# untouched, so a genuine UNC path or a POSIX target is never altered.
_WIN_EXTENDED = "\\\\?\\"  # the four characters: backslash backslash ? backslash
_WIN_EXTENDED_UNC = _WIN_EXTENDED + "UNC\\"


def _normalize_link_target(target: str) -> str:
    """Windows extended-length prefix removed; every other path untouched."""
    if target.startswith(_WIN_EXTENDED_UNC):
        # \\?\\UNC\\server\\share  ->  \\\\server\\share
        return "\\\\" + target[len(_WIN_EXTENDED_UNC) :]
    if target.startswith(_WIN_EXTENDED):
        return target[len(_WIN_EXTENDED) :]
    return target


def _link_info(path: str) -> Dict[str, Any]:
    """``{type, target}`` when ``path`` is itself a symlink, else empty.

    Read from lstat BEFORE following, because a config file replaced by a
    symlink to /dev/null is exactly the drift worth catching -- and stat()
    alone would report the target's innocuous state and hide it.
    """
    try:
        if not stat_module.S_ISLNK(os.lstat(path).st_mode):
            return {}
        return {
            "type": TYPE_SYMLINK,
            "target": _normalize_link_target(os.readlink(path)),
        }
    except OSError:
        return {}


def _file_type(mode: int) -> str:
    if stat_module.S_ISREG(mode):
        return TYPE_REGULAR
    if stat_module.S_ISDIR(mode):
        return TYPE_DIRECTORY
    return TYPE_OTHER


def file_state(path: str) -> Dict[str, Any]:
    """One row for one watched path. Never raises, never returns None."""
    link = _link_info(path)
    try:
        info = os.stat(path)
    except FileNotFoundError:
        # Includes a DANGLING symlink: the link exists, its content does not.
        # Reported absent, but the link fields survive so an operator can see
        # the difference between "deleted" and "points at nothing".
        row = _empty_row(path, STATE_ABSENT)
        row.update(link)
        return row
    except PermissionError:
        row = _empty_row(path, STATE_UNREADABLE)
        row.update(link)
        return row
    except OSError as exc:
        # ELOOP, ENAMETOOLONG, a dead NFS mount. Not absent -- we do not know.
        logger.debug("file_state(%s): %s", path, exc)
        row = _empty_row(
            path,
            STATE_ABSENT if exc.errno == errno.ENOENT else STATE_UNREADABLE,
        )
        row.update(link)
        return row

    ftype = link.get("type") or _file_type(info.st_mode)
    row = _empty_row(path, STATE_PRESENT)
    row.update(
        {
            "size": info.st_size,
            # Octal, zero-padded: "644" and "0644" would otherwise compare
            # unequal across hosts for identical permissions.
            "mode": format(stat_module.S_IMODE(info.st_mode), "04o"),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mtime": int(info.st_mtime),
            "type": ftype,
            "target": link.get("target"),
        }
    )
    row.update(_owner_names(info.st_uid, info.st_gid))

    if not stat_module.S_ISREG(info.st_mode):
        row["state"] = STATE_NOT_A_FILE
        return row
    if info.st_size > MAX_HASH_BYTES:
        row["state"] = STATE_TOO_LARGE
        return row

    digest = _sha256(path)
    if digest is None:
        # Readable to stat, not to open -- or it vanished between the two.
        row["state"] = STATE_UNREADABLE
        return row
    row["sha256"] = digest
    return row


def build_file_state(paths: Iterable[str]) -> List[Dict[str, Any]]:
    """The ``sysmanage_file_state`` table for a watch list.

    Order follows the watch list, and duplicates are collapsed, so two hosts
    given the same list produce row-for-row comparable tables.
    """
    seen = set()
    rows = []
    for path in paths or ():
        if not path or path in seen:
            continue
        seen.add(path)
        rows.append(file_state(path))
    return rows
