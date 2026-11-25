# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The files a detached off-site run keeps (server ROADMAP 27.3).

Under ``<agent state>/offsite-cloud/<copy id>/`` (0700, the agent's own):

* ``run.lock``    -- held (flock) for as long as a run lives: "is it
  running" is "is it locked", which a reused pid cannot fake;
* ``job.json``    -- what the agent asked for (no secret in it);
* ``state.json``  -- an upload's progress, so an interrupted one RESUMES:
  the snapshot it took and, per dataset, the parts already in the bucket;
* ``status.json`` -- what it is doing now, read for progress reports;
* ``result.json`` -- how it ended, read and reported by the agent, then
  removed;
* ``run.log``     -- its output.

The secrets never touch these files: the agent writes them to the run's
standard input, and the run keeps them in memory only.
"""

import errno
import json
import os
import tempfile
from typing import Any, Dict, Optional

LOCK, JOB, STATE, STATUS, RESULT, LOG = (
    "run.lock", "job.json", "state.json", "status.json", "result.json", "run.log",
)  # fmt: skip
SPOOL = "spool"


def run_dir(state_root: str, copy_id: str) -> str:
    return os.path.join(state_root, "offsite-cloud", copy_id)


def ensure(directory: str) -> str:
    os.makedirs(directory, mode=0o700, exist_ok=True)
    # Owner only: tighter than anything the rule asks for.
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(directory, 0o700)
    return directory


def read_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_json(path: str, data: Dict[str, Any]) -> None:
    """Atomically (a temporary file renamed over it), 0600."""
    directory = os.path.dirname(path)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            json.dump(data, out, sort_keys=True)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def remove(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def take_lock(directory: str):
    """The run's lock, held by the returned file; None when another run holds
    it."""
    import fcntl  # pylint: disable=import-outside-toplevel  # Unix only

    # pylint: disable-next=consider-using-with
    handle = open(os.path.join(directory, LOCK), "a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        handle.close()
        if error.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
            return None
        raise
    return handle


def running(directory: str) -> bool:
    """Whether a run holds this copy's lock now."""
    path = os.path.join(directory, LOCK)
    if not os.path.exists(path):
        return False
    held = take_lock(directory)
    if held is None:
        return True
    held.close()
    return False
