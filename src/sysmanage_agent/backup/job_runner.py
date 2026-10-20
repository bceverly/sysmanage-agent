# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""How a restate job is started and watched, per platform (Phase 24).

* Linux: systemd runs the fixed ``restate-job@<name>.service`` unit restate
  ships; the agent starts it with ``systemctl --no-block start`` and reads
  ``systemctl show``.
* FreeBSD (a storage host -- a NAS on ZFS): there is no systemd, so the agent
  starts ``restate run <job file>`` itself under daemon(8), detached, so the
  run outlives the agent the way a unit does.  ``daemon -p`` writes the
  child's pid to a pidfile and holds an exclusive lock on it until the child
  exits, then removes it -- so "is it still running" is "is that pidfile
  locked", which a reused pid cannot fake.  daemon forwards SIGTERM to the
  child, so stopping the run stops restate.

On FreeBSD the command line is still never built from server data: it is the
job file's fixed path (``<policy uuid>.<action>.conf``, both validated), and
the sudoers rule for it is a regular expression that admits nothing else.
"""

import os
import posixpath
from typing import List, Optional

SYSTEMD = "systemd"
DAEMON = "daemon"
DAEMON_PATH = "/usr/sbin/daemon"

# Which runner drives restate on each platform.system().  Anything else is
# not driven (yet), and the backup capability reports wrong_platform.
RUNNERS = {"Linux": SYSTEMD, "FreeBSD": DAEMON}

# The roles each runner may drive.  A FreeBSD host is a storage host only:
# the host role checks its NFS mount through /proc/self/mountinfo, which the
# BSDs do not have.
ROLES = {SYSTEMD: ("host", "storage"), DAEMON: ("storage",)}

LOG_TAIL_BYTES = 2000


def runner_for(system: Optional[str]) -> Optional[str]:
    """The runner for ``platform.system()``, or None when it is not driven."""
    return RUNNERS.get(system or "")


def run_dir(state_dir: str) -> str:
    """Where daemon(8) keeps each run's pidfile and output."""
    return posixpath.join(state_dir, "backup", "run")


def pidfile(state_dir: str, name: str) -> str:
    return posixpath.join(run_dir(state_dir), name + ".pid")


def logfile(state_dir: str, name: str) -> str:
    return posixpath.join(run_dir(state_dir), name + ".log")


def daemon_argv(
    restate: str, job_file: str, pid_path: str, log_path: str, privileged
) -> List[str]:
    """``daemon -f -p PIDFILE -o LOG [sudo -n] RESTATE run JOBFILE``.

    daemon itself runs as the agent, so its pidfile and log are the agent's
    to read; only restate is elevated.
    """
    return [DAEMON_PATH, "-f", "-p", pid_path, "-o", log_path] + privileged(
        [restate, "run", job_file]
    )


def pidfile_locked(path: str) -> bool:
    """True while daemon(8) still holds ``path``'s lock: the run is going."""
    import fcntl  # pylint: disable=import-outside-toplevel  # Unix only

    try:
        handle = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    try:
        fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError:
        return True
    finally:
        os.close(handle)
    return False


def log_tail(path: str) -> Optional[str]:
    """The end of a run's output, for a run that left no result file."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - LOG_TAIL_BYTES))
            text = handle.read().decode("utf-8", "replace").strip()
    except OSError:
        return None
    return text or None
