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

* Linux without systemd (Alpine, OpenRC) and macOS (25.8): neither systemd
  nor daemon(8), so the agent starts the run through ``backup/detach.py``,
  which does what ``daemon -f -p`` does -- detached, its pidfile locked until
  restate exits, SIGTERM passed on -- and is watched the same way.

Off systemd the command line is still never built from server data: it is
the job file's fixed path (``<policy uuid>.<action>.conf``, both validated),
and the sudoers rule for it is a regular expression that admits nothing else.

OpenBSD and NetBSD (25.5): their NFS clients speak NFSv2 and v3 only, and a
host's repository is an NFSv4 export, so they back up only through
restate-proxy, over HTTPS -- once their restate captures through it.  Then
``detach.py`` drives them as it does macOS, as backed-up hosts only (they
are never storage hosts: no NFSv4 server for the repositories either).
"""

import os
import posixpath
import sys
from typing import List, Optional, Tuple

SYSTEMD = "systemd"
DAEMON = "daemon"
DETACH = "detach"
DAEMON_PATH = "/usr/sbin/daemon"
DETACH_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detach.py")

# Which runner drives restate on each platform.system() (Linux: systemd when
# it is PID 1, else DETACH).  Anything else is not driven, and the backup
# capability reports wrong_platform.
RUNNERS = {"FreeBSD": DAEMON, "Darwin": DETACH, "OpenBSD": DETACH, "NetBSD": DETACH}

# The roles each runner may drive.  ``self`` (24.13): a storage host backing
# up its own OS.  Every runner drives all three; a platform may take fewer
# (PLATFORM_ROLES): macOS is never a storage host (no ZFS or btrfs to
# prepare, no NFS server set up for it).
ALL_ROLES = ("host", "storage", "self")
ROLES = {SYSTEMD: ALL_ROLES, DAEMON: ALL_ROLES, DETACH: ALL_ROLES}
PLATFORM_ROLES = {"Darwin": ("host",), "OpenBSD": ("host",), "NetBSD": ("host",)}
# No NFSv4 client: these back up through restate-proxy alone.
NO_NFSV4 = ("OpenBSD", "NetBSD")

LOG_TAIL_BYTES = 2000


def systemd_running(isdir=os.path.isdir) -> bool:
    """systemd is PID 1 (sd_booted's test)."""
    return isdir("/run/systemd/system")


def runner_for(system: Optional[str], systemd=None) -> Optional[str]:
    """The runner for ``platform.system()``, or None when it is not driven.
    ``systemd``: whether systemd is PID 1 (looked up when not given)."""
    if system == "Linux":
        if systemd is None:
            systemd = systemd_running()
        return SYSTEMD if systemd else DETACH
    return RUNNERS.get(system or "")


def roles_for(system: Optional[str], runner: Optional[str]) -> Tuple[str, ...]:
    """The roles this platform's runner may drive."""
    roles = ROLES.get(runner or "", ())
    allowed = PLATFORM_ROLES.get(system or "")
    return tuple(role for role in roles if allowed is None or role in allowed)


def detached(runner: Optional[str]) -> bool:
    """Watched through a locked pidfile (daemon(8) or detach.py), not systemd."""
    return runner in (DAEMON, DETACH)


def run_dir(state_dir: str) -> str:
    """Where daemon(8) and detach.py keep each run's pidfile and output."""
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


def detach_argv(
    restate: str, job_file: str, pid_path: str, log_path: str, privileged
) -> List[str]:
    """``python3 -I detach.py PIDFILE LOG -- [sudo -n] RESTATE run JOBFILE``.

    The agent's own interpreter, isolated (-I: no environment, no user site,
    not the agent's directory on the path); detach.py runs as the agent and
    only restate is elevated, as under daemon(8).
    """
    return [sys.executable, "-I", DETACH_SCRIPT, pid_path, log_path, "--"] + privileged(
        [restate, "run", job_file]
    )


def start_argv(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    runner: str, restate: str, job_file: str, pid_path: str, log_path: str, privileged
) -> List[str]:
    """The command that starts one detached run on ``runner``."""
    build = daemon_argv if runner == DAEMON else detach_argv
    return build(restate, job_file, pid_path, log_path, privileged)


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
