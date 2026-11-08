# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Run one command detached, the way FreeBSD's daemon(8) does (25.8).

    python3 -I detach.py PIDFILE LOGFILE -- COMMAND [ARG ...]

For the hosts that have neither systemd nor daemon(8) -- Alpine (OpenRC) and
macOS -- the agent starts restate's job through this script, so the run
outlives the agent the way a unit does, and the agent watches it exactly as
it watches daemon(8) on FreeBSD (``job_runner.pidfile_locked``):

* PIDFILE is opened and locked (flock, exclusive) BEFORE anything starts, and
  the lock is held by the supervising process until COMMAND has exited.  "Is
  it still running" is "is that file locked", which a reused pid cannot fake.
  A second start while one runs fails at once: the lock is taken.
* The supervisor leaves the agent's session (setsid) and its output goes to
  LOGFILE, so neither an agent restart nor a closed pipe stops the run; the
  first process returns as soon as the run has started (like ``daemon -f``).
* SIGTERM, SIGINT and SIGHUP are passed on to COMMAND, so stopping the
  supervisor stops restate.

It runs as the agent; only COMMAND is elevated (``sudo -n restate run JOB``,
whose arguments the agent never takes from the server).  Standard library
only, and nothing from the agent is imported: it runs under ``-I``.
"""

import os
import signal
import subprocess  # nosec B404 - runs the one fixed command it is given
import sys

ALREADY_RUNNING = 3
USAGE = 2


def _lock(path: str) -> int:
    """The pidfile, opened and locked; exits ALREADY_RUNNING when held."""
    import fcntl  # pylint: disable=import-outside-toplevel  # Unix only

    handle = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.stderr.write(f"detach: {path} is locked: already running\n")
        sys.exit(ALREADY_RUNNING)
    return handle


def _detach_output(log_path: str) -> None:
    null = os.open(os.devnull, os.O_RDONLY)
    log = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.dup2(null, 0)
    os.dup2(log, 1)
    os.dup2(log, 2)
    os.close(null)
    os.close(log)


def _supervise(pid_handle: int, command: list) -> int:
    """In the detached child: run COMMAND, pass signals on, return its exit."""
    # pylint: disable-next=consider-using-with  # waited on below, not scoped
    child = subprocess.Popen(command)  # nosec B603 - fixed argv, no shell
    os.ftruncate(pid_handle, 0)
    os.write(pid_handle, f"{child.pid}\n".encode())

    def forward(signum, _frame):
        try:
            child.send_signal(signum)
        except OSError:
            pass

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, forward)
    while True:
        try:
            code = child.wait()
            break
        except InterruptedError:  # pragma: no cover - retried by wait() itself
            continue
    return code if code >= 0 else 128 - code


def main(argv: list) -> int:
    if len(argv) < 4 or argv[2] != "--":
        sys.stderr.write("usage: detach.py PIDFILE LOGFILE -- COMMAND [ARG ...]\n")
        return USAGE
    pid_path, log_path, command = argv[0], argv[1], argv[3:]
    pid_handle = _lock(pid_path)
    if os.fork():
        # The child holds the lock through the same open file: closing ours
        # leaves it held until the run ends.
        os.close(pid_handle)
        return 0
    os.setsid()
    _detach_output(log_path)
    code = _supervise(pid_handle, command)
    os.close(pid_handle)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
