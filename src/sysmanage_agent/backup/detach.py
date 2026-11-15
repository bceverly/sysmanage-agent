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
import re
import signal
import subprocess  # nosec B404 - runs the one fixed command it is given
import sys

ALREADY_RUNNING = 3
USAGE = 2

# The pidfile and log are ``<state dir>/backup/run/<job name>.{pid,log}``
# (``job_runner.pidfile`` / ``logfile``) and the command is
# ``[sudo -n] RESTATE run JOBFILE`` (``job_runner.detach_argv``).  Anything
# else is refused, not run: argv is validated here, never passed through.
RUN_DIR_TAIL = ("backup", "run")
_NAME = r"[0-9A-Za-z][0-9A-Za-z._-]{0,254}"
_PID_NAME = re.compile(_NAME + r"\.pid")
_LOG_NAME = re.compile(_NAME + r"\.log")
_JOB_NAME = re.compile(_NAME + r"\.conf")
RESTATE_NAME = "restate"
SUDO = ("sudo", "-n")


class Refused(ValueError):
    """An argument that is not what the agent passes; nothing is started."""


def _confined(path: str, pattern: "re.Pattern") -> str:
    """``path`` resolved: an absolute file named by ``pattern`` that stays
    inside its (resolved) directory; else Refused."""
    if "\0" in path or not os.path.isabs(path):
        raise Refused(f"not an absolute path: {path!r}")
    name = os.path.basename(path)
    if not pattern.fullmatch(name):
        raise Refused(f"unexpected file name: {name!r}")
    base = os.path.realpath(os.path.dirname(path))
    if not os.path.isdir(base):
        raise Refused(f"not a directory: {os.path.dirname(path)!r}")
    resolved = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, resolved]) != base:
        raise Refused(f"outside {base!r}: {path!r}")
    return resolved


def run_files(pid_path: str, log_path: str) -> tuple:
    """The validated (pidfile, log): both in the same ``.../backup/run``."""
    pid = _confined(pid_path, _PID_NAME)
    log = _confined(log_path, _LOG_NAME)
    base = os.path.dirname(pid)
    if os.path.dirname(log) != base:
        raise Refused("the pidfile and the log are in different directories")
    if tuple(base.split(os.sep)[-len(RUN_DIR_TAIL) :]) != RUN_DIR_TAIL:
        raise Refused(f"not a backup run directory: {base!r}")
    return pid, log


def _executable(path: str) -> str:
    """restate's absolute path, resolved; else Refused."""
    if "\0" in path or not os.path.isabs(path):
        raise Refused(f"not an absolute path: {path!r}")
    if os.path.basename(path) != RESTATE_NAME:
        raise Refused(f"not restate: {path!r}")
    resolved = os.path.realpath(path)
    if not (os.path.isfile(resolved) and os.access(resolved, os.X_OK)):
        raise Refused(f"not an executable file: {path!r}")
    return os.path.join(os.path.dirname(os.path.normpath(path)), RESTATE_NAME)


def _job_file(path: str) -> str:
    if "\0" in path or not os.path.isabs(path):
        raise Refused(f"not an absolute path: {path!r}")
    name = os.path.basename(path)
    if not _JOB_NAME.fullmatch(name) or ".." in path.split("/"):
        raise Refused(f"not a job file: {path!r}")
    return os.path.join(os.path.normpath(os.path.dirname(path)), name)


def command_argv(command: list) -> list:
    """The child's argv, built from the allow-list: ``[sudo -n] RESTATE run
    JOBFILE`` and nothing else."""
    elevated = tuple(command[: len(SUDO)]) == SUDO
    rest = command[len(SUDO) :] if elevated else command
    if len(rest) != 3 or rest[1] != "run":
        raise Refused("the command is not [sudo -n] restate run JOBFILE")
    argv = [_executable(rest[0]), "run", _job_file(rest[2])]
    return list(SUDO) + argv if elevated else argv


def _lock(path: str) -> int:
    """The pidfile, opened and locked; exits ALREADY_RUNNING when held."""
    import fcntl  # pylint: disable=import-outside-toplevel  # Unix only

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    handle = os.open(path, flags, 0o600)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.stderr.write(f"detach: {path} is locked: already running\n")
        sys.exit(ALREADY_RUNNING)
    return handle


def _detach_output(log_path: str) -> None:
    null = os.open(os.devnull, os.O_RDONLY)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    log = os.open(log_path, flags, 0o600)
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
    try:
        pid_path, log_path = run_files(argv[0], argv[1])
        command = command_argv(argv[3:])
    except Refused as refused:
        sys.stderr.write(f"detach: refused: {refused}\n")
        return USAGE
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
