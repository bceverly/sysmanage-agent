# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""``subprocess.run`` whose timeout actually ends the wait on Windows.

On timeout ``subprocess.run`` kills its DIRECT child and then waits for the
output pipes to close.  On Windows many tools are launchers: Chocolatey's
``choco.exe`` in ``chocolatey\\bin`` is a shim that starts the real one, and
``winget`` hands off to an app-execution alias.  Killing the launcher leaves
the real process running with the pipe open, and the "bounded" call waits
forever -- on x13s (2026-09-30) a ``choco outdated -r`` with a 60 s timeout
was still holding the agent's update check 20 minutes later, and with it
every command the server sent.

``run_bounded`` takes the same arguments as ``subprocess.run``.  On Windows,
when the timeout fires it kills the whole process TREE (``taskkill /T /F``)
and stops waiting for output a few seconds later no matter what, then raises
``TimeoutExpired`` as ``subprocess.run`` would.  Elsewhere it is exactly
``subprocess.run``.
"""

import platform
import subprocess  # nosec B404
from typing import Any, Optional

_DRAIN_SECONDS = 10


def _kill_tree(pid: int) -> None:
    try:
        subprocess.run(  # nosec B603, B607
            ["taskkill", "/T", "/F", "/PID", str(pid)],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def run_bounded(
    cmd: Any, timeout: Optional[float] = None, check: bool = False, **kwargs: Any
) -> subprocess.CompletedProcess:
    """``subprocess.run(cmd, timeout=..., check=..., **kwargs)`` that cannot
    outlive its timeout on Windows (see the module docstring)."""
    if platform.system() != "Windows" or timeout is None:
        return subprocess.run(cmd, timeout=timeout, check=check, **kwargs)  # nosec B603
    if kwargs.pop("capture_output", False):
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    with subprocess.Popen(cmd, **kwargs) as process:  # nosec B603
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(process.pid)
            try:
                stdout, stderr = process.communicate(timeout=_DRAIN_SECONDS)
            except subprocess.TimeoutExpired:
                stdout, stderr = None, None
            raise subprocess.TimeoutExpired(
                cmd, timeout, output=stdout, stderr=stderr
            ) from None
    result = subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result
