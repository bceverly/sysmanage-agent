# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""run_bounded (2026-09-30): a Windows timeout kills the whole process tree.

On x13s a ``choco outdated -r`` with a 60 s timeout held the agent for 20+
minutes: subprocess.run killed the Chocolatey shim, the real choco.exe kept
the pipe open, and the wait never ended.
"""

import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from src.sysmanage_agent.core import bounded_subprocess as bounded


def test_off_windows_it_is_exactly_subprocess_run():
    with patch.object(bounded.platform, "system", return_value="Linux"), patch.object(
        bounded.subprocess, "run", return_value="ran"
    ) as run:
        assert bounded.run_bounded(["x"], timeout=5, capture_output=True) == "ran"
    run.assert_called_once_with(["x"], timeout=5, check=False, capture_output=True)


def _popen(communicate_effects):
    process = MagicMock()
    process.pid = 4242
    process.returncode = 0
    process.communicate.side_effect = communicate_effects
    process.__enter__.return_value = process
    process.__exit__.return_value = False
    return process


def test_on_windows_a_timeout_kills_the_tree_and_stops_waiting():
    stuck = subprocess.TimeoutExpired("choco", 60)
    process = _popen([stuck, subprocess.TimeoutExpired("choco", 10)])
    with patch.object(bounded.platform, "system", return_value="Windows"), patch.object(
        bounded.subprocess, "Popen", return_value=process
    ), patch.object(bounded.subprocess, "run") as run:
        with pytest.raises(subprocess.TimeoutExpired):
            bounded.run_bounded(
                ["choco", "outdated", "-r"], timeout=60, capture_output=True
            )
    assert run.call_args.args[0] == ["taskkill", "/T", "/F", "/PID", "4242"]
    # It stopped waiting after the drain window instead of forever.
    assert process.communicate.call_count == 2


def test_on_windows_a_normal_run_returns_a_completed_process():
    process = _popen([("out", "err")])
    process.returncode = 3
    with patch.object(bounded.platform, "system", return_value="Windows"), patch.object(
        bounded.subprocess, "Popen", return_value=process
    ) as popen:
        result = bounded.run_bounded(
            ["winget"], timeout=5, capture_output=True, text=True
        )
        with pytest.raises(subprocess.CalledProcessError):
            process.communicate.side_effect = [("", "")]
            bounded.run_bounded(["winget"], timeout=5, check=True)
    assert (result.returncode, result.stdout, result.stderr) == (3, "out", "err")
    kwargs = popen.call_args_list[0].kwargs
    assert kwargs["stdout"] is subprocess.PIPE and kwargs["text"] is True


@pytest.mark.skipif(sys.platform != "win32", reason="real process tree on Windows")
def test_real_windows_grandchild_cannot_hold_the_wait():
    # cmd starts a grandchild that outlives it and inherits the pipe.
    with pytest.raises(subprocess.TimeoutExpired):
        bounded.run_bounded(
            ["cmd", "/c", "start", "/b", "ping", "-n", "30", "127.0.0.1"],
            timeout=2,
            capture_output=True,
        )
