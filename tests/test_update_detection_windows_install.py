"""
Tests for sysmanage_agent.collection.update_detection_windows_install.

Trivial mixin: two methods that shell out to winget/choco. Mocked at the
subprocess level — verifies argv, success/failure shapes, and error
messages.
"""

# pylint: disable=redefined-outer-name,protected-access
# pylint: disable=missing-class-docstring,missing-function-docstring

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from src.sysmanage_agent.collection.update_detection_windows_install import (
    WindowsPackageInstallerMixin,
)


@pytest.fixture
def installer():
    """The mixin can be exercised on a bare instance — none of these methods
    touch other class state."""

    class _Bag(WindowsPackageInstallerMixin):
        pass

    return _Bag()


def _completed(returncode=0, stdout="", stderr=""):
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


# ---------------------------------------------------------------------------
# _install_with_winget
# ---------------------------------------------------------------------------


class TestInstallWithWinget:
    def test_success_returns_success_payload(self, installer):
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_install.subprocess.run",
            return_value=_completed(0, stdout="installed"),
        ) as run:
            result = installer._install_with_winget("Microsoft.PowerToys")
        assert result["success"] is True
        assert result["output"] == "installed"
        argv = run.call_args.args[0]
        assert argv[:3] == ["winget", "install", "--id"]
        assert "Microsoft.PowerToys" in argv
        assert "--silent" in argv

    def test_failure_returns_error_with_stderr(self, installer):
        err = subprocess.CalledProcessError(
            returncode=1,
            cmd=["winget", "install"],
            stderr="package not found",
            output="",
        )
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_install.subprocess.run",
            side_effect=err,
        ):
            result = installer._install_with_winget("Bogus.Pkg")
        assert result["success"] is False
        assert "package not found" in result["error"]
        assert "Bogus.Pkg" in result["error"]

    def test_failure_falls_back_to_stdout_when_stderr_empty(self, installer):
        err = subprocess.CalledProcessError(
            returncode=1,
            cmd=["winget", "install"],
            stderr="",
            output="installer crashed",
        )
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_install.subprocess.run",
            side_effect=err,
        ):
            result = installer._install_with_winget("Pkg")
        assert "installer crashed" in result["error"]


# ---------------------------------------------------------------------------
# _install_with_choco
# ---------------------------------------------------------------------------


class TestInstallWithChoco:
    def test_success_returns_success_payload(self, installer):
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_install.subprocess.run",
            return_value=_completed(0, stdout="ok"),
        ) as run:
            result = installer._install_with_choco("git")
        assert result["success"] is True
        argv = run.call_args.args[0]
        assert argv == ["choco", "install", "git", "-y"]

    def test_failure_returns_error(self, installer):
        err = subprocess.CalledProcessError(
            returncode=1,
            cmd=["choco", "install"],
            stderr="needs admin",
            output="",
        )
        with patch(
            "src.sysmanage_agent.collection.update_detection_windows_install.subprocess.run",
            side_effect=err,
        ):
            result = installer._install_with_choco("git")
        assert result["success"] is False
        assert "needs admin" in result["error"]
