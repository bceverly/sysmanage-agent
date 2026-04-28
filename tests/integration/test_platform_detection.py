"""
Integration tests for cross-platform detection.

These run on every OS in the matrix (Linux, Windows, macOS, FreeBSD,
OpenBSD, NetBSD).  They exercise the agent's platform-detection paths
on a real host instead of via mocks, which is the whole reason we
have a multi-OS workflow at all.

All tests are tagged @pytest.mark.integration so they're picked up by
.github/workflows/integration-tests.yml and bsd-tests.yml.
"""

# pylint: disable=missing-function-docstring,missing-class-docstring,invalid-name

import os
import platform
import sys

import pytest

from src.sysmanage_agent.core.agent_utils import is_running_privileged

# Set of OS names we care about — keep this in sync with the workflow
# matrix.  The integration suite needs to know "what host am I on" so
# OS-specific tests can opt themselves in/out.
KNOWN_BSDS = {"FreeBSD", "OpenBSD", "NetBSD"}
KNOWN_OSES = {"Linux", "Darwin", "Windows"} | KNOWN_BSDS


@pytest.mark.integration
def test_platform_system_is_recognised():
    """The agent is meant to run on a known OS family — assert that."""
    actual = platform.system()
    assert actual in KNOWN_OSES, (
        f"platform.system()={actual!r} is not in our supported set; "
        f"either the runner regressed or we need to extend KNOWN_OSES."
    )


@pytest.mark.integration
def test_python_version_meets_floor():
    """sysmanage-agent supports Python >=3.9.  Floor must hold on every runner."""
    assert sys.version_info >= (3, 9), (
        f"Python {sys.version_info[:2]} is below the sysmanage-agent floor of 3.9.  "
        f"Pinning a different Python in CI?"
    )


@pytest.mark.integration
def test_sys_platform_consistent_with_platform_system():
    """sys.platform and platform.system() should agree about the OS family."""
    sysp = sys.platform
    pls = platform.system()
    if pls == "Linux":
        assert sysp.startswith("linux"), f"sys.platform={sysp!r}, system=Linux"
    elif pls == "Darwin":
        assert sysp == "darwin", f"sys.platform={sysp!r}, system=Darwin"
    elif pls == "Windows":
        assert sysp.startswith("win"), f"sys.platform={sysp!r}, system=Windows"
    elif pls == "FreeBSD":
        assert sysp.startswith("freebsd"), f"sys.platform={sysp!r}, system=FreeBSD"
    elif pls == "OpenBSD":
        assert sysp.startswith("openbsd"), f"sys.platform={sysp!r}, system=OpenBSD"
    elif pls == "NetBSD":
        assert sysp.startswith("netbsd"), f"sys.platform={sysp!r}, system=NetBSD"
    else:
        pytest.fail(f"Unhandled platform.system()={pls!r}")


@pytest.mark.integration
def test_is_running_privileged_returns_bool():
    """is_running_privileged() must always return a bool, even on weird OSes."""
    result = is_running_privileged()
    assert isinstance(result, bool), f"got {type(result).__name__}, want bool"


@pytest.mark.integration
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only check")
def test_unprivileged_runner_is_unprivileged():
    """A normal CI runner runs as a non-root user — verify the detector agrees.

    GitHub-hosted runners run as `runner` (uid 1001 on Linux).  BSD QEMU
    images for cross-platform-actions run as `runner` too.  None are root.
    If this test ever fails, either the runner image regressed or the
    detector is broken.
    """
    if os.geteuid() == 0:
        pytest.skip("Test only meaningful when not root.")
    assert is_running_privileged() is False
