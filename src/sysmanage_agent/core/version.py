"""
Agent version detection module.
Provides the running agent version for heartbeat and registration messages.
"""

# PEP 604 ``X | None`` and PEP 585 ``list[str]`` syntax used below need
# either Python 3.10+ or this future import.  Agent CI matrix includes
# 3.9 (Rocky/RHEL/Amazon Linux 9 default), so the future import keeps
# annotations as strings and the types stay valid at runtime.
from __future__ import annotations

import logging
import subprocess
from importlib.metadata import version as pkg_version

from src.i18n import _

logger = logging.getLogger(__name__)

_CACHED_VERSION: dict[str, str] = {}


def _try_run(argv: list[str]) -> str | None:
    """Run a command with a 5s timeout and return stdout on rc=0, else None."""
    try:
        result = subprocess.run(  # nosec B603 - args are hardcoded constants
            argv,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    out = result.stdout.strip()
    return out or None


def _from_os_package_manager() -> str | None:
    """Query the host's package manager for the installed agent version.

    Covers the case where the agent was installed via .deb / .rpm / pkg
    but the package didn't drop a Python ``dist-info/METADATA`` directory
    (which is the typical state for native OS packages — they don't run
    pip, so ``importlib.metadata`` can't see the version).
    """
    # Debian/Ubuntu: dpkg-query -W -f='${Version}' sysmanage-agent
    out = _try_run(["dpkg-query", "-W", "-f=${Version}", "sysmanage-agent"])
    if out:
        return out
    # RHEL/Oracle/Fedora/SUSE: rpm -q --queryformat='%{VERSION}-%{RELEASE}'
    out = _try_run(
        ["rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", "sysmanage-agent"]
    )
    if out and "is not installed" not in out and "not installed" not in out:
        # Trim the package manager's "-N.distroX" release suffix when present;
        # the upstream version is what the server cares about.
        return out
    # FreeBSD: pkg query "%v" sysmanage-agent
    out = _try_run(["pkg", "query", "%v", "sysmanage-agent"])
    if out:
        return out
    return None


def get_agent_version() -> str:
    """
    Get the sysmanage-agent version string.

    Resolution order:
    1. ``importlib.metadata`` — works for ``pip install`` deployments.
    2. OS package manager (dpkg / rpm / pkg) — works for the .deb / .rpm /
       pkg packages we ship via GitHub releases (the typical install
       method for child hosts created via the Pro+ engine plans, where
       the package doesn't drop a Python ``dist-info`` for
       ``importlib.metadata``).
    3. ``git describe --tags`` with a ``-dev`` suffix — running from a
       source checkout.
    4. ``"unknown"`` fallback.

    The result is cached after the first call.
    """
    if "value" in _CACHED_VERSION:
        return _CACHED_VERSION["value"]

    # 1. importlib.metadata (pip installs)
    try:
        _CACHED_VERSION["value"] = pkg_version("sysmanage-agent")
        logger.info(
            _("Agent version from package metadata: %s"), _CACHED_VERSION["value"]
        )
        return _CACHED_VERSION["value"]
    except Exception:  # pylint: disable=broad-except
        pass  # nosec B110 - expected fallthrough

    # 2. OS package manager (.deb / .rpm / FreeBSD pkg)
    os_pkg_version = _from_os_package_manager()
    if os_pkg_version:
        _CACHED_VERSION["value"] = os_pkg_version
        logger.info(_("Agent version from OS package manager: %s"), os_pkg_version)
        return os_pkg_version

    # 3. git describe (source checkout)
    git_out = _try_run(["git", "describe", "--tags", "--abbrev=0"])
    if git_out:
        _CACHED_VERSION["value"] = git_out + "-dev"
        logger.info(_("Agent version from git: %s"), _CACHED_VERSION["value"])
        return _CACHED_VERSION["value"]

    _CACHED_VERSION["value"] = "unknown"
    logger.warning(_("Could not determine agent version, using 'unknown'"))
    return _CACHED_VERSION["value"]
