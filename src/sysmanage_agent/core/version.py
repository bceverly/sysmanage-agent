# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

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
from pathlib import Path

from src.i18n import _

logger = logging.getLogger(__name__)

_CACHED_VERSION: dict[str, str] = {}


def _try_run(argv: list[str]) -> str | None:
    """Run a command with a 5s timeout and return stdout on rc=0, else None."""
    return _try_run_in(argv, None)


def _try_run_in(argv: list[str], cwd) -> str | None:
    """``_try_run`` with an explicit working directory."""
    try:
        result = subprocess.run(  # nosec B603 - args are hardcoded constants
            argv,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            cwd=cwd,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    out = result.stdout.strip()
    return out or None


def _repo_root() -> Path:
    """The checkout root, derived from this file's own location.

    ``src/sysmanage_agent/core/version.py`` -- four levels up is the repo.
    """
    return Path(__file__).resolve().parents[3]


def _is_source_checkout() -> bool:
    """Are we running from a git working tree rather than an install?

    A packaged agent (.deb/.rpm/pkg/pip) never ships ``.git``, so this is
    unambiguous in both directions.
    """
    try:
        return (_repo_root() / ".git").exists()
    except OSError:
        return False


def _from_git() -> str | None:
    """The checkout's own tag, with a ``-dev`` suffix.

    Run with ``cwd`` pinned to the repo root. Without that, ``git describe``
    inherits the agent's working directory -- which for a service is wherever
    the rc script left it, quite possibly a different repository or none --
    and would answer about the wrong tree or not at all.
    """
    root = _repo_root()
    # ``-c safe.directory=<root>``: git refuses to operate on a repository
    # owned by another user ("detected dubious ownership") and exits non-zero.
    # The agent normally runs as ROOT from a checkout owned by an operator --
    # which is exactly how ``make start-privileged`` deploys it -- so every
    # privileged agent reported its version as "unknown". Measured on OpenBSD
    # 7.9 on 2026-09-21; the same checkout resolved correctly as the owning
    # user moments earlier.
    #
    # Scoped to THIS path for THIS invocation: no global config is written and
    # nothing else on the host becomes trusted. The path is derived from this
    # module's own ``__file__``, so it is the code that is already executing.
    out = _try_run_in(
        [
            "git",
            "-c",
            f"safe.directory={root}",
            "describe",
            "--tags",
            "--abbrev=0",
        ],
        root,
    )
    return out + "-dev" if out else None


def _from_os_package_manager() -> str | None:
    """Query the host's package manager for the installed agent version.

    Covers the case where the agent was installed via .deb / .rpm / pkg
    but the package didn't drop a Python ``dist-info/METADATA`` directory
    (which is the typical state for native OS packages -- they don't run
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
    0. A git checkout describes ITSELF -- an installed package on the same
       box must not shadow the code that is actually running.
    1. ``importlib.metadata`` -- works for ``pip install`` deployments.
    2. OS package manager (dpkg / rpm / pkg) -- works for the .deb / .rpm /
       pkg packages we ship via GitHub releases (the typical install
       method for child hosts created via the Pro+ engine plans, where
       the package doesn't drop a Python ``dist-info`` for
       ``importlib.metadata``).
    3. ``git describe --tags`` with a ``-dev`` suffix -- running from a
       source checkout.
    4. ``"unknown"`` fallback.

    The result is cached after the first call.
    """
    if "value" in _CACHED_VERSION:
        return _CACHED_VERSION["value"]

    # 0. A source checkout answers for ITSELF, before anything installed.
    #
    # Without this, a dev box that ALSO has the agent package installed
    # reports the package's version forever: steps 1 and 2 below both find a
    # record that a ``git pull`` cannot touch, because it does not come from
    # the code. Observed 2026-09-21 on a FreeBSD host running a current
    # checkout -- it advertised the Phase 21.1 fact coverage built that day
    # while reporting 3.5.1.10, the version of a pkg installed months earlier.
    #
    # That is not merely cosmetic: the server compares agent_version against
    # the latest release, so a stale string makes a fully up-to-date host look
    # like it needs an upgrade it has already had.
    #
    # Safe in production by construction: a packaged install has no ``.git``,
    # so this step is invisible there and the order below is unchanged.
    if _is_source_checkout():
        git_first = _from_git()
        if git_first:
            _CACHED_VERSION["value"] = git_first
            logger.info("Agent version from source checkout: %s", git_first)
            return git_first

    # 1. importlib.metadata (pip installs)
    try:
        _CACHED_VERSION["value"] = pkg_version("sysmanage-agent")
        logger.info("Agent version from package metadata: %s", _CACHED_VERSION["value"])
        return _CACHED_VERSION["value"]
    except Exception:  # pylint: disable=broad-except
        pass  # nosec B110 - expected fallthrough

    # 2. OS package manager (.deb / .rpm / FreeBSD pkg)
    os_pkg_version = _from_os_package_manager()
    if os_pkg_version:
        _CACHED_VERSION["value"] = os_pkg_version
        logger.info("Agent version from OS package manager: %s", os_pkg_version)
        return os_pkg_version

    # 3. git describe -- reached when there is no ``.git`` beside the source
    # but git can still describe the working directory (a vendored tree, say).
    git_out = _from_git()
    if git_out:
        _CACHED_VERSION["value"] = git_out
        logger.info("Agent version from git: %s", git_out)
        return git_out

    _CACHED_VERSION["value"] = "unknown"
    logger.warning(_("Could not determine agent version, using 'unknown'"))
    return _CACHED_VERSION["value"]
