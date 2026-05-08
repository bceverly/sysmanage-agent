"""Tests for ``sysmanage_agent.core.version`` agent-version resolution.

Covers the four-tier resolution order:
1. ``importlib.metadata`` (pip installs)
2. OS package manager — dpkg / rpm / pkg (the .deb/.rpm/FreeBSD pkg
   shipped via GitHub releases, which don't drop a Python dist-info)
3. ``git describe --tags`` with ``-dev`` suffix (source checkouts)
4. ``"unknown"`` fallback

The OS-package-manager tier was added to fix child hosts created by the
Pro+ engine plans showing ``agent_version = unknown``: those hosts
install the agent from .deb / .rpm, so importlib.metadata returns
``PackageNotFoundError`` and the version was falling through to
``unknown``.
"""

import importlib.metadata
import subprocess
from unittest.mock import patch

from src.sysmanage_agent.core import version


def _reset_cache():
    version._CACHED_VERSION.clear()  # pylint: disable=protected-access


def _make_completed(stdout: str, returncode: int = 0):
    """Build a ``CompletedProcess`` shaped like ``subprocess.run`` returns."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=""
    )


class TestImportlibMetadataTier:
    """When pip-installed, ``importlib.metadata`` is the source of truth."""

    def test_returns_pip_version_when_installed(self):
        """Returns the value from ``importlib.metadata.version`` directly."""
        _reset_cache()
        with patch(
            "src.sysmanage_agent.core.version.pkg_version", return_value="1.2.3"
        ):
            assert version.get_agent_version() == "1.2.3"


class TestOsPackageManagerTier:
    """Fired when ``importlib.metadata`` raises (i.e. .deb / .rpm install)."""

    def test_dpkg_query_succeeds(self):
        """Debian/Ubuntu hosts resolve via ``dpkg-query -W -f``."""
        _reset_cache()

        def fake_run(argv, **_kwargs):
            if argv[0] == "dpkg-query":
                return _make_completed("2.2.0.2\n")
            return _make_completed("", returncode=1)

        with patch(
            "src.sysmanage_agent.core.version.pkg_version",
            side_effect=importlib.metadata.PackageNotFoundError(),
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run", side_effect=fake_run
        ):
            assert version.get_agent_version() == "2.2.0.2"

    def test_rpm_query_succeeds_when_dpkg_absent(self):
        """RHEL/Oracle/Fedora/SUSE hosts resolve via ``rpm -q --queryformat``."""
        _reset_cache()

        def fake_run(argv, **_kwargs):
            if argv[0] == "dpkg-query":
                raise FileNotFoundError("dpkg-query: not found")
            if argv[0] == "rpm":
                return _make_completed("2.2.0.2-1.el9")
            return _make_completed("", returncode=1)

        with patch(
            "src.sysmanage_agent.core.version.pkg_version",
            side_effect=importlib.metadata.PackageNotFoundError(),
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run", side_effect=fake_run
        ):
            assert version.get_agent_version() == "2.2.0.2-1.el9"

    def test_freebsd_pkg_succeeds_when_dpkg_and_rpm_absent(self):
        """FreeBSD hosts resolve via ``pkg query %v``."""
        _reset_cache()

        def fake_run(argv, **_kwargs):
            if argv[0] in ("dpkg-query", "rpm"):
                raise FileNotFoundError(f"{argv[0]}: not found")
            if argv[0] == "pkg":
                return _make_completed("2.2.0.2")
            return _make_completed("", returncode=1)

        with patch(
            "src.sysmanage_agent.core.version.pkg_version",
            side_effect=importlib.metadata.PackageNotFoundError(),
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run", side_effect=fake_run
        ):
            assert version.get_agent_version() == "2.2.0.2"

    def test_rpm_not_installed_message_treated_as_miss(self):
        """``rpm -q sysmanage-agent`` on a host without the package emits
        ``package sysmanage-agent is not installed`` to stdout with a
        non-zero rc.  Make sure we don't return that as the version."""
        _reset_cache()

        def fake_run(argv, **_kwargs):
            if argv[0] == "dpkg-query":
                raise FileNotFoundError()
            if argv[0] == "rpm":
                return _make_completed(
                    "package sysmanage-agent is not installed\n", returncode=1
                )
            if argv[0] == "pkg":
                raise FileNotFoundError()
            if argv[0] == "git":
                return _make_completed("v2.2.0.2")
            return _make_completed("", returncode=1)

        with patch(
            "src.sysmanage_agent.core.version.pkg_version",
            side_effect=importlib.metadata.PackageNotFoundError(),
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run", side_effect=fake_run
        ):
            # rpm declined → falls through to git → "v2.2.0.2-dev"
            assert version.get_agent_version() == "v2.2.0.2-dev"


class TestGitTier:
    """Source-checkout deployments resolve via ``git describe``."""

    def test_git_describe_appends_dev_suffix(self):
        """Tag value gets ``-dev`` appended to mark it as a working-tree build."""
        _reset_cache()

        def fake_run(argv, **_kwargs):
            if argv[0] == "git":
                return _make_completed("v2.2.0.2")
            return _make_completed("", returncode=1)

        with patch(
            "src.sysmanage_agent.core.version.pkg_version",
            side_effect=importlib.metadata.PackageNotFoundError(),
        ), patch(
            "src.sysmanage_agent.core.version._from_os_package_manager",
            return_value=None,
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run", side_effect=fake_run
        ):
            assert version.get_agent_version() == "v2.2.0.2-dev"


class TestUnknownFallback:
    """When no resolver tier produces a value, return the literal ``unknown``."""

    def test_unknown_when_all_tiers_fail(self):
        """Returns ``unknown`` rather than raising when every tier fails."""
        _reset_cache()
        with patch(
            "src.sysmanage_agent.core.version.pkg_version",
            side_effect=importlib.metadata.PackageNotFoundError(),
        ), patch(
            "src.sysmanage_agent.core.version._from_os_package_manager",
            return_value=None,
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            assert version.get_agent_version() == "unknown"


class TestCaching:
    """The first successful resolution is cached for the process lifetime."""

    def test_value_cached_after_first_call(self):
        """``pkg_version`` should be hit exactly once across repeated calls."""
        _reset_cache()
        with patch(
            "src.sysmanage_agent.core.version.pkg_version", return_value="1.0.0"
        ) as mock_pkg:
            version.get_agent_version()
            version.get_agent_version()
            version.get_agent_version()
            assert mock_pkg.call_count == 1
