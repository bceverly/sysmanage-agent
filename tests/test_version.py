# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Tests for ``sysmanage_agent.core.version`` agent-version resolution.

Covers the resolution order:
0. a git checkout describing ITSELF (added 2026-09-21 — see
   ``TestSourceCheckoutTier``)
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

import pytest

from src.sysmanage_agent.core import version


def _reset_cache():
    version._CACHED_VERSION.clear()  # pylint: disable=protected-access


@pytest.fixture(autouse=True)
def not_a_checkout(request):
    """Pin every test to "installed, not a checkout" unless it says otherwise.

    These are TIER tests: each one asserts what a given tier answers, so the
    tier has to be controlled rather than inherited from wherever the suite
    happens to be running.  Without this they pass in a release tarball and
    fail in a working tree — and it was a working tree that surfaced the bug
    the checkout tier exists to fix.
    """
    if "checkout" in request.node.name:
        yield
        return
    with patch(
        "src.sysmanage_agent.core.version._is_source_checkout", return_value=False
    ):
        yield


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


class TestSourceCheckoutTier:
    """A checkout answers for ITSELF, ahead of anything installed.

    The bug, seen on a live FreeBSD host 2026-09-21: it was running a current
    checkout — its capability report carried the Phase 21.1 fact coverage
    built that day — while reporting ``3.5.1.10``, the version of a pkg
    installed months earlier.  A ``git pull`` could never fix it, because the
    string was not coming from the code.
    """

    def test_checkout_wins_over_a_stale_installed_package(self):
        _reset_cache()

        def fake_run(argv, **_kwargs):
            if argv[0] == "git":
                return _make_completed("v3.8.0.1")
            return _make_completed("", returncode=1)

        with patch(
            "src.sysmanage_agent.core.version._is_source_checkout", return_value=True
        ), patch(
            "src.sysmanage_agent.core.version.pkg_version", return_value="3.5.1.10"
        ), patch(
            "src.sysmanage_agent.core.version._from_os_package_manager",
            return_value="3.5.1.10",
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run", side_effect=fake_run
        ):
            assert version.get_agent_version() == "v3.8.0.1-dev"

    def test_checkout_describes_its_own_tree_not_the_working_directory(self):
        """``cwd`` is pinned to the repo root.  A service's working directory
        is wherever its rc script left it — quite possibly another repo."""
        _reset_cache()
        seen = {}

        def fake_run(argv, **kwargs):
            if argv[0] == "git":
                seen["cwd"] = kwargs.get("cwd")
                return _make_completed("v3.8.0.1")
            return _make_completed("", returncode=1)

        with patch(
            "src.sysmanage_agent.core.version._is_source_checkout", return_value=True
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run", side_effect=fake_run
        ):
            version.get_agent_version()
        assert seen["cwd"] == version._repo_root()  # pylint: disable=protected-access

    def test_a_checkout_with_no_tags_falls_through_rather_than_lying(self):
        """A shallow clone has no tags.  That is not a reason to report
        nothing — the installed package is still a true answer."""
        _reset_cache()

        def fake_run(argv, **_kwargs):
            return _make_completed("", returncode=1)

        with patch(
            "src.sysmanage_agent.core.version._is_source_checkout", return_value=True
        ), patch(
            "src.sysmanage_agent.core.version.pkg_version",
            side_effect=importlib.metadata.PackageNotFoundError(),
        ), patch(
            "src.sysmanage_agent.core.version._from_os_package_manager",
            return_value="3.5.1.10",
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run", side_effect=fake_run
        ):
            assert version.get_agent_version() == "3.5.1.10"

    def test_a_packaged_install_is_not_treated_as_a_checkout(self):
        """Production is unaffected: a .deb/.rpm/pkg ships no ``.git``, so the
        new step is invisible there and the old order stands."""
        _reset_cache()
        with patch(
            "src.sysmanage_agent.core.version._is_source_checkout", return_value=False
        ), patch(
            "src.sysmanage_agent.core.version.pkg_version",
            side_effect=importlib.metadata.PackageNotFoundError(),
        ), patch(
            "src.sysmanage_agent.core.version._from_os_package_manager",
            return_value="3.5.1.10",
        ):
            assert version.get_agent_version() == "3.5.1.10"


class TestRootOwnedCheckout:
    """A privileged agent must still know its version.

    git refuses to operate on a repository owned by another user — "detected
    dubious ownership" — and exits non-zero. The agent normally runs as ROOT
    from a checkout owned by an operator, which is exactly how
    ``make start-privileged`` deploys it, so every privileged agent reported
    its version as ``unknown``. Measured on OpenBSD 7.9 on 2026-09-21: the
    same checkout resolved correctly as the owning user moments earlier.
    """

    def test_the_repo_is_trusted_for_this_invocation(self):
        _reset_cache()
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            seen["cwd"] = kwargs.get("cwd")
            return _make_completed("v3.8.0.1")

        with patch(
            "src.sysmanage_agent.core.version._is_source_checkout", return_value=True
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run", side_effect=fake_run
        ):
            assert version.get_agent_version() == "v3.8.0.1-dev"

        root = str(version._repo_root())  # pylint: disable=protected-access
        assert "-c" in seen["argv"]
        assert f"safe.directory={root}" in seen["argv"]

    def test_only_this_path_is_trusted_not_a_wildcard(self):
        """A global or wildcard exception would make every repository on the
        host trusted by root — far more than reading one version needs."""
        _reset_cache()
        seen = {}

        def fake_run(argv, **_kwargs):
            seen["argv"] = argv
            return _make_completed("v3.8.0.1")

        with patch(
            "src.sysmanage_agent.core.version._is_source_checkout", return_value=True
        ), patch(
            "src.sysmanage_agent.core.version.subprocess.run", side_effect=fake_run
        ):
            version.get_agent_version()

        assert "safe.directory=*" not in seen["argv"]
        assert "--global" not in seen["argv"]
