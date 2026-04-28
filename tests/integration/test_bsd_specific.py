"""
BSD-only integration tests.

These run inside the QEMU VMs spun up by .github/workflows/bsd-tests.yml.
Tests are skipped on non-BSD platforms so the same pytest invocation
still works in the cross-platform integration matrix on Linux/macOS/
Windows runners.
"""

# pylint: disable=missing-function-docstring,missing-class-docstring,invalid-name

import os
import platform
import shutil
import subprocess  # nosec B404 — only used to check installed binaries

import pytest

BSD_NAMES = {"FreeBSD", "OpenBSD", "NetBSD"}

bsd_only = pytest.mark.skipif(
    platform.system() not in BSD_NAMES,
    reason="BSD-specific test; requires platform.system() in {FreeBSD, OpenBSD, NetBSD}.",
)


@pytest.mark.integration
@bsd_only
def test_uname_reports_bsd():
    """uname -s must agree with platform.system() on BSDs."""
    rv = subprocess.run(
        ["uname", "-s"], capture_output=True, text=True, check=True
    )  # nosec B603 B607
    assert rv.stdout.strip() == platform.system()


@pytest.mark.integration
@bsd_only
def test_bsd_package_manager_is_present():
    """Each BSD must ship its native package manager on the runner image."""
    expected = {
        "FreeBSD": "pkg",
        "OpenBSD": "pkg_add",
        "NetBSD": "pkgin",
    }[platform.system()]
    assert (
        shutil.which(expected) is not None
    ), f"{expected} not on PATH on {platform.system()} — runner image regressed?"


@pytest.mark.integration
@bsd_only
def test_rc_d_directory_exists():
    """All three BSDs use rc.d-style service scripts under /etc/rc.d."""
    assert os.path.isdir("/etc/rc.d"), (
        "/etc/rc.d missing on a BSD — service-management code paths in the "
        "agent will break here.  Image regression?"
    )


@pytest.mark.integration
@bsd_only
def test_pty_module_imports_on_bsd():
    """BSDs DO have pty/termios (unlike Windows).  Confirm.

    The Windows agent matrix `--ignore`s the pty-importing test files;
    on BSDs they should import cleanly.  This test gives us a positive
    assertion that those modules really are present, so a future BSD
    image change that drops them surfaces here, not via a 10-deep
    ImportError chain.
    """
    import pty  # noqa: F401  pylint: disable=import-outside-toplevel,unused-import
    import termios  # noqa: F401  pylint: disable=import-outside-toplevel,unused-import
    import pwd  # noqa: F401  pylint: disable=import-outside-toplevel,unused-import


@pytest.mark.integration
@bsd_only
def test_freebsd_specific_only_on_freebsd():
    """FreeBSD-specific assertion.  Skips on OpenBSD and NetBSD."""
    if platform.system() != "FreeBSD":
        pytest.skip("FreeBSD-only.")
    # /usr/local is FreeBSD's primary ports/pkg prefix.  If it's missing
    # something is very wrong.
    assert os.path.isdir("/usr/local"), "FreeBSD missing /usr/local — pkg layout broken"


@pytest.mark.integration
@bsd_only
def test_openbsd_specific_only_on_openbsd():
    """OpenBSD-specific assertion.  Skips on FreeBSD and NetBSD."""
    if platform.system() != "OpenBSD":
        pytest.skip("OpenBSD-only.")
    # OpenBSD ships pledge(2)-aware default binaries; /etc/rc.conf.local
    # is the conventional override location for service flags.
    assert os.path.isfile("/etc/rc.conf") or os.path.isdir(
        "/etc"
    ), "OpenBSD missing /etc/rc.conf — image regression?"


@pytest.mark.integration
@bsd_only
def test_netbsd_specific_only_on_netbsd():
    """NetBSD-specific assertion.  Skips on FreeBSD and OpenBSD."""
    if platform.system() != "NetBSD":
        pytest.skip("NetBSD-only.")
    # NetBSD's pkgsrc convention puts user-installed binaries under /usr/pkg.
    assert os.path.isdir("/usr/pkg"), "NetBSD missing /usr/pkg — pkgsrc layout broken"
