# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""A packaged agent cannot read its own sudoers fragment (sudo requires
/etc/sudoers.d to be root-only), so it asks sudo for its grants with
``sudo -n -l``.  Before 2026-10-15 it fell through to ``sudo -n true`` --
never on the allowlist -- and every packaged agent reported itself
unprivileged, which disabled reboot, roles, accounts and more in the UI.
The listing below is RECORDED from a PPA-installed Ubuntu 26.04 agent."""

from pathlib import Path
from unittest.mock import patch

from src.sysmanage_agent.core import agent_privileges as ap

LISTING = (
    Path(__file__).parent / "fixtures" / "privileges" / "ubuntu_sudo_listing.txt"
).read_text()


def _check(listing):
    with patch.object(ap, "_read_sudoers_file", return_value=None), patch.object(
        ap, "_sudo_listing", return_value=listing
    ), patch.object(ap, "_test_sudo_access", return_value=False) as fallback:
        return ap._check_sudoers_privileges("sysmanage-agent"), fallback


def test_the_packaged_ubuntu_allowlist_is_privileged():
    assert ap._parse_sudo_listing(LISTING) == {"apt", "systemctl"}
    privileged, fallback = _check(LISTING)
    assert privileged is True
    fallback.assert_not_called()


def test_a_package_manager_without_service_control_is_not_enough():
    only_apt = "    (ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get\n"
    assert _check(only_apt)[0] is False


def test_rpm_hosts_count_too():
    # constructed text: an RPM allowlist names dnf, never apt
    rpm = (
        "    (ALL) NOPASSWD: /usr/bin/dnf\n"
        "    (ALL) NOPASSWD: /usr/bin/systemctl restart *, /usr/bin/systemctl start *\n"
    )
    assert _check(rpm)[0] is True
    sudoers_file = (
        "sysmanage-agent ALL=(ALL) NOPASSWD: /usr/bin/zypper, /usr/bin/systemctl\n"
    )
    assert ap._grants_suffice(
        ap._parse_sudoers_content(sudoers_file, "sysmanage-agent")
    )


def test_full_sudo_is_privileged():
    assert _check("    (ALL : ALL) NOPASSWD: ALL\n")[0] is True


def test_no_listing_falls_back_to_the_sudo_probe():
    privileged, fallback = _check(None)
    assert privileged is False
    fallback.assert_called_once()
