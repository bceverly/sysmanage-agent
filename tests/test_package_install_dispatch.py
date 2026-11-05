# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Installing from the server's Install dialog works on every platform.

Found on fresh Ubuntu 24.04 and FreeBSD 14.5 hosts (2026-11-05): the dialog
sends ``package_manager: "auto"``, which was taken to mean apt everywhere,
so FreeBSD ran apt-get; and on Ubuntu ``sudo DEBIAN_FRONTEND=... apt-get``
was refused because the sudoers rule has no SETENV.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from src.sysmanage_agent.operations import package_installation_helpers as helpers
from src.sysmanage_agent.operations.package_operations import PackageOperations

ROOT = Path(__file__).resolve().parents[1]


def test_auto_resolves_to_the_hosts_own_package_manager():
    with patch.object(helpers, "_host_package_manager", return_value="pkg"):
        groups = helpers.group_packages_by_manager(
            [{"package_name": "tree", "package_manager": "auto"}]
        )
    assert list(groups) == ["pkg"]


def test_an_explicit_manager_is_kept():
    groups = helpers.group_packages_by_manager(
        [{"package_name": "tree", "package_manager": "brew"}]
    )
    assert list(groups) == ["brew"]


def test_apt_gets_its_settings_from_the_environment_not_sudo_arguments():
    ops = PackageOperations(MagicMock())
    calls = []

    async def fake_exec(*args, **kwargs):
        calls.append((args, kwargs))
        process = MagicMock()
        process.returncode = 0
        process.communicate = AsyncMock(return_value=(b"", b""))
        return process

    with patch("asyncio.create_subprocess_exec", side_effect=fake_exec), patch.object(
        ops, "_get_package_versions", AsyncMock(return_value={})
    ):
        result = asyncio.run(
            ops._install_packages_with_apt(["tree"])
        )  # pylint: disable=protected-access
    assert result["success"]
    for args, kwargs in calls:
        assert args[:2] == ("sudo", "apt-get")
        assert not [a for a in args if "=" in a and a.split("=")[0].isupper()]
        assert kwargs["env"]["DEBIAN_FRONTEND"] == "noninteractive"


def test_sudoers_keeps_exactly_those_variables():
    sudoers = (ROOT / "installer/ubuntu/sysmanage-agent.sudoers").read_text()
    assert 'env_keep += "DEBIAN_FRONTEND DEBCONF_NONINTERACTIVE_SEEN"' in sudoers
    rules = [line for line in sudoers.splitlines() if not line.lstrip().startswith("#")]
    assert not [line for line in rules if "SETENV" in line]


def test_the_freebsd_service_can_find_sudo():
    rc = (ROOT / "installer/freebsd/sysmanage-agent.rc").read_text()
    assert "/usr/local/bin" in rc.split("export PATH=", 1)[1].splitlines()[0]
