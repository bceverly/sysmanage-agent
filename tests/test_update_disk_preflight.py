# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""An update the disk cannot hold is refused before anything changes
(2026-11-20: a 37-package update ran out of room on a host with 1.3 MB free
and left dpkg half-configured)."""

from collections import namedtuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations import update_disk_preflight as preflight
from src.sysmanage_agent.operations.update_operations import UpdateOperations

Usage = namedtuple("Usage", "total used free")
MIB = preflight.MIB
SYSTEMD = {"name": "systemd", "package_manager": "apt"}
KERNEL = {"name": "linux-image-6.8.0-151-generic", "package_manager": "apt"}


def _disks(free_by_path, device_by_path=None):
    device_by_path = device_by_path or {p: i for i, p in enumerate(free_by_path)}

    def usage(path):
        return Usage(10**12, 0, free_by_path[path])

    def device(path):
        return device_by_path[path]

    return usage, device


@pytest.fixture(autouse=True)
def unix(monkeypatch):
    monkeypatch.setattr(preflight.os, "name", "posix")
    monkeypatch.setattr(
        preflight.os.path, "isdir", lambda p: p in ("/", "/var", "/boot")
    )


def test_the_production_case_is_refused():
    usage, device = _disks({"/": int(1.3 * MIB), "/var": int(1.3 * MIB), "/boot": 700 * MIB},
                           {"/": 1, "/var": 1, "/boot": 2})  # fmt: skip
    why = preflight.shortage([SYSTEMD, KERNEL], usage=usage, device_of=device)
    assert why.startswith("Not enough disk space: / has 1 MB free")
    assert "Nothing was changed" in why


def test_room_everywhere_passes():
    usage, device = _disks({"/": 16 * 1024 * MIB, "/var": 16 * 1024 * MIB, "/boot": 700 * MIB},
                           {"/": 1, "/var": 1, "/boot": 2})  # fmt: skip
    assert preflight.shortage([SYSTEMD, KERNEL], usage=usage, device_of=device) is None


def test_a_full_boot_matters_only_for_a_kernel():
    usage, device = _disks({"/": 9000 * MIB, "/var": 9000 * MIB, "/boot": 100 * MIB},
                           {"/": 1, "/var": 1, "/boot": 2})  # fmt: skip
    assert preflight.shortage([SYSTEMD], usage=usage, device_of=device) is None
    assert "/boot has 100 MB free" in preflight.shortage(
        [KERNEL], usage=usage, device_of=device
    )


def test_a_separate_var_is_checked_too():
    usage, device = _disks({"/": 9000 * MIB, "/var": 50 * MIB, "/boot": 700 * MIB})
    assert "/var has 50 MB free" in preflight.shortage(
        [SYSTEMD], usage=usage, device_of=device
    )


def test_a_path_that_cannot_be_checked_is_never_refused_on():
    def usage(_path):
        raise OSError("gone")

    assert preflight.shortage([SYSTEMD], usage=usage, device_of=lambda p: 1) is None
    assert preflight.shortage([], usage=usage) is None


def test_every_package_is_reported_failed_with_the_reason():
    assert preflight.refused([SYSTEMD, KERNEL], "full") == [
        {"package_name": "systemd", "package_manager": "apt", "error": "full"},
        {"package_name": KERNEL["name"], "package_manager": "apt", "error": "full"},
    ]


@pytest.mark.asyncio
async def test_a_refused_batch_never_reaches_the_package_manager():
    agent = MagicMock()
    agent.registration.get_system_info.return_value = {"hostname": "fp"}
    ops = UpdateOperations(agent)
    ops._send_update_results_with_retry = AsyncMock(return_value=False)
    detector = MagicMock()
    with patch(
        "src.sysmanage_agent.operations.update_operations.UpdateDetector",
        return_value=detector,
    ), patch.object(preflight, "shortage", return_value="Not enough disk space"):
        await ops._apply_updates_background(
            ["systemd"], None,
            [{"package_name": "systemd", "package_manager": "apt"}],
        )  # fmt: skip
    detector.apply_updates.assert_not_called()
    sent = agent.create_message.call_args.args[1]
    assert sent["failed_packages"][0]["error"] == "Not enough disk space"
    assert sent["updated_packages"] == []
