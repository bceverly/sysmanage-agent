# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Package manager health as its own message (2026-11-19): riding only on
the update scan, which a reconnecting agent skips when one ran recently, a
host left with a half-configured kernel showed healthy for hours."""

# pylint: disable=protected-access

import asyncio
from unittest.mock import AsyncMock, Mock, patch

from src.sysmanage_agent.collection import boot_safety, package_manager_health
from src.sysmanage_agent.communication import send_on_change
from src.sysmanage_agent.communication.data_collector import DataCollector


def _collector(approved=True):
    agent = Mock()
    approval = Mock(host_id="host-1") if approved else None
    agent.registration_manager.get_host_approval_from_db.return_value = approval
    agent.create_message.side_effect = lambda kind, data: {"type": kind, "data": data}
    agent.send_message = AsyncMock(return_value=True)
    return DataCollector(agent), agent


BROKEN = {"manager": "dpkg", "needs_repair": True, "repairable": True,
          "reason": "Packages not fully installed: linux-image-7.0.0-44-generic"}  # fmt: skip


def test_the_health_and_reboot_verdict_go_up_with_the_host_id():
    dc, agent = _collector()
    verdict = {"reboot_unsafe": True, "reboot_unsafe_reason": "Not safe to reboot"}
    with patch.object(package_manager_health, "check", return_value=dict(BROKEN)), \
            patch.object(boot_safety, "assess", return_value=verdict):  # fmt: skip
        asyncio.run(dc._send_package_manager_health())
    message = agent.send_message.await_args.args[0]
    assert message["type"] == "package_manager_health"
    assert message["data"] == {**BROKEN, **verdict, "host_id": "host-1"}


def test_nothing_is_sent_where_nothing_is_checked():
    dc, agent = _collector()
    with patch.object(package_manager_health, "check", return_value={"manager": None}):
        asyncio.run(dc._send_package_manager_health())
    agent.send_message.assert_not_awaited()


def test_nothing_is_sent_before_approval():
    dc, agent = _collector(approved=False)
    with patch.object(package_manager_health, "check") as check:
        asyncio.run(dc._send_package_manager_health())
    check.assert_not_called()
    agent.send_message.assert_not_awaited()


def test_it_is_sent_only_when_it_changes():
    """send-on-change gates it like the other status reports."""
    assert "package_manager_health" in send_on_change.SNAPSHOT_TYPES
    assert send_on_change.supersedes("package_manager_health")


def test_it_runs_with_every_periodic_collection():
    import inspect  # pylint: disable=import-outside-toplevel

    source = inspect.getsource(DataCollector)
    assert "self._send_package_manager_health," in source
