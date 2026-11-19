# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The agent's own package is upgraded last, on its own (2026-11-19).

Production: "update all" upgraded sysmanage-agent in the same apt run as a
new kernel; its restart lost the result on seven of nine hosts and took the
agent's private /var/tmp, so three kernels were left without an initramfs."""

# pylint: disable=protected-access

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.update_operations import UpdateOperations

MODULE = "src.sysmanage_agent.operations.update_operations"


def _ops():
    agent = Mock()
    agent.registration.get_system_info.return_value = {"hostname": "beast"}
    agent.create_message = Mock(
        side_effect=lambda kind, data: {"type": kind, "data": data}
    )
    agent.send_message = AsyncMock(return_value=True)
    agent.update_agent = AsyncMock(return_value={"success": True})
    ops = UpdateOperations(agent)
    return ops, agent


def _pkg(name):
    return {"package_name": name, "package_manager": "apt", "bundle_id": None}


@pytest.mark.asyncio
async def test_the_batch_runs_and_answers_before_the_agent_upgrades_itself():
    ops, agent = _ops()
    order = []
    detector = Mock()

    def apply(packages):
        order.append(("apply", [p["name"] for p in packages]))
        return {"updated_packages": [{"package_name": "linux-image-generic",
                                      "package_manager": "apt"}],
                "failed_packages": []}  # fmt: skip

    detector.apply_updates.side_effect = apply

    async def sent(message):
        order.append(("send", message["type"]))
        return True

    agent.send_message.side_effect = sent

    async def upgrade():
        order.append(("upgrade_self", None))
        return {"success": True}

    agent.update_agent.side_effect = upgrade
    with patch(f"{MODULE}.UpdateDetector", return_value=detector), \
            patch.object(ops, "_rescan_and_send_updates", new=AsyncMock()):  # fmt: skip
        await ops._apply_updates_background(
            ["linux-image-generic", "sysmanage-agent"], None,
            [_pkg("linux-image-generic"), _pkg("sysmanage-agent")],
        )  # fmt: skip

    assert order == [
        ("apply", ["linux-image-generic"]),  # never in the same apt run
        ("send", "update_apply_result"),
        ("upgrade_self", None),
    ]
    result = agent.create_message.call_args_list[0].args[1]
    names = [p["package_name"] for p in result["updated_packages"]]
    assert names == ["linux-image-generic", "sysmanage-agent"]
    assert result["updated_packages"][1]["deferred"] is True


@pytest.mark.asyncio
async def test_only_the_agent_still_answers_then_upgrades():
    ops, agent = _ops()
    detector = Mock()
    with patch(f"{MODULE}.UpdateDetector", return_value=detector), \
            patch.object(ops, "_rescan_and_send_updates", new=AsyncMock()):  # fmt: skip
        await ops._apply_updates_background(
            ["sysmanage-agent"], None, [_pkg("sysmanage-agent")]
        )
    detector.apply_updates.assert_not_called()
    agent.send_message.assert_awaited()
    agent.update_agent.assert_awaited_once()


@pytest.mark.asyncio
async def test_a_batch_without_the_agent_never_upgrades_it():
    ops, agent = _ops()
    detector = Mock()
    detector.apply_updates.return_value = {
        "updated_packages": [],
        "failed_packages": [],
    }
    with patch(f"{MODULE}.UpdateDetector", return_value=detector), \
            patch.object(ops, "_rescan_and_send_updates", new=AsyncMock()):  # fmt: skip
        await ops._apply_updates_background(["curl"], None, [_pkg("curl")])
    agent.update_agent.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failed_self_upgrade_is_logged_not_raised():
    ops, agent = _ops()
    agent.update_agent.return_value = {"success": False, "error": "E: lock"}
    with patch(f"{MODULE}.UpdateDetector", return_value=Mock()), \
            patch.object(ops, "_rescan_and_send_updates", new=AsyncMock()):  # fmt: skip
        await ops._apply_updates_background(
            ["sysmanage-agent"], None, [_pkg("sysmanage-agent")]
        )
    agent.update_agent.assert_awaited_once()
