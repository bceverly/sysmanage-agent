# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""After applying updates the agent reports whether the host needs a reboot,
past the send-on-change gate (ROADMAP 26.1 lab, 2026-11-16): the report was
dropped as unchanged, and the server kept a stale "reboot required"."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.communication import send_on_change
from src.sysmanage_agent.operations.update_operations import UpdateOperations


@pytest.mark.asyncio
async def test_post_update_reboot_status_is_forced():
    seen = {}

    async def check():
        seen["forced"] = send_on_change.is_forced()
        return {"success": True, "reboot_required": False}

    agent = MagicMock()
    agent.connected = True
    agent.send_message = AsyncMock()
    agent.update_manager.check_reboot_status = check
    ops = UpdateOperations(agent)
    detector = MagicMock()
    detector.get_available_updates.return_value = {"total_updates": 0}
    with patch(
        "src.sysmanage_agent.operations.update_operations.UpdateDetector",
        return_value=detector,
    ):
        await ops._rescan_and_send_updates("lab")  # pylint: disable=protected-access
    assert seen == {"forced": True}
    assert send_on_change.is_forced() is False
