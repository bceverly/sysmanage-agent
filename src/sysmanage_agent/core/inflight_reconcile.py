# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Startup reconciliation of in-flight subprocess journals (Phase 11.6).

Moved out of ``agent_utils`` to keep that module under the 1000-line limit;
``agent_utils`` re-exports it, so existing imports keep working.
"""

import logging
from typing import Any, Dict

from src.database.models import Priority
from src.i18n import _
from src.sysmanage_agent.operations import inflight_journal


async def reconcile_inflight_journal(agent) -> Dict[str, Any]:
    """Phase 11.6 startup hook: reconcile leftover in-flight subprocess journals.

    Runs once at agent startup, before the WebSocket connection is
    established.  Walks ``~/.sysmanage-agent/inflight/`` and for each
    leftover journal entry:

        * If the recorded PID is still alive (the agent restarted but the
          subprocess kept running): leave the entry in place and log it.
        * If the PID is gone: queue a synthetic ``command_result`` with
          ``killed_by_restart=True`` so the server's DISPATCHED row clears,
          then delete the entry.

    Args:
        agent: The SysManageAgent instance (used to access the
            persistent outbound message queue).

    Returns:
        Dict with ``live`` and ``dead`` lists of message_ids that were
        classified, suitable for diagnostic logging.
    """
    logger = logging.getLogger(__name__)
    pending: list = []

    def _enqueue(payload: Dict[str, Any]) -> None:
        # Wrap as a normal command_result message; queue_outbound_message
        # is async, but scan_inflight_on_startup is sync, so we collect
        # the payloads here and ship them in the loop below.
        pending.append(payload)

    classified = inflight_journal.scan_inflight_on_startup(_enqueue)

    for payload in pending:
        try:
            message = agent.create_message("command_result", payload)
            await agent.message_handler.queue_outbound_message(
                message, priority=Priority.HIGH
            )
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.exception(
                _("Failed to queue synthetic command_result for in-flight journal: %s"),
                error,
            )

    if classified["live"] or classified["dead"]:
        logger.info(
            "In-flight journal reconciliation: %d live, %d dead",
            len(classified["live"]),
            len(classified["dead"]),
        )
    return classified
