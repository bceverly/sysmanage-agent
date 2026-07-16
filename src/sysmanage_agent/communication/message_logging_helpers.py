# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Message logging helper functions.

Standalone logging functions extracted from MessageHandler to reduce module size.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from src.i18n import _


def log_child_host_received(
    logger, data: Dict[str, Any], queue_message_id: str, params: Dict[str, Any]
) -> None:
    """Log detailed info when a create_child_host command is received."""
    timestamp = datetime.now(timezone.utc).isoformat()
    # Structural diagnostic marker (field=value trace), not user prose.
    logger.info(
        ">>> [CREATE_CHILD_HOST_RECEIVED] timestamp=%s queue_message_id=%s "
        "message_id=%s vm_name=%s hostname=%s child_host_id=%s",
        timestamp,
        queue_message_id,
        data.get("message_id"),
        params.get("vm_name"),
        params.get("hostname"),
        params.get("child_host_id"),
    )


def log_duplicate_message(
    logger, command_type: str, params: Dict[str, Any], queue_message_id: str
) -> None:
    """Log when a duplicate message is skipped."""
    if command_type == "create_child_host":
        logger.info(
            _(
                ">>> [CREATE_CHILD_HOST_DUPLICATE] Skipping duplicate vm_name=%s "
                "queue_message_id=%s"
            ),
            params.get("vm_name"),
            queue_message_id,
        )
    logger.info(_("Skipping duplicate command message: %s"), queue_message_id)
