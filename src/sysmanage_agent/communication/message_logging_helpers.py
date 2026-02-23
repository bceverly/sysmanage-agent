"""
Message logging helper functions.

Standalone logging functions extracted from MessageHandler to reduce module size.
"""

from datetime import datetime, timezone
from typing import Any, Dict


def log_child_host_received(
    logger, data: Dict[str, Any], queue_message_id: str, params: Dict[str, Any]
) -> None:
    """Log detailed info when a create_child_host command is received."""
    timestamp = datetime.now(timezone.utc).isoformat()
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
            ">>> [CREATE_CHILD_HOST_DUPLICATE] Skipping duplicate vm_name=%s "
            "queue_message_id=%s",
            params.get("vm_name"),
            queue_message_id,
        )
    logger.info("Skipping duplicate command message: %s", queue_message_id)
