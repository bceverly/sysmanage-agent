"""
UTC timestamp logging formatter for SysManage Agent.

This module provides a custom logging formatter that prefixes all log entries
with a UTC timezone timestamp in square brackets followed by a space.
"""

import datetime
import logging


class UTCTimestampFormatter(logging.Formatter):
    """
    Custom logging formatter that adds UTC timestamps in square brackets.

    Format: [YYYY-MM-DD HH:MM:SS.sss UTC] LEVEL: message
    """

    def format(self, record):
        # Get current UTC timestamp
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        timestamp = utc_now.strftime("%Y-%m-%d %H:%M:%S.%f")[
            :-3
        ]  # Include milliseconds

        # Format the original message
        original_message = super().format(record)

        # Prefix with UTC timestamp in square brackets
        return f"[{timestamp} UTC] {original_message}"
