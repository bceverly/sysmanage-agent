"""
Tests for UTC timestamp logging formatter module.
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
import re
import sys
from datetime import datetime, timezone

import pytest

from src.sysmanage_agent.utils.logging_formatter import UTCTimestampFormatter


@pytest.fixture
def formatter():
    """Create a UTCTimestampFormatter for testing."""
    return UTCTimestampFormatter()


@pytest.fixture
def log_record():
    """Create a sample log record for testing."""
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    return record


class TestUTCTimestampFormatter:
    """Tests for UTCTimestampFormatter class."""

    def test_format_includes_utc_prefix(self, formatter, log_record):
        """Test that format includes UTC timestamp prefix."""
        result = formatter.format(log_record)

        assert "UTC]" in result
        assert "Test message" in result

    def test_format_timestamp_pattern(self, formatter, log_record):
        """Test that timestamp follows expected pattern."""
        result = formatter.format(log_record)

        # Pattern: [YYYY-MM-DD HH:MM:SS.mmm UTC]
        pattern = r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} UTC\]"
        assert re.search(pattern, result) is not None

    def test_format_preserves_message(self, formatter, log_record):
        """Test that format preserves the original message."""
        log_record.msg = "My custom test message"
        result = formatter.format(log_record)

        assert "My custom test message" in result

    def test_format_with_formatted_message(self, formatter):
        """Test formatting with message arguments."""
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Value is %d",
            args=(42,),
            exc_info=None,
        )

        result = formatter.format(record)

        assert "Value is 42" in result

    def test_format_different_log_levels(self, formatter):
        """Test formatting with different log levels."""
        levels = [
            (logging.DEBUG, "DEBUG"),
            (logging.INFO, "INFO"),
            (logging.WARNING, "WARNING"),
            (logging.ERROR, "ERROR"),
            (logging.CRITICAL, "CRITICAL"),
        ]

        for level, _ in levels:
            record = logging.LogRecord(
                name="test_logger",
                level=level,
                pathname="test.py",
                lineno=1,
                msg="Test",
                args=(),
                exc_info=None,
            )
            result = formatter.format(record)
            assert "[" in result
            assert "UTC]" in result

    def test_timestamp_is_recent(self, formatter, log_record):
        """Test that timestamp is recent (within a few seconds)."""
        before = datetime.now(timezone.utc)
        result = formatter.format(log_record)
        after = datetime.now(timezone.utc)

        # Extract timestamp from result
        match = re.search(
            r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) UTC\]", result
        )
        assert match is not None

        timestamp_str = match.group(1)
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        timestamp = timestamp.replace(tzinfo=timezone.utc)

        # Truncate before/after to milliseconds to match formatter precision
        # The formatter only outputs 3 decimal places (milliseconds)
        before_ms = before.replace(microsecond=(before.microsecond // 1000) * 1000)
        after_ms = after.replace(microsecond=(after.microsecond // 1000) * 1000)

        # Timestamp should be between before and after (with millisecond precision)
        assert before_ms <= timestamp <= after_ms

    def test_format_with_exception_info(self, formatter):
        """Test formatting with exception information."""
        exc_info = None
        try:
            raise ValueError("Test exception")
        except ValueError:
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test_logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="An error occurred",
            args=(),
            exc_info=exc_info,
        )

        result = formatter.format(record)

        assert "UTC]" in result
        assert "An error occurred" in result
        # Exception info should be included
        assert "ValueError" in result or "Test exception" in result

    def test_milliseconds_included(self, formatter, log_record):
        """Test that milliseconds are included in timestamp."""
        result = formatter.format(log_record)

        # Check that milliseconds are present (3 digits after seconds)
        pattern = r"\d{2}:\d{2}:\d{2}\.\d{3}"
        assert re.search(pattern, result) is not None

    def test_inherits_from_formatter(self, formatter):
        """Test that UTCTimestampFormatter inherits from logging.Formatter."""
        assert isinstance(formatter, logging.Formatter)
