"""
Tests for base software inventory collection module.
"""

# pylint: disable=redefined-outer-name,protected-access

import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.software_inventory_base import (
    SoftwareInventoryCollectorBase,
)


@pytest.fixture
def collector():
    """Create a SoftwareInventoryCollectorBase for testing."""
    return SoftwareInventoryCollectorBase()


class TestSoftwareInventoryCollectorBaseInit:
    """Tests for SoftwareInventoryCollectorBase initialization."""

    def test_init_sets_empty_collected_packages(self, collector):
        """Test that __init__ sets empty collected_packages list."""
        assert collector.collected_packages == []

    def test_init_sets_package_managers_to_none(self, collector):
        """Test that __init__ sets _package_managers to None."""
        assert collector._package_managers is None


class TestCommandExists:
    """Tests for _command_exists method."""

    def test_command_exists_returns_true(self, collector):
        """Test _command_exists returns True for existing command."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = collector._command_exists("test_cmd")

        assert result is True

    def test_command_exists_returns_false_file_not_found(self, collector):
        """Test _command_exists returns False for non-existent command."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = collector._command_exists("nonexistent")

        assert result is False

    def test_command_exists_returns_false_timeout(self, collector):
        """Test _command_exists returns False on timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5)):
            result = collector._command_exists("slow_cmd")

        assert result is False

    def test_command_exists_returns_false_os_error(self, collector):
        """Test _command_exists returns False on OSError."""
        with patch("subprocess.run", side_effect=OSError("test error")):
            result = collector._command_exists("bad_cmd")

        assert result is False

    def test_command_exists_pkg_info_special_case(self, collector):
        """Test _command_exists handles pkg_info specially."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = collector._command_exists("pkg_info")

        assert result is True
        # Verify pkg_info was called without --version
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args == ["pkg_info"]

    def test_command_exists_pkg_info_usage_error(self, collector):
        """Test _command_exists handles pkg_info usage error (return code 1)."""
        mock_result = Mock()
        mock_result.returncode = 1  # Usage error is acceptable for pkg_info

        with patch("subprocess.run", return_value=mock_result):
            result = collector._command_exists("pkg_info")

        assert result is True


class TestParseSizeString:
    """Tests for _parse_size_string method."""

    def test_parse_size_bytes(self, collector):
        """Test parsing bytes."""
        result = collector._parse_size_string("1024B")
        assert result == 1024

    def test_parse_size_kilobytes(self, collector):
        """Test parsing kilobytes."""
        result = collector._parse_size_string("1KB")
        assert result == 1024

    def test_parse_size_megabytes(self, collector):
        """Test parsing megabytes."""
        result = collector._parse_size_string("1MB")
        assert result == 1024 * 1024

    def test_parse_size_gigabytes(self, collector):
        """Test parsing gigabytes."""
        result = collector._parse_size_string("1GB")
        assert result == 1024**3

    def test_parse_size_terabytes(self, collector):
        """Test parsing terabytes."""
        result = collector._parse_size_string("1TB")
        assert result == 1024**4

    def test_parse_size_with_decimal(self, collector):
        """Test parsing size with decimal value."""
        result = collector._parse_size_string("1.5MB")
        assert result == int(1.5 * 1024 * 1024)

    def test_parse_size_with_space(self, collector):
        """Test parsing size with space between number and unit."""
        result = collector._parse_size_string("100 MB")
        assert result == 100 * 1024 * 1024

    def test_parse_size_lowercase(self, collector):
        """Test parsing lowercase size string."""
        result = collector._parse_size_string("10mb")
        assert result == 10 * 1024 * 1024

    def test_parse_size_empty_string(self, collector):
        """Test parsing empty string returns None."""
        result = collector._parse_size_string("")
        assert result is None

    def test_parse_size_whitespace_string(self, collector):
        """Test parsing whitespace string returns None."""
        result = collector._parse_size_string("   ")
        assert result is None

    def test_parse_size_none_input(self, collector):
        """Test parsing None input returns None."""
        result = collector._parse_size_string(None)
        assert result is None

    def test_parse_size_invalid_format(self, collector):
        """Test parsing invalid format returns None."""
        result = collector._parse_size_string("invalid")
        assert result is None

    def test_parse_size_number_only(self, collector):
        """Test parsing number without unit uses default multiplier."""
        result = collector._parse_size_string("1024")
        assert result == 1024
