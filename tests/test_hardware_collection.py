"""
Tests for the hardware collection module.
"""

# pylint: disable=protected-access

from unittest.mock import patch

import pytest

from src.sysmanage_agent.collection.hardware_collection import HardwareCollector


class TestHardwareCollector:
    """Test hardware information collection functionality."""

    @pytest.fixture
    def hardware_collector(self):
        """Create a hardware collector instance for testing."""
        return HardwareCollector()

    def test_hardware_collector_initialization(self, hardware_collector):
        """Test that HardwareCollector initializes correctly."""
        assert hardware_collector is not None
        assert hasattr(hardware_collector, "logger")

    @patch("platform.system")
    def test_get_hardware_info_unsupported_platform(
        self, mock_system, hardware_collector
    ):
        """Test hardware collection for unsupported platform."""
        mock_system.return_value = "UnsupportedOS"

        result = hardware_collector.get_hardware_info()

        assert "hardware_details" in result
        assert "storage_details" in result
        assert "network_details" in result

    @patch("subprocess.run")
    def test_get_linux_storage_info_command_failure(self, mock_run, hardware_collector):
        """Test Linux storage info when lsblk command fails."""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""

        storage_info = hardware_collector._get_linux_storage_info()

        assert storage_info == []

    @patch("subprocess.run")
    def test_get_macos_cpu_info_command_failure(self, mock_run, hardware_collector):
        """Test macOS CPU info when sysctl command fails."""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""

        cpu_info = hardware_collector._get_macos_cpu_info()

        assert cpu_info == {}

    @patch("subprocess.run")
    def test_get_windows_cpu_info_command_failure(self, mock_run, hardware_collector):
        """Test Windows CPU info when wmic command fails."""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""

        cpu_info = hardware_collector._get_windows_cpu_info()

        assert cpu_info == {}
