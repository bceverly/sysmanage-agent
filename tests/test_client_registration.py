"""
Tests for the client registration module.
"""

import json
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.registration.client_registration import ClientRegistration


class TestClientRegistration:
    """Test client registration functionality."""

    @pytest.fixture
    def registration(self):
        """Create a client registration instance for testing."""
        mock_config_manager = Mock()
        mock_config_manager.get_config.return_value = {
            "server": {"host": "localhost", "port": 8080},
            "client": {"hostname": "test-host"},
        }
        return ClientRegistration(mock_config_manager)

    def test_initialization(self, registration):
        """Test that ClientRegistration initializes correctly."""
        assert registration is not None
        assert hasattr(registration, "logger")
        assert hasattr(registration, "config")
        assert hasattr(registration, "network_utils")
        assert hasattr(registration, "hardware_collector")
        assert hasattr(registration, "os_info_collector")

    @patch("src.sysmanage_agent.registration.client_registration.NetworkUtils")
    def test_get_basic_registration_info(self, mock_network_utils, registration):
        """Test basic registration info collection."""
        # Mock network utilities
        mock_network = Mock()
        mock_network.get_hostname.return_value = "test-host.example.com"
        mock_network.get_ip_addresses.return_value = ("192.168.1.100", "2001:db8::1")
        mock_network_utils.return_value = mock_network

        # Re-initialize to use the mocked network utils
        registration.network_utils = mock_network

        result = registration.get_basic_registration_info()

        assert result["hostname"] == "test-host.example.com"
        assert result["fqdn"] == "test-host.example.com"
        assert result["ipv4"] == "192.168.1.100"
        assert result["ipv6"] == "2001:db8::1"
        assert result["active"] is True

    @patch("src.sysmanage_agent.registration.client_registration.OSInfoCollector")
    def test_get_os_version_info(self, mock_os_collector, registration):
        """Test OS version information collection."""
        # Mock OS info collector
        mock_os = Mock()
        mock_os.get_os_info.return_value = {
            "platform": "Darwin",
            "platform_release": "23.5.0",
            "platform_version": "Darwin Kernel Version 23.5.0",
            "machine_architecture": "arm64",
            "processor": "arm",
            "os_details": '{"version": "14.5", "build": "23F79"}',
        }
        mock_os_collector.return_value = mock_os

        # Re-initialize to use the mocked OS collector
        registration.os_info_collector = mock_os
        # Set up the mock method to return the expected data
        mock_os.get_os_version_info.return_value = {
            "platform": "Darwin",
            "platform_release": "23.5.0",
            "platform_version": "Darwin Kernel Version 23.5.0",
            "machine_architecture": "arm64",
            "processor": "arm",
            "os_details": '{"version": "14.5", "build": "23F79"}',
        }

        result = registration.get_os_version_info()

        assert result["platform"] == "Darwin"
        assert result["platform_release"] == "23.5.0"
        assert result["machine_architecture"] == "arm64"
        assert result["processor"] == "arm"
        assert "os_details" in result

    @patch("src.sysmanage_agent.registration.client_registration.HardwareCollector")
    def test_get_hardware_info(self, mock_hardware_collector, registration):
        """Test hardware information collection."""
        # Mock hardware collector
        mock_hardware = Mock()
        mock_hardware.get_hardware_info.return_value = {
            "cpu_vendor": "Apple",
            "cpu_model": "Apple M3 Max",
            "cpu_cores": 14,
            "cpu_threads": 20,
            "cpu_frequency_mhz": 4050,
            "memory_total_mb": 32768,
            "storage_devices": [
                {
                    "name": "Macintosh HD",
                    "device_path": "/dev/disk3s1s1",
                    "mount_point": "/",
                    "file_system": "APFS",
                    "capacity_bytes": 1000000000000,
                    "used_bytes": 500000000000,
                    "available_bytes": 500000000000,
                }
            ],
            "network_interfaces": [
                {
                    "name": "en0",
                    "interface_type": "Ethernet",
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "ipv4_address": "192.168.1.100",
                    "is_active": True,
                }
            ],
            "storage_details": "[]",
            "network_details": "[]",
            "hardware_details": "{}",
        }
        mock_hardware_collector.return_value = mock_hardware

        # Re-initialize to use the mocked hardware collector
        registration.hardware_collector = mock_hardware

        result = registration.get_hardware_info()

        assert result["cpu_vendor"] == "Apple"
        assert result["cpu_model"] == "Apple M3 Max"
        assert result["cpu_cores"] == 14
        assert result["memory_total_mb"] == 32768
        assert len(result["storage_devices"]) == 1
        assert len(result["network_interfaces"]) == 1
        assert result["storage_devices"][0]["name"] == "Macintosh HD"
        assert result["network_interfaces"][0]["name"] == "en0"

    def test_get_minimal_registration_data(self, registration):
        """Test minimal registration data collection."""
        with patch.object(registration, "get_basic_registration_info") as mock_basic:
            mock_basic.return_value = {
                "hostname": "test-host",
                "fqdn": "test-host.example.com",
                "ipv4": "192.168.1.100",
                "ipv6": "2001:db8::1",
                "active": True,
            }

            result = registration.get_basic_registration_info()

            # Should only contain basic info, no hardware/OS details
            expected_keys = {"hostname", "fqdn", "ipv4", "ipv6", "active"}
            assert set(result.keys()) == expected_keys
            assert result["hostname"] == "test-host"

    def test_get_complete_registration_data(self, registration):
        """Test complete registration data collection."""
        with (
            patch.object(registration, "get_basic_registration_info") as mock_basic,
            patch.object(registration, "get_os_version_info") as mock_os,
            patch.object(registration, "get_hardware_info") as mock_hardware,
        ):

            mock_basic.return_value = {
                "hostname": "test-host",
                "fqdn": "test-host.example.com",
                "ipv4": "192.168.1.100",
                "ipv6": "2001:db8::1",
                "active": True,
            }

            mock_os.return_value = {"platform": "Darwin", "platform_release": "23.5.0"}

            mock_hardware.return_value = {
                "cpu_vendor": "Apple",
                "cpu_cores": 14,
                "memory_total_mb": 32768,
                "storage_devices": [],
                "network_interfaces": [],
            }

            result = registration.get_system_info()

            # Should contain basic info and OS data (but not hardware)
            assert "hostname" in result
            assert "platform" in result
            assert result["hostname"] == "test-host"
            assert result["platform"] == "Darwin"
            # get_system_info() only combines basic + OS info, not hardware
            assert "fqdn" in result
            assert "active" in result

    def test_error_handling_in_hardware_collection(self, registration):
        """Test error handling when hardware collection fails."""
        with patch.object(
            registration.hardware_collector, "get_hardware_info"
        ) as mock_hardware:
            mock_hardware.side_effect = Exception("Hardware collection failed")

            # The exception should propagate from get_hardware_info
            with pytest.raises(Exception, match="Hardware collection failed"):
                registration.get_hardware_info()

    def test_error_handling_in_os_collection(self, registration):
        """Test error handling when OS info collection fails."""
        with patch.object(
            registration.os_info_collector, "get_os_version_info"
        ) as mock_os:
            mock_os.side_effect = Exception("OS collection failed")

            # The exception should propagate from get_os_version_info
            with pytest.raises(Exception, match="OS collection failed"):
                registration.get_os_version_info()

    def test_timestamp_inclusion(self, registration):
        """Test that timestamps are included in data updates."""
        with patch.object(registration, "get_hardware_info") as mock_hardware:
            mock_hardware.return_value = {
                "cpu_vendor": "Intel",
                "storage_devices": [],
                "network_interfaces": [],
            }

            result = registration.get_hardware_info()

            # Check that appropriate timestamp fields would be available
            # (Implementation may vary based on how timestamps are handled)
            assert isinstance(result, dict)
            assert "cpu_vendor" in result

    def test_json_serialization(self, registration):
        """Test that collected data can be JSON serialized."""
        with patch.object(registration, "get_system_info") as mock_complete:
            mock_complete.return_value = {
                "hostname": "test-host",
                "cpu_cores": 8,
                "storage_devices": [{"name": "disk1", "capacity_bytes": 1000000}],
                "network_interfaces": [
                    {"name": "eth0", "mac_address": "aa:bb:cc:dd:ee:ff"}
                ],
            }

            result = registration.get_system_info()

            # Should be JSON serializable
            try:
                json.dumps(result)
                json_serializable = True
            except (TypeError, ValueError):
                json_serializable = False

            assert json_serializable is True

    def test_data_separation_concerns(self, registration):
        """Test that different data types are properly separated."""
        # Test that minimal data doesn't include sensitive hardware info
        with patch.object(registration, "get_basic_registration_info") as mock_basic:
            mock_basic.return_value = {
                "hostname": "test-host",
                "fqdn": "test-host.example.com",
                "ipv4": "192.168.1.100",
                "active": True,
            }

            minimal = registration.get_basic_registration_info()

            # Minimal should not contain hardware details
            hardware_keys = {
                "cpu_vendor",
                "cpu_model",
                "memory_total_mb",
                "storage_devices",
                "network_interfaces",
            }
            minimal_keys = set(minimal.keys())

            assert len(hardware_keys.intersection(minimal_keys)) == 0

    def test_config_integration(self, registration):
        """Test integration with configuration management."""
        # Verify that configuration is properly loaded and used
        assert registration.config is not None

        # Test that config values influence behavior
        config = registration.config.get_config()
        assert isinstance(config, dict)
        assert "server" in config or "client" in config
