"""
Tests for the OS information collection module.
"""

import json
import sys
from unittest.mock import patch

import pytest

from os_info_collection import OSInfoCollector


class TestOSInfoCollector:
    """Test OS information collection functionality."""

    @pytest.fixture
    def os_collector(self):
        """Create an OS info collector instance for testing."""
        return OSInfoCollector()

    def test_os_collector_initialization(self, os_collector):
        """Test that OSInfoCollector initializes correctly."""
        assert os_collector is not None
        assert hasattr(os_collector, "logger")

    @patch("platform.system")
    @patch("platform.release")
    @patch("platform.version")
    @patch("platform.machine")
    @patch("platform.processor")
    @patch("platform.architecture")
    @patch("platform.python_version")
    def test_get_basic_platform_info(  # pylint: disable=too-many-positional-arguments
        self,
        mock_python_version,
        mock_architecture,
        mock_processor,
        mock_machine,
        mock_version,
        mock_release,
        mock_system,
        os_collector,
    ):
        """Test basic platform information collection."""
        # Mock platform module calls
        mock_system.return_value = "Darwin"
        mock_release.return_value = "23.5.0"
        mock_version.return_value = "Darwin Kernel Version 23.5.0"
        mock_machine.return_value = "arm64"
        mock_processor.return_value = "arm"
        mock_architecture.return_value = ("64bit", "")
        mock_python_version.return_value = "3.11.5"

        result = os_collector.get_os_version_info()

        assert result["platform"] == "Darwin"
        assert result["platform_release"] == "23.5.0"
        assert result["platform_version"] == "Darwin Kernel Version 23.5.0"
        assert result["machine_architecture"] == "arm64"
        assert result["processor"] == "arm"
        assert result["architecture"] == "64bit"
        assert result["python_version"] == "3.11.5"

    @patch("platform.system")
    @patch("platform.mac_ver")
    def test_get_macos_details_success(self, mock_mac_ver, mock_system, os_collector):
        """Test macOS-specific details collection."""
        mock_system.return_value = "Darwin"
        mock_mac_ver.return_value = ("14.0", ("", "", ""), "arm64")

        with patch("platform.release") as mock_release, patch(
            "platform.version"
        ) as mock_version, patch("platform.machine") as mock_machine, patch(
            "platform.processor"
        ) as mock_processor, patch(
            "platform.architecture"
        ) as mock_architecture, patch(
            "platform.python_version"
        ) as mock_python_version:

            mock_release.return_value = "23.0.0"
            mock_version.return_value = "Darwin Kernel Version 23.0.0"
            mock_machine.return_value = "arm64"
            mock_processor.return_value = "arm"
            mock_architecture.return_value = ("64bit", "")
            mock_python_version.return_value = "3.11.5"

            result = os_collector.get_os_version_info()

            assert result["platform"] == "Darwin"
            assert "os_info" in result
            assert result["os_info"]["mac_version"] == "14.0"

    @patch("platform.system")
    def test_get_linux_details_success(self, mock_system, os_collector):
        """Test Linux-specific details collection."""
        mock_system.return_value = "Linux"

        with patch("platform.release") as mock_release, patch(
            "platform.version"
        ) as mock_version, patch("platform.machine") as mock_machine, patch(
            "platform.processor"
        ) as mock_processor, patch(
            "platform.architecture"
        ) as mock_architecture, patch(
            "platform.python_version"
        ) as mock_python_version:

            mock_release.return_value = "5.15.0"
            mock_version.return_value = "#72-Ubuntu"
            mock_machine.return_value = "x86_64"
            mock_processor.return_value = "x86_64"
            mock_architecture.return_value = ("64bit", "ELF")
            mock_python_version.return_value = "3.10.6"

            # Mock freedesktop_os_release only if it exists in this Python version
            if sys.version_info >= (3, 10):
                with patch(
                    "platform.freedesktop_os_release",
                    return_value={
                        "NAME": "Ubuntu",
                        "VERSION_ID": "22.04",
                        "VERSION_CODENAME": "jammy",
                    },
                ):
                    result = os_collector.get_os_version_info()

                    assert result["platform"] == "Linux"
                    assert "os_info" in result
                    assert result["os_info"]["distribution"] == "Ubuntu"
                    assert result["os_info"]["distribution_version"] == "22.04"
            else:
                # For Python < 3.10, just verify basic functionality
                result = os_collector.get_os_version_info()

                assert result["platform"] == "Linux"
                assert "os_info" in result

    @patch("platform.system")
    def test_get_linux_details_file_not_found(self, mock_system, os_collector):
        """Test Linux details when os-release file is not found."""
        mock_system.return_value = "Linux"

        with patch("platform.release") as mock_release, patch(
            "platform.version"
        ) as mock_version, patch("platform.machine") as mock_machine, patch(
            "platform.processor"
        ) as mock_processor, patch(
            "platform.architecture"
        ) as mock_architecture, patch(
            "platform.python_version"
        ) as mock_python_version:

            mock_release.return_value = "5.15.0"
            mock_version.return_value = "#72-Ubuntu"
            mock_machine.return_value = "x86_64"
            mock_processor.return_value = "x86_64"
            mock_architecture.return_value = ("64bit", "ELF")
            mock_python_version.return_value = "3.10.6"

            # Mock freedesktop_os_release only if it exists in this Python version
            if sys.version_info >= (3, 10):
                with patch(
                    "platform.freedesktop_os_release",
                    side_effect=OSError("File not found"),
                ):
                    result = os_collector.get_os_version_info()

                    assert result["platform"] == "Linux"
                    # os_info should still be present but without distribution info
                    assert "os_info" in result
            else:
                # For Python < 3.10, just verify basic functionality
                result = os_collector.get_os_version_info()

                assert result["platform"] == "Linux"
                # os_info should still be present
                assert "os_info" in result

    @patch("platform.system")
    @patch("platform.win32_ver")
    def test_get_windows_details_success(
        self, mock_win32_ver, mock_system, os_collector
    ):
        """Test Windows-specific details collection."""
        mock_system.return_value = "Windows"
        mock_win32_ver.return_value = ("10", "SP0", "10.0.19045", "Multiprocessor Free")

        with patch("platform.release") as mock_release, patch(
            "platform.version"
        ) as mock_version, patch("platform.machine") as mock_machine, patch(
            "platform.processor"
        ) as mock_processor, patch(
            "platform.architecture"
        ) as mock_architecture, patch(
            "platform.python_version"
        ) as mock_python_version:

            mock_release.return_value = "10"
            mock_version.return_value = "10.0.19045"
            mock_machine.return_value = "AMD64"
            mock_processor.return_value = "Intel64 Family 6 Model 142 Stepping 12"
            mock_architecture.return_value = ("64bit", "WindowsPE")
            mock_python_version.return_value = "3.11.5"

            result = os_collector.get_os_version_info()

            assert result["platform"] == "Windows"
            assert "os_info" in result
            assert result["os_info"]["windows_version"] == "10"
            assert result["os_info"]["windows_service_pack"] == "SP0"

    def test_get_os_info_integration(self, os_collector):
        """Test actual OS info collection (integration test)."""
        result = os_collector.get_os_version_info()

        # Test that basic fields are present
        required_fields = [
            "platform",
            "platform_release",
            "platform_version",
            "architecture",
            "processor",
            "machine_architecture",
            "python_version",
            "os_info",
        ]

        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

        # Test that platform-specific info is included in os_info
        assert isinstance(result["os_info"], dict)

        # Verify data types
        assert isinstance(result["platform"], str)
        assert isinstance(result["platform_release"], str)
        assert isinstance(result["machine_architecture"], str)

    def test_error_handling_platform_calls(self, os_collector):
        """Test error handling when platform calls fail."""
        with patch("platform.system") as mock_system:
            mock_system.side_effect = Exception("Platform error")

            # Exception should propagate since there's no error handling
            with pytest.raises(Exception, match="Platform error"):
                os_collector.get_os_version_info()

    def test_json_serialization_of_os_details(self, os_collector):
        """Test that OS details can be JSON serialized."""
        result = os_collector.get_os_version_info()

        # Should be JSON serializable
        json_str = json.dumps(result)
        assert isinstance(json_str, str)

        # Should be able to deserialize
        deserialized = json.loads(json_str)
        assert isinstance(deserialized, dict)
        assert "platform" in deserialized
