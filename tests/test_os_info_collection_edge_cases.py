"""
Test edge cases and error handling for os_info_collection.py.
Focused on improving test coverage by targeting uncovered paths.
"""

import json
import subprocess
from unittest.mock import Mock, patch

from src.sysmanage_agent.collection.os_info_collection import OSInfoCollector


class TestOSInfoCollectorEdgeCases:  # pylint: disable=too-many-public-methods
    """Test edge cases for OSInfoCollector class."""

    # pylint: disable=protected-access

    def setup_method(self):
        """Set up test environment."""
        # pylint: disable=attribute-defined-outside-init
        self.collector = OSInfoCollector()

    def test_get_macos_friendly_name_unknown_version(self):
        """Test macOS friendly name with unknown Darwin version."""
        result = self.collector._get_macos_friendly_name("99.0.0")
        assert result == "99.0.0"  # Should return original version

    def test_get_macos_friendly_name_malformed_version(self):
        """Test macOS friendly name with malformed version string."""
        result = self.collector._get_macos_friendly_name("invalid")
        assert result == "invalid"

    def test_get_macos_friendly_name_no_mac_version(self):
        """Test macOS friendly name when platform.mac_ver() returns empty."""
        with patch("platform.mac_ver", return_value=("", "", "")):
            result = self.collector._get_macos_friendly_name("24.0.0")
            assert result == "24.0.0"

    def test_get_macos_friendly_name_partial_mac_version(self):
        """Test macOS friendly name with incomplete mac_ver."""
        with patch("platform.mac_ver", return_value=("15", "", "")):
            result = self.collector._get_macos_friendly_name("24.0.0")
            assert "Sequoia 15" in result

    def test_get_linux_distribution_info_no_freedesktop_os_release(self):
        """Test Linux distribution info when freedesktop_os_release is not available."""
        with patch("platform.release", return_value="5.4.0-generic"):
            # Mock hasattr to return False for freedesktop_os_release
            original_hasattr = hasattr

            def mock_hasattr(obj, name):
                if name == "freedesktop_os_release":
                    return False
                return original_hasattr(obj, name)

            with patch("builtins.hasattr", side_effect=mock_hasattr):
                name, version = self.collector._get_linux_distribution_info()
                assert name == "Linux"
                assert version == "5.4.0-generic"

    def test_get_linux_distribution_info_os_error(self):
        """Test Linux distribution info with OSError."""
        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            side_effect=OSError("No such file"),
            create=True,
        ):
            with patch("platform.release", return_value="5.4.0-generic"):
                name, version = self.collector._get_linux_distribution_info()
                assert name == "Linux"
                assert version == "5.4.0-generic"

    def test_get_linux_distribution_info_missing_fields(self):
        """Test Linux distribution info with missing NAME or VERSION_ID."""
        mock_os_release = {"PRETTY_NAME": "Ubuntu 20.04"}

        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            create=True,
            return_value=mock_os_release,
        ):
            with patch("platform.release", return_value="5.4.0-generic"):
                name, version = self.collector._get_linux_distribution_info()
                assert name == "Linux"
                assert version == "5.4.0-generic"

    def test_get_linux_distribution_info_linux_suffix_removal(self):
        """Test removal of 'Linux' suffix from distribution name."""
        mock_os_release = {"NAME": "Ubuntu Linux", "VERSION_ID": "20.04"}

        with patch(
            "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
            create=True,
            return_value=mock_os_release,
        ):
            name, version = self.collector._get_linux_distribution_info()
            assert name == "Ubuntu"
            assert version == "20.04"

    def test_get_ubuntu_pro_info_command_not_found(self):
        """Test Ubuntu Pro info when pro command is not found."""
        with patch(
            "subprocess.run", side_effect=FileNotFoundError("pro: command not found")
        ):
            result = self.collector._get_ubuntu_pro_info()

            assert not result["available"]
            assert not result["attached"]
            assert not result["services"]

    def test_get_ubuntu_pro_info_timeout(self):
        """Test Ubuntu Pro info with command timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pro", 10)):
            result = self.collector._get_ubuntu_pro_info()

            assert not result["available"]

    def test_get_ubuntu_pro_info_command_failure(self):
        """Test Ubuntu Pro info with command returning error."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector._get_ubuntu_pro_info()

            assert not result["available"]

    def test_get_ubuntu_pro_info_json_decode_error(self):
        """Test Ubuntu Pro info with invalid JSON response."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid json"

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector._get_ubuntu_pro_info()

            assert not result["available"]

    def test_get_ubuntu_pro_info_processing_exception(self):
        """Test Ubuntu Pro info with exception during data processing."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = '{"attached": true}'

        with patch("subprocess.run", return_value=mock_result):
            with patch("json.loads", side_effect=Exception("Processing error")):
                result = self.collector._get_ubuntu_pro_info()

                assert not result["available"]

    def test_get_ubuntu_pro_info_service_status_mapping(self):
        """Test Ubuntu Pro service status mapping logic."""
        pro_data = {
            "attached": True,
            "services": [
                {
                    "name": "esm-infra",
                    "status": "enabled",
                    "available": "yes",
                    "entitled": "yes",
                },
                {
                    "name": "livepatch",
                    "status": "disabled",
                    "available": "yes",
                    "entitled": "yes",
                },
                {"name": "fips", "status": "n/a", "available": "no", "entitled": "no"},
                {
                    "name": "ros",
                    "status": "active",
                    "available": "yes",
                    "entitled": "yes",
                },
            ],
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(pro_data)

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector._get_ubuntu_pro_info()

            services = result["services"]
            assert len(services) == 4

            # Check status mapping
            esm_service = next(s for s in services if s["name"] == "esm-infra")
            assert esm_service["status"] == "enabled"

            livepatch_service = next(s for s in services if s["name"] == "livepatch")
            assert livepatch_service["status"] == "disabled"

            fips_service = next(s for s in services if s["name"] == "fips")
            assert fips_service["status"] == "n/a"

            ros_service = next(s for s in services if s["name"] == "ros")
            assert ros_service["status"] == "enabled"  # "active" maps to "enabled"

    def test_get_os_version_info_windows_platform(self):
        """Test OS version info collection for Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch("platform.release", return_value="10"):
                with patch("platform.version", return_value="10.0.19041"):
                    with patch(
                        "platform.architecture", return_value=("64bit", "WindowsPE")
                    ):
                        with patch(
                            "platform.processor",
                            return_value="Intel64 Family 6 Model 142",
                        ):
                            with patch("platform.machine", return_value="AMD64"):
                                with patch(
                                    "platform.python_version", return_value="3.9.0"
                                ):
                                    with patch(
                                        "platform.win32_ver",
                                        return_value=(
                                            "10",
                                            "10.0.19041",
                                            "SP0",
                                            "Multiprocessor Free",
                                        ),
                                    ):
                                        result = self.collector.get_os_version_info()

                                        assert result["platform"] == "Windows"
                                        assert result["platform_release"] == "10"
                                        assert (
                                            result["os_info"]["windows_version"] == "10"
                                        )
                                        assert (
                                            result["os_info"]["windows_service_pack"]
                                            == "10.0.19041"
                                        )

    def test_get_os_version_info_windows_empty_version(self):
        """Test Windows OS version info with empty win32_ver."""
        with patch("platform.system", return_value="Windows"):
            with patch("platform.release", return_value="10"):
                with patch("platform.win32_ver", return_value=("", "", "", "")):
                    result = self.collector.get_os_version_info()

                    assert result["os_info"]["windows_version"] == ""
                    assert result["os_info"]["windows_service_pack"] == ""

    def test_get_os_version_info_linux_ubuntu_pro(self):
        """Test Linux OS version info with Ubuntu Pro information."""
        mock_os_release = {
            "NAME": "Ubuntu",
            "VERSION_ID": "20.04",
            "VERSION_CODENAME": "focal",
        }

        with patch("platform.system", return_value="Linux"):
            with patch("platform.release", return_value="5.4.0-generic"):
                with patch(
                    "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
                    return_value=mock_os_release,
                    create=True,
                ):
                    with patch.object(
                        self.collector,
                        "_get_ubuntu_pro_info",
                        return_value={"available": True, "attached": False},
                    ) as mock_pro:
                        result = self.collector.get_os_version_info()

                        assert result["os_info"]["distribution"] == "Ubuntu"
                        assert result["os_info"]["ubuntu_pro"]["available"] is True
                        mock_pro.assert_called_once()

    def test_get_os_version_info_linux_non_ubuntu(self):
        """Test Linux OS version info for non-Ubuntu distribution."""
        mock_os_release = {"NAME": "Fedora", "VERSION_ID": "34"}

        with patch("platform.system", return_value="Linux"):
            with patch(
                "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
                create=True,
                return_value=mock_os_release,
            ):
                result = self.collector.get_os_version_info()

                assert "ubuntu_pro" not in result["os_info"]

    def test_get_os_version_info_linux_freedesktop_exception(self):
        """Test Linux OS version info with freedesktop_os_release exception."""
        with patch("platform.system", return_value="Linux"):
            with patch("platform.release", return_value="5.4.0-generic"):
                with patch(
                    "src.sysmanage_agent.collection.os_info_collection.platform.freedesktop_os_release",
                    side_effect=AttributeError("Not available"),
                    create=True,
                ):
                    result = self.collector.get_os_version_info()

                    assert result["platform"] == "Linux"
                    # Should still work without distribution info

    def test_get_os_version_info_unknown_platform(self):
        """Test OS version info for unknown platform."""
        with patch("platform.system", return_value="UnknownOS"):
            with patch("platform.release", return_value="1.0"):
                result = self.collector.get_os_version_info()

                assert result["platform"] == "UnknownOS"
                assert result["platform_release"] == "1.0"

    def test_get_os_version_info_darwin_edge_cases(self):
        """Test Darwin/macOS OS version info edge cases."""
        with patch("platform.system", return_value="Darwin"):
            with patch("platform.release", return_value="20.6.0"):
                with patch("platform.mac_ver", return_value=("11.5.2", "", "")):
                    with patch.object(
                        self.collector,
                        "_get_macos_friendly_name",
                        return_value="Big Sur 11.5",
                    ) as mock_friendly:
                        result = self.collector.get_os_version_info()

                        assert result["platform"] == "macOS"
                        assert result["platform_release"] == "Big Sur 11.5"
                        assert result["os_info"]["mac_version"] == "11.5.2"
                        mock_friendly.assert_called_once_with("20.6.0")

    def test_get_os_version_info_darwin_no_mac_version(self):
        """Test Darwin OS version info when mac_ver returns empty."""
        with patch("platform.system", return_value="Darwin"):
            with patch("platform.mac_ver", return_value=("", "", "")):
                result = self.collector.get_os_version_info()

                assert result["os_info"]["mac_version"] == ""

    def test_macos_version_names_mapping(self):
        """Test macOS version names mapping completeness."""
        # Test that all version mappings work
        test_cases = [
            ("24.0.0", "Sequoia"),
            ("23.0.0", "Sonoma"),
            ("22.0.0", "Ventura"),
            ("21.0.0", "Monterey"),
            ("20.0.0", "Big Sur"),
            ("19.0.0", "Catalina"),
        ]

        for darwin_version, expected_name in test_cases:
            with patch("platform.mac_ver", return_value=("15.0", "", "")):
                result = self.collector._get_macos_friendly_name(darwin_version)
                assert expected_name in result

    def test_ubuntu_pro_info_empty_services(self):
        """Test Ubuntu Pro info with empty services list."""
        pro_data = {"attached": True, "services": []}

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(pro_data)

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector._get_ubuntu_pro_info()

            assert result["available"] is True
            assert result["attached"] is True
            assert len(result["services"]) == 0

    def test_ubuntu_pro_info_missing_optional_fields(self):
        """Test Ubuntu Pro info with missing optional fields."""
        pro_data = {
            "attached": False
            # Missing version, expires, account, contract, services
        }

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(pro_data)

        with patch("subprocess.run", return_value=mock_result):
            result = self.collector._get_ubuntu_pro_info()

            assert result["available"] is True
            assert result["attached"] is False
            assert result["version"] == ""
            assert result["expires"] is None
            assert result["account_name"] == ""
            assert result["contract_name"] == ""
