"""
Tests for commercial antivirus collection module.
Tests detection of commercial antivirus software (Microsoft Defender) on various platforms.
"""

# pylint: disable=redefined-outer-name,protected-access

import json
import subprocess
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.collection.commercial_antivirus_collection import (
    CommercialAntivirusCollector,
)


@pytest.fixture
def collector():
    """Create a CommercialAntivirusCollector instance for testing."""
    return CommercialAntivirusCollector()


class TestCommercialAntivirusCollectorInit:
    """Tests for CommercialAntivirusCollector initialization."""

    def test_init_creates_logger(self, collector):
        """Test that __init__ creates logger."""
        assert collector.logger is not None

    def test_init_detects_system(self, collector):
        """Test that __init__ detects system."""
        assert collector.system is not None


class TestCollectCommercialAntivirusStatus:
    """Tests for collect_commercial_antivirus_status method."""

    def test_collect_status_windows(self, collector):
        """Test status collection on Windows."""
        collector.system = "Windows"

        defender_info = {
            "product_name": "Microsoft Defender",
            "product_version": "4.18.2301.0",
            "service_enabled": True,
            "antivirus_enabled": True,
            "realtime_protection_enabled": True,
        }

        with patch.object(
            collector,
            "_detect_windows_commercial_antivirus",
            return_value=defender_info,
        ):
            result = collector.collect_commercial_antivirus_status()

        assert result["product_name"] == "Microsoft Defender"
        assert result["antivirus_enabled"] is True

    def test_collect_status_macos(self, collector):
        """Test status collection on macOS."""
        collector.system = "Darwin"

        defender_info = {
            "product_name": "Microsoft Defender for Endpoint",
            "product_version": "101.12345.0",
            "service_enabled": True,
            "antivirus_enabled": True,
        }

        with patch.object(
            collector,
            "_detect_macos_commercial_antivirus",
            return_value=defender_info,
        ):
            result = collector.collect_commercial_antivirus_status()

        assert result["product_name"] == "Microsoft Defender for Endpoint"

    def test_collect_status_linux(self, collector):
        """Test status collection on Linux returns None."""
        collector.system = "Linux"

        result = collector.collect_commercial_antivirus_status()

        assert result is None

    def test_collect_status_exception(self, collector):
        """Test status collection handles exceptions."""
        collector.system = "Windows"

        with patch.object(
            collector,
            "_detect_windows_commercial_antivirus",
            side_effect=Exception("Detection failed"),
        ):
            result = collector.collect_commercial_antivirus_status()

        assert result is None


class TestDetectWindowsCommercialAntivirus:
    """Tests for _detect_windows_commercial_antivirus method."""

    def test_detect_defender_running(self, collector):
        """Test detection of running Microsoft Defender."""
        service_result = Mock()
        service_result.returncode = 0
        service_result.stdout = "Running"

        status_json = {
            "AMServiceEnabled": True,
            "AntispywareEnabled": True,
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "FullScanAge": 7,
            "QuickScanAge": 1,
            "FullScanEndTime": "01/01/2024 12:00:00 PM",
            "QuickScanEndTime": "01/07/2024 12:00:00 PM",
            "AntivirusSignatureLastUpdated": "01/08/2024 06:00:00 AM",
            "AntivirusSignatureVersion": "1.403.123.0",
            "IsTamperProtected": True,
        }

        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = json.dumps(status_json)

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "4.18.2301.0\n"

        with patch(
            "subprocess.run",
            side_effect=[service_result, status_result, version_result],
        ):
            result = collector._detect_windows_commercial_antivirus()

        assert result["product_name"] == "Microsoft Defender"
        assert result["product_version"] == "4.18.2301.0"
        assert result["service_enabled"] is True
        assert result["antivirus_enabled"] is True
        assert result["realtime_protection_enabled"] is True
        assert result["tamper_protection_enabled"] is True

    def test_detect_defender_not_running(self, collector):
        """Test detection when Defender is not running."""
        service_result = Mock()
        service_result.returncode = 0
        service_result.stdout = "Stopped"

        with patch("subprocess.run", return_value=service_result):
            result = collector._detect_windows_commercial_antivirus()

        assert result is None

    def test_detect_defender_service_not_found(self, collector):
        """Test detection when Defender service doesn't exist."""
        service_result = Mock()
        service_result.returncode = 1
        service_result.stdout = ""

        with patch("subprocess.run", return_value=service_result):
            result = collector._detect_windows_commercial_antivirus()

        assert result is None

    def test_detect_defender_status_command_fails(self, collector):
        """Test detection when status command fails."""
        service_result = Mock()
        service_result.returncode = 0
        service_result.stdout = "Running"

        status_result = Mock()
        status_result.returncode = 1
        status_result.stderr = "Access denied"

        with patch("subprocess.run", side_effect=[service_result, status_result]):
            result = collector._detect_windows_commercial_antivirus()

        assert result is None

    def test_detect_defender_json_parse_error(self, collector):
        """Test detection when JSON parsing fails."""
        service_result = Mock()
        service_result.returncode = 0
        service_result.stdout = "Running"

        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = "invalid json {"

        with patch("subprocess.run", side_effect=[service_result, status_result]):
            result = collector._detect_windows_commercial_antivirus()

        assert result is None

    def test_detect_defender_timeout(self, collector):
        """Test detection when command times out."""
        service_result = Mock()
        service_result.returncode = 0
        service_result.stdout = "Running"

        with patch(
            "subprocess.run",
            side_effect=[service_result, subprocess.TimeoutExpired("cmd", 30)],
        ):
            result = collector._detect_windows_commercial_antivirus()

        assert result is None

    def test_detect_defender_exception(self, collector):
        """Test detection handles general exceptions."""
        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            result = collector._detect_windows_commercial_antivirus()

        assert result is None


class TestDetectMacosCommercialAntivirus:
    """Tests for _detect_macos_commercial_antivirus method."""

    def test_detect_defender_macos_installed(self, collector):
        """Test detection of Microsoft Defender on macOS."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/local/bin/mdatp\n"

        health_output = """healthy : true
licensed : true
app_version : 101.12345.0
real_time_protection_enabled : true
definitions_version : 1.403.123.0
definitions_updated : Oct 10, 2025 at 06:15:49 PM
"""

        health_result = Mock()
        health_result.returncode = 0
        health_result.stdout = health_output

        with patch("subprocess.run", side_effect=[which_result, health_result]):
            result = collector._detect_macos_commercial_antivirus()

        assert result["product_name"] == "Microsoft Defender for Endpoint"
        assert result["product_version"] == "101.12345.0"
        assert result["realtime_protection_enabled"] is True

    def test_detect_defender_macos_not_installed(self, collector):
        """Test detection when Defender is not installed on macOS."""
        which_result = Mock()
        which_result.returncode = 1
        which_result.stdout = ""

        with patch("subprocess.run", return_value=which_result):
            result = collector._detect_macos_commercial_antivirus()

        assert result is None

    def test_detect_defender_macos_health_fails(self, collector):
        """Test detection when health command fails on macOS."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/local/bin/mdatp\n"

        health_result = Mock()
        health_result.returncode = 1
        health_result.stderr = "Error getting health status"

        with patch("subprocess.run", side_effect=[which_result, health_result]):
            result = collector._detect_macos_commercial_antivirus()

        assert result is None

    def test_detect_defender_macos_timeout(self, collector):
        """Test detection when command times out on macOS."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/local/bin/mdatp\n"

        with patch(
            "subprocess.run",
            side_effect=[which_result, subprocess.TimeoutExpired("cmd", 10)],
        ):
            result = collector._detect_macos_commercial_antivirus()

        assert result is None

    def test_detect_defender_macos_exception(self, collector):
        """Test detection handles general exceptions on macOS."""
        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            result = collector._detect_macos_commercial_antivirus()

        assert result is None


class TestParsePsDatetime:
    """Tests for _parse_ps_datetime method."""

    def test_parse_datetime_12_hour_format(self, collector):
        """Test parsing 12-hour format datetime."""
        result = collector._parse_ps_datetime("01/08/2024 06:15:49 AM")

        assert result is not None
        assert "2024" in result

    def test_parse_datetime_24_hour_format(self, collector):
        """Test parsing 24-hour format datetime."""
        result = collector._parse_ps_datetime("01/08/2024 18:15:49")

        assert result is not None
        assert "2024" in result

    def test_parse_datetime_iso_format(self, collector):
        """Test parsing ISO format datetime."""
        result = collector._parse_ps_datetime("2024-01-08 18:15:49")

        assert result is not None
        assert "2024" in result

    def test_parse_datetime_iso_t_format(self, collector):
        """Test parsing ISO T format datetime."""
        result = collector._parse_ps_datetime("2024-01-08T18:15:49")

        assert result is not None
        assert "2024" in result

    def test_parse_datetime_iso_microseconds(self, collector):
        """Test parsing ISO format with microseconds."""
        result = collector._parse_ps_datetime("2024-01-08T18:15:49.123456")

        assert result is not None
        assert "2024" in result

    def test_parse_datetime_empty_string(self, collector):
        """Test parsing empty string."""
        result = collector._parse_ps_datetime("")

        assert result is None

    def test_parse_datetime_none(self, collector):
        """Test parsing None."""
        result = collector._parse_ps_datetime(None)

        assert result is None

    def test_parse_datetime_invalid_format(self, collector):
        """Test parsing invalid format."""
        result = collector._parse_ps_datetime("invalid date string")

        assert result is None


class TestParseMacosDatetime:
    """Tests for _parse_macos_datetime method."""

    def test_parse_macos_datetime_mdatp_format(self, collector):
        """Test parsing mdatp format datetime."""
        result = collector._parse_macos_datetime("Oct 10, 2025 at 06:15:49 PM")

        assert result is not None
        assert "2025" in result

    def test_parse_macos_datetime_standard_format(self, collector):
        """Test parsing standard format datetime."""
        result = collector._parse_macos_datetime("2025-10-10 18:15:49")

        assert result is not None
        assert "2025" in result

    def test_parse_macos_datetime_iso_format(self, collector):
        """Test parsing ISO format datetime."""
        result = collector._parse_macos_datetime("2025-10-10T18:15:49")

        assert result is not None
        assert "2025" in result

    def test_parse_macos_datetime_ctime_format(self, collector):
        """Test parsing ctime format datetime."""
        result = collector._parse_macos_datetime("Fri Oct 10 18:15:49 2025")

        assert result is not None
        assert "2025" in result

    def test_parse_macos_datetime_iso_passthrough(self, collector):
        """Test ISO-like string is passed through."""
        result = collector._parse_macos_datetime("2025-10-10 at 18:15:49")

        # Should return as-is if it looks like ISO
        assert result is not None

    def test_parse_macos_datetime_empty_string(self, collector):
        """Test parsing empty string."""
        result = collector._parse_macos_datetime("")

        assert result is None

    def test_parse_macos_datetime_none(self, collector):
        """Test parsing None."""
        result = collector._parse_macos_datetime(None)

        assert result is None

    def test_parse_macos_datetime_invalid_format(self, collector):
        """Test parsing invalid format."""
        result = collector._parse_macos_datetime("not a valid date")

        assert result is None


class TestParseMdatpOutput:
    """Tests for _parse_mdatp_output method."""

    def test_parse_mdatp_output_basic(self, collector):
        """Test parsing basic mdatp output."""
        output = """healthy : true
licensed : true
app_version : 101.12345.0
"""
        result = collector._parse_mdatp_output(output)

        assert result["healthy"] is True
        assert result["licensed"] is True
        assert result["app_version"] == "101.12345.0"

    def test_parse_mdatp_output_with_managed_suffix(self, collector):
        """Test parsing mdatp output with [managed] suffix."""
        output = """real_time_protection_enabled : true [managed]
cloud_enabled : true
"""
        result = collector._parse_mdatp_output(output)

        assert result["real_time_protection_enabled"] is True
        assert result["cloud_enabled"] is True

    def test_parse_mdatp_output_with_quotes(self, collector):
        """Test parsing mdatp output with quoted values."""
        output = """organization_id : "test-org-id"
app_version : 101.12345.0
"""
        result = collector._parse_mdatp_output(output)

        assert result["organization_id"] == "test-org-id"

    def test_parse_mdatp_output_false_values(self, collector):
        """Test parsing mdatp output with false values."""
        output = """real_time_protection_enabled : false
cloud_enabled : false
"""
        result = collector._parse_mdatp_output(output)

        assert result["real_time_protection_enabled"] is False
        assert result["cloud_enabled"] is False

    def test_parse_mdatp_output_skip_lines_without_colon(self, collector):
        """Test parsing mdatp output skips lines without colon."""
        output = """healthy : true
Some random line without colon
app_version : 101.12345.0
"""
        result = collector._parse_mdatp_output(output)

        assert "healthy" in result
        assert "app_version" in result
        assert len(result) == 2

    def test_parse_mdatp_output_empty(self, collector):
        """Test parsing empty mdatp output."""
        result = collector._parse_mdatp_output("")

        assert result == {}


class TestDefenderStatusFields:
    """Tests for verifying all Defender status fields are captured."""

    def test_all_fields_captured(self, collector):
        """Test that all Defender status fields are captured."""
        service_result = Mock()
        service_result.returncode = 0
        service_result.stdout = "Running"

        status_json = {
            "AMServiceEnabled": True,
            "AntispywareEnabled": True,
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "FullScanAge": 7,
            "QuickScanAge": 1,
            "FullScanEndTime": "01/01/2024 12:00:00 PM",
            "QuickScanEndTime": "01/07/2024 12:00:00 PM",
            "AntivirusSignatureLastUpdated": "01/08/2024 06:00:00 AM",
            "AntivirusSignatureVersion": "1.403.123.0",
            "IsTamperProtected": True,
        }

        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = json.dumps(status_json)

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "4.18.2301.0\n"

        with patch(
            "subprocess.run",
            side_effect=[service_result, status_result, version_result],
        ):
            result = collector._detect_windows_commercial_antivirus()

        # Verify all expected fields are present
        expected_fields = [
            "product_name",
            "product_version",
            "service_enabled",
            "antispyware_enabled",
            "antivirus_enabled",
            "realtime_protection_enabled",
            "full_scan_age",
            "quick_scan_age",
            "full_scan_end_time",
            "quick_scan_end_time",
            "signature_last_updated",
            "signature_version",
            "tamper_protection_enabled",
        ]

        for field in expected_fields:
            assert field in result, f"Missing field: {field}"

    def test_macos_fields_captured(self, collector):
        """Test that macOS Defender fields are captured."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/local/bin/mdatp\n"

        health_output = """healthy : true
licensed : true
app_version : 101.12345.0
real_time_protection_enabled : true
definitions_version : 1.403.123.0
definitions_updated : Oct 10, 2025 at 06:15:49 PM
"""

        health_result = Mock()
        health_result.returncode = 0
        health_result.stdout = health_output

        with patch("subprocess.run", side_effect=[which_result, health_result]):
            result = collector._detect_macos_commercial_antivirus()

        # Verify key fields are present
        assert result["product_name"] == "Microsoft Defender for Endpoint"
        assert result["product_version"] is not None
        assert "realtime_protection_enabled" in result
        assert "signature_version" in result


class TestMacosDefenderAlternativeFields:
    """Tests for macOS Defender with alternative field names."""

    def test_macos_realtime_protection_alternative_field(self, collector):
        """Test macOS detection with alternative realTimeProtectionEnabled field."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/local/bin/mdatp\n"

        health_output = """healthy : true
licensed : true
app_version : 101.12345.0
realTimeProtectionEnabled : true
definitions_version : 1.403.123.0
"""

        health_result = Mock()
        health_result.returncode = 0
        health_result.stdout = health_output

        with patch("subprocess.run", side_effect=[which_result, health_result]):
            result = collector._detect_macos_commercial_antivirus()

        assert result["realtime_protection_enabled"] is True

    def test_macos_no_realtime_protection_field(self, collector):
        """Test macOS detection when realtime protection field is missing."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/local/bin/mdatp\n"

        health_output = """healthy : true
licensed : true
app_version : 101.12345.0
"""

        health_result = Mock()
        health_result.returncode = 0
        health_result.stdout = health_output

        with patch("subprocess.run", side_effect=[which_result, health_result]):
            result = collector._detect_macos_commercial_antivirus()

        # Should still succeed, just with None for realtime_protection
        assert result is not None
        assert result["realtime_protection_enabled"] is None


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_windows_version_command_fails(self, collector):
        """Test Windows detection when version command fails."""
        service_result = Mock()
        service_result.returncode = 0
        service_result.stdout = "Running"

        status_json = {"AntivirusEnabled": True}

        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = json.dumps(status_json)

        version_result = Mock()
        version_result.returncode = 1
        version_result.stdout = ""

        with patch(
            "subprocess.run",
            side_effect=[service_result, status_result, version_result],
        ):
            result = collector._detect_windows_commercial_antivirus()

        # Should still return result, just with None version
        assert result is not None
        assert result["product_version"] is None

    def test_windows_empty_status_fields(self, collector):
        """Test Windows detection with empty status fields."""
        service_result = Mock()
        service_result.returncode = 0
        service_result.stdout = "Running"

        # Minimal JSON response
        status_json = {}

        status_result = Mock()
        status_result.returncode = 0
        status_result.stdout = json.dumps(status_json)

        version_result = Mock()
        version_result.returncode = 0
        version_result.stdout = "4.18.2301.0\n"

        with patch(
            "subprocess.run",
            side_effect=[service_result, status_result, version_result],
        ):
            result = collector._detect_windows_commercial_antivirus()

        # Should still return result with None values
        assert result is not None
        assert result["product_name"] == "Microsoft Defender"
        assert result["service_enabled"] is None
        assert result["antivirus_enabled"] is None

    def test_macos_empty_health_output(self, collector):
        """Test macOS detection with empty health output."""
        which_result = Mock()
        which_result.returncode = 0
        which_result.stdout = "/usr/local/bin/mdatp\n"

        health_result = Mock()
        health_result.returncode = 0
        health_result.stdout = ""

        with patch("subprocess.run", side_effect=[which_result, health_result]):
            result = collector._detect_macos_commercial_antivirus()

        # Should still return result with None values
        assert result is not None
        assert result["product_name"] == "Microsoft Defender for Endpoint"
        assert result["product_version"] is None
