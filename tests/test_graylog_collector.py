"""
Tests for Graylog collector module.
Tests Graylog attachment status detection on various platforms.
"""

# pylint: disable=redefined-outer-name,protected-access

import socket
from unittest.mock import Mock, patch, mock_open

import pytest

from src.sysmanage_agent.collection.graylog_collector import GraylogCollector


@pytest.fixture
def collector():
    """Create a Graylog collector for testing."""
    return GraylogCollector()


class TestGraylogCollectorInit:
    """Tests for GraylogCollector initialization."""

    def test_init_creates_logger(self, collector):
        """Test that __init__ creates logger."""
        assert collector.logger is not None

    def test_init_detects_system(self, collector):
        """Test that __init__ detects system."""
        assert collector.system is not None


class TestNoAttachment:
    """Tests for _no_attachment method."""

    def test_no_attachment_returns_correct_structure(self, collector):
        """Test that _no_attachment returns correct structure."""
        result = collector._no_attachment()

        assert result["is_attached"] is False
        assert result["target_hostname"] is None
        assert result["target_ip"] is None
        assert result["mechanism"] is None
        assert result["port"] is None


class TestCollectGraylogStatus:
    """Tests for collect_graylog_status method."""

    def test_collect_status_linux(self, collector):
        """Test status collection on Linux."""
        collector.system = "Linux"

        with patch.object(collector, "_detect_linux_syslog") as mock_detect:
            mock_detect.return_value = collector._no_attachment()
            result = collector.collect_graylog_status()

        mock_detect.assert_called_once()
        assert result["is_attached"] is False

    def test_collect_status_bsd(self, collector):
        """Test status collection on BSD."""
        collector.system = "FreeBSD"

        with patch.object(collector, "_detect_bsd_syslog") as mock_detect:
            mock_detect.return_value = collector._no_attachment()
            _ = collector.collect_graylog_status()

        mock_detect.assert_called_once()

    def test_collect_status_windows(self, collector):
        """Test status collection on Windows."""
        collector.system = "Windows"

        with patch.object(collector, "_detect_windows_sidecar") as mock_detect:
            mock_detect.return_value = collector._no_attachment()
            _ = collector.collect_graylog_status()

        mock_detect.assert_called_once()

    def test_collect_status_unsupported_platform(self, collector):
        """Test status collection on unsupported platform."""
        collector.system = "Unknown"

        result = collector.collect_graylog_status()

        assert result["is_attached"] is False

    def test_collect_status_exception(self, collector):
        """Test status collection with exception."""
        collector.system = "Linux"

        with patch.object(
            collector, "_detect_linux_syslog", side_effect=Exception("test")
        ):
            result = collector.collect_graylog_status()

        assert result["is_attached"] is False


class TestDetectBsdSyslog:
    """Tests for _detect_bsd_syslog method."""

    def test_bsd_no_syslog_conf(self, collector):
        """Test BSD detection when syslog.conf doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = collector._detect_bsd_syslog()

        assert result["is_attached"] is False

    def test_bsd_tcp_forwarding(self, collector):
        """Test BSD TCP forwarding detection."""
        config_content = """
# Syslog configuration
*.* @@192.168.1.100:514
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_content)):
                with patch.object(
                    collector, "_resolve_target", return_value=(None, "192.168.1.100")
                ):
                    result = collector._detect_bsd_syslog()

        assert result["is_attached"] is True
        assert result["target_ip"] == "192.168.1.100"
        assert result["mechanism"] == "syslog_tcp"
        assert result["port"] == 514

    def test_bsd_udp_forwarding(self, collector):
        """Test BSD UDP forwarding detection."""
        config_content = """
# Syslog configuration
*.* @192.168.1.100:514
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_content)):
                with patch.object(
                    collector, "_resolve_target", return_value=(None, "192.168.1.100")
                ):
                    result = collector._detect_bsd_syslog()

        assert result["is_attached"] is True
        assert result["mechanism"] == "syslog_udp"

    def test_bsd_hostname_forwarding(self, collector):
        """Test BSD forwarding to hostname."""
        config_content = """
*.* @graylog.example.com:514
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_content)):
                with patch.object(
                    collector,
                    "_resolve_target",
                    return_value=("graylog.example.com", "10.0.0.1"),
                ):
                    result = collector._detect_bsd_syslog()

        assert result["is_attached"] is True
        assert result["target_hostname"] == "graylog.example.com"
        assert result["target_ip"] == "10.0.0.1"

    def test_bsd_skip_comments(self, collector):
        """Test BSD skips comment lines."""
        config_content = """
# *.* @192.168.1.100:514
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_content)):
                result = collector._detect_bsd_syslog()

        assert result["is_attached"] is False

    def test_bsd_default_port(self, collector):
        """Test BSD default port when not specified."""
        config_content = """
*.* @192.168.1.100
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_content)):
                with patch.object(
                    collector, "_resolve_target", return_value=(None, "192.168.1.100")
                ):
                    result = collector._detect_bsd_syslog()

        assert result["port"] == 514


class TestDetectLinuxSyslog:
    """Tests for _detect_linux_syslog method."""

    def test_linux_rsyslog_running_with_forwarding(self, collector):
        """Test Linux rsyslog with forwarding."""
        with patch.object(collector, "_is_service_running") as mock_service:
            mock_service.side_effect = lambda s: s == "rsyslog"
            with patch.object(collector, "_parse_rsyslog_config") as mock_parse:
                mock_parse.return_value = {
                    "is_attached": True,
                    "target_hostname": None,
                    "target_ip": "192.168.1.100",
                    "mechanism": "syslog_tcp",
                    "port": 514,
                }
                result = collector._detect_linux_syslog()

        assert result["is_attached"] is True

    def test_linux_syslog_ng_running(self, collector):
        """Test Linux syslog-ng with forwarding."""
        with patch.object(collector, "_is_service_running") as mock_service:
            mock_service.side_effect = lambda s: s == "syslog-ng"
            with patch.object(collector, "_parse_rsyslog_config") as mock_rsyslog:
                mock_rsyslog.return_value = collector._no_attachment()
                with patch.object(collector, "_parse_syslog_ng_config") as mock_ng:
                    mock_ng.return_value = {
                        "is_attached": True,
                        "target_hostname": None,
                        "target_ip": "192.168.1.100",
                        "mechanism": "syslog_tcp",
                        "port": 514,
                    }
                    result = collector._detect_linux_syslog()

        assert result["is_attached"] is True

    def test_linux_no_syslog_service(self, collector):
        """Test Linux without syslog services."""
        with patch.object(collector, "_is_service_running", return_value=False):
            result = collector._detect_linux_syslog()

        assert result["is_attached"] is False


class TestParseRsyslogConfig:
    """Tests for _parse_rsyslog_config method."""

    def test_rsyslog_tcp_forwarding(self, collector):
        """Test rsyslog TCP forwarding detection."""
        config_content = """
# Rsyslog configuration
*.* @@192.168.1.100:514
"""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/etc/rsyslog.conf"
            with patch("builtins.open", mock_open(read_data=config_content)):
                with patch.object(
                    collector, "_resolve_target", return_value=(None, "192.168.1.100")
                ):
                    result = collector._parse_rsyslog_config()

        assert result["is_attached"] is True
        assert result["mechanism"] == "syslog_tcp"

    def test_rsyslog_gelf_forwarding(self, collector):
        """Test rsyslog GELF forwarding detection."""
        config_content = """
*.* @192.168.1.100:12201;GELF
"""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/etc/rsyslog.conf"
            with patch("builtins.open", mock_open(read_data=config_content)):
                with patch.object(
                    collector, "_resolve_target", return_value=(None, "192.168.1.100")
                ):
                    result = collector._parse_rsyslog_config()

        assert result["is_attached"] is True
        assert result["mechanism"] == "gelf_tcp"
        assert result["port"] == 12201

    def test_rsyslog_udp_forwarding(self, collector):
        """Test rsyslog UDP forwarding detection."""
        config_content = """
*.* @192.168.1.100:514
"""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/etc/rsyslog.conf"
            with patch("builtins.open", mock_open(read_data=config_content)):
                with patch.object(
                    collector, "_resolve_target", return_value=(None, "192.168.1.100")
                ):
                    result = collector._parse_rsyslog_config()

        assert result["is_attached"] is True
        assert result["mechanism"] == "syslog_udp"


class TestParseSyslogNgConfig:
    """Tests for _parse_syslog_ng_config method."""

    def test_syslog_ng_no_config(self, collector):
        """Test syslog-ng when config doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = collector._parse_syslog_ng_config()

        assert result["is_attached"] is False

    def test_syslog_ng_tcp_destination(self, collector):
        """Test syslog-ng TCP destination detection."""
        config_content = """
destination d_graylog {
    network("192.168.1.100" port(514) transport("tcp"));
};
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_content)):
                with patch.object(
                    collector, "_resolve_target", return_value=(None, "192.168.1.100")
                ):
                    result = collector._parse_syslog_ng_config()

        assert result["is_attached"] is True
        assert result["mechanism"] == "syslog_tcp"
        assert result["port"] == 514


class TestDetectWindowsSidecar:
    """Tests for _detect_windows_sidecar method."""

    def test_windows_sidecar_service_not_running(self, collector):
        """Test Windows Sidecar when service not running."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            result = collector._detect_windows_sidecar()

        assert result["is_attached"] is False

    def test_windows_sidecar_not_in_running_state(self, collector):
        """Test Windows Sidecar when service exists but not running."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "STATE: STOPPED"

        with patch("subprocess.run", return_value=mock_result):
            result = collector._detect_windows_sidecar()

        assert result["is_attached"] is False

    def test_windows_sidecar_running_with_config(self, collector):
        """Test Windows Sidecar when running with valid config."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "STATE: RUNNING"

        config_content = """
server_url: http://graylog.example.com:9000/api/
"""
        with patch("subprocess.run", return_value=mock_result):
            with patch("os.path.exists", return_value=True):
                with patch("builtins.open", mock_open(read_data=config_content)):
                    with patch.object(
                        collector,
                        "_resolve_target",
                        return_value=("graylog.example.com", "10.0.0.1"),
                    ):
                        result = collector._detect_windows_sidecar()

        assert result["is_attached"] is True
        assert result["mechanism"] == "windows_sidecar"
        assert result["port"] == 5044


class TestIsServiceRunning:
    """Tests for _is_service_running method."""

    def test_service_running(self, collector):
        """Test service is running."""
        mock_result = Mock()
        mock_result.stdout = "active\n"

        with patch("subprocess.run", return_value=mock_result):
            result = collector._is_service_running("rsyslog")

        assert result is True

    def test_service_not_running(self, collector):
        """Test service is not running."""
        mock_result = Mock()
        mock_result.stdout = "inactive\n"

        with patch("subprocess.run", return_value=mock_result):
            result = collector._is_service_running("rsyslog")

        assert result is False

    def test_service_check_exception(self, collector):
        """Test service check with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            result = collector._is_service_running("rsyslog")

        assert result is False


class TestResolveTarget:
    """Tests for _resolve_target method."""

    def test_resolve_ip_address(self, collector):
        """Test resolving an IP address."""
        hostname, ip_addr = collector._resolve_target("192.168.1.100")

        assert hostname is None
        assert ip_addr == "192.168.1.100"

    def test_resolve_ipv6_address(self, collector):
        """Test resolving an IPv6 address."""
        hostname, ip_addr = collector._resolve_target("2001:db8::1")

        assert hostname is None
        assert ip_addr == "2001:db8::1"

    def test_resolve_hostname_success(self, collector):
        """Test resolving a hostname successfully."""
        with patch("socket.gethostbyname", return_value="10.0.0.1"):
            hostname, ip_addr = collector._resolve_target("graylog.example.com")

        assert hostname == "graylog.example.com"
        assert ip_addr == "10.0.0.1"

    def test_resolve_hostname_failure(self, collector):
        """Test resolving a hostname that fails."""
        with patch("socket.gethostbyname", side_effect=socket.gaierror):
            hostname, ip_addr = collector._resolve_target("unknown.example.com")

        assert hostname == "unknown.example.com"
        assert ip_addr is None
