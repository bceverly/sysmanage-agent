"""
Comprehensive unit tests for KVM DNS detection utilities.

Tests cover:
- IP address validation
- DNS extraction from various system command outputs
- DNS parsing from different sources (systemd-resolve, resolvectl, resolv.conf, nmcli)
- Fallback behavior when DNS cannot be detected
- Error handling for all detection methods
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
import subprocess
from unittest.mock import Mock, mock_open, patch

import pytest

from src.sysmanage_agent.operations.child_host_kvm_dns import (
    is_valid_ip,
    _extract_dns_from_header_line,
    _extract_dns_continuation,
    _parse_dns_from_systemd_resolve,
    _get_dns_from_systemd_resolve,
    _get_dns_from_resolvectl,
    _get_dns_from_resolv_conf,
    _parse_nmcli_dns,
    _get_dns_from_networkmanager,
    get_host_dns_servers,
)


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_kvm_dns")


class TestIsValidIp:
    """Tests for is_valid_ip function."""

    def test_valid_ip_addresses(self):
        """Test valid IPv4 addresses are recognized."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "8.8.4.4",
            "255.255.255.255",
            "0.0.0.0",
            "1.1.1.1",
            "127.0.0.1",
            "127.0.0.53",
        ]
        for ip_address in valid_ips:
            assert is_valid_ip(ip_address) is True, f"Expected {ip_address} to be valid"

    def test_invalid_ip_out_of_range(self):
        """Test IP addresses with out-of-range octets."""
        invalid_ips = [
            "256.1.1.1",
            "1.256.1.1",
            "1.1.256.1",
            "1.1.1.256",
            "999.999.999.999",
            "300.200.100.50",
        ]
        for ip_address in invalid_ips:
            assert (
                is_valid_ip(ip_address) is False
            ), f"Expected {ip_address} to be invalid"

    def test_invalid_ip_wrong_format(self):
        """Test strings that are not valid IP address format."""
        invalid_formats = [
            "",
            "not.an.ip",
            "192.168.1",
            "192.168.1.1.1",
            "192.168.1.1.extra",
            "abc.def.ghi.jkl",
            "192.168.1.a",
            "192.168.1.",
            ".192.168.1.1",
            "192..168.1.1",
            " 192.168.1.1",
            "192.168.1.1 ",
            "2001:db8::1",  # IPv6 not supported
        ]
        for value in invalid_formats:
            assert is_valid_ip(value) is False, f"Expected {value} to be invalid"

    def test_edge_case_octets(self):
        """Test edge case octet values."""
        assert is_valid_ip("0.0.0.0") is True
        assert is_valid_ip("255.255.255.255") is True
        assert is_valid_ip("0.0.0.1") is True
        assert is_valid_ip("1.0.0.0") is True


class TestExtractDnsFromHeaderLine:
    """Tests for _extract_dns_from_header_line function."""

    def test_dns_on_header_line_with_ip(self):
        """Test extracting DNS IP directly on the header line."""
        line = "         DNS Servers: 192.168.1.1"
        result = _extract_dns_from_header_line(line)
        assert result == "192.168.1.1"

    def test_dns_on_header_line_with_multiple_values(self):
        """Test extracting first DNS IP when multiple are on header line."""
        line = "DNS Servers: 8.8.8.8 8.8.4.4"
        result = _extract_dns_from_header_line(line)
        assert result == "8.8.8.8"

    def test_dns_header_with_no_ip(self):
        """Test header line with no IP following."""
        line = "         DNS Servers:"
        result = _extract_dns_from_header_line(line)
        assert result is None

    def test_dns_header_with_empty_after_colon(self):
        """Test header line with only whitespace after colon."""
        line = "         DNS Servers:   "
        result = _extract_dns_from_header_line(line)
        assert result is None

    def test_dns_header_with_invalid_ip(self):
        """Test header line with invalid IP."""
        line = "         DNS Servers: invalid.ip.address"
        result = _extract_dns_from_header_line(line)
        assert result is None

    def test_line_without_dns_servers_prefix(self):
        """Test line that doesn't contain DNS Servers prefix."""
        line = "Some other content: 192.168.1.1"
        result = _extract_dns_from_header_line(line)
        assert result is None


class TestExtractDnsContinuation:
    """Tests for _extract_dns_continuation function."""

    def test_continuation_line_with_valid_ip(self):
        """Test extracting IP from continuation line."""
        line = "                      192.168.1.2"
        result = _extract_dns_continuation(line)
        assert result == "192.168.1.2"

    def test_continuation_line_with_colon(self):
        """Test that lines with colons return None (new section)."""
        line = "   DNSSEC NTA: some.domain"
        result = _extract_dns_continuation(line)
        assert result is None

    def test_empty_line(self):
        """Test that empty lines return None."""
        result = _extract_dns_continuation("")
        assert result is None

    def test_whitespace_only_line(self):
        """Test that whitespace-only lines return None."""
        result = _extract_dns_continuation("     ")
        assert result is None

    def test_continuation_with_invalid_ip(self):
        """Test continuation line with invalid IP."""
        line = "                      not.valid.ip"
        result = _extract_dns_continuation(line)
        assert result is None

    def test_continuation_with_multiple_values(self):
        """Test continuation line returns first valid IP."""
        line = "                      10.0.0.1 10.0.0.2"
        result = _extract_dns_continuation(line)
        assert result == "10.0.0.1"


class TestParseDnsFromSystemdResolve:
    """Tests for _parse_dns_from_systemd_resolve function."""

    def test_single_dns_on_header(self):
        """Test parsing single DNS on header line."""
        output = """Link 2 (eth0)
      Current Scopes: DNS
       LLMNR setting: no
MulticastDNS setting: no
  DNSSEC supported: no
       DNS Servers: 192.168.1.1
        DNS Domain: example.com
"""
        result = _parse_dns_from_systemd_resolve(output)
        assert result == ["192.168.1.1"]

    def test_multiple_dns_servers(self):
        """Test parsing multiple DNS servers."""
        output = """Link 2 (eth0)
      Current Scopes: DNS
       DNS Servers: 8.8.8.8
                    8.8.4.4
        DNS Domain: example.com
"""
        result = _parse_dns_from_systemd_resolve(output)
        assert result == ["8.8.8.8", "8.8.4.4"]

    def test_dns_on_header_and_continuation(self):
        """Test DNS on header line plus continuation lines."""
        output = """Global
       DNS Servers: 192.168.1.1
                    192.168.1.2
                    10.0.0.1
        DNS Domain: ~.
"""
        result = _parse_dns_from_systemd_resolve(output)
        assert result == ["192.168.1.1", "192.168.1.2", "10.0.0.1"]

    def test_no_dns_servers(self):
        """Test output with no DNS servers."""
        output = """Link 2 (eth0)
      Current Scopes: none
       LLMNR setting: no
"""
        result = _parse_dns_from_systemd_resolve(output)
        assert not result

    def test_empty_output(self):
        """Test empty output."""
        result = _parse_dns_from_systemd_resolve("")
        assert not result

    def test_dns_section_ends_with_new_section(self):
        """Test that DNS section ends when new section starts."""
        output = """Global
       DNS Servers: 1.1.1.1
                    1.0.0.1
      DNSSEC NTA: 10.in-addr.arpa
"""
        result = _parse_dns_from_systemd_resolve(output)
        assert result == ["1.1.1.1", "1.0.0.1"]

    def test_dns_section_ends_with_invalid_line(self):
        """Test DNS section ends with non-IP continuation."""
        output = """Global
       DNS Servers: 9.9.9.9
                    invalid
        DNS Domain: example.com
"""
        result = _parse_dns_from_systemd_resolve(output)
        assert result == ["9.9.9.9"]


class TestGetDnsFromSystemdResolve:
    """Tests for _get_dns_from_systemd_resolve function."""

    def test_success(self):
        """Test successful DNS retrieval from systemd-resolve."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Global
       DNS Servers: 192.168.1.1
        DNS Domain: example.com
"""
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = _get_dns_from_systemd_resolve()

        assert result == ["192.168.1.1"]
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["systemd-resolve", "--status"]

    def test_command_fails(self):
        """Test handling when systemd-resolve command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = _get_dns_from_systemd_resolve()

        assert not result

    def test_command_not_found(self):
        """Test handling when systemd-resolve is not installed."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = _get_dns_from_systemd_resolve()

        assert not result

    def test_timeout(self):
        """Test handling timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
            result = _get_dns_from_systemd_resolve()

        assert not result

    def test_generic_exception(self):
        """Test handling generic exception."""
        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            result = _get_dns_from_systemd_resolve()

        assert not result


class TestGetDnsFromResolvectl:
    """Tests for _get_dns_from_resolvectl function."""

    def test_success(self):
        """Test successful DNS retrieval from resolvectl."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """Global
       DNS Servers: 8.8.8.8
                    8.8.4.4
"""
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = _get_dns_from_resolvectl()

        assert result == ["8.8.8.8", "8.8.4.4"]
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["resolvectl", "status"]

    def test_command_fails(self):
        """Test handling when resolvectl command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = _get_dns_from_resolvectl()

        assert not result

    def test_command_not_found(self):
        """Test handling when resolvectl is not installed."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = _get_dns_from_resolvectl()

        assert not result

    def test_timeout(self):
        """Test handling timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
            result = _get_dns_from_resolvectl()

        assert not result


class TestGetDnsFromResolvConf:
    """Tests for _get_dns_from_resolv_conf function."""

    def test_basic_resolv_conf(self):
        """Test parsing basic resolv.conf."""
        resolv_content = """# Generated by NetworkManager
nameserver 192.168.1.1
nameserver 192.168.1.2
search example.com
"""
        with patch("os.path.islink", return_value=False):
            with patch("builtins.open", mock_open(read_data=resolv_content)):
                result = _get_dns_from_resolv_conf()

        assert result == ["192.168.1.1", "192.168.1.2"]

    def test_skips_stub_resolver_127_0_0_53(self):
        """Test that stub resolver 127.0.0.53 is skipped."""
        resolv_content = """# systemd-resolved stub
nameserver 127.0.0.53
options edns0 trust-ad
"""
        with patch("os.path.islink", return_value=False):
            with patch("builtins.open", mock_open(read_data=resolv_content)):
                result = _get_dns_from_resolv_conf()

        assert not result

    def test_skips_localhost_127_0_0_1(self):
        """Test that localhost 127.0.0.1 is skipped."""
        resolv_content = """nameserver 127.0.0.1
nameserver 8.8.8.8
"""
        with patch("os.path.islink", return_value=False):
            with patch("builtins.open", mock_open(read_data=resolv_content)):
                result = _get_dns_from_resolv_conf()

        assert result == ["8.8.8.8"]

    def test_symlink_to_systemd_resolve_conf(self):
        """Test following symlink to systemd resolve.conf."""
        resolv_content = """nameserver 10.0.0.1
nameserver 10.0.0.2
"""
        with patch("os.path.islink", return_value=True):
            with patch("os.path.exists", return_value=True):
                with patch("builtins.open", mock_open(read_data=resolv_content)):
                    result = _get_dns_from_resolv_conf()

        assert result == ["10.0.0.1", "10.0.0.2"]

    def test_symlink_fallback_to_resolvconf(self):
        """Test fallback to resolvconf when systemd path doesn't exist."""
        resolv_content = """nameserver 172.16.0.1
"""

        def exists_side_effect(path):
            if path == "/run/systemd/resolve/resolv.conf":
                return False
            if path == "/run/resolvconf/resolv.conf":
                return True
            return False

        with patch("os.path.islink", return_value=True):
            with patch("os.path.exists", side_effect=exists_side_effect):
                with patch("builtins.open", mock_open(read_data=resolv_content)):
                    result = _get_dns_from_resolv_conf()

        assert result == ["172.16.0.1"]

    def test_file_not_found(self):
        """Test handling when resolv.conf doesn't exist."""
        with patch("os.path.islink", return_value=False):
            with patch("builtins.open", side_effect=FileNotFoundError()):
                result = _get_dns_from_resolv_conf()

        assert not result

    def test_permission_denied(self):
        """Test handling permission denied error."""
        with patch("os.path.islink", return_value=False):
            with patch("builtins.open", side_effect=PermissionError()):
                result = _get_dns_from_resolv_conf()

        assert not result

    def test_empty_file(self):
        """Test handling empty resolv.conf."""
        with patch("os.path.islink", return_value=False):
            with patch("builtins.open", mock_open(read_data="")):
                result = _get_dns_from_resolv_conf()

        assert not result

    def test_comments_and_empty_lines(self):
        """Test handling comments and empty lines in resolv.conf."""
        resolv_content = """# This is a comment
# Another comment

nameserver 1.1.1.1

# More comments
nameserver 1.0.0.1
"""
        with patch("os.path.islink", return_value=False):
            with patch("builtins.open", mock_open(read_data=resolv_content)):
                result = _get_dns_from_resolv_conf()

        assert result == ["1.1.1.1", "1.0.0.1"]

    def test_invalid_nameserver_lines(self):
        """Test handling malformed nameserver lines.

        Note: The source code accesses line.split()[1] directly without
        checking if there are enough elements. If a line has only 'nameserver'
        with no IP, it throws IndexError which is caught, causing early return.
        """
        # When all lines are valid, they're all parsed
        resolv_content = """nameserver 8.8.8.8
nameserver invalid
nameserver 8.8.4.4
"""
        with patch("os.path.islink", return_value=False):
            with patch("builtins.open", mock_open(read_data=resolv_content)):
                result = _get_dns_from_resolv_conf()

        # 'invalid' is not a valid IP so it's skipped, but valid IPs are included
        assert result == ["8.8.8.8", "8.8.4.4"]

    def test_nameserver_without_ip_causes_exception(self):
        """Test that 'nameserver' without IP causes IndexError and returns early."""
        resolv_content = """nameserver 8.8.8.8
nameserver
nameserver 8.8.4.4
"""
        with patch("os.path.islink", return_value=False):
            with patch("builtins.open", mock_open(read_data=resolv_content)):
                result = _get_dns_from_resolv_conf()

        # IndexError on 'nameserver' line causes early return with only first DNS
        assert result == ["8.8.8.8"]

    def test_no_alternate_paths_exist(self):
        """Test when symlink exists but no alternate paths work."""
        with patch("os.path.islink", return_value=True):
            with patch("os.path.exists", return_value=False):
                with patch("builtins.open", mock_open(read_data="nameserver 5.5.5.5")):
                    result = _get_dns_from_resolv_conf()

        # Falls back to original /etc/resolv.conf path
        assert result == ["5.5.5.5"]


class TestParseNmcliDns:
    """Tests for _parse_nmcli_dns function."""

    def test_single_dns(self):
        """Test parsing single DNS server from nmcli output."""
        output = """GENERAL.DEVICE:                         eth0
GENERAL.TYPE:                           ethernet
IP4.DNS[1]:                             192.168.1.1
"""
        result = _parse_nmcli_dns(output)
        assert result == ["192.168.1.1"]

    def test_multiple_dns_servers(self):
        """Test parsing multiple DNS servers from nmcli output."""
        output = """GENERAL.DEVICE:                         eth0
IP4.DNS[1]:                             8.8.8.8
IP4.DNS[2]:                             8.8.4.4
IP4.ADDRESS[1]:                         192.168.1.100/24
"""
        result = _parse_nmcli_dns(output)
        assert result == ["8.8.8.8", "8.8.4.4"]

    def test_no_dns_servers(self):
        """Test output with no DNS servers."""
        output = """GENERAL.DEVICE:                         eth0
GENERAL.TYPE:                           ethernet
IP4.ADDRESS[1]:                         192.168.1.100/24
"""
        result = _parse_nmcli_dns(output)
        assert not result

    def test_empty_output(self):
        """Test empty output."""
        result = _parse_nmcli_dns("")
        assert not result

    def test_duplicate_dns_servers(self):
        """Test that duplicate DNS servers are not added."""
        output = """GENERAL.DEVICE:                         eth0
IP4.DNS[1]:                             8.8.8.8
GENERAL.DEVICE:                         wlan0
IP4.DNS[1]:                             8.8.8.8
IP4.DNS[2]:                             1.1.1.1
"""
        result = _parse_nmcli_dns(output)
        assert result == ["8.8.8.8", "1.1.1.1"]

    def test_invalid_dns_values(self):
        """Test handling invalid DNS values."""
        output = """IP4.DNS[1]:                             invalid
IP4.DNS[2]:                             8.8.8.8
IP4.DNS[3]:
"""
        result = _parse_nmcli_dns(output)
        assert result == ["8.8.8.8"]

    def test_malformed_lines(self):
        """Test handling malformed lines."""
        output = """IP4.DNS[1]
IP4.DNS[2]: 8.8.8.8
IP4.DNS without colon 1.1.1.1
"""
        result = _parse_nmcli_dns(output)
        assert result == ["8.8.8.8"]


class TestGetDnsFromNetworkManager:
    """Tests for _get_dns_from_networkmanager function."""

    def test_success(self):
        """Test successful DNS retrieval from NetworkManager."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """GENERAL.DEVICE:                         eth0
IP4.DNS[1]:                             192.168.1.1
IP4.DNS[2]:                             192.168.1.2
"""
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = _get_dns_from_networkmanager()

        assert result == ["192.168.1.1", "192.168.1.2"]
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["nmcli", "dev", "show"]

    def test_command_fails(self):
        """Test handling when nmcli command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = _get_dns_from_networkmanager()

        assert not result

    def test_command_not_found(self):
        """Test handling when nmcli is not installed."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = _get_dns_from_networkmanager()

        assert not result

    def test_timeout(self):
        """Test handling timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
            result = _get_dns_from_networkmanager()

        assert not result


class TestGetHostDnsServers:
    """Tests for get_host_dns_servers function."""

    def test_uses_systemd_resolve_first(self, logger):
        """Test that systemd-resolve is tried first."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_systemd_resolve",
            return_value=["1.1.1.1"],
        ) as mock_systemd:
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolvectl"
            ) as mock_resolvectl:
                result = get_host_dns_servers(logger)

        assert result == ["1.1.1.1"]
        mock_systemd.assert_called_once()
        mock_resolvectl.assert_not_called()

    def test_falls_back_to_resolvectl(self, logger):
        """Test fallback to resolvectl when systemd-resolve fails."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_systemd_resolve",
            return_value=[],
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolvectl",
                return_value=["2.2.2.2"],
            ) as mock_resolvectl:
                with patch(
                    "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolv_conf"
                ) as mock_resolv:
                    result = get_host_dns_servers(logger)

        assert result == ["2.2.2.2"]
        mock_resolvectl.assert_called_once()
        mock_resolv.assert_not_called()

    def test_falls_back_to_resolv_conf(self, logger):
        """Test fallback to resolv.conf when resolvectl fails."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_systemd_resolve",
            return_value=[],
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolvectl",
                return_value=[],
            ):
                with patch(
                    "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolv_conf",
                    return_value=["3.3.3.3"],
                ) as mock_resolv:
                    with patch(
                        "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_networkmanager"
                    ) as mock_nm:
                        result = get_host_dns_servers(logger)

        assert result == ["3.3.3.3"]
        mock_resolv.assert_called_once()
        mock_nm.assert_not_called()

    def test_falls_back_to_networkmanager(self, logger):
        """Test fallback to NetworkManager when resolv.conf fails."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_systemd_resolve",
            return_value=[],
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolvectl",
                return_value=[],
            ):
                with patch(
                    "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolv_conf",
                    return_value=[],
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_networkmanager",
                        return_value=["4.4.4.4"],
                    ) as mock_nm:
                        result = get_host_dns_servers(logger)

        assert result == ["4.4.4.4"]
        mock_nm.assert_called_once()

    def test_uses_fallback_dns_when_all_fail(self, logger):
        """Test fallback to public DNS when all methods fail."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_systemd_resolve",
            return_value=[],
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolvectl",
                return_value=[],
            ):
                with patch(
                    "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolv_conf",
                    return_value=[],
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_networkmanager",
                        return_value=[],
                    ):
                        result = get_host_dns_servers(logger)

        assert result == ["8.8.8.8", "8.8.4.4"]

    def test_limits_to_three_dns_servers(self, logger):
        """Test that result is limited to 3 DNS servers."""
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_systemd_resolve",
            return_value=["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"],
        ):
            result = get_host_dns_servers(logger)

        assert len(result) == 3
        assert result == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    def test_logs_warning_on_fallback(self):
        """Test that warning is logged when using fallback DNS."""
        mock_logger = Mock()
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_systemd_resolve",
            return_value=[],
        ):
            with patch(
                "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolvectl",
                return_value=[],
            ):
                with patch(
                    "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_resolv_conf",
                    return_value=[],
                ):
                    with patch(
                        "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_networkmanager",
                        return_value=[],
                    ):
                        get_host_dns_servers(mock_logger)

        mock_logger.warning.assert_called_once()

    def test_logs_info_with_detected_servers(self):
        """Test that info is logged with detected DNS servers."""
        mock_logger = Mock()
        with patch(
            "src.sysmanage_agent.operations.child_host_kvm_dns._get_dns_from_systemd_resolve",
            return_value=["9.9.9.9"],
        ):
            get_host_dns_servers(mock_logger)

        mock_logger.info.assert_called_once()


class TestIntegration:
    """Integration tests for DNS detection."""

    def test_real_systemd_resolve_output_parsing(self):
        """Test parsing real-world systemd-resolve output."""
        real_output = """Global
         DNSSEC NTA: 10.in-addr.arpa
                     16.172.in-addr.arpa
                     168.192.in-addr.arpa
                     17.172.in-addr.arpa

Link 2 (eth0)
      Current Scopes: DNS
       LLMNR setting: yes
MulticastDNS setting: no
      DNSSEC setting: no
    DNSSEC supported: no
         DNS Servers: 10.0.2.3
          DNS Domain: ~.
"""
        result = _parse_dns_from_systemd_resolve(real_output)
        assert result == ["10.0.2.3"]

    def test_real_nmcli_output_parsing(self):
        """Test parsing real-world nmcli output."""
        real_output = """GENERAL.DEVICE:                         enp0s3
GENERAL.TYPE:                           ethernet
GENERAL.HWADDR:                         08:00:27:8E:28:53
GENERAL.MTU:                            1500
GENERAL.STATE:                          100 (connected)
GENERAL.CONNECTION:                     Wired connection 1
GENERAL.CON-PATH:                       /org/freedesktop/NetworkManager/ActiveConnection/1
WIRED-PROPERTIES.CARRIER:               on
IP4.ADDRESS[1]:                         10.0.2.15/24
IP4.GATEWAY:                            10.0.2.2
IP4.ROUTE[1]:                           dst = 0.0.0.0/0, nh = 10.0.2.2, mt = 100
IP4.ROUTE[2]:                           dst = 10.0.2.0/24, nh = 0.0.0.0, mt = 100
IP4.ROUTE[3]:                           dst = 169.254.0.0/16, nh = 0.0.0.0, mt = 1000
IP4.DNS[1]:                             10.0.2.3
IP6.ADDRESS[1]:                         fe80::a00:27ff:fe8e:2853/64
IP6.GATEWAY:                            --
IP6.ROUTE[1]:                           dst = fe80::/64, nh = ::, mt = 100
"""
        result = _parse_nmcli_dns(real_output)
        assert result == ["10.0.2.3"]

    def test_real_resolv_conf_with_mixed_content(self):
        """Test parsing real-world resolv.conf with various content."""
        resolv_content = """# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "resolvectl status" to see details about the actual nameservers.

nameserver 127.0.0.53
options edns0 trust-ad
search localdomain
"""
        with patch("os.path.islink", return_value=False):
            with patch("builtins.open", mock_open(read_data=resolv_content)):
                result = _get_dns_from_resolv_conf()

        # 127.0.0.53 should be filtered out
        assert not result

    def test_resolvectl_output_format(self):
        """Test parsing resolvectl output format (slightly different from systemd-resolve)."""
        resolvectl_output = """Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub
Current DNS Server: 8.8.8.8
       DNS Servers: 8.8.8.8
                    8.8.4.4
        DNS Domain: ~.

Link 2 (eth0)
    Current Scopes: DNS
         Protocols: +DefaultRoute +LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 10.0.2.3
       DNS Servers: 10.0.2.3
        DNS Domain: ~.
"""
        result = _parse_dns_from_systemd_resolve(resolvectl_output)
        # Should get the first DNS servers section's entries
        assert "8.8.8.8" in result
        assert "8.8.4.4" in result
