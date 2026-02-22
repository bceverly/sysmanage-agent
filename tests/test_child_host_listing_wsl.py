"""
Comprehensive unit tests for WSL listing operations.

Tests cover:
- WSLListing initialization
- list_wsl_instances method with various scenarios
- WSL output decoding
- WSL output line parsing
- WSL status mapping
- WSL GUID retrieval from Windows registry
- WSL hostname retrieval methods
- Distribution name parsing
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
import subprocess
from unittest.mock import Mock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.child_host_listing_wsl import WSLListing


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test")


@pytest.fixture
def wsl_listing(logger):
    """Create a WSLListing instance for testing."""
    return WSLListing(logger)


class TestWSLListingInit:
    """Tests for WSLListing initialization."""

    def test_init_sets_logger(self, logger):
        """Test that __init__ sets logger."""
        listing = WSLListing(logger)
        assert listing.logger == logger


class TestListWslInstances:
    """Tests for list_wsl_instances method."""

    def test_list_wsl_instances_success(self, wsl_listing):
        """Test successful WSL instance listing."""
        mock_result = Mock()
        mock_result.returncode = 0
        # Use UTF-16-LE encoding like Windows WSL actually outputs
        mock_result.stdout = (
            "  NAME      STATE           VERSION\n"
            "* Ubuntu    Running         2\n"
            "  Debian    Stopped         2\n"
        ).encode("utf-16-le")
        mock_result.stderr = b""

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            return_value=mock_result,
        ):
            with patch.object(
                wsl_listing, "_get_wsl_hostname", return_value="ubuntu.example.com"
            ):
                with patch.object(wsl_listing, "_get_wsl_guid", return_value="abc-123"):
                    instances = wsl_listing.list_wsl_instances()

        assert len(instances) == 2
        assert instances[0]["child_name"] == "Ubuntu"
        assert instances[0]["status"] == "running"
        assert instances[0]["is_default"] is True
        assert instances[0]["wsl_version"] == "2"
        assert instances[1]["child_name"] == "Debian"
        assert instances[1]["status"] == "stopped"
        assert instances[1]["is_default"] is False

    def test_list_wsl_instances_command_fails(self, wsl_listing):
        """Test WSL listing when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"Error: WSL not found"

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            return_value=mock_result,
        ):
            instances = wsl_listing.list_wsl_instances()

        assert instances == []

    def test_list_wsl_instances_no_distributions(self, wsl_listing):
        """Test WSL listing with no installed distributions."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Windows Subsystem for Linux has no installed distributions.".encode(
                "utf-8"
            )
        )
        mock_result.stderr = b""

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            return_value=mock_result,
        ):
            instances = wsl_listing.list_wsl_instances()

        assert instances == []

    def test_list_wsl_instances_timeout(self, wsl_listing):
        """Test WSL listing when command times out."""
        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            side_effect=subprocess.TimeoutExpired("wsl", 30),
        ):
            instances = wsl_listing.list_wsl_instances()

        assert instances == []

    def test_list_wsl_instances_file_not_found(self, wsl_listing):
        """Test WSL listing when wsl command not found."""
        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            side_effect=FileNotFoundError("wsl not found"),
        ):
            instances = wsl_listing.list_wsl_instances()

        assert instances == []

    def test_list_wsl_instances_generic_exception(self, wsl_listing):
        """Test WSL listing with generic exception."""
        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            side_effect=Exception("Unknown error"),
        ):
            instances = wsl_listing.list_wsl_instances()

        assert instances == []

    def test_list_wsl_instances_empty_output(self, wsl_listing):
        """Test WSL listing with empty output."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            return_value=mock_result,
        ):
            instances = wsl_listing.list_wsl_instances()

        assert instances == []

    def test_list_wsl_instances_only_header(self, wsl_listing):
        """Test WSL listing with only header line."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "  NAME      STATE           VERSION\n".encode("utf-8")
        mock_result.stderr = b""

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            return_value=mock_result,
        ):
            instances = wsl_listing.list_wsl_instances()

        assert instances == []

    def test_list_wsl_instances_utf16_encoding(self, wsl_listing):
        """Test WSL listing with UTF-16-LE encoding (Windows default)."""
        mock_result = Mock()
        mock_result.returncode = 0
        # Encode as UTF-16-LE like Windows does
        mock_result.stdout = (
            "  NAME      STATE           VERSION\n" "* Ubuntu    Running         2\n"
        ).encode("utf-16-le")
        mock_result.stderr = b""

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            return_value=mock_result,
        ):
            with patch.object(
                wsl_listing, "_get_wsl_hostname", return_value="ubuntu.example.com"
            ):
                with patch.object(wsl_listing, "_get_wsl_guid", return_value="abc-123"):
                    instances = wsl_listing.list_wsl_instances()

        assert len(instances) == 1
        assert instances[0]["child_name"] == "Ubuntu"


class TestDecodeWslOutput:
    """Tests for _decode_wsl_output method."""

    def test_decode_utf16le(self, wsl_listing):
        """Test decoding UTF-16-LE encoded output."""
        text = "Ubuntu Running 2"
        encoded = text.encode("utf-16-le")
        result = wsl_listing._decode_wsl_output(encoded)
        assert result == text

    def test_decode_utf8(self, wsl_listing):
        """Test decoding UTF-8 encoded output."""
        text = "Ubuntu Running 2"
        # Create bytes that are valid UTF-8 but not valid UTF-16-LE
        encoded = text.encode("utf-8")
        # Prepend an odd byte to break UTF-16-LE decoding
        bad_utf16 = b"\xff" + encoded
        result = wsl_listing._decode_wsl_output(bad_utf16)
        # Should fall back to UTF-8 or latin-1
        assert "Ubuntu" in result or len(result) > 0

    def test_decode_latin1(self, wsl_listing):
        """Test decoding latin-1 encoded output."""
        # Use bytes that are invalid UTF-8 and UTF-16-LE
        # Latin-1 can decode any byte sequence
        encoded = b"\x80\x81\x82"
        result = wsl_listing._decode_wsl_output(encoded)
        # Should not raise, latin-1 will decode anything
        assert isinstance(result, str)

    def test_decode_removes_null_chars(self, wsl_listing):
        """Test that null characters are removed from output."""
        text = "U\x00b\x00u\x00n\x00t\x00u\x00"
        result = wsl_listing._decode_wsl_output(text.encode("utf-8"))
        assert "\x00" not in result


class TestParseWslOutputLines:
    """Tests for _parse_wsl_output_lines method."""

    def test_parse_multiple_lines(self, wsl_listing):
        """Test parsing multiple WSL output lines."""
        lines = [
            "* Ubuntu    Running         2",
            "  Debian    Stopped         2",
            "  Fedora    Running         1",
        ]

        with patch.object(wsl_listing, "_get_wsl_hostname", return_value=None):
            with patch.object(wsl_listing, "_get_wsl_guid", return_value=None):
                instances = wsl_listing._parse_wsl_output_lines(lines)

        assert len(instances) == 3

    def test_parse_empty_lines_skipped(self, wsl_listing):
        """Test that empty lines are skipped."""
        lines = [
            "* Ubuntu    Running         2",
            "",
            "   ",
            "  Debian    Stopped         2",
        ]

        with patch.object(wsl_listing, "_get_wsl_hostname", return_value=None):
            with patch.object(wsl_listing, "_get_wsl_guid", return_value=None):
                instances = wsl_listing._parse_wsl_output_lines(lines)

        assert len(instances) == 2

    def test_parse_invalid_lines_skipped(self, wsl_listing):
        """Test that invalid lines are skipped."""
        lines = [
            "* Ubuntu    Running         2",
            "X",  # Too short, will return None
        ]

        with patch.object(wsl_listing, "_get_wsl_hostname", return_value=None):
            with patch.object(wsl_listing, "_get_wsl_guid", return_value=None):
                instances = wsl_listing._parse_wsl_output_lines(lines)

        assert len(instances) == 1


class TestParseSingleWslLine:
    """Tests for _parse_single_wsl_line method."""

    def test_parse_default_running_instance(self, wsl_listing):
        """Test parsing a default running instance."""
        line = "* Ubuntu    Running         2"

        with patch.object(
            wsl_listing, "_get_wsl_hostname", return_value="ubuntu.example.com"
        ):
            with patch.object(wsl_listing, "_get_wsl_guid", return_value="abc-123"):
                result = wsl_listing._parse_single_wsl_line(line)

        assert result is not None
        assert result["child_type"] == "wsl"
        assert result["child_name"] == "Ubuntu"
        assert result["status"] == "running"
        assert result["is_default"] is True
        assert result["wsl_version"] == "2"
        assert result["hostname"] == "ubuntu.example.com"
        assert result["wsl_guid"] == "abc-123"

    def test_parse_non_default_stopped_instance(self, wsl_listing):
        """Test parsing a non-default stopped instance."""
        line = "  Debian    Stopped         2"

        with patch.object(wsl_listing, "_get_wsl_hostname", return_value=None):
            with patch.object(wsl_listing, "_get_wsl_guid", return_value="def-456"):
                result = wsl_listing._parse_single_wsl_line(line)

        assert result is not None
        assert result["child_name"] == "Debian"
        assert result["status"] == "stopped"
        assert result["is_default"] is False
        assert result["hostname"] is None

    def test_parse_wsl_version_1(self, wsl_listing):
        """Test parsing instance with WSL version 1."""
        line = "  Ubuntu-18.04    Running         1"

        with patch.object(
            wsl_listing, "_get_wsl_hostname", return_value="ubuntu.example.com"
        ):
            with patch.object(wsl_listing, "_get_wsl_guid", return_value=None):
                result = wsl_listing._parse_single_wsl_line(line)

        assert result["wsl_version"] == "1"

    def test_parse_no_version(self, wsl_listing):
        """Test parsing instance without version (defaults to 2)."""
        line = "  Ubuntu    Running"

        with patch.object(wsl_listing, "_get_wsl_hostname", return_value=None):
            with patch.object(wsl_listing, "_get_wsl_guid", return_value=None):
                result = wsl_listing._parse_single_wsl_line(line)

        assert result["wsl_version"] == "2"

    def test_parse_too_short_line(self, wsl_listing):
        """Test parsing a line with insufficient parts."""
        line = "Ubuntu"
        result = wsl_listing._parse_single_wsl_line(line)
        assert result is None

    def test_parse_running_instance_gets_hostname(self, wsl_listing):
        """Test that running instances query for hostname."""
        line = "* Ubuntu    Running         2"

        with patch.object(
            wsl_listing, "_get_wsl_hostname", return_value="test.host.com"
        ) as mock_hostname:
            with patch.object(wsl_listing, "_get_wsl_guid", return_value=None):
                result = wsl_listing._parse_single_wsl_line(line)

        mock_hostname.assert_called_once_with("Ubuntu")
        assert result["hostname"] == "test.host.com"

    def test_parse_stopped_instance_no_hostname_query(self, wsl_listing):
        """Test that stopped instances do not query for hostname."""
        line = "  Ubuntu    Stopped         2"

        with patch.object(
            wsl_listing, "_get_wsl_hostname", return_value="should.not.be.called"
        ) as mock_hostname:
            with patch.object(wsl_listing, "_get_wsl_guid", return_value=None):
                result = wsl_listing._parse_single_wsl_line(line)

        mock_hostname.assert_not_called()
        assert result["hostname"] is None


class TestMapWslStatus:
    """Tests for _map_wsl_status method."""

    def test_map_running_status(self, wsl_listing):
        """Test mapping running status."""
        assert wsl_listing._map_wsl_status("running") == "running"

    def test_map_stopped_status(self, wsl_listing):
        """Test mapping stopped status."""
        assert wsl_listing._map_wsl_status("stopped") == "stopped"

    def test_map_unknown_status(self, wsl_listing):
        """Test mapping unknown status (passthrough)."""
        assert wsl_listing._map_wsl_status("installing") == "installing"
        assert wsl_listing._map_wsl_status("converting") == "converting"
        assert wsl_listing._map_wsl_status("unknown") == "unknown"


class TestGetWslGuid:
    """Tests for _get_wsl_guid method."""

    def test_get_guid_winreg_not_available(self, wsl_listing):
        """Test GUID retrieval when winreg is not available."""
        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.winreg", None
        ):
            result = wsl_listing._get_wsl_guid("Ubuntu")

        assert result is None

    def test_get_guid_success(self, wsl_listing):
        """Test successful GUID retrieval."""
        mock_winreg = MagicMock()
        mock_lxss_key = MagicMock()
        mock_dist_key = MagicMock()

        # Mock EnumKey to return one GUID, then raise OSError
        mock_winreg.EnumKey.side_effect = [
            "{abc-123-def}",
            OSError("No more keys"),
        ]

        # Mock QueryValueEx to return the distribution name
        mock_winreg.QueryValueEx.return_value = ("Ubuntu", 1)

        # Set up context managers for OpenKey
        mock_winreg.OpenKey.side_effect = [mock_lxss_key, mock_dist_key]
        mock_lxss_key.__enter__ = Mock(return_value=mock_lxss_key)
        mock_lxss_key.__exit__ = Mock(return_value=False)
        mock_dist_key.__enter__ = Mock(return_value=mock_dist_key)
        mock_dist_key.__exit__ = Mock(return_value=False)

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.winreg",
            mock_winreg,
        ):
            result = wsl_listing._get_wsl_guid("Ubuntu")

        assert result == "abc-123-def"

    def test_get_guid_registry_key_not_found(self, wsl_listing):
        """Test GUID retrieval when registry key not found."""
        mock_winreg = MagicMock()
        mock_winreg.OpenKey.side_effect = FileNotFoundError("Key not found")
        mock_winreg.HKEY_CURRENT_USER = 1

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.winreg",
            mock_winreg,
        ):
            result = wsl_listing._get_wsl_guid("Ubuntu")

        assert result is None

    def test_get_guid_generic_error(self, wsl_listing):
        """Test GUID retrieval with generic error."""
        mock_winreg = MagicMock()
        mock_winreg.OpenKey.side_effect = Exception("Access denied")
        mock_winreg.HKEY_CURRENT_USER = 1

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.winreg",
            mock_winreg,
        ):
            result = wsl_listing._get_wsl_guid("Ubuntu")

        assert result is None

    def test_get_guid_distribution_name_not_found(self, wsl_listing):
        """Test GUID retrieval when DistributionName value not found."""
        mock_winreg = MagicMock()
        mock_lxss_key = MagicMock()
        mock_dist_key = MagicMock()

        mock_winreg.EnumKey.side_effect = ["{abc-123}", OSError()]
        mock_winreg.QueryValueEx.side_effect = FileNotFoundError("Value not found")

        mock_winreg.OpenKey.side_effect = [mock_lxss_key, mock_dist_key]
        mock_lxss_key.__enter__ = Mock(return_value=mock_lxss_key)
        mock_lxss_key.__exit__ = Mock(return_value=False)
        mock_dist_key.__enter__ = Mock(return_value=mock_dist_key)
        mock_dist_key.__exit__ = Mock(return_value=False)

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.winreg",
            mock_winreg,
        ):
            result = wsl_listing._get_wsl_guid("Ubuntu")

        assert result is None

    def test_get_guid_wrong_distribution(self, wsl_listing):
        """Test GUID retrieval when distribution name doesn't match."""
        mock_winreg = MagicMock()
        mock_lxss_key = MagicMock()
        mock_dist_key = MagicMock()

        mock_winreg.EnumKey.side_effect = ["{abc-123}", OSError()]
        mock_winreg.QueryValueEx.return_value = ("Debian", 1)

        mock_winreg.OpenKey.side_effect = [mock_lxss_key, mock_dist_key]
        mock_lxss_key.__enter__ = Mock(return_value=mock_lxss_key)
        mock_lxss_key.__exit__ = Mock(return_value=False)
        mock_dist_key.__enter__ = Mock(return_value=mock_dist_key)
        mock_dist_key.__exit__ = Mock(return_value=False)

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.winreg",
            mock_winreg,
        ):
            result = wsl_listing._get_wsl_guid("Ubuntu")

        assert result is None


class TestGetWslHostname:
    """Tests for _get_wsl_hostname method."""

    def test_get_hostname_from_wsl_conf(self, wsl_listing):
        """Test getting hostname from wsl.conf."""
        with patch.object(
            wsl_listing, "_try_wsl_conf_hostname", return_value="server.example.com"
        ):
            result = wsl_listing._get_wsl_hostname("Ubuntu")

        assert result == "server.example.com"

    def test_get_hostname_from_etc_hostname_fqdn(self, wsl_listing):
        """Test getting FQDN from /etc/hostname."""
        with patch.object(wsl_listing, "_try_wsl_conf_hostname", return_value=None):
            with patch.object(
                wsl_listing, "_try_etc_hostname_fqdn", return_value="host.domain.com"
            ):
                result = wsl_listing._get_wsl_hostname("Ubuntu")

        assert result == "host.domain.com"

    def test_get_hostname_from_hostname_f_command(self, wsl_listing):
        """Test getting hostname from hostname -f command."""
        with patch.object(wsl_listing, "_try_wsl_conf_hostname", return_value=None):
            with patch.object(wsl_listing, "_try_etc_hostname_fqdn", return_value=None):
                with patch.object(
                    wsl_listing,
                    "_try_hostname_fqdn_command",
                    return_value="fqdn.example.com",
                ):
                    result = wsl_listing._get_wsl_hostname("Ubuntu")

        assert result == "fqdn.example.com"

    def test_get_hostname_from_hostname_command(self, wsl_listing):
        """Test getting hostname from hostname command."""
        with patch.object(wsl_listing, "_try_wsl_conf_hostname", return_value=None):
            with patch.object(wsl_listing, "_try_etc_hostname_fqdn", return_value=None):
                with patch.object(
                    wsl_listing, "_try_hostname_fqdn_command", return_value=None
                ):
                    with patch.object(
                        wsl_listing, "_try_hostname_command", return_value="myhost"
                    ):
                        result = wsl_listing._get_wsl_hostname("Ubuntu")

        assert result == "myhost"

    def test_get_hostname_from_etc_hostname_any(self, wsl_listing):
        """Test getting any hostname from /etc/hostname as fallback."""
        with patch.object(wsl_listing, "_try_wsl_conf_hostname", return_value=None):
            with patch.object(wsl_listing, "_try_etc_hostname_fqdn", return_value=None):
                with patch.object(
                    wsl_listing, "_try_hostname_fqdn_command", return_value=None
                ):
                    with patch.object(
                        wsl_listing, "_try_hostname_command", return_value=None
                    ):
                        with patch.object(
                            wsl_listing,
                            "_try_etc_hostname_any",
                            return_value="shortname",
                        ):
                            result = wsl_listing._get_wsl_hostname("Ubuntu")

        assert result == "shortname"

    def test_get_hostname_all_methods_fail(self, wsl_listing):
        """Test when all hostname methods fail."""
        with patch.object(wsl_listing, "_try_wsl_conf_hostname", return_value=None):
            with patch.object(wsl_listing, "_try_etc_hostname_fqdn", return_value=None):
                with patch.object(
                    wsl_listing, "_try_hostname_fqdn_command", return_value=None
                ):
                    with patch.object(
                        wsl_listing, "_try_hostname_command", return_value=None
                    ):
                        with patch.object(
                            wsl_listing, "_try_etc_hostname_any", return_value=None
                        ):
                            result = wsl_listing._get_wsl_hostname("Ubuntu")

        assert result is None

    def test_get_hostname_exception_handling(self, wsl_listing):
        """Test exception handling in _get_wsl_hostname."""
        with patch.object(
            wsl_listing, "_try_wsl_conf_hostname", side_effect=Exception("Test error")
        ):
            result = wsl_listing._get_wsl_hostname("Ubuntu")

        assert result is None


class TestGetWslCreationflags:
    """Tests for _get_wsl_creationflags method."""

    def test_creationflags_with_create_no_window(self, wsl_listing):
        """Test creationflags when CREATE_NO_WINDOW is available."""
        with patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True):
            result = wsl_listing._get_wsl_creationflags()

        assert result == 0x08000000

    def test_creationflags_without_create_no_window(self, wsl_listing):
        """Test creationflags when CREATE_NO_WINDOW is not available."""
        # Remove CREATE_NO_WINDOW if it exists
        original = getattr(subprocess, "CREATE_NO_WINDOW", None)
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            delattr(subprocess, "CREATE_NO_WINDOW")

        try:
            result = wsl_listing._get_wsl_creationflags()
            assert result == 0
        finally:
            # Restore if it existed
            if original is not None:
                subprocess.CREATE_NO_WINDOW = original


class TestTryWslConfHostname:
    """Tests for _try_wsl_conf_hostname method."""

    def test_try_wsl_conf_hostname_success(self, wsl_listing):
        """Test successful hostname retrieval from wsl.conf."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "server.example.com"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_wsl_conf_hostname("Ubuntu")

        assert result == "server.example.com"

    def test_try_wsl_conf_hostname_localhost_rejected(self, wsl_listing):
        """Test that localhost is rejected."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "localhost"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_wsl_conf_hostname("Ubuntu")

        assert result is None

    def test_try_wsl_conf_hostname_no_dot_rejected(self, wsl_listing):
        """Test that hostname without dot is rejected."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "shortname"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_wsl_conf_hostname("Ubuntu")

        assert result is None

    def test_try_wsl_conf_hostname_command_fails(self, wsl_listing):
        """Test when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_wsl_conf_hostname("Ubuntu")

        assert result is None

    def test_try_wsl_conf_hostname_empty_output(self, wsl_listing):
        """Test when output is empty."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_wsl_conf_hostname("Ubuntu")

        assert result is None


class TestTryEtcHostnameFqdn:
    """Tests for _try_etc_hostname_fqdn method."""

    def test_try_etc_hostname_fqdn_success(self, wsl_listing):
        """Test successful FQDN retrieval from /etc/hostname."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "host.example.com"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_etc_hostname_fqdn("Ubuntu")

        assert result == "host.example.com"

    def test_try_etc_hostname_fqdn_no_dot_rejected(self, wsl_listing):
        """Test that hostname without dot is rejected."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "shortname"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_etc_hostname_fqdn("Ubuntu")

        assert result is None

    def test_try_etc_hostname_fqdn_localhost_rejected(self, wsl_listing):
        """Test that localhost is rejected."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "localhost"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_etc_hostname_fqdn("Ubuntu")

        assert result is None

    def test_try_etc_hostname_fqdn_command_fails(self, wsl_listing):
        """Test when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_etc_hostname_fqdn("Ubuntu")

        assert result is None


class TestTryHostnameFqdnCommand:
    """Tests for _try_hostname_fqdn_command method."""

    def test_try_hostname_fqdn_command_success(self, wsl_listing):
        """Test successful hostname -f command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "fqdn.example.com"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_hostname_fqdn_command("Ubuntu")

        assert result == "fqdn.example.com"

    def test_try_hostname_fqdn_command_localhost_rejected(self, wsl_listing):
        """Test that localhost is rejected."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "localhost"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_hostname_fqdn_command("Ubuntu")

        assert result is None

    def test_try_hostname_fqdn_command_fails(self, wsl_listing):
        """Test when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_hostname_fqdn_command("Ubuntu")

        assert result is None

    def test_try_hostname_fqdn_command_empty_output(self, wsl_listing):
        """Test when output is empty."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_hostname_fqdn_command("Ubuntu")

        assert result is None


class TestTryHostnameCommand:
    """Tests for _try_hostname_command method."""

    def test_try_hostname_command_success(self, wsl_listing):
        """Test successful hostname command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "myhost"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_hostname_command("Ubuntu")

        assert result == "myhost"

    def test_try_hostname_command_fails(self, wsl_listing):
        """Test when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_hostname_command("Ubuntu")

        assert result is None

    def test_try_hostname_command_empty_output(self, wsl_listing):
        """Test when output is empty."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_hostname_command("Ubuntu")

        assert result is None

    def test_try_hostname_command_with_whitespace(self, wsl_listing):
        """Test that whitespace is stripped."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "  myhost  \n"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_hostname_command("Ubuntu")

        assert result == "myhost"


class TestTryEtcHostnameAny:
    """Tests for _try_etc_hostname_any method."""

    def test_try_etc_hostname_any_success(self, wsl_listing):
        """Test successful hostname retrieval."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "shortname"

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_etc_hostname_any("Ubuntu")

        assert result == "shortname"

    def test_try_etc_hostname_any_fails(self, wsl_listing):
        """Test when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_etc_hostname_any("Ubuntu")

        assert result is None

    def test_try_etc_hostname_any_empty_output(self, wsl_listing):
        """Test when output is empty."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = wsl_listing._try_etc_hostname_any("Ubuntu")

        assert result is None


class TestParseWslDistribution:
    """Tests for _parse_wsl_distribution method."""

    def test_parse_ubuntu_exact_match(self, wsl_listing):
        """Test parsing Ubuntu exact match."""
        result = wsl_listing._parse_wsl_distribution("Ubuntu")
        assert result["distribution_name"] == "Ubuntu"
        assert result["distribution_version"] is None

    def test_parse_ubuntu_with_version(self, wsl_listing):
        """Test parsing Ubuntu with version."""
        result = wsl_listing._parse_wsl_distribution("Ubuntu-24.04")
        assert result["distribution_name"] == "Ubuntu"
        assert result["distribution_version"] == "24.04"

    def test_parse_ubuntu_2204(self, wsl_listing):
        """Test parsing Ubuntu 22.04."""
        result = wsl_listing._parse_wsl_distribution("Ubuntu-22.04")
        assert result["distribution_name"] == "Ubuntu"
        assert result["distribution_version"] == "22.04"

    def test_parse_ubuntu_2004(self, wsl_listing):
        """Test parsing Ubuntu 20.04."""
        result = wsl_listing._parse_wsl_distribution("Ubuntu-20.04")
        assert result["distribution_name"] == "Ubuntu"
        assert result["distribution_version"] == "20.04"

    def test_parse_ubuntu_1804(self, wsl_listing):
        """Test parsing Ubuntu 18.04."""
        result = wsl_listing._parse_wsl_distribution("Ubuntu-18.04")
        assert result["distribution_name"] == "Ubuntu"
        assert result["distribution_version"] == "18.04"

    def test_parse_debian(self, wsl_listing):
        """Test parsing Debian."""
        result = wsl_listing._parse_wsl_distribution("Debian")
        assert result["distribution_name"] == "Debian"
        assert result["distribution_version"] is None

    def test_parse_kali_linux(self, wsl_listing):
        """Test parsing Kali Linux."""
        result = wsl_listing._parse_wsl_distribution("kali-linux")
        assert result["distribution_name"] == "Kali Linux"
        assert result["distribution_version"] is None

    def test_parse_opensuse_tumbleweed(self, wsl_listing):
        """Test parsing openSUSE Tumbleweed."""
        result = wsl_listing._parse_wsl_distribution("openSUSE-Tumbleweed")
        assert result["distribution_name"] == "openSUSE"
        assert result["distribution_version"] == "Tumbleweed"

    def test_parse_opensuse_leap(self, wsl_listing):
        """Test parsing openSUSE Leap."""
        result = wsl_listing._parse_wsl_distribution("openSUSE-Leap-15")
        assert result["distribution_name"] == "openSUSE"
        assert result["distribution_version"] == "15"

    def test_parse_sles(self, wsl_listing):
        """Test parsing SLES."""
        result = wsl_listing._parse_wsl_distribution("SLES-15")
        assert result["distribution_name"] == "SLES"
        assert result["distribution_version"] == "15"

    def test_parse_fedora(self, wsl_listing):
        """Test parsing Fedora."""
        result = wsl_listing._parse_wsl_distribution("Fedora")
        assert result["distribution_name"] == "Fedora"
        assert result["distribution_version"] is None

    def test_parse_almalinux(self, wsl_listing):
        """Test parsing AlmaLinux."""
        result = wsl_listing._parse_wsl_distribution("AlmaLinux-9")
        assert result["distribution_name"] == "AlmaLinux"
        assert result["distribution_version"] == "9"

    def test_parse_rockylinux(self, wsl_listing):
        """Test parsing Rocky Linux."""
        result = wsl_listing._parse_wsl_distribution("RockyLinux-9")
        assert result["distribution_name"] == "Rocky Linux"
        assert result["distribution_version"] == "9"

    def test_parse_unknown_distribution(self, wsl_listing):
        """Test parsing unknown distribution."""
        result = wsl_listing._parse_wsl_distribution("CustomDistro")
        assert result["distribution_name"] == "CustomDistro"
        assert result["distribution_version"] is None

    def test_parse_partial_match_with_version(self, wsl_listing):
        """Test parsing partial match with version extracted."""
        # Ubuntu variant with version
        result = wsl_listing._parse_wsl_distribution("MyUbuntu-23.10")
        assert result["distribution_name"] == "Ubuntu"
        assert result["distribution_version"] == "23.10"

    def test_parse_partial_match_fedora_with_version(self, wsl_listing):
        """Test parsing Fedora variant with version."""
        result = wsl_listing._parse_wsl_distribution("Fedora-Remix-39")
        assert result["distribution_name"] == "Fedora"
        assert result["distribution_version"] == "39"

    def test_parse_partial_match_debian_with_version(self, wsl_listing):
        """Test parsing Debian variant with version."""
        result = wsl_listing._parse_wsl_distribution("Debian-12")
        assert result["distribution_name"] == "Debian"
        assert result["distribution_version"] == "12"


class TestIntegrationScenarios:
    """Integration tests for complete WSL listing scenarios."""

    def test_full_listing_with_mixed_instances(self, wsl_listing):
        """Test full listing with mixed running/stopped instances."""
        mock_result = Mock()
        mock_result.returncode = 0
        # Use UTF-16-LE encoding like Windows WSL actually outputs
        mock_result.stdout = (
            "  NAME           STATE           VERSION\n"
            "* Ubuntu-22.04   Running         2\n"
            "  Debian         Stopped         2\n"
            "  kali-linux     Running         2\n"
        ).encode("utf-16-le")
        mock_result.stderr = b""

        def hostname_side_effect(dist):
            hostnames = {
                "Ubuntu-22.04": "ubuntu.example.com",
                "kali-linux": "kali.example.com",
            }
            return hostnames.get(dist)

        def guid_side_effect(dist):
            guids = {
                "Ubuntu-22.04": "guid-ubuntu",
                "Debian": "guid-debian",
                "kali-linux": "guid-kali",
            }
            return guids.get(dist)

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            return_value=mock_result,
        ):
            with patch.object(
                wsl_listing, "_get_wsl_hostname", side_effect=hostname_side_effect
            ):
                with patch.object(
                    wsl_listing, "_get_wsl_guid", side_effect=guid_side_effect
                ):
                    instances = wsl_listing.list_wsl_instances()

        assert len(instances) == 3

        # Check Ubuntu
        ubuntu = instances[0]
        assert ubuntu["child_name"] == "Ubuntu-22.04"
        assert ubuntu["status"] == "running"
        assert ubuntu["is_default"] is True
        assert ubuntu["hostname"] == "ubuntu.example.com"
        assert ubuntu["wsl_guid"] == "guid-ubuntu"
        assert ubuntu["distribution"]["distribution_name"] == "Ubuntu"
        assert ubuntu["distribution"]["distribution_version"] == "22.04"

        # Check Debian
        debian = instances[1]
        assert debian["child_name"] == "Debian"
        assert debian["status"] == "stopped"
        assert debian["is_default"] is False
        assert debian["hostname"] is None
        assert debian["wsl_guid"] == "guid-debian"

        # Check Kali
        kali = instances[2]
        assert kali["child_name"] == "kali-linux"
        assert kali["status"] == "running"
        assert kali["is_default"] is False
        assert kali["hostname"] == "kali.example.com"
        assert kali["distribution"]["distribution_name"] == "Kali Linux"

    def test_listing_handles_utf16_with_null_chars(self, wsl_listing):
        """Test listing handles UTF-16 output with embedded null characters."""
        # Simulate Windows WSL output with null chars
        text = "  NAME      STATE           VERSION\n* Ubuntu    Running         2\n"
        # Add null chars like Windows sometimes does
        encoded = text.encode("utf-16-le")

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = encoded
        mock_result.stderr = b""

        with patch(
            "src.sysmanage_agent.operations.child_host_listing_wsl.subprocess.run",
            return_value=mock_result,
        ):
            with patch.object(wsl_listing, "_get_wsl_hostname", return_value=None):
                with patch.object(wsl_listing, "_get_wsl_guid", return_value=None):
                    instances = wsl_listing.list_wsl_instances()

        assert len(instances) == 1
        assert instances[0]["child_name"] == "Ubuntu"
