"""
Tests for GitHub API integration for sysmanage-agent version checking.
"""

# pylint: disable=redefined-outer-name,protected-access

import json
import urllib.error
from io import BytesIO
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_vmm_github import GitHubVersionChecker


class MockResponse:
    """Mock class for urllib response."""

    def __init__(self, data, status_code=200):
        self.data = data
        self.status_code = status_code

    def read(self):
        """Read response data."""
        if isinstance(self.data, bytes):
            return self.data
        return json.dumps(self.data).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@pytest.fixture
def mock_logger():
    """Create a mock logger instance."""
    logger = Mock()
    logger.info = Mock()
    logger.error = Mock()
    logger.warning = Mock()
    logger.debug = Mock()
    return logger


@pytest.fixture
def version_checker(mock_logger):
    """Create a GitHubVersionChecker instance for testing."""
    return GitHubVersionChecker(mock_logger)


class TestGitHubVersionCheckerInit:
    """Tests for GitHubVersionChecker initialization."""

    def test_init_sets_logger(self, mock_logger):
        """Test that __init__ sets the logger correctly."""
        checker = GitHubVersionChecker(mock_logger)
        assert checker.logger == mock_logger

    def test_init_github_api_url(self, mock_logger):
        """Test that GITHUB_API_URL is correctly set."""
        checker = GitHubVersionChecker(mock_logger)
        expected_url = (
            "https://api.github.com/repos/bceverly/sysmanage-agent/releases/latest"
        )
        assert checker.GITHUB_API_URL == expected_url

    def test_init_github_releases_url(self, mock_logger):
        """Test that GITHUB_RELEASES_URL is correctly set."""
        checker = GitHubVersionChecker(mock_logger)
        expected_url = "https://github.com/bceverly/sysmanage-agent/releases/download"
        assert checker.GITHUB_RELEASES_URL == expected_url


class TestGetLatestVersion:
    """Tests for get_latest_version method."""

    def test_get_latest_version_success(self, version_checker, mock_logger):
        """Test successful version retrieval from GitHub."""
        mock_response_data = {
            "tag_name": "v0.9.9.8",
            "name": "Release 0.9.9.8",
            "body": "Release notes here",
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["success"] is True
        assert result["version"] == "0.9.9.8"
        assert result["tag_name"] == "v0.9.9.8"
        assert result["error"] is None
        mock_logger.info.assert_called()

    def test_get_latest_version_success_without_v_prefix(self, version_checker):
        """Test version retrieval when tag doesn't have v prefix."""
        mock_response_data = {
            "tag_name": "1.0.0",
            "name": "Release 1.0.0",
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["success"] is True
        assert result["version"] == "1.0.0"
        assert result["tag_name"] == "1.0.0"
        assert result["error"] is None

    def test_get_latest_version_empty_tag_name(self, version_checker):
        """Test version retrieval when tag_name is empty."""
        mock_response_data = {
            "tag_name": "",
            "name": "Release",
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert result["tag_name"] is None
        assert "No tag_name" in result["error"]

    def test_get_latest_version_missing_tag_name(self, version_checker):
        """Test version retrieval when tag_name is missing."""
        mock_response_data = {
            "name": "Release",
            "body": "No tag_name field",
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert result["tag_name"] is None
        assert "No tag_name" in result["error"]

    def test_get_latest_version_http_error_404(self, version_checker, mock_logger):
        """Test version retrieval with HTTP 404 error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                url="https://api.github.com/...",
                code=404,
                msg="Not Found",
                hdrs={},
                fp=BytesIO(b""),
            )
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert result["tag_name"] is None
        assert "GitHub API error" in result["error"]
        mock_logger.error.assert_called()

    def test_get_latest_version_http_error_403_rate_limit(
        self, version_checker, mock_logger
    ):
        """Test version retrieval with HTTP 403 rate limit error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                url="https://api.github.com/...",
                code=403,
                msg="Forbidden",
                hdrs={},
                fp=BytesIO(b"Rate limit exceeded"),
            )
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert "GitHub API error" in result["error"]
        mock_logger.error.assert_called()

    def test_get_latest_version_http_error_500(self, version_checker):
        """Test version retrieval with HTTP 500 server error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                url="https://api.github.com/...",
                code=500,
                msg="Internal Server Error",
                hdrs={},
                fp=BytesIO(b""),
            )
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert "GitHub API error" in result["error"]

    def test_get_latest_version_url_error_network(self, version_checker, mock_logger):
        """Test version retrieval with network URL error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError(
                reason="Connection refused"
            )
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert result["tag_name"] is None
        assert "Network error" in result["error"]
        mock_logger.error.assert_called()

    def test_get_latest_version_url_error_dns(self, version_checker):
        """Test version retrieval with DNS resolution error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError(
                reason="Name or service not known"
            )
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert "Network error" in result["error"]

    def test_get_latest_version_url_error_timeout(self, version_checker):
        """Test version retrieval with timeout error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError(
                reason="Connection timed out"
            )
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert "Network error" in result["error"]

    def test_get_latest_version_json_decode_error(self, version_checker, mock_logger):
        """Test version retrieval with invalid JSON response."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(b"not valid json {{{")
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert result["tag_name"] is None
        assert "Invalid JSON response" in result["error"]
        mock_logger.error.assert_called()

    def test_get_latest_version_json_decode_error_empty_response(self, version_checker):
        """Test version retrieval with empty response."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(b"")
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert "Invalid JSON response" in result["error"]

    def test_get_latest_version_unexpected_exception(
        self, version_checker, mock_logger
    ):
        """Test version retrieval with unexpected exception."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = RuntimeError("Unexpected error occurred")
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None
        assert result["tag_name"] is None
        assert "Unexpected error" in result["error"]
        mock_logger.error.assert_called()

    def test_get_latest_version_memory_error(self, version_checker):
        """Test version retrieval with memory error exception."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = MemoryError("Out of memory")
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert "Unexpected error" in result["error"]

    def test_get_latest_version_keyboard_interrupt(self, version_checker):
        """Test version retrieval handles KeyboardInterrupt gracefully."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = Exception("KeyboardInterrupt simulation")
            result = version_checker.get_latest_version()

        assert result["success"] is False
        assert result["version"] is None

    def test_get_latest_version_request_headers(self, version_checker):
        """Test that request includes correct headers."""
        mock_response_data = {"tag_name": "v1.0.0"}

        with patch("urllib.request.urlopen") as mock_urlopen:
            with patch("urllib.request.Request") as mock_request:
                mock_urlopen.return_value = MockResponse(mock_response_data)
                version_checker.get_latest_version()

                # Verify Request was called with correct headers
                mock_request.assert_called_once()
                call_args = mock_request.call_args
                assert (
                    call_args[1]["headers"]["Accept"]
                    == "application/vnd.github.v3+json"
                )


class TestGetPortTarballUrl:
    """Tests for get_port_tarball_url method."""

    def test_get_port_tarball_url_standard_version(self, version_checker):
        """Test URL generation for standard version."""
        url = version_checker.get_port_tarball_url("0.9.9.8")
        expected = (
            "https://github.com/bceverly/sysmanage-agent/releases/download/"
            "v0.9.9.8/sysmanage-agent-0.9.9.8-openbsd-port.tar.gz"
        )
        assert url == expected

    def test_get_port_tarball_url_simple_version(self, version_checker):
        """Test URL generation for simple version."""
        url = version_checker.get_port_tarball_url("1.0.0")
        expected = (
            "https://github.com/bceverly/sysmanage-agent/releases/download/"
            "v1.0.0/sysmanage-agent-1.0.0-openbsd-port.tar.gz"
        )
        assert url == expected

    def test_get_port_tarball_url_two_part_version(self, version_checker):
        """Test URL generation for two-part version."""
        url = version_checker.get_port_tarball_url("1.0")
        expected = (
            "https://github.com/bceverly/sysmanage-agent/releases/download/"
            "v1.0/sysmanage-agent-1.0-openbsd-port.tar.gz"
        )
        assert url == expected

    def test_get_port_tarball_url_five_part_version(self, version_checker):
        """Test URL generation for five-part version."""
        url = version_checker.get_port_tarball_url("1.2.3.4.5")
        expected = (
            "https://github.com/bceverly/sysmanage-agent/releases/download/"
            "v1.2.3.4.5/sysmanage-agent-1.2.3.4.5-openbsd-port.tar.gz"
        )
        assert url == expected

    def test_get_port_tarball_url_single_digit_version(self, version_checker):
        """Test URL generation for single digit version."""
        url = version_checker.get_port_tarball_url("1")
        expected = (
            "https://github.com/bceverly/sysmanage-agent/releases/download/"
            "v1/sysmanage-agent-1-openbsd-port.tar.gz"
        )
        assert url == expected


class TestCompareVersions:
    """Tests for compare_versions static method."""

    def test_compare_versions_equal_three_parts(self):
        """Test comparing equal three-part versions."""
        result = GitHubVersionChecker.compare_versions("1.0.0", "1.0.0")
        assert result == 0

    def test_compare_versions_equal_four_parts(self):
        """Test comparing equal four-part versions."""
        result = GitHubVersionChecker.compare_versions("0.9.9.8", "0.9.9.8")
        assert result == 0

    def test_compare_versions_first_greater_major(self):
        """Test first version greater in major component."""
        result = GitHubVersionChecker.compare_versions("2.0.0", "1.0.0")
        assert result == 1

    def test_compare_versions_first_greater_minor(self):
        """Test first version greater in minor component."""
        result = GitHubVersionChecker.compare_versions("1.2.0", "1.1.0")
        assert result == 1

    def test_compare_versions_first_greater_patch(self):
        """Test first version greater in patch component."""
        result = GitHubVersionChecker.compare_versions("1.0.2", "1.0.1")
        assert result == 1

    def test_compare_versions_first_greater_fourth_part(self):
        """Test first version greater in fourth component."""
        result = GitHubVersionChecker.compare_versions("0.9.9.9", "0.9.9.8")
        assert result == 1

    def test_compare_versions_first_less_major(self):
        """Test first version less in major component."""
        result = GitHubVersionChecker.compare_versions("1.0.0", "2.0.0")
        assert result == -1

    def test_compare_versions_first_less_minor(self):
        """Test first version less in minor component."""
        result = GitHubVersionChecker.compare_versions("1.0.0", "1.1.0")
        assert result == -1

    def test_compare_versions_first_less_patch(self):
        """Test first version less in patch component."""
        result = GitHubVersionChecker.compare_versions("1.0.0", "1.0.1")
        assert result == -1

    def test_compare_versions_first_less_fourth_part(self):
        """Test first version less in fourth component."""
        result = GitHubVersionChecker.compare_versions("0.9.9.7", "0.9.9.8")
        assert result == -1

    def test_compare_versions_different_lengths_first_shorter(self):
        """Test comparing versions with different lengths, first shorter."""
        result = GitHubVersionChecker.compare_versions("1.0", "1.0.0")
        assert result == 0

    def test_compare_versions_different_lengths_second_shorter(self):
        """Test comparing versions with different lengths, second shorter."""
        result = GitHubVersionChecker.compare_versions("1.0.0", "1.0")
        assert result == 0

    def test_compare_versions_different_lengths_first_greater(self):
        """Test comparing versions with different lengths, first greater."""
        result = GitHubVersionChecker.compare_versions("1.0.1", "1.0")
        assert result == 1

    def test_compare_versions_different_lengths_second_greater(self):
        """Test comparing versions with different lengths, second greater."""
        result = GitHubVersionChecker.compare_versions("1.0", "1.0.1")
        assert result == -1

    def test_compare_versions_padding_with_zeros(self):
        """Test that shorter versions are padded with zeros."""
        # 1.0 should equal 1.0.0.0
        result = GitHubVersionChecker.compare_versions("1.0", "1.0.0.0")
        assert result == 0

    def test_compare_versions_single_digit(self):
        """Test comparing single digit versions."""
        result = GitHubVersionChecker.compare_versions("1", "2")
        assert result == -1

    def test_compare_versions_single_digit_equal(self):
        """Test comparing equal single digit versions."""
        result = GitHubVersionChecker.compare_versions("5", "5")
        assert result == 0

    def test_compare_versions_large_numbers(self):
        """Test comparing versions with large numbers."""
        result = GitHubVersionChecker.compare_versions("100.200.300", "100.200.300")
        assert result == 0

    def test_compare_versions_large_numbers_greater(self):
        """Test comparing versions with large numbers, first greater."""
        result = GitHubVersionChecker.compare_versions("100.201.0", "100.200.999")
        assert result == 1

    def test_compare_versions_typical_upgrade(self):
        """Test typical version upgrade scenario."""
        result = GitHubVersionChecker.compare_versions("0.9.9.8", "0.9.9.7")
        assert result == 1

    def test_compare_versions_major_upgrade(self):
        """Test major version upgrade scenario."""
        result = GitHubVersionChecker.compare_versions("1.0.0", "0.9.9.9")
        assert result == 1

    def test_compare_versions_real_world_example(self):
        """Test real-world version comparison example."""
        # Current version vs available version
        current = "0.9.9.7"
        available = "0.9.9.8"
        result = GitHubVersionChecker.compare_versions(available, current)
        assert result == 1  # available is newer

    def test_compare_versions_zero_versions(self):
        """Test comparing versions with zeros."""
        result = GitHubVersionChecker.compare_versions("0.0.0", "0.0.1")
        assert result == -1


class TestGitHubVersionCheckerIntegration:
    """Integration-style tests for GitHubVersionChecker."""

    def test_full_version_check_and_comparison(self, version_checker):
        """Test version check followed by comparison."""
        mock_response_data = {"tag_name": "v1.0.0"}

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["success"] is True
        assert result["version"] == "1.0.0"

        # Compare with current version
        current_version = "0.9.9.8"
        comparison = GitHubVersionChecker.compare_versions(
            result["version"], current_version
        )
        assert comparison == 1  # New version is available

    def test_version_check_and_url_generation(self, version_checker):
        """Test version check followed by URL generation."""
        mock_response_data = {"tag_name": "v0.9.9.9"}

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["success"] is True

        # Generate download URL
        url = version_checker.get_port_tarball_url(result["version"])
        assert "v0.9.9.9" in url
        assert "sysmanage-agent-0.9.9.9-openbsd-port.tar.gz" in url

    def test_no_update_needed_scenario(self, version_checker):
        """Test scenario where no update is needed."""
        mock_response_data = {"tag_name": "v0.9.9.8"}

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["success"] is True

        # Compare with same version
        current_version = "0.9.9.8"
        comparison = GitHubVersionChecker.compare_versions(
            result["version"], current_version
        )
        assert comparison == 0  # No update needed

    def test_downgrade_scenario(self, version_checker):
        """Test scenario where current version is newer (e.g., development)."""
        mock_response_data = {"tag_name": "v0.9.9.7"}

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["success"] is True

        # Compare with newer local version (dev version)
        current_version = "0.9.9.8"
        comparison = GitHubVersionChecker.compare_versions(
            result["version"], current_version
        )
        assert comparison == -1  # Latest release is older than current


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_version_with_leading_v_stripped(self, version_checker):
        """Test that 'v' prefix is properly stripped from version."""
        mock_response_data = {"tag_name": "v1.2.3.4"}

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["version"] == "1.2.3.4"
        assert result["tag_name"] == "v1.2.3.4"

    def test_version_with_multiple_v_prefix(self, version_checker):
        """Test version with multiple v characters at start."""
        mock_response_data = {"tag_name": "vvv1.0.0"}

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        # lstrip('v') removes all leading 'v' characters
        assert result["version"] == "1.0.0"

    def test_tag_name_preserved_with_prefix(self, version_checker):
        """Test that original tag_name is preserved."""
        mock_response_data = {"tag_name": "v2.0.0-beta"}

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["tag_name"] == "v2.0.0-beta"
        assert result["version"] == "2.0.0-beta"

    def test_response_with_extra_fields(self, version_checker):
        """Test that response with extra fields is handled correctly."""
        mock_response_data = {
            "tag_name": "v1.0.0",
            "name": "Release 1.0.0",
            "body": "Release notes",
            "author": {"login": "developer"},
            "created_at": "2024-01-01T00:00:00Z",
            "published_at": "2024-01-01T00:00:00Z",
            "draft": False,
            "prerelease": False,
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            result = version_checker.get_latest_version()

        assert result["success"] is True
        assert result["version"] == "1.0.0"

    def test_compare_versions_with_trailing_zeros(self):
        """Test version comparison with trailing zeros."""
        # 1.0.0 should equal 1.0.0
        result = GitHubVersionChecker.compare_versions("1.0.0", "1.0.0.0.0")
        assert result == 0

    def test_url_generation_special_characters(self, version_checker):
        """Test URL generation doesn't break with special version strings."""
        # Note: This tests that the method doesn't crash, actual URL might be invalid
        url = version_checker.get_port_tarball_url("1.0.0-beta")
        assert "v1.0.0-beta" in url
        assert "sysmanage-agent-1.0.0-beta-openbsd-port.tar.gz" in url


class TestLoggerCalls:
    """Tests to verify correct logger usage."""

    def test_info_log_on_success(self, version_checker, mock_logger):
        """Test that info log is called on successful version check."""
        mock_response_data = {"tag_name": "v1.0.0"}

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(mock_response_data)
            version_checker.get_latest_version()

        # Should log at least twice: once at start, once with version info
        assert mock_logger.info.call_count >= 2

    def test_error_log_on_http_error(self, version_checker, mock_logger):
        """Test that error log is called on HTTP error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                url="", code=404, msg="Not Found", hdrs={}, fp=BytesIO(b"")
            )
            version_checker.get_latest_version()

        mock_logger.error.assert_called()

    def test_error_log_on_url_error(self, version_checker, mock_logger):
        """Test that error log is called on URL error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError(reason="Network error")
            version_checker.get_latest_version()

        mock_logger.error.assert_called()

    def test_error_log_on_json_error(self, version_checker, mock_logger):
        """Test that error log is called on JSON decode error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = MockResponse(b"invalid json")
            version_checker.get_latest_version()

        mock_logger.error.assert_called()

    def test_error_log_on_unexpected_error(self, version_checker, mock_logger):
        """Test that error log is called on unexpected error."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = RuntimeError("Unexpected")
            version_checker.get_latest_version()

        mock_logger.error.assert_called()
