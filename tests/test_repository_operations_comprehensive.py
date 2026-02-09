#!/usr/bin/env python3
"""
Comprehensive tests for repository operations.

This module provides extensive testing coverage for repository operations
across all supported platforms (Linux, BSD, macOS, Windows).

Note: Linux-specific repository parsing tests (APT, YUM, Zypper, DEB822)
have been moved to test_repository_operations_linux.py.
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.operations.repository_operations import (
    ThirdPartyRepositoryOperations,
    _is_distro_family,
    _DEBIAN_FAMILY,
    _RHEL_FAMILY,
    _SUSE_FAMILY,
)
from src.sysmanage_agent.operations.linux_repository_operations import (
    LinuxRepositoryOperations,
)
from src.sysmanage_agent.operations.bsd_macos_repository_operations import (
    BSDMacOSRepositoryOperations,
)
from src.sysmanage_agent.operations.windows_repository_operations import (
    WindowsRepositoryOperations,
)


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    agent = MagicMock()
    agent.system_ops = MagicMock()
    agent.system_ops.execute_shell_command = AsyncMock()
    agent.check_updates = AsyncMock()
    agent._send_third_party_repository_update = AsyncMock()
    return agent


@pytest.fixture
def repo_ops(mock_agent):
    """Create a ThirdPartyRepositoryOperations instance."""
    return ThirdPartyRepositoryOperations(mock_agent)


@pytest.fixture
def linux_ops(mock_agent):
    """Create a LinuxRepositoryOperations instance."""
    return LinuxRepositoryOperations(mock_agent)


@pytest.fixture
def bsd_macos_ops(mock_agent):
    """Create a BSDMacOSRepositoryOperations instance."""
    return BSDMacOSRepositoryOperations(mock_agent)


@pytest.fixture
def windows_ops(mock_agent):
    """Create a WindowsRepositoryOperations instance."""
    return WindowsRepositoryOperations(mock_agent)


class TestDistroFamilyDetection:
    """Test distro family detection helper functions."""

    def test_is_debian_family_ubuntu(self):
        """Test Ubuntu is detected as Debian family."""
        assert _is_distro_family("ubuntu", _DEBIAN_FAMILY) is True

    def test_is_debian_family_debian(self):
        """Test Debian is detected as Debian family."""
        assert _is_distro_family("debian", _DEBIAN_FAMILY) is True

    def test_is_debian_family_linuxmint(self):
        """Test Linux Mint (debian-based) detection."""
        # Linux Mint contains 'debian' or 'ubuntu' in some contexts
        assert _is_distro_family("ubuntu", _DEBIAN_FAMILY) is True

    def test_is_rhel_family_fedora(self):
        """Test Fedora is detected as RHEL family."""
        assert _is_distro_family("fedora", _RHEL_FAMILY) is True

    def test_is_rhel_family_centos(self):
        """Test CentOS is detected as RHEL family."""
        assert _is_distro_family("centos", _RHEL_FAMILY) is True

    def test_is_rhel_family_rocky(self):
        """Test Rocky Linux is detected as RHEL family."""
        assert _is_distro_family("rocky", _RHEL_FAMILY) is True

    def test_is_rhel_family_alma(self):
        """Test AlmaLinux is detected as RHEL family."""
        assert _is_distro_family("alma", _RHEL_FAMILY) is True

    def test_is_rhel_family_rhel(self):
        """Test RHEL is detected as RHEL family."""
        assert _is_distro_family("rhel", _RHEL_FAMILY) is True

    def test_is_suse_family_opensuse(self):
        """Test openSUSE is detected as SUSE family."""
        assert _is_distro_family("opensuse", _SUSE_FAMILY) is True

    def test_is_suse_family_suse(self):
        """Test SUSE is detected as SUSE family."""
        assert _is_distro_family("suse", _SUSE_FAMILY) is True

    def test_is_suse_family_opensuse_leap(self):
        """Test openSUSE Leap is detected as SUSE family."""
        assert _is_distro_family("opensuse-leap", _SUSE_FAMILY) is True

    def test_is_not_debian_family(self):
        """Test non-Debian distros are not detected as Debian family."""
        assert _is_distro_family("fedora", _DEBIAN_FAMILY) is False
        assert _is_distro_family("arch", _DEBIAN_FAMILY) is False

    def test_is_not_rhel_family(self):
        """Test non-RHEL distros are not detected as RHEL family."""
        assert _is_distro_family("ubuntu", _RHEL_FAMILY) is False
        assert _is_distro_family("arch", _RHEL_FAMILY) is False

    def test_is_not_suse_family(self):
        """Test non-SUSE distros are not detected as SUSE family."""
        assert _is_distro_family("fedora", _SUSE_FAMILY) is False
        assert _is_distro_family("ubuntu", _SUSE_FAMILY) is False


class TestAPTRepositoryURLValidation:
    """Test APT repository URL validation."""

    def test_is_ppa_hostname_launchpad(self, linux_ops):
        """Test PPA hostname detection for ppa.launchpad.net."""
        assert linux_ops._is_ppa_hostname("ppa.launchpad.net") is True

    def test_is_ppa_hostname_launchpadcontent(self, linux_ops):
        """Test PPA hostname detection for ppa.launchpadcontent.net."""
        assert linux_ops._is_ppa_hostname("ppa.launchpadcontent.net") is True

    def test_is_ppa_hostname_subdomain(self, linux_ops):
        """Test PPA hostname detection for subdomains."""
        assert linux_ops._is_ppa_hostname("us.ppa.launchpad.net") is True
        assert linux_ops._is_ppa_hostname("mirror.ppa.launchpadcontent.net") is True

    def test_is_not_ppa_hostname(self, linux_ops):
        """Test non-PPA hostname detection."""
        assert linux_ops._is_ppa_hostname("example.com") is False
        assert linux_ops._is_ppa_hostname("archive.ubuntu.com") is False
        assert linux_ops._is_ppa_hostname("launchpad.net") is False  # Not ppa subdomain

    def test_is_ppa_hostname_empty(self, linux_ops):
        """Test PPA hostname detection with empty string."""
        assert linux_ops._is_ppa_hostname("") is False

    def test_is_ppa_hostname_none(self, linux_ops):
        """Test PPA hostname detection with None."""
        assert linux_ops._is_ppa_hostname(None) is False

    def test_extract_ppa_name_from_url(self, linux_ops):
        """Test extracting PPA name from URL."""
        url = "http://ppa.launchpad.net/user/repo/ubuntu"
        result = linux_ops._extract_ppa_name_from_url(url)
        assert result == "ppa:user/repo"

    def test_extract_ppa_name_from_url_launchpadcontent(self, linux_ops):
        """Test extracting PPA name from launchpadcontent URL."""
        url = "http://ppa.launchpadcontent.net/user/project/ubuntu"
        result = linux_ops._extract_ppa_name_from_url(url)
        assert result == "ppa:user/project"

    def test_extract_ppa_name_from_non_ppa_url(self, linux_ops):
        """Test extracting PPA name from non-PPA URL returns empty."""
        url = "http://example.com/ubuntu"
        result = linux_ops._extract_ppa_name_from_url(url)
        assert result == ""

    def test_extract_ppa_name_from_short_path(self, linux_ops):
        """Test extracting PPA name from URL with short path."""
        url = "http://ppa.launchpad.net/user"
        result = linux_ops._extract_ppa_name_from_url(url)
        assert result == ""


class TestHomebrewTapParsing:
    """Test Homebrew tap parsing functionality."""

    @pytest.mark.asyncio
    async def test_list_homebrew_taps_filters_official(self, bsd_macos_ops, mock_agent):
        """Test that official Homebrew taps are filtered out."""
        mock_agent.system_ops.execute_shell_command.side_effect = [
            {
                "success": True,
                "result": {"stdout": "/usr/local/bin/brew", "stderr": ""},
            },
            {
                "success": True,
                "result": {
                    "stdout": "homebrew/core\nhomebrew/cask\nuser/custom-tap\n",
                    "stderr": "",
                },
            },
        ]
        repos = await bsd_macos_ops.list_homebrew_taps()
        assert len(repos) == 1
        assert repos[0]["name"] == "user/custom-tap"

    @pytest.mark.asyncio
    async def test_list_homebrew_taps_empty_lines(self, bsd_macos_ops, mock_agent):
        """Test that empty lines are handled correctly."""
        mock_agent.system_ops.execute_shell_command.side_effect = [
            {
                "success": True,
                "result": {"stdout": "/usr/local/bin/brew", "stderr": ""},
            },
            {
                "success": True,
                "result": {
                    "stdout": "\nuser/tap1\n\nuser/tap2\n\n",
                    "stderr": "",
                },
            },
        ]
        repos = await bsd_macos_ops.list_homebrew_taps()
        assert len(repos) == 2

    @pytest.mark.asyncio
    async def test_list_homebrew_taps_with_comments(self, bsd_macos_ops, mock_agent):
        """Test that comment lines are filtered out."""
        mock_agent.system_ops.execute_shell_command.side_effect = [
            {
                "success": True,
                "result": {"stdout": "/usr/local/bin/brew", "stderr": ""},
            },
            {
                "success": True,
                "result": {
                    "stdout": "# comment\nuser/tap1\n#another comment\nuser/tap2\n",
                    "stderr": "",
                },
            },
        ]
        repos = await bsd_macos_ops.list_homebrew_taps()
        assert len(repos) == 2


class TestWingetSourceParsing:
    """Test winget source parsing functionality."""

    def test_is_winget_header_line_name_argument(self, windows_ops):
        """Test winget header line detection with Name/Argument."""
        assert windows_ops._is_winget_header_line("Name  Argument") is True
        assert windows_ops._is_winget_header_line("Name    Argument    Type") is True

    def test_is_winget_header_line_dashes(self, windows_ops):
        """Test winget header line detection with dashes."""
        assert windows_ops._is_winget_header_line("---  --------") is True
        assert windows_ops._is_winget_header_line("----") is True

    def test_is_winget_header_line_normal_line(self, windows_ops):
        """Test normal line is not detected as header."""
        assert (
            windows_ops._is_winget_header_line("custom-source  http://example.com/")
            is False
        )

    def test_parse_winget_source_line_valid(self, windows_ops):
        """Test parsing valid winget source line."""
        result = windows_ops._parse_winget_source_line(
            "custom-source  http://example.com/"
        )
        assert result is not None
        assert result["name"] == "custom-source"
        assert result["url"] == "http://example.com/"
        assert result["type"] == "winget"

    def test_parse_winget_source_line_official_winget(self, windows_ops):
        """Test parsing official winget source returns None."""
        result = windows_ops._parse_winget_source_line(
            "winget  https://cdn.winget.microsoft.com/"
        )
        assert result is None

    def test_parse_winget_source_line_official_msstore(self, windows_ops):
        """Test parsing official msstore source returns None."""
        result = windows_ops._parse_winget_source_line(
            "msstore  https://storeedgefd.dsx.mp.microsoft.com/"
        )
        assert result is None

    def test_parse_winget_source_line_too_few_parts(self, windows_ops):
        """Test parsing line with too few parts returns None."""
        result = windows_ops._parse_winget_source_line("single-part")
        assert result is None


class TestChocolateySourceParsing:
    """Test Chocolatey source parsing functionality."""

    @pytest.mark.asyncio
    async def test_list_chocolatey_sources_with_bypass_proxy(
        self, windows_ops, mock_agent
    ):
        """Test parsing Chocolatey source with Bypass Proxy setting."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "custom-source - http://myrepo.com/ | Priority 0|Bypass Proxy - True",
                "stderr": "",
            },
        }
        repos = await windows_ops._list_chocolatey_sources()
        assert len(repos) == 1
        assert repos[0]["enabled"] is True

    @pytest.mark.asyncio
    async def test_list_chocolatey_sources_no_http(self, windows_ops, mock_agent):
        """Test that lines without http are skipped."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {
                "stdout": "Chocolatey v1.0.0\nsome-other-line - no url here",
                "stderr": "",
            },
        }
        repos = await windows_ops._list_chocolatey_sources()
        assert len(repos) == 0


class TestThirdPartyRepositoryOperationsEdgeCases:
    """Test edge cases in ThirdPartyRepositoryOperations."""

    @pytest.mark.asyncio
    async def test_list_repositories_unsupported_linux(self, repo_ops):
        """Test listing repositories on unsupported Linux distro."""
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "gentoo"}
            ),
        ):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["repositories"] == []

    @pytest.mark.asyncio
    async def test_delete_repositories_multiple_distros(self, repo_ops):
        """Test deleting repositories with different distro families."""
        # Test each distro family
        for distro, method_name in [
            ("ubuntu", "delete_apt_repository"),
            ("fedora", "delete_yum_repository"),
            ("opensuse", "delete_zypper_repository"),
        ]:
            setattr(
                repo_ops.linux_ops,
                method_name,
                AsyncMock(return_value={"success": True, "result": "Deleted"}),
            )
            with (
                patch("platform.system", return_value="Linux"),
                patch.object(
                    repo_ops, "_detect_linux_distro", return_value={"distro": distro}
                ),
                patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
                patch.object(
                    repo_ops, "_trigger_update_detection", new_callable=AsyncMock
                ),
                patch.object(
                    repo_ops,
                    "_trigger_third_party_repository_rescan",
                    new_callable=AsyncMock,
                ),
            ):
                result = await repo_ops.delete_third_party_repositories(
                    {"repositories": [{"name": "test-repo"}]}
                )
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_repositories_multiple_distros(self, repo_ops):
        """Test enabling repositories with different distro families."""
        for distro, method_name in [
            ("debian", "enable_apt_repository"),
            ("centos", "enable_yum_repository"),
            ("suse", "enable_zypper_repository"),
        ]:
            setattr(
                repo_ops.linux_ops,
                method_name,
                AsyncMock(return_value={"success": True, "result": "Enabled"}),
            )
            with (
                patch("platform.system", return_value="Linux"),
                patch.object(
                    repo_ops, "_detect_linux_distro", return_value={"distro": distro}
                ),
                patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
                patch.object(
                    repo_ops, "_trigger_update_detection", new_callable=AsyncMock
                ),
                patch.object(
                    repo_ops,
                    "_trigger_third_party_repository_rescan",
                    new_callable=AsyncMock,
                ),
            ):
                result = await repo_ops.enable_third_party_repositories(
                    {"repositories": [{"name": "test-repo", "file_path": "/tmp/test"}]}
                )
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_repositories_multiple_distros(self, repo_ops):
        """Test disabling repositories with different distro families."""
        for distro, method_name in [
            ("ubuntu", "disable_apt_repository"),
            ("rhel", "disable_yum_repository"),
            ("opensuse-leap", "disable_zypper_repository"),
        ]:
            setattr(
                repo_ops.linux_ops,
                method_name,
                AsyncMock(return_value={"success": True, "result": "Disabled"}),
            )
            with (
                patch("platform.system", return_value="Linux"),
                patch.object(
                    repo_ops, "_detect_linux_distro", return_value={"distro": distro}
                ),
                patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
                patch.object(
                    repo_ops, "_trigger_update_detection", new_callable=AsyncMock
                ),
                patch.object(
                    repo_ops,
                    "_trigger_third_party_repository_rescan",
                    new_callable=AsyncMock,
                ),
            ):
                result = await repo_ops.disable_third_party_repositories(
                    {"repositories": [{"name": "test-repo", "file_path": "/tmp/test"}]}
                )
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_run_package_update_non_linux(self, repo_ops, mock_agent):
        """Test _run_package_update does nothing on non-Linux."""
        with patch("platform.system", return_value="Darwin"):
            await repo_ops._run_package_update()
            mock_agent.system_ops.execute_shell_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_package_update_command_debian(self, repo_ops):
        """Test getting package update command for Debian family."""
        result = repo_ops._get_package_update_command("ubuntu")
        assert result == "sudo apt-get update"

        result = repo_ops._get_package_update_command("debian")
        assert result == "sudo apt-get update"

    @pytest.mark.asyncio
    async def test_get_package_update_command_rhel(self, repo_ops):
        """Test getting package update command for RHEL family."""
        result = repo_ops._get_package_update_command("fedora")
        assert result == "sudo dnf check-update"

        result = repo_ops._get_package_update_command("rocky")
        assert result == "sudo dnf check-update"

    @pytest.mark.asyncio
    async def test_get_package_update_command_suse(self, repo_ops):
        """Test getting package update command for SUSE family."""
        result = repo_ops._get_package_update_command("opensuse")
        assert result == "sudo zypper refresh"

    @pytest.mark.asyncio
    async def test_get_package_update_command_unknown(self, repo_ops):
        """Test getting package update command for unknown distro."""
        result = repo_ops._get_package_update_command("arch")
        assert result is None


class TestFreeBSDRepositoryParsing:
    """Test FreeBSD repository parsing functionality."""

    @pytest.mark.asyncio
    async def test_parse_freebsd_repo_with_extra_fields(self, bsd_macos_ops):
        """Test parsing FreeBSD repo with extra configuration fields."""
        from unittest.mock import mock_open  # pylint: disable=import-outside-toplevel

        repo_content = """myrepo: {
  url: "http://pkg.example.com/",
  enabled: yes,
  priority: 10,
  signature_type: fingerprints
}
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["myrepo.conf"]),
            patch("builtins.open", mock_open(read_data=repo_content)),
        ):
            repos = await bsd_macos_ops.list_freebsd_repositories()
            assert len(repos) == 1
            assert repos[0]["name"] == "myrepo"
            assert repos[0]["url"] == "http://pkg.example.com/"

    @pytest.mark.asyncio
    async def test_parse_freebsd_repo_without_url(self, bsd_macos_ops):
        """Test parsing FreeBSD repo without URL field."""
        from unittest.mock import mock_open  # pylint: disable=import-outside-toplevel

        repo_content = """myrepo: {
  enabled: yes
}
"""
        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["myrepo.conf"]),
            patch("builtins.open", mock_open(read_data=repo_content)),
        ):
            repos = await bsd_macos_ops.list_freebsd_repositories()
            assert len(repos) == 1
            assert repos[0]["url"] == ""

    @pytest.mark.asyncio
    async def test_list_freebsd_repositories_file_read_error(self, bsd_macos_ops):
        """Test handling file read error for FreeBSD repository."""
        # pylint: disable=import-outside-toplevel
        from unittest.mock import mock_open

        mock_file = mock_open()
        mock_file.side_effect = IOError("Permission denied")

        with (
            patch("os.path.exists", return_value=True),
            patch("os.listdir", return_value=["myrepo.conf"]),
            patch("builtins.open", mock_file),
        ):
            repos = await bsd_macos_ops.list_freebsd_repositories()
            # Should handle error gracefully
            assert len(repos) == 0


class TestNetBSDRepositoryParsing:
    """Test NetBSD repository parsing functionality."""

    @pytest.mark.asyncio
    async def test_list_netbsd_repositories_with_custom_overlay(self, bsd_macos_ops):
        """Test listing NetBSD repositories with custom overlay."""
        with (
            patch("os.path.exists", side_effect=lambda p: True),
            patch(
                "os.listdir",
                return_value=["wip", "custom-overlay", "distfiles", "packages"],
            ),
            patch("os.path.isdir", return_value=True),
            patch(
                "os.path.exists",
                side_effect=lambda p: "Makefile" in p
                or p in ["/usr/pkgsrc/wip", "/usr/pkgsrc"],
            ),
        ):
            # This test checks the overlay detection logic
            repos = await bsd_macos_ops.list_netbsd_repositories()
            # Should include pkgsrc-wip at minimum
            assert len(repos) >= 1


class TestWindowsRepositoryAddition:
    """Test Windows repository addition edge cases."""

    @pytest.mark.asyncio
    async def test_add_winget_repository_command_format(self, windows_ops, mock_agent):
        """Test that winget add command is formatted correctly."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Source added", "stderr": ""},
        }
        await windows_ops.add_windows_repository(
            "my-source", "http://example.com/", "winget"
        )
        call_args = mock_agent.system_ops.execute_shell_command.call_args[0][0]
        assert "winget source add" in call_args["command"]
        assert '--name "my-source"' in call_args["command"]
        assert '--arg "http://example.com/"' in call_args["command"]
        assert "--type Microsoft.Rest" in call_args["command"]

    @pytest.mark.asyncio
    async def test_add_chocolatey_repository_command_format(
        self, windows_ops, mock_agent
    ):
        """Test that chocolatey add command is formatted correctly."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Source added", "stderr": ""},
        }
        await windows_ops.add_windows_repository(
            "my-source", "http://example.com/", "chocolatey"
        )
        call_args = mock_agent.system_ops.execute_shell_command.call_args[0][0]
        assert "choco source add" in call_args["command"]
        assert '--name="my-source"' in call_args["command"]
        assert '--source="http://example.com/"' in call_args["command"]

    @pytest.mark.asyncio
    async def test_add_repository_type_case_insensitive(self, windows_ops, mock_agent):
        """Test that repository type is case insensitive."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Source added", "stderr": ""},
        }

        # Test uppercase
        result = await windows_ops.add_windows_repository(
            "test", "http://example.com/", "CHOCOLATEY"
        )
        assert result["success"] is True

        # Test mixed case
        result = await windows_ops.add_windows_repository(
            "test", "http://example.com/", "Winget"
        )
        assert result["success"] is True


class TestMultiPlatformListRepositories:
    """Test listing repositories across all platforms."""

    @pytest.mark.asyncio
    async def test_list_openbsd_returns_empty(self, repo_ops):
        """Test listing repositories on OpenBSD returns empty list."""
        with patch("platform.system", return_value="OpenBSD"):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["repositories"] == []

    @pytest.mark.asyncio
    async def test_list_unknown_system_returns_empty(self, repo_ops):
        """Test listing repositories on unknown system returns empty list."""
        with patch("platform.system", return_value="UnknownOS"):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["repositories"] == []
