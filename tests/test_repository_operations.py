#!/usr/bin/env python3
"""
Tests for ThirdPartyRepositoryOperations class.
"""

# pylint: disable=redefined-outer-name,protected-access,broad-exception-raised

from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from src.sysmanage_agent.operations.repository_operations import (
    ThirdPartyRepositoryOperations,
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


class TestInit:
    """Test initialization."""

    @pytest.mark.asyncio
    async def test_init(self, mock_agent):
        """Test initialization creates all helper instances."""
        ops = ThirdPartyRepositoryOperations(mock_agent)
        assert ops.agent_instance == mock_agent
        assert ops.logger is not None
        assert ops.linux_ops is not None
        assert ops.bsd_macos_ops is not None
        assert ops.windows_ops is not None


class TestDetectLinuxDistro:
    """Test Linux distribution detection."""

    @pytest.mark.asyncio
    async def test_detect_ubuntu(self, repo_ops):
        """Test detecting Ubuntu distribution."""
        os_release_content = 'ID=ubuntu\nVERSION_ID="22.04"\n'
        with (
            patch("os.path.exists", return_value=True),
            patch("builtins.open", mock_open(read_data=os_release_content)),
        ):
            result = await repo_ops._detect_linux_distro()
            assert result["distro"] == "ubuntu"

    @pytest.mark.asyncio
    async def test_detect_debian(self, repo_ops):
        """Test detecting Debian distribution."""
        os_release_content = 'ID=debian\nVERSION_ID="11"\n'
        with (
            patch("os.path.exists", return_value=True),
            patch("builtins.open", mock_open(read_data=os_release_content)),
        ):
            result = await repo_ops._detect_linux_distro()
            assert result["distro"] == "debian"

    @pytest.mark.asyncio
    async def test_detect_fedora(self, repo_ops):
        """Test detecting Fedora distribution."""
        os_release_content = 'ID=fedora\nVERSION_ID="38"\n'
        with (
            patch("os.path.exists", return_value=True),
            patch("builtins.open", mock_open(read_data=os_release_content)),
        ):
            result = await repo_ops._detect_linux_distro()
            assert result["distro"] == "fedora"

    @pytest.mark.asyncio
    async def test_detect_opensuse(self, repo_ops):
        """Test detecting openSUSE distribution."""
        os_release_content = 'ID="opensuse-leap"\nVERSION_ID="15.4"\n'
        with (
            patch("os.path.exists", return_value=True),
            patch("builtins.open", mock_open(read_data=os_release_content)),
        ):
            result = await repo_ops._detect_linux_distro()
            assert result["distro"] == "opensuse-leap"

    @pytest.mark.asyncio
    async def test_detect_no_os_release(self, repo_ops):
        """Test detection when /etc/os-release doesn't exist."""
        with (
            patch("os.path.exists", return_value=False),
            patch("platform.system", return_value="Linux"),
        ):
            result = await repo_ops._detect_linux_distro()
            assert result["distro"] == "Linux"

    @pytest.mark.asyncio
    async def test_detect_error(self, repo_ops):
        """Test error handling in distribution detection."""
        # Mock open to raise exception for /etc/os-release specifically
        original_open = open

        def mock_open_func(path, *args, **kwargs):
            if path == "/etc/os-release":
                raise Exception("Test error")
            return original_open(path, *args, **kwargs)

        with (
            patch("builtins.open", side_effect=mock_open_func),
            patch("os.path.exists", return_value=True),
        ):
            result = await repo_ops._detect_linux_distro()
            assert result["distro"] == "unknown"


class TestListRepositories:
    """Test repository listing."""

    @pytest.mark.asyncio
    async def test_list_ubuntu_repositories(self, repo_ops):
        """Test listing repositories on Ubuntu."""
        repo_ops.linux_ops.list_apt_repositories = AsyncMock(
            return_value=[
                {
                    "name": "ppa:test/ppa",
                    "type": "PPA",
                    "url": "http://ppa.launchpad.net/test/ppa/ubuntu",
                    "enabled": True,
                    "file_path": "/etc/apt/sources.list.d/test.list",
                }
            ]
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "ubuntu"}
            ),
        ):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["count"] == 1
            assert result["repositories"][0]["type"] == "PPA"

    @pytest.mark.asyncio
    async def test_list_fedora_repositories(self, repo_ops):
        """Test listing repositories on Fedora."""
        repo_ops.linux_ops.list_yum_repositories = AsyncMock(
            return_value=[
                {
                    "name": "copr:test/repo",
                    "type": "COPR",
                    "url": "http://copr.fedorainfracloud.org/",
                    "enabled": True,
                    "file_path": "/etc/yum.repos.d/copr.repo",
                }
            ]
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "fedora"}
            ),
        ):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["count"] == 1
            assert result["repositories"][0]["type"] == "COPR"

    @pytest.mark.asyncio
    async def test_list_opensuse_repositories(self, repo_ops):
        """Test listing repositories on openSUSE."""
        repo_ops.linux_ops.list_zypper_repositories = AsyncMock(
            return_value=[
                {
                    "name": "obs-repo",
                    "type": "OBS",
                    "url": "http://download.opensuse.org/",
                    "enabled": True,
                    "file_path": "/etc/zypp/repos.d/obs-repo.repo",
                }
            ]
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "opensuse"}
            ),
        ):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["count"] == 1
            assert result["repositories"][0]["type"] == "OBS"

    @pytest.mark.asyncio
    async def test_list_macos_repositories(self, repo_ops):
        """Test listing repositories on macOS."""
        repo_ops.bsd_macos_ops.list_homebrew_taps = AsyncMock(
            return_value=[
                {
                    "name": "user/tap",
                    "type": "Homebrew Tap",
                    "url": "https://github.com/user/tap",
                    "enabled": True,
                    "file_path": "/usr/local/Homebrew/Library/Taps/user/homebrew-tap",
                }
            ]
        )
        with patch("platform.system", return_value="Darwin"):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["count"] == 1
            assert result["repositories"][0]["type"] == "Homebrew Tap"

    @pytest.mark.asyncio
    async def test_list_freebsd_repositories(self, repo_ops):
        """Test listing repositories on FreeBSD."""
        repo_ops.bsd_macos_ops.list_freebsd_repositories = AsyncMock(
            return_value=[
                {
                    "name": "custom-repo",
                    "type": "FreeBSD pkg",
                    "url": "http://pkg.freebsd.org/",
                    "enabled": True,
                    "file_path": "/usr/local/etc/pkg/repos/custom-repo.conf",
                }
            ]
        )
        with patch("platform.system", return_value="FreeBSD"):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["count"] == 1
            assert result["repositories"][0]["type"] == "FreeBSD pkg"

    @pytest.mark.asyncio
    async def test_list_netbsd_repositories(self, repo_ops):
        """Test listing repositories on NetBSD."""
        repo_ops.bsd_macos_ops.list_netbsd_repositories = AsyncMock(
            return_value=[
                {
                    "name": "pkgsrc-wip",
                    "type": "pkgsrc-wip",
                    "url": "https://github.com/NetBSD/pkgsrc-wip",
                    "enabled": True,
                    "file_path": "/usr/pkgsrc/wip",
                }
            ]
        )
        with patch("platform.system", return_value="NetBSD"):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["count"] == 1
            assert result["repositories"][0]["type"] == "pkgsrc-wip"

    @pytest.mark.asyncio
    async def test_list_windows_repositories(self, repo_ops):
        """Test listing repositories on Windows."""
        repo_ops.windows_ops.list_windows_repositories = AsyncMock(
            return_value=[
                {
                    "name": "custom-source",
                    "type": "Chocolatey",
                    "url": "http://myrepo.com/",
                    "enabled": True,
                    "file_path": None,
                }
            ]
        )
        with patch("platform.system", return_value="Windows"):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is True
            assert result["count"] == 1
            assert result["repositories"][0]["type"] == "Chocolatey"

    @pytest.mark.asyncio
    async def test_list_repositories_error(self, repo_ops):
        """Test error handling when listing repositories."""
        with patch("platform.system", side_effect=Exception("Test error")):
            result = await repo_ops.list_third_party_repositories({})
            assert result["success"] is False
            assert "Test error" in result["error"]


class TestAddRepository:
    """Test adding repositories."""

    @pytest.mark.asyncio
    async def test_add_repository_no_identifier(self, repo_ops):
        """Test adding repository without identifier."""
        result = await repo_ops.add_third_party_repository({})
        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_add_apt_repository(self, repo_ops):
        """Test adding APT repository on Ubuntu."""
        repo_ops.linux_ops.add_apt_repository = AsyncMock(
            return_value={"success": True, "result": "Repository added successfully"}
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "ubuntu"}
            ),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.add_third_party_repository(
                {"repository": "ppa:test/ppa"}
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_add_yum_repository(self, repo_ops):
        """Test adding YUM repository on Fedora."""
        repo_ops.linux_ops.add_yum_repository = AsyncMock(
            return_value={"success": True, "result": "Repository added successfully"}
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "fedora"}
            ),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.add_third_party_repository(
                {"repository": "user/repo"}
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_add_zypper_repository(self, repo_ops):
        """Test adding Zypper repository on openSUSE."""
        repo_ops.linux_ops.add_zypper_repository = AsyncMock(
            return_value={"success": True, "result": "Repository added successfully"}
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "opensuse"}
            ),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.add_third_party_repository(
                {"repository": "obs-repo", "url": "http://download.opensuse.org/"}
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_add_homebrew_tap(self, repo_ops):
        """Test adding Homebrew tap on macOS."""
        repo_ops.bsd_macos_ops.add_homebrew_tap = AsyncMock(
            return_value={"success": True, "result": "Tap added successfully"}
        )
        with (
            patch("platform.system", return_value="Darwin"),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.add_third_party_repository(
                {"repository": "user/tap"}
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_add_freebsd_repository(self, repo_ops):
        """Test adding FreeBSD repository."""
        repo_ops.bsd_macos_ops.add_freebsd_repository = AsyncMock(
            return_value={"success": True, "result": "Repository added successfully"}
        )
        with (
            patch("platform.system", return_value="FreeBSD"),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.add_third_party_repository(
                {"repository": "custom-repo", "url": "http://pkg.freebsd.org/"}
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_add_netbsd_repository(self, repo_ops):
        """Test adding NetBSD repository."""
        repo_ops.bsd_macos_ops.add_netbsd_repository = AsyncMock(
            return_value={"success": True, "result": "Repository cloned successfully"}
        )
        with (
            patch("platform.system", return_value="NetBSD"),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.add_third_party_repository(
                {
                    "repository": "pkgsrc-wip",
                    "url": "https://github.com/NetBSD/pkgsrc-wip",
                }
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_add_windows_repository(self, repo_ops):
        """Test adding Windows repository."""
        repo_ops.windows_ops.add_windows_repository = AsyncMock(
            return_value={"success": True, "result": "Repository added successfully"}
        )
        with (
            patch("platform.system", return_value="Windows"),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.add_third_party_repository(
                {
                    "repository": "custom-source",
                    "url": "http://myrepo.com/",
                    "type": "chocolatey",
                }
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_add_repository_unsupported_distro(self, repo_ops):
        """Test adding repository on unsupported Linux distribution."""
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "slackware"}
            ),
        ):
            result = await repo_ops.add_third_party_repository(
                {"repository": "test-repo"}
            )
            assert result["success"] is False
            assert "Unsupported distribution" in result["error"]

    @pytest.mark.asyncio
    async def test_add_repository_unsupported_os(self, repo_ops):
        """Test adding repository on unsupported OS."""
        with patch("platform.system", return_value="Solaris"):
            result = await repo_ops.add_third_party_repository(
                {"repository": "test-repo"}
            )
            assert result["success"] is False
            assert "Unsupported operating system" in result["error"]

    @pytest.mark.asyncio
    async def test_add_repository_error(self, repo_ops):
        """Test error handling when adding repository."""
        with patch("platform.system", side_effect=Exception("Test error")):
            result = await repo_ops.add_third_party_repository(
                {"repository": "test-repo"}
            )
            assert result["success"] is False
            assert "Test error" in result["error"]


class TestDeleteRepositories:
    """Test deleting repositories."""

    @pytest.mark.asyncio
    async def test_delete_no_repositories(self, repo_ops):
        """Test deleting without specifying repositories."""
        result = await repo_ops.delete_third_party_repositories({})
        assert result["success"] is False
        assert "No repositories specified" in result["error"]

    @pytest.mark.asyncio
    async def test_delete_apt_repositories(self, repo_ops):
        """Test deleting APT repositories."""
        repo_ops.linux_ops.delete_apt_repository = AsyncMock(
            return_value={"success": True, "result": "Repository removed successfully"}
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "ubuntu"}
            ),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.delete_third_party_repositories(
                {
                    "repositories": [
                        {"name": "ppa:test/ppa", "file_path": "/tmp/test.list"}
                    ]
                }
            )
            assert result["success"] is True
            assert result["results"][0]["success"] is True

    @pytest.mark.asyncio
    async def test_delete_multiple_repositories(self, repo_ops):
        """Test deleting multiple repositories."""
        repo_ops.linux_ops.delete_apt_repository = AsyncMock(
            return_value={"success": True, "result": "Repository removed successfully"}
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "ubuntu"}
            ),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.delete_third_party_repositories(
                {
                    "repositories": [
                        {"name": "ppa:test1/ppa"},
                        {"name": "ppa:test2/ppa"},
                    ]
                }
            )
            assert result["success"] is True
            assert len(result["results"]) == 2

    @pytest.mark.asyncio
    async def test_delete_repositories_partial_failure(self, repo_ops):
        """Test deleting repositories with partial failure."""
        repo_ops.linux_ops.delete_apt_repository = AsyncMock(
            side_effect=[
                {"success": True, "result": "Repository removed successfully"},
                {"success": False, "error": "Repository not found"},
            ]
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "ubuntu"}
            ),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.delete_third_party_repositories(
                {
                    "repositories": [
                        {"name": "ppa:test1/ppa"},
                        {"name": "ppa:test2/ppa"},
                    ]
                }
            )
            assert result["success"] is False
            assert result["results"][0]["success"] is True
            assert result["results"][1]["success"] is False

    @pytest.mark.asyncio
    async def test_delete_repositories_unsupported_os(self, repo_ops):
        """Test deleting repositories on unsupported OS."""
        with patch("platform.system", return_value="Solaris"):
            result = await repo_ops.delete_third_party_repositories(
                {"repositories": [{"name": "test-repo"}]}
            )
            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_delete_repositories_error(self, repo_ops):
        """Test error handling when deleting repositories."""
        with patch("platform.system", side_effect=Exception("Test error")):
            result = await repo_ops.delete_third_party_repositories(
                {"repositories": [{"name": "test-repo"}]}
            )
            assert result["success"] is False
            assert "Test error" in result["error"]


class TestEnableRepositories:
    """Test enabling repositories."""

    @pytest.mark.asyncio
    async def test_enable_no_repositories(self, repo_ops):
        """Test enabling without specifying repositories."""
        result = await repo_ops.enable_third_party_repositories({})
        assert result["success"] is False
        assert "No repositories specified" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_apt_repositories(self, repo_ops):
        """Test enabling APT repositories."""
        repo_ops.linux_ops.enable_apt_repository = AsyncMock(
            return_value={"success": True, "result": "Repository enabled successfully"}
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "ubuntu"}
            ),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.enable_third_party_repositories(
                {
                    "repositories": [
                        {"name": "ppa:test/ppa", "file_path": "/tmp/test.list"}
                    ]
                }
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_repositories_non_linux(self, repo_ops):
        """Test enabling repositories on non-Linux OS."""
        with patch("platform.system", return_value="Darwin"):
            result = await repo_ops.enable_third_party_repositories(
                {"repositories": [{"name": "test-repo"}]}
            )
            assert result["success"] is False
            assert "Unsupported operating system" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_repositories_error(self, repo_ops):
        """Test error handling when enabling repositories."""
        with patch("platform.system", side_effect=Exception("Test error")):
            result = await repo_ops.enable_third_party_repositories(
                {"repositories": [{"name": "test-repo"}]}
            )
            assert result["success"] is False
            assert "Test error" in result["error"]


class TestDisableRepositories:
    """Test disabling repositories."""

    @pytest.mark.asyncio
    async def test_disable_no_repositories(self, repo_ops):
        """Test disabling without specifying repositories."""
        result = await repo_ops.disable_third_party_repositories({})
        assert result["success"] is False
        assert "No repositories specified" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_apt_repositories(self, repo_ops):
        """Test disabling APT repositories."""
        repo_ops.linux_ops.disable_apt_repository = AsyncMock(
            return_value={"success": True, "result": "Repository disabled successfully"}
        )
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "ubuntu"}
            ),
            patch.object(repo_ops, "_run_package_update", new_callable=AsyncMock),
            patch.object(repo_ops, "_trigger_update_detection", new_callable=AsyncMock),
            patch.object(
                repo_ops,
                "_trigger_third_party_repository_rescan",
                new_callable=AsyncMock,
            ),
        ):
            result = await repo_ops.disable_third_party_repositories(
                {
                    "repositories": [
                        {"name": "ppa:test/ppa", "file_path": "/tmp/test.list"}
                    ]
                }
            )
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_repositories_non_linux(self, repo_ops):
        """Test disabling repositories on non-Linux OS."""
        with patch("platform.system", return_value="FreeBSD"):
            result = await repo_ops.disable_third_party_repositories(
                {"repositories": [{"name": "test-repo"}]}
            )
            assert result["success"] is False
            assert "Unsupported operating system" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_repositories_error(self, repo_ops):
        """Test error handling when disabling repositories."""
        with patch("platform.system", side_effect=Exception("Test error")):
            result = await repo_ops.disable_third_party_repositories(
                {"repositories": [{"name": "test-repo"}]}
            )
            assert result["success"] is False
            assert "Test error" in result["error"]


class TestHelperMethods:
    """Test helper methods."""

    @pytest.mark.asyncio
    async def test_run_package_update_ubuntu(self, repo_ops, mock_agent):
        """Test running package update on Ubuntu."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Updated", "stderr": ""},
        }
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "ubuntu"}
            ),
        ):
            await repo_ops._run_package_update()
            mock_agent.system_ops.execute_shell_command.assert_called_once()
            call_args = mock_agent.system_ops.execute_shell_command.call_args[0][0]
            assert "apt-get update" in call_args["command"]

    @pytest.mark.asyncio
    async def test_run_package_update_fedora(self, repo_ops, mock_agent):
        """Test running package update on Fedora."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Updated", "stderr": ""},
        }
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "fedora"}
            ),
        ):
            await repo_ops._run_package_update()
            mock_agent.system_ops.execute_shell_command.assert_called_once()
            call_args = mock_agent.system_ops.execute_shell_command.call_args[0][0]
            assert "dnf check-update" in call_args["command"]

    @pytest.mark.asyncio
    async def test_run_package_update_opensuse(self, repo_ops, mock_agent):
        """Test running package update on openSUSE."""
        mock_agent.system_ops.execute_shell_command.return_value = {
            "success": True,
            "result": {"stdout": "Updated", "stderr": ""},
        }
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "opensuse"}
            ),
        ):
            await repo_ops._run_package_update()
            mock_agent.system_ops.execute_shell_command.assert_called_once()
            call_args = mock_agent.system_ops.execute_shell_command.call_args[0][0]
            assert "zypper refresh" in call_args["command"]

    @pytest.mark.asyncio
    async def test_run_package_update_unsupported(self, repo_ops, mock_agent):
        """Test running package update on unsupported distro."""
        with (
            patch("platform.system", return_value="Linux"),
            patch.object(
                repo_ops, "_detect_linux_distro", return_value={"distro": "slackware"}
            ),
        ):
            await repo_ops._run_package_update()
            mock_agent.system_ops.execute_shell_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_run_package_update_error(self, repo_ops):
        """Test error handling in package update."""
        with patch("platform.system", side_effect=Exception("Test error")):
            await repo_ops._run_package_update()
            # Should not raise exception

    @pytest.mark.asyncio
    async def test_trigger_update_detection(self, repo_ops, mock_agent):
        """Test triggering update detection."""
        await repo_ops._trigger_update_detection()
        mock_agent.check_updates.assert_called_once()

    @pytest.mark.asyncio
    async def test_trigger_update_detection_error(self, repo_ops, mock_agent):
        """Test error handling in update detection trigger."""
        mock_agent.check_updates.side_effect = Exception("Test error")
        await repo_ops._trigger_update_detection()
        # Should not raise exception

    @pytest.mark.asyncio
    async def test_trigger_repository_rescan(self, repo_ops, mock_agent):
        """Test triggering repository rescan."""
        await repo_ops._trigger_third_party_repository_rescan()
        mock_agent._send_third_party_repository_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_trigger_repository_rescan_no_method(self, repo_ops, mock_agent):
        """Test triggering repository rescan when method doesn't exist."""
        delattr(mock_agent, "_send_third_party_repository_update")
        await repo_ops._trigger_third_party_repository_rescan()
        # Should not raise exception

    @pytest.mark.asyncio
    async def test_trigger_repository_rescan_error(self, repo_ops, mock_agent):
        """Test error handling in repository rescan trigger."""
        mock_agent._send_third_party_repository_update.side_effect = Exception(
            "Test error"
        )
        await repo_ops._trigger_third_party_repository_rescan()
        # Should not raise exception
