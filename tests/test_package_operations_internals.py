# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Unit tests for src.sysmanage_agent.operations.package_operations module.

Internal-helper coverage split out of test_package_operations.py: apt
install/uninstall helpers, package-version lookup, installation completion
and status-update notifications, package-update, and update-detection trigger.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,import-outside-toplevel

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.package_operations import PackageOperations


class TestPackageOperationsInternals:
    """Test cases for PackageOperations internal helper methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.hostname = "test-host"
        self.mock_agent.platform = "Linux"
        self.mock_agent.ipv4 = "192.168.1.100"
        self.mock_agent.ipv6 = "::1"

        # Mock the registration.get_system_info() method
        self.mock_agent.registration = Mock()
        self.mock_agent.registration.get_system_info = Mock(
            return_value={
                "hostname": "test-host",
                "fqdn": "test-host.example.com",
            }
        )

        # Mock get_host_approval_from_db
        mock_host_approval = Mock()
        mock_host_approval.host_id = 12345
        self.mock_agent.get_host_approval_from_db = Mock(
            return_value=mock_host_approval
        )

        # Mock send_message — the agent's outbound queue path.  Both
        # _send_installation_completion and _send_installation_status_update
        # go through this; tests assert send_message rather than the
        # removed call_server_api HTTP helper.
        self.mock_agent.send_message = AsyncMock(return_value=True)

        self.package_ops = PackageOperations(self.mock_agent)

    # ========================================================================
    # Tests for _install_packages_with_apt method
    # ========================================================================

    @pytest.mark.asyncio
    async def test_install_packages_with_apt_success(self):
        """Test successful apt package installation."""
        mock_update_process = Mock()
        mock_update_process.returncode = 0
        mock_update_process.communicate = AsyncMock(return_value=(b"", b""))

        mock_install_process = Mock()
        mock_install_process.returncode = 0
        mock_install_process.communicate = AsyncMock(
            return_value=(b"Successfully installed packages", b"")
        )

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.side_effect = [mock_update_process, mock_install_process]

            # Mock _get_package_versions
            self.package_ops._get_package_versions = AsyncMock(
                return_value={"vim": "8.2", "curl": "7.68"}
            )

            result = await self.package_ops._install_packages_with_apt(["vim", "curl"])

            assert result["success"] is True
            assert result["versions"] == {"vim": "8.2", "curl": "7.68"}
            assert mock_exec.call_count == 2

    @pytest.mark.asyncio
    async def test_install_packages_with_apt_empty_list(self):
        """Test apt installation with empty package list."""
        result = await self.package_ops._install_packages_with_apt([])

        assert result["success"] is False
        assert "No packages to install" in result["error"]

    @pytest.mark.asyncio
    async def test_install_packages_with_apt_install_failure(self):
        """Test apt installation failure."""
        mock_update_process = Mock()
        mock_update_process.returncode = 0
        mock_update_process.communicate = AsyncMock(return_value=(b"", b""))

        mock_install_process = Mock()
        mock_install_process.returncode = 1
        mock_install_process.communicate = AsyncMock(
            return_value=(b"", b"E: Unable to locate package badpkg")
        )

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.side_effect = [mock_update_process, mock_install_process]

            result = await self.package_ops._install_packages_with_apt(["badpkg"])

            assert result["success"] is False
            assert "apt-get install failed" in result["error"]
            assert "Unable to locate package" in result["error"]

    @pytest.mark.asyncio
    async def test_install_packages_with_apt_exception(self):
        """Test apt installation with exception."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("Process creation failed"),
        ):
            result = await self.package_ops._install_packages_with_apt(["vim"])

            assert result["success"] is False
            assert "Exception during apt-get install" in result["error"]

    # ========================================================================
    # Tests for _uninstall_packages_with_apt method
    # ========================================================================

    @pytest.mark.asyncio
    async def test_uninstall_packages_with_apt_success(self):
        """Test successful apt package uninstallation."""
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(
            return_value=(b"Packages removed successfully", b"")
        )

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = mock_process

            result = await self.package_ops._uninstall_packages_with_apt(
                ["vim", "curl"]
            )

            assert result["success"] is True
            assert "Packages removed successfully" in result["output"]

    @pytest.mark.asyncio
    async def test_uninstall_packages_with_apt_empty_list(self):
        """Test apt uninstallation with empty package list."""
        result = await self.package_ops._uninstall_packages_with_apt([])

        assert result["success"] is False
        assert "No packages to uninstall" in result["error"]

    @pytest.mark.asyncio
    async def test_uninstall_packages_with_apt_failure(self):
        """Test apt uninstallation failure."""
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(
            return_value=(b"", b"E: Package not installed")
        )

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = mock_process

            result = await self.package_ops._uninstall_packages_with_apt(
                ["notinstalled"]
            )

            assert result["success"] is False
            assert "apt-get remove failed" in result["error"]

    @pytest.mark.asyncio
    async def test_uninstall_packages_with_apt_exception(self):
        """Test apt uninstallation with exception."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("Process creation failed"),
        ):
            result = await self.package_ops._uninstall_packages_with_apt(["vim"])

            assert result["success"] is False
            assert "Exception during apt-get remove" in result["error"]

    # ========================================================================
    # Tests for _get_package_versions method
    # ========================================================================

    @pytest.mark.asyncio
    async def test_get_package_versions_success(self):
        """Test successful package version retrieval."""
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(
            return_value=(b"Version: 8.2.0\nOther: info\n", b"")
        )

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = mock_process

            result = await self.package_ops._get_package_versions(["vim"])

            assert result == {"vim": "8.2.0"}

    @pytest.mark.asyncio
    async def test_get_package_versions_not_installed(self):
        """Test package version for not installed package."""
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"not installed"))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = mock_process

            result = await self.package_ops._get_package_versions(["notinstalled"])

            assert result == {"notinstalled": "unknown"}

    @pytest.mark.asyncio
    async def test_get_package_versions_no_version_line(self):
        """Test package version when Version line is missing."""
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"Other: info\n", b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = mock_process

            result = await self.package_ops._get_package_versions(["pkg"])

            assert result == {"pkg": "unknown"}

    @pytest.mark.asyncio
    async def test_get_package_versions_exception(self):
        """Test package version with exception."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("dpkg error"),
        ):
            result = await self.package_ops._get_package_versions(["vim"])

            assert result == {"vim": "unknown"}

    @pytest.mark.asyncio
    async def test_get_package_versions_multiple_packages(self):
        """Test version retrieval for multiple packages."""
        mock_process1 = Mock()
        mock_process1.returncode = 0
        mock_process1.communicate = AsyncMock(return_value=(b"Version: 8.2.0\n", b""))

        mock_process2 = Mock()
        mock_process2.returncode = 0
        mock_process2.communicate = AsyncMock(return_value=(b"Version: 7.68.0\n", b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.side_effect = [mock_process1, mock_process2]

            result = await self.package_ops._get_package_versions(["vim", "curl"])

            assert result == {"vim": "8.2.0", "curl": "7.68.0"}

    # ========================================================================
    # Tests for _send_installation_completion method
    # ========================================================================

    @pytest.mark.asyncio
    async def test_send_installation_completion_success(self):
        """Completion is queued via send_message with the right payload shape."""
        self.mock_agent.send_message = AsyncMock(return_value=True)

        await self.package_ops._send_installation_completion(
            "req-123", True, "All packages installed"
        )

        self.mock_agent.send_message.assert_called_once()
        sent = self.mock_agent.send_message.call_args[0][0]
        assert sent["message_type"] == "installation_complete"
        assert sent["request_id"] == "req-123"
        assert sent["success"] is True
        assert sent["result_log"] == "All packages installed"
        assert sent["host_id"] == "12345"
        assert sent["hostname"] == "test-host"

    @pytest.mark.asyncio
    async def test_send_installation_completion_queue_returns_falsy(self):
        """If send_message returns falsy (queue rejected the row), the
        method still returns normally — error is logged, not raised."""
        self.mock_agent.send_message = AsyncMock(return_value=False)

        await self.package_ops._send_installation_completion(
            "req-456", False, "Some packages failed"
        )

        self.mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_installation_completion_exception(self):
        """Exceptions raised by send_message are propagated."""
        self.mock_agent.send_message = AsyncMock(side_effect=Exception("Queue error"))

        with pytest.raises(Exception):
            await self.package_ops._send_installation_completion(
                "req-789", True, "Packages installed"
            )

    # ========================================================================
    # Tests for _send_installation_status_update method
    # ========================================================================

    @pytest.mark.asyncio
    async def test_send_installation_status_update_installing(self):
        """Test status update for installing state."""
        await self.package_ops._send_installation_status_update(
            "install-123", "installing", "vim", "admin"
        )

        assert self.mock_agent.send_message.call_count == 1
        call_args = self.mock_agent.send_message.call_args[0][0]

        assert call_args["message_type"] == "package_installation_status"
        assert call_args["installation_id"] == "install-123"
        assert call_args["status"] == "installing"
        assert call_args["package_name"] == "vim"
        assert call_args["requested_by"] == "admin"
        assert call_args["hostname"] == "test-host"
        assert call_args["host_id"] == "12345"

    @pytest.mark.asyncio
    async def test_send_installation_status_update_completed(self):
        """Test status update for completed state with all fields."""
        await self.package_ops._send_installation_status_update(
            "install-456",
            "completed",
            "curl",
            "user",
            error_message=None,
            installed_version="7.68.0",
            installation_log="Successfully installed curl",
        )

        call_args = self.mock_agent.send_message.call_args[0][0]

        assert call_args["status"] == "completed"
        assert call_args["installed_version"] == "7.68.0"
        assert call_args["installation_log"] == "Successfully installed curl"
        assert "error_message" not in call_args

    @pytest.mark.asyncio
    async def test_send_installation_status_update_failed(self):
        """Test status update for failed state."""
        await self.package_ops._send_installation_status_update(
            "install-789",
            "failed",
            "badpkg",
            "user",
            error_message="Package not found",
            installed_version=None,
            installation_log=None,
        )

        call_args = self.mock_agent.send_message.call_args[0][0]

        assert call_args["status"] == "failed"
        assert call_args["error_message"] == "Package not found"
        assert "installed_version" not in call_args
        assert "installation_log" not in call_args

    @pytest.mark.asyncio
    async def test_send_installation_status_update_no_host_id(self):
        """Test status update when host_id is not available."""
        self.mock_agent.get_host_approval_from_db = Mock(return_value=None)

        await self.package_ops._send_installation_status_update(
            "install-nohost", "installing", "git", "admin"
        )

        call_args = self.mock_agent.send_message.call_args[0][0]
        assert "host_id" not in call_args

    @pytest.mark.asyncio
    async def test_send_installation_status_update_exception(self):
        """Test status update with exception."""
        self.mock_agent.send_message = AsyncMock(side_effect=Exception("Send failed"))

        # Should not raise exception
        await self.package_ops._send_installation_status_update(
            "install-err", "installing", "pkg", "user"
        )

    # ========================================================================
    # Tests for _run_package_update method
    # ========================================================================

    @pytest.mark.asyncio
    async def test_run_package_update_ubuntu(self):
        """Test package update for Ubuntu."""
        from src.sysmanage_agent.operations.system_operations import SystemOperations

        mock_system_ops = Mock(spec=SystemOperations)
        mock_system_ops._detect_linux_distro = AsyncMock(
            return_value={"distro": "Ubuntu 20.04"}
        )
        mock_system_ops.execute_shell_command = AsyncMock()
        self.mock_agent.system_ops = mock_system_ops

        with patch("platform.system", return_value="Linux"):
            await self.package_ops._run_package_update()

            mock_system_ops.execute_shell_command.assert_called_once_with(
                {"command": "sudo apt-get update"}
            )

    @pytest.mark.asyncio
    async def test_run_package_update_debian(self):
        """Test package update for Debian."""
        from src.sysmanage_agent.operations.system_operations import SystemOperations

        mock_system_ops = Mock(spec=SystemOperations)
        mock_system_ops._detect_linux_distro = AsyncMock(
            return_value={"distro": "Debian GNU/Linux 11"}
        )
        mock_system_ops.execute_shell_command = AsyncMock()
        self.mock_agent.system_ops = mock_system_ops

        with patch("platform.system", return_value="Linux"):
            await self.package_ops._run_package_update()

            mock_system_ops.execute_shell_command.assert_called_once_with(
                {"command": "sudo apt-get update"}
            )

    @pytest.mark.asyncio
    async def test_run_package_update_fedora(self):
        """Test package update for Fedora."""
        from src.sysmanage_agent.operations.system_operations import SystemOperations

        mock_system_ops = Mock(spec=SystemOperations)
        mock_system_ops._detect_linux_distro = AsyncMock(
            return_value={"distro": "Fedora 35"}
        )
        mock_system_ops.execute_shell_command = AsyncMock()
        self.mock_agent.system_ops = mock_system_ops

        with patch("platform.system", return_value="Linux"):
            await self.package_ops._run_package_update()

            mock_system_ops.execute_shell_command.assert_called_once_with(
                {"command": "sudo dnf check-update"}
            )

    @pytest.mark.asyncio
    async def test_run_package_update_rhel(self):
        """Test package update for RHEL."""
        from src.sysmanage_agent.operations.system_operations import SystemOperations

        mock_system_ops = Mock(spec=SystemOperations)
        mock_system_ops._detect_linux_distro = AsyncMock(
            return_value={"distro": "RHEL 8.5"}
        )
        mock_system_ops.execute_shell_command = AsyncMock()
        self.mock_agent.system_ops = mock_system_ops

        with patch("platform.system", return_value="Linux"):
            await self.package_ops._run_package_update()

            mock_system_ops.execute_shell_command.assert_called_once_with(
                {"command": "sudo dnf check-update"}
            )

    @pytest.mark.asyncio
    async def test_run_package_update_opensuse(self):
        """Test package update for OpenSUSE."""
        from src.sysmanage_agent.operations.system_operations import SystemOperations

        mock_system_ops = Mock(spec=SystemOperations)
        mock_system_ops._detect_linux_distro = AsyncMock(
            return_value={"distro": "openSUSE Leap 15.3"}
        )
        mock_system_ops.execute_shell_command = AsyncMock()
        self.mock_agent.system_ops = mock_system_ops

        with patch("platform.system", return_value="Linux"):
            await self.package_ops._run_package_update()

            mock_system_ops.execute_shell_command.assert_called_once_with(
                {"command": "sudo zypper refresh"}
            )

    @pytest.mark.asyncio
    async def test_run_package_update_unsupported_distro(self):
        """Test package update for unsupported distro."""
        mock_system_ops = Mock()
        mock_system_ops._detect_linux_distro = AsyncMock(
            return_value={"distro": "Unknown Linux"}
        )
        mock_system_ops.execute_shell_command = AsyncMock()
        self.mock_agent.system_ops = mock_system_ops

        with patch("platform.system", return_value="Linux"):
            await self.package_ops._run_package_update()

            # Should not call execute_shell_command for unsupported distro
            mock_system_ops.execute_shell_command.assert_not_called()

    @pytest.mark.asyncio
    async def test_run_package_update_not_linux(self):
        """Test package update on non-Linux system."""
        with patch("platform.system", return_value="Windows"):
            await self.package_ops._run_package_update()
            # Should return early and do nothing

    @pytest.mark.asyncio
    async def test_run_package_update_no_system_ops(self):
        """Test package update when system_ops is not available."""
        self.mock_agent.system_ops = None

        with patch("platform.system", return_value="Linux"):
            await self.package_ops._run_package_update()
            # Should handle gracefully

    @pytest.mark.asyncio
    async def test_run_package_update_exception(self):
        """Test package update with exception."""
        mock_system_ops = Mock()
        mock_system_ops._detect_linux_distro = AsyncMock(
            side_effect=Exception("Distro detection failed")
        )
        self.mock_agent.system_ops = mock_system_ops

        with patch("platform.system", return_value="Linux"):
            # Should not raise exception
            await self.package_ops._run_package_update()

    # ========================================================================
    # Tests for _trigger_update_detection method
    # ========================================================================

    @pytest.mark.asyncio
    async def test_trigger_update_detection_success(self):
        """Test successful update detection trigger."""
        self.mock_agent.check_updates = AsyncMock()

        await self.package_ops._trigger_update_detection()

        self.mock_agent.check_updates.assert_called_once()

    @pytest.mark.asyncio
    async def test_trigger_update_detection_exception(self):
        """Test update detection trigger with exception."""
        self.mock_agent.check_updates = AsyncMock(
            side_effect=Exception("Update check failed")
        )

        # Should not raise exception
        await self.package_ops._trigger_update_detection()
