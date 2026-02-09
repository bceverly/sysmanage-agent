"""
Unit tests for src.sysmanage_agent.operations.package_manager_operations module.
Comprehensive tests for enabling package managers (flatpak, snap, homebrew, chocolatey, scoop).
"""

# pylint: disable=protected-access,attribute-defined-outside-init,too-many-lines

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.package_manager_operations import (
    PackageManagerOperations,
    _get_linux_package_manager,
    _run_package_install,
)


class TestRunPackageInstall:
    """Test cases for _run_package_install helper function."""

    @pytest.mark.asyncio
    async def test_run_package_install_success(self):
        """Test successful package installation."""
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(
            return_value=(b"Package installed successfully", b"")
        )

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await _run_package_install(
                "/usr/bin/apt", "vim", ["install", "-y"]
            )

            assert returncode == 0
            assert "Package installed successfully" in stdout
            assert stderr == ""
            mock_exec.assert_called_once_with(
                "sudo",
                "/usr/bin/apt",
                "install",
                "-y",
                "vim",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

    @pytest.mark.asyncio
    async def test_run_package_install_failure(self):
        """Test failed package installation."""
        mock_process = Mock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(
            return_value=(b"", b"E: Unable to locate package nonexistent")
        )

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await _run_package_install(
                "/usr/bin/apt", "nonexistent", ["install", "-y"]
            )

            assert returncode == 1
            assert stdout == ""
            assert "Unable to locate package" in stderr

    @pytest.mark.asyncio
    async def test_run_package_install_timeout(self):
        """Test package installation timeout."""

        async def mock_communicate():
            await asyncio.sleep(10)
            return b"", b""

        mock_process = Mock()
        mock_process.communicate = mock_communicate

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock
        ) as mock_exec:
            mock_exec.return_value = mock_process

            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    _run_package_install("/usr/bin/apt", "vim", ["install", "-y"]),
                    timeout=0.1,
                )


class TestGetLinuxPackageManager:
    """Test cases for _get_linux_package_manager helper function."""

    def test_get_linux_package_manager_apt(self):
        """Test apt package manager detection."""
        with patch("shutil.which") as mock_which:
            mock_which.side_effect = lambda x: "/usr/bin/apt" if x == "apt" else None

            result = _get_linux_package_manager()

            assert result is not None
            assert result[0] == "/usr/bin/apt"
            assert result[1] == ["install", "-y"]

    def test_get_linux_package_manager_dnf(self):
        """Test dnf package manager detection."""
        with patch("shutil.which") as mock_which:

            def which_side_effect(cmd):
                if cmd == "dnf":
                    return "/usr/bin/dnf"
                return None

            mock_which.side_effect = which_side_effect

            result = _get_linux_package_manager()

            assert result is not None
            assert result[0] == "/usr/bin/dnf"
            assert result[1] == ["install", "-y"]

    def test_get_linux_package_manager_zypper(self):
        """Test zypper package manager detection."""
        with patch("shutil.which") as mock_which:

            def which_side_effect(cmd):
                if cmd == "zypper":
                    return "/usr/bin/zypper"
                return None

            mock_which.side_effect = which_side_effect

            result = _get_linux_package_manager()

            assert result is not None
            assert result[0] == "/usr/bin/zypper"
            assert result[1] == ["install", "-y"]

    def test_get_linux_package_manager_none_found(self):
        """Test when no package manager is found."""
        with patch("shutil.which", return_value=None):
            result = _get_linux_package_manager()

            assert result is None


class TestPackageManagerOperationsInit:
    """Test cases for PackageManagerOperations initialization."""

    def test_init_with_agent(self):
        """Test initialization with agent instance."""
        mock_agent = Mock()
        ops = PackageManagerOperations(mock_agent)

        assert ops.agent == mock_agent
        assert ops.logger is not None

    def test_init_with_custom_logger(self):
        """Test initialization with custom logger."""
        mock_agent = Mock()
        mock_logger = Mock()
        ops = PackageManagerOperations(mock_agent, logger=mock_logger)

        assert ops.agent == mock_agent
        assert ops.logger == mock_logger

    @patch("platform.system")
    def test_init_detects_system(self, mock_system):
        """Test that initialization detects the operating system."""
        mock_system.return_value = "Linux"
        mock_agent = Mock()

        ops = PackageManagerOperations(mock_agent)

        assert ops.system == "Linux"


class TestEnablePackageManager:
    """Test cases for enable_package_manager method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_package_manager_empty_name(self):
        """Test enabling package manager with empty name."""
        parameters = {"package_manager": "", "os_name": "Ubuntu"}

        result = await self.ops.enable_package_manager(parameters)

        assert result["success"] is False
        assert "required" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_package_manager_unknown(self):
        """Test enabling unknown package manager."""
        with patch(
            "src.sysmanage_agent.operations.package_manager_operations.is_running_privileged",
            return_value=True,
        ):
            parameters = {"package_manager": "unknown_pm", "os_name": "Ubuntu"}

            result = await self.ops.enable_package_manager(parameters)

            assert result["success"] is False
            assert "unknown" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_package_manager_not_privileged(self):
        """Test enabling package manager without privileges."""
        with patch(
            "src.sysmanage_agent.operations.package_manager_operations.is_running_privileged",
            return_value=False,
        ):
            parameters = {"package_manager": "flatpak", "os_name": "Ubuntu"}

            result = await self.ops.enable_package_manager(parameters)

            assert result["success"] is False
            assert "privileged" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_package_manager_flatpak_dispatch(self):
        """Test that flatpak is dispatched to correct handler."""
        with patch(
            "src.sysmanage_agent.operations.package_manager_operations.is_running_privileged",
            return_value=True,
        ):
            self.ops._enable_flatpak = AsyncMock(
                return_value={"success": True, "message": "Flatpak installed"}
            )

            parameters = {"package_manager": "flatpak", "os_name": "Ubuntu"}
            result = await self.ops.enable_package_manager(parameters)

            assert result["success"] is True
            self.ops._enable_flatpak.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_package_manager_snap_dispatch(self):
        """Test that snap is dispatched to correct handler."""
        with patch(
            "src.sysmanage_agent.operations.package_manager_operations.is_running_privileged",
            return_value=True,
        ):
            self.ops._enable_snap = AsyncMock(
                return_value={"success": True, "message": "Snap installed"}
            )

            parameters = {"package_manager": "snap", "os_name": "Ubuntu"}
            result = await self.ops.enable_package_manager(parameters)

            assert result["success"] is True
            self.ops._enable_snap.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_package_manager_homebrew_dispatch(self):
        """Test that homebrew is dispatched to correct handler."""
        with patch(
            "src.sysmanage_agent.operations.package_manager_operations.is_running_privileged",
            return_value=True,
        ):
            self.ops._enable_homebrew = AsyncMock(
                return_value={"success": False, "requires_manual_install": True}
            )

            parameters = {"package_manager": "homebrew", "os_name": "macOS"}
            _result = await self.ops.enable_package_manager(parameters)

            self.ops._enable_homebrew.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_package_manager_chocolatey_dispatch(self):
        """Test that chocolatey is dispatched to correct handler."""
        with patch(
            "src.sysmanage_agent.operations.package_manager_operations.is_running_privileged",
            return_value=True,
        ):
            self.ops._enable_chocolatey = AsyncMock(
                return_value={"success": True, "message": "Chocolatey installed"}
            )

            parameters = {"package_manager": "chocolatey", "os_name": "Windows"}
            result = await self.ops.enable_package_manager(parameters)

            assert result["success"] is True
            self.ops._enable_chocolatey.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_package_manager_scoop_dispatch(self):
        """Test that scoop is dispatched to correct handler."""
        with patch(
            "src.sysmanage_agent.operations.package_manager_operations.is_running_privileged",
            return_value=True,
        ):
            self.ops._enable_scoop = AsyncMock(
                return_value={"success": True, "message": "Scoop installed"}
            )

            parameters = {"package_manager": "scoop", "os_name": "Windows"}
            result = await self.ops.enable_package_manager(parameters)

            assert result["success"] is True
            self.ops._enable_scoop.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_package_manager_handler_exception(self):
        """Test enabling package manager when handler raises exception."""
        with patch(
            "src.sysmanage_agent.operations.package_manager_operations.is_running_privileged",
            return_value=True,
        ):
            self.ops._enable_flatpak = AsyncMock(
                side_effect=Exception("Installation failed")
            )

            parameters = {"package_manager": "flatpak", "os_name": "Ubuntu"}
            result = await self.ops.enable_package_manager(parameters)

            assert result["success"] is False
            assert "Installation failed" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_package_manager_case_insensitive(self):
        """Test that package manager names are case insensitive."""
        with patch(
            "src.sysmanage_agent.operations.package_manager_operations.is_running_privileged",
            return_value=True,
        ):
            self.ops._enable_flatpak = AsyncMock(
                return_value={"success": True, "message": "Flatpak installed"}
            )

            parameters = {"package_manager": "FLATPAK", "os_name": "Ubuntu"}
            result = await self.ops.enable_package_manager(parameters)

            assert result["success"] is True
            self.ops._enable_flatpak.assert_called_once()


class TestEnableFlatpak:
    """Test cases for _enable_flatpak method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_flatpak_non_linux(self):
        """Test enabling flatpak on non-Linux system."""
        self.ops.system = "Windows"

        result = await self.ops._enable_flatpak()

        assert result["success"] is False
        assert "Linux" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_flatpak_already_installed(self):
        """Test enabling flatpak when already installed."""
        self.ops.system = "Linux"

        with patch("shutil.which", return_value="/usr/bin/flatpak"):
            self.ops._add_flathub_repo = AsyncMock()

            result = await self.ops._enable_flatpak()

            assert result["success"] is True
            assert result.get("already_installed") is True
            self.ops._add_flathub_repo.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_flatpak_install_success(self):
        """Test successful flatpak installation."""
        self.ops.system = "Linux"

        with patch("shutil.which") as mock_which:
            # First call (check if installed) returns None
            # Second call (for apt) returns /usr/bin/apt
            mock_which.side_effect = [None, "/usr/bin/apt"]

            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(b"Flatpak installed", b"")
            )

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process
                self.ops._add_flathub_repo = AsyncMock()

                result = await self.ops._enable_flatpak()

                assert result["success"] is True
                assert "installed successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_enable_flatpak_install_failure(self):
        """Test failed flatpak installation."""
        self.ops.system = "Linux"

        with patch("shutil.which") as mock_which:
            mock_which.side_effect = [None, "/usr/bin/apt"]

            mock_process = Mock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(
                return_value=(b"", b"E: Unable to install flatpak")
            )

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._enable_flatpak()

                assert result["success"] is False
                assert "Unable to install flatpak" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_flatpak_no_package_manager(self):
        """Test enabling flatpak when no package manager is available."""
        self.ops.system = "Linux"

        with patch("shutil.which", return_value=None):
            result = await self.ops._enable_flatpak()

            assert result["success"] is False
            assert "No supported package manager" in result["error"]


class TestAddFlathubRepo:
    """Test cases for _add_flathub_repo method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_add_flathub_repo_success(self):
        """Test successful flathub repo addition."""
        with patch("shutil.which", return_value="/usr/bin/flatpak"):
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b"", b""))

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                await self.ops._add_flathub_repo()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0]
                assert "flatpak" in call_args[1]
                assert "flathub" in call_args

    @pytest.mark.asyncio
    async def test_add_flathub_repo_no_flatpak(self):
        """Test flathub repo addition when flatpak is not available."""
        with patch("shutil.which", return_value=None):
            # Should return without error
            await self.ops._add_flathub_repo()

    @pytest.mark.asyncio
    async def test_add_flathub_repo_exception(self):
        """Test flathub repo addition with exception."""
        with patch("shutil.which", return_value="/usr/bin/flatpak"):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=Exception("Command failed"),
            ):
                # Should not raise exception
                await self.ops._add_flathub_repo()


class TestEnableSnap:
    """Test cases for _enable_snap method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_snap_non_linux(self):
        """Test enabling snap on non-Linux system."""
        self.ops.system = "Darwin"

        result = await self.ops._enable_snap()

        assert result["success"] is False
        assert "Linux" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_snap_already_installed(self):
        """Test enabling snap when already installed."""
        self.ops.system = "Linux"

        with patch("shutil.which", return_value="/usr/bin/snap"):
            result = await self.ops._enable_snap()

            assert result["success"] is True
            assert result.get("already_installed") is True

    @pytest.mark.asyncio
    async def test_enable_snap_install_success(self):
        """Test successful snap installation."""
        self.ops.system = "Linux"

        with patch("shutil.which") as mock_which:
            mock_which.side_effect = [None, "/usr/bin/apt"]

            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"Snapd installed", b""))

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process
                self.ops._enable_snapd_service = AsyncMock()

                result = await self.ops._enable_snap()

                assert result["success"] is True
                self.ops._enable_snapd_service.assert_called_once()


class TestEnableSnapdService:
    """Test cases for _enable_snapd_service method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_snapd_service_success(self):
        """Test successful snapd service enablement."""
        with patch("shutil.which", return_value="/usr/bin/systemctl"):
            mock_process = Mock()
            mock_process.communicate = AsyncMock(return_value=(b"", b""))

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                await self.ops._enable_snapd_service()

                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0]
                assert "systemctl" in call_args[1]
                assert "enable" in call_args
                assert "snapd.socket" in call_args

    @pytest.mark.asyncio
    async def test_enable_snapd_service_no_systemctl(self):
        """Test snapd service enablement when systemctl is not available."""
        with patch("shutil.which", return_value=None):
            # Should return without error
            await self.ops._enable_snapd_service()

    @pytest.mark.asyncio
    async def test_enable_snapd_service_exception(self):
        """Test snapd service enablement with exception."""
        with patch("shutil.which", return_value="/usr/bin/systemctl"):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=Exception("Service error"),
            ):
                # Should not raise exception
                await self.ops._enable_snapd_service()


class TestEnableHomebrew:
    """Test cases for _enable_homebrew method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_homebrew_already_installed(self):
        """Test enabling homebrew when already installed."""
        with patch("shutil.which", return_value="/opt/homebrew/bin/brew"):
            result = await self.ops._enable_homebrew()

            assert result["success"] is True
            assert result.get("already_installed") is True

    @pytest.mark.asyncio
    async def test_enable_homebrew_requires_manual_install(self):
        """Test enabling homebrew when not installed requires manual intervention."""
        with patch("shutil.which", return_value=None):
            result = await self.ops._enable_homebrew()

            assert result["success"] is False
            assert result.get("requires_manual_install") is True
            assert "manual intervention" in result["error"].lower()


class TestEnableChocolatey:
    """Test cases for _enable_chocolatey method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_chocolatey_non_windows(self):
        """Test enabling chocolatey on non-Windows system."""
        self.ops.system = "Linux"

        result = await self.ops._enable_chocolatey()

        assert result["success"] is False
        assert "Windows" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_chocolatey_already_installed(self):
        """Test enabling chocolatey when already installed."""
        self.ops.system = "Windows"

        with patch(
            "shutil.which", return_value="C:\\ProgramData\\chocolatey\\bin\\choco.exe"
        ):
            result = await self.ops._enable_chocolatey()

            assert result["success"] is True
            assert result.get("already_installed") is True

    @pytest.mark.asyncio
    async def test_enable_chocolatey_install_success(self):
        """Test successful chocolatey installation."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(b"Chocolatey installed", b"")
            )

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._enable_chocolatey()

                assert result["success"] is True
                assert "installed successfully" in result["message"]
                mock_exec.assert_called_once()
                call_args = mock_exec.call_args[0]
                assert "powershell" in call_args

    @pytest.mark.asyncio
    async def test_enable_chocolatey_install_failure(self):
        """Test failed chocolatey installation."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            mock_process = Mock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(
                return_value=(b"", b"PowerShell error")
            )

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._enable_chocolatey()

                assert result["success"] is False
                assert "PowerShell error" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_chocolatey_timeout(self):
        """Test chocolatey installation timeout."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_process = Mock()

                async def slow_communicate():
                    await asyncio.sleep(10)
                    return b"", b""

                mock_process.communicate = slow_communicate
                mock_exec.return_value = mock_process

                with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                    result = await self.ops._enable_chocolatey()

                    assert result["success"] is False
                    assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_chocolatey_exception(self):
        """Test chocolatey installation with exception."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=Exception("PowerShell not found"),
            ):
                result = await self.ops._enable_chocolatey()

                assert result["success"] is False
                assert "PowerShell not found" in result["error"]


class TestEnableScoop:
    """Test cases for _enable_scoop method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_enable_scoop_non_windows(self):
        """Test enabling scoop on non-Windows system."""
        self.ops.system = "Darwin"

        result = await self.ops._enable_scoop()

        assert result["success"] is False
        assert "Windows" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_scoop_already_installed(self):
        """Test enabling scoop when already installed."""
        self.ops.system = "Windows"

        with patch(
            "shutil.which", return_value="C:\\Users\\user\\scoop\\shims\\scoop.exe"
        ):
            result = await self.ops._enable_scoop()

            assert result["success"] is True
            assert result.get("already_installed") is True

    @pytest.mark.asyncio
    async def test_enable_scoop_install_success(self):
        """Test successful scoop installation."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"Scoop installed", b""))

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._enable_scoop()

                assert result["success"] is True
                assert "installed successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_enable_scoop_install_failure(self):
        """Test failed scoop installation."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            mock_process = Mock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(
                return_value=(b"", b"Installation error")
            )

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._enable_scoop()

                assert result["success"] is False
                assert "Installation error" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_scoop_timeout(self):
        """Test scoop installation timeout."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_process = Mock()

                async def slow_communicate():
                    await asyncio.sleep(10)
                    return b"", b""

                mock_process.communicate = slow_communicate
                mock_exec.return_value = mock_process

                with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                    result = await self.ops._enable_scoop()

                    assert result["success"] is False
                    assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_enable_scoop_exception(self):
        """Test scoop installation with exception."""
        self.ops.system = "Windows"

        with patch("shutil.which", return_value=None):
            with patch(
                "asyncio.create_subprocess_exec",
                side_effect=Exception("PowerShell error"),
            ):
                result = await self.ops._enable_scoop()

                assert result["success"] is False
                assert "PowerShell error" in result["error"]


class TestInstallLinuxPackage:
    """Test cases for _install_linux_package method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.ops = PackageManagerOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_install_linux_package_no_package_manager(self):
        """Test installing package when no package manager is available."""
        with patch("shutil.which", return_value=None):
            result = await self.ops._install_linux_package("flatpak", "Flatpak", None)

            assert result["success"] is False
            assert "No supported package manager" in result["error"]

    @pytest.mark.asyncio
    async def test_install_linux_package_success_with_hook(self):
        """Test successful package installation with post-install hook."""
        with patch("shutil.which", return_value="/usr/bin/apt"):
            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(
                return_value=(b"Package installed", b"")
            )

            async def mock_post_install():
                pass

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._install_linux_package(
                    "flatpak", "Flatpak", mock_post_install
                )

                assert result["success"] is True
                assert "installed successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_install_linux_package_success_no_hook(self):
        """Test successful package installation without post-install hook."""
        with patch("shutil.which", return_value="/usr/bin/apt"):
            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._install_linux_package("vim", "Vim", None)

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_install_linux_package_failure(self):
        """Test failed package installation."""
        with patch("shutil.which", return_value="/usr/bin/apt"):
            mock_process = Mock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(
                return_value=(b"", b"E: Package not found")
            )

            with patch(
                "asyncio.create_subprocess_exec", new_callable=AsyncMock
            ) as mock_exec:
                mock_exec.return_value = mock_process

                result = await self.ops._install_linux_package(
                    "nonexistent", "Nonexistent", None
                )

                assert result["success"] is False
                assert "Package not found" in result["error"]

    @pytest.mark.asyncio
    async def test_install_linux_package_timeout(self):
        """Test package installation timeout."""
        with patch("shutil.which", return_value="/usr/bin/apt"):
            with patch(
                "src.sysmanage_agent.operations.package_manager_operations._run_package_install"
            ) as mock_run:
                mock_run.side_effect = asyncio.TimeoutError()

                result = await self.ops._install_linux_package("vim", "Vim", None)

                assert result["success"] is False
                assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_install_linux_package_exception(self):
        """Test package installation with exception."""
        with patch("shutil.which", return_value="/usr/bin/apt"):
            with patch(
                "src.sysmanage_agent.operations.package_manager_operations._run_package_install"
            ) as mock_run:
                mock_run.side_effect = Exception("Subprocess error")

                result = await self.ops._install_linux_package("vim", "Vim", None)

                assert result["success"] is False
                assert "Subprocess error" in result["error"]
