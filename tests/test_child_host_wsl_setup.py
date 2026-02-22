"""
Unit tests for src.sysmanage_agent.operations.child_host_wsl_setup module.
Tests WSL setup operations for user creation, systemd, and agent installation.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import asyncio
import configparser
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch, MagicMock

import pytest

from src.sysmanage_agent.operations.child_host_wsl_setup import WslSetupOperations


class TestWslSetupOperationsInit:
    """Test cases for WslSetupOperations initialization."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock(return_value="decoded output")

    def test_init_sets_logger(self):
        """Test that __init__ sets logger."""
        ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)
        assert ops.logger == self.mock_logger

    def test_init_sets_decode_function(self):
        """Test that __init__ sets decode function."""
        ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)
        assert ops._decode_wsl_output == self.mock_decode_func


class TestGetCreationFlags:
    """Test cases for _get_creationflags method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    def test_get_creationflags_with_create_no_window(self):
        """Test creationflags when CREATE_NO_WINDOW is available."""
        with patch("subprocess.CREATE_NO_WINDOW", 0x08000000, create=True):
            result = self.ops._get_creationflags()
            assert result == 0x08000000

    def test_get_creationflags_without_create_no_window(self):
        """Test creationflags when CREATE_NO_WINDOW is not available."""
        # On non-Windows systems, CREATE_NO_WINDOW doesn't exist
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            # If it exists, patch it away
            original = subprocess.CREATE_NO_WINDOW
            delattr(subprocess, "CREATE_NO_WINDOW")
            result = self.ops._get_creationflags()
            subprocess.CREATE_NO_WINDOW = original
        else:
            result = self.ops._get_creationflags()
        assert result == 0


class TestGetExecutableName:
    """Test cases for get_executable_name method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    def test_get_executable_name_ubuntu_2404(self):
        """Test executable name for Ubuntu 24.04."""
        result = self.ops.get_executable_name("Ubuntu-24.04")
        assert result == "ubuntu2404.exe"

    def test_get_executable_name_ubuntu_2204(self):
        """Test executable name for Ubuntu 22.04."""
        result = self.ops.get_executable_name("ubuntu-22.04")
        assert result == "ubuntu2204.exe"

    def test_get_executable_name_ubuntu_2004(self):
        """Test executable name for Ubuntu 20.04."""
        result = self.ops.get_executable_name("Ubuntu-20.04")
        assert result == "ubuntu2004.exe"

    def test_get_executable_name_ubuntu_1804(self):
        """Test executable name for Ubuntu 18.04."""
        result = self.ops.get_executable_name("ubuntu-18.04")
        assert result == "ubuntu1804.exe"

    def test_get_executable_name_ubuntu_generic(self):
        """Test executable name for generic Ubuntu."""
        result = self.ops.get_executable_name("Ubuntu")
        assert result == "ubuntu.exe"

    def test_get_executable_name_debian(self):
        """Test executable name for Debian."""
        result = self.ops.get_executable_name("Debian")
        assert result == "debian.exe"

    def test_get_executable_name_kali(self):
        """Test executable name for Kali Linux."""
        result = self.ops.get_executable_name("kali-linux")
        assert result == "kali.exe"

    def test_get_executable_name_opensuse_tumbleweed(self):
        """Test executable name for openSUSE Tumbleweed."""
        result = self.ops.get_executable_name("openSUSE-Tumbleweed")
        assert result == "opensuse-tumbleweed.exe"

    def test_get_executable_name_opensuse_leap(self):
        """Test executable name for openSUSE Leap 15."""
        result = self.ops.get_executable_name("openSUSE-Leap-15")
        assert result == "opensuse-leap-15.exe"

    def test_get_executable_name_sles(self):
        """Test executable name for SLES 15."""
        result = self.ops.get_executable_name("SLES-15")
        assert result == "sles-15.exe"

    def test_get_executable_name_fedora(self):
        """Test executable name for Fedora."""
        result = self.ops.get_executable_name("Fedora")
        assert result == "fedora.exe"

    def test_get_executable_name_fedora_dynamic(self):
        """Test executable name for FedoraLinux-43 (dynamic name)."""
        result = self.ops.get_executable_name("FedoraLinux-43")
        assert result == "fedora.exe"

    def test_get_executable_name_almalinux(self):
        """Test executable name for AlmaLinux 9."""
        result = self.ops.get_executable_name("almalinux-9")
        assert result == "almalinux-9.exe"

    def test_get_executable_name_rockylinux(self):
        """Test executable name for Rocky Linux 9."""
        result = self.ops.get_executable_name("rockylinux-9")
        assert result == "rockylinux-9.exe"

    def test_get_executable_name_oraclelinux(self):
        """Test executable name for Oracle Linux 9."""
        result = self.ops.get_executable_name("oraclelinux-9")
        assert result == "oraclelinux-9.exe"

    def test_get_executable_name_unknown(self):
        """Test executable name for unknown distribution."""
        result = self.ops.get_executable_name("UnknownDistro")
        assert result is None


class TestConfigureDefaultUser:
    """Test cases for configure_default_user method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    @pytest.mark.asyncio
    async def test_configure_default_user_with_exe_success(self):
        """Test configure default user with distribution executable success."""
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch("shutil.which", return_value="/usr/bin/ubuntu2404.exe"):
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_proc,
            ):
                result = await self.ops.configure_default_user(
                    "Ubuntu-24.04", "ubuntu2404.exe", "testuser"
                )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_configure_default_user_with_exe_failure(self):
        """Test configure default user with distribution executable failure."""
        mock_proc = Mock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch("shutil.which", return_value="/usr/bin/ubuntu2404.exe"):
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_proc,
            ):
                # When exe command fails, it falls through to fallback
                result = await self.ops.configure_default_user(
                    "Ubuntu-24.04", "ubuntu2404.exe", "testuser"
                )

        # Fallback path returns success for non-root users
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_configure_default_user_with_exe_timeout(self):
        """Test configure default user with timeout."""
        mock_proc = Mock()
        mock_proc.returncode = None
        mock_proc.kill = Mock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch("shutil.which", return_value="/usr/bin/ubuntu2404.exe"):
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_proc,
            ):
                result = await self.ops.configure_default_user(
                    "Ubuntu-24.04", "ubuntu2404.exe", "testuser"
                )

        assert result["success"] is False
        assert "timed out" in result["error"]
        mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_configure_default_user_no_exe_path(self):
        """Test configure default user when exe not found in PATH."""
        with patch("shutil.which", return_value=None):
            result = await self.ops.configure_default_user(
                "Ubuntu-24.04", "ubuntu2404.exe", "testuser"
            )

        # Fallback path returns success for non-root users
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_configure_default_user_no_exe_name(self):
        """Test configure default user with no exe name provided."""
        result = await self.ops.configure_default_user("Ubuntu-24.04", None, "testuser")

        # Fallback path returns success for non-root users
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_configure_default_user_root(self):
        """Test configure default user for root user."""
        result = await self.ops.configure_default_user("Ubuntu-24.04", None, "root")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_configure_default_user_exception(self):
        """Test configure default user with exception."""
        with patch("shutil.which", side_effect=Exception("Test error")):
            result = await self.ops.configure_default_user(
                "Ubuntu-24.04", "ubuntu2404.exe", "testuser"
            )

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestRunWslCommand:
    """Test cases for _run_wsl_command method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    @pytest.mark.asyncio
    async def test_run_wsl_command_success(self):
        """Test successful WSL command execution."""
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"command output", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=mock_proc,
        ) as mock_exec:
            result = await self.ops._run_wsl_command("Ubuntu", "echo test")

        assert result["returncode"] == 0
        assert result["stdout"] == "command output"
        assert result["stderr"] == ""

        mock_exec.assert_called_once_with(
            "wsl",
            "-d",
            "Ubuntu",
            "--",
            "sh",
            "-c",
            "echo test",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    @pytest.mark.asyncio
    async def test_run_wsl_command_failure(self):
        """Test failed WSL command execution."""
        mock_proc = Mock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"command failed"))

        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=mock_proc,
        ):
            result = await self.ops._run_wsl_command("Ubuntu", "false")

        assert result["returncode"] == 1
        assert result["stderr"] == "command failed"

    @pytest.mark.asyncio
    async def test_run_wsl_command_timeout(self):
        """Test WSL command timeout."""
        mock_proc = Mock()
        mock_proc.kill = Mock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=mock_proc,
        ):
            result = await self.ops._run_wsl_command("Ubuntu", "sleep 100", timeout=1)

        assert result["returncode"] == -1
        assert result["stderr"] == "Command timed out"
        mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_wsl_command_with_custom_timeout(self):
        """Test WSL command with custom timeout."""
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"output", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=mock_proc,
        ):
            result = await self.ops._run_wsl_command("Ubuntu", "echo test", timeout=60)

        assert result["returncode"] == 0


class TestCreateUser:
    """Test cases for create_user method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    @pytest.mark.asyncio
    async def test_create_user_success(self):
        """Test successful user creation."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            # All commands succeed
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            result = await self.ops.create_user("Ubuntu", "testuser", "$6$salt$hash")

        assert result["success"] is True
        # Verify useradd, chpasswd, and usermod were called
        assert mock_run.call_count >= 3

    @pytest.mark.asyncio
    async def test_create_user_useradd_fails(self):
        """Test user creation when useradd fails."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {
                "returncode": 1,
                "stdout": "",
                "stderr": "useradd failed",
            }

            result = await self.ops.create_user("Ubuntu", "testuser", "$6$salt$hash")

        assert result["success"] is False
        assert "Failed to create user" in result["error"]

    @pytest.mark.asyncio
    async def test_create_user_already_exists(self):
        """Test user creation when user already exists."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            # First call (useradd) returns "already exists" error
            # Subsequent calls succeed
            mock_run.side_effect = [
                {"returncode": 1, "stdout": "", "stderr": "user already exists"},
                {"returncode": 0, "stdout": "", "stderr": ""},  # chpasswd
                {"returncode": 0, "stdout": "", "stderr": ""},  # usermod sudo
            ]

            result = await self.ops.create_user("Ubuntu", "testuser", "$6$salt$hash")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_user_chpasswd_fails(self):
        """Test user creation when chpasswd fails."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.side_effect = [
                {"returncode": 0, "stdout": "", "stderr": ""},  # useradd
                {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "chpasswd failed",
                },  # chpasswd
            ]

            result = await self.ops.create_user("Ubuntu", "testuser", "$6$salt$hash")

        assert result["success"] is False
        assert "Failed to set password" in result["error"]

    @pytest.mark.asyncio
    async def test_create_user_sudo_group_fallback(self):
        """Test user creation with fallback from sudo to wheel group."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.side_effect = [
                {"returncode": 0, "stdout": "", "stderr": ""},  # useradd
                {"returncode": 0, "stdout": "", "stderr": ""},  # chpasswd
                {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "sudo group not found",
                },  # usermod sudo
                {"returncode": 0, "stdout": "", "stderr": ""},  # usermod wheel
            ]

            result = await self.ops.create_user("Ubuntu", "testuser", "$6$salt$hash")

        assert result["success"] is True
        assert mock_run.call_count == 4

    @pytest.mark.asyncio
    async def test_create_user_exception(self):
        """Test user creation with exception."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            side_effect=Exception("Test error"),
        ):
            result = await self.ops.create_user("Ubuntu", "testuser", "$6$salt$hash")

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestEnableSystemd:
    """Test cases for enable_systemd method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    @pytest.mark.asyncio
    async def test_enable_systemd_success(self):
        """Test successful systemd enablement."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            result = await self.ops.enable_systemd("Ubuntu")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_systemd_failure(self):
        """Test systemd enablement failure."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {
                "returncode": 1,
                "stdout": "",
                "stderr": "failed to write",
            }

            result = await self.ops.enable_systemd("Ubuntu")

        assert result["success"] is False
        assert "Failed to enable systemd" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_systemd_exception(self):
        """Test systemd enablement with exception."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            side_effect=Exception("Test error"),
        ):
            result = await self.ops.enable_systemd("Ubuntu")

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestSetHostname:
    """Test cases for set_hostname method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    @pytest.mark.asyncio
    async def test_set_hostname_success(self):
        """Test successful hostname setting."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            result = await self.ops.set_hostname("Ubuntu", "myhost.example.com")

        assert result["success"] is True
        # Verify multiple commands were run
        assert mock_run.call_count >= 2

    @pytest.mark.asyncio
    async def test_set_hostname_short_name(self):
        """Test hostname setting with short name (no FQDN)."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            result = await self.ops.set_hostname("Ubuntu", "myhost")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_set_hostname_etc_hostname_fails(self):
        """Test hostname setting when /etc/hostname write fails."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {
                "returncode": 1,
                "stdout": "",
                "stderr": "permission denied",
            }

            result = await self.ops.set_hostname("Ubuntu", "myhost")

        assert result["success"] is False
        assert "Failed to set hostname" in result["error"]

    @pytest.mark.asyncio
    async def test_set_hostname_hosts_fails_but_continues(self):
        """Test hostname setting when /etc/hosts write fails but continues."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.side_effect = [
                {"returncode": 0, "stdout": "", "stderr": ""},  # /etc/hostname
                {"returncode": 1, "stdout": "", "stderr": "error"},  # /etc/hosts
                {"returncode": 0, "stdout": "", "stderr": ""},  # wsl.conf
            ]

            result = await self.ops.set_hostname("Ubuntu", "myhost.example.com")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_set_hostname_wslconf_fails_but_continues(self):
        """Test hostname setting when wsl.conf write fails but continues."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.side_effect = [
                {"returncode": 0, "stdout": "", "stderr": ""},  # /etc/hostname
                {"returncode": 0, "stdout": "", "stderr": ""},  # /etc/hosts
                {"returncode": 1, "stdout": "", "stderr": "error"},  # wsl.conf
            ]

            result = await self.ops.set_hostname("Ubuntu", "myhost")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_set_hostname_exception(self):
        """Test hostname setting with exception."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            side_effect=Exception("Test error"),
        ):
            result = await self.ops.set_hostname("Ubuntu", "myhost")

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestRestartInstance:
    """Test cases for restart_instance method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock(return_value="decoded output")
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    @pytest.mark.asyncio
    async def test_restart_instance_success(self):
        """Test successful instance restart."""
        mock_term_proc = Mock()
        mock_term_proc.returncode = 0
        mock_term_proc.communicate = AsyncMock(return_value=(b"", b""))

        mock_start_proc = Mock()
        mock_start_proc.returncode = 0
        mock_start_proc.communicate = AsyncMock(return_value=(b"Started", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            side_effect=[mock_term_proc, mock_start_proc],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await self.ops.restart_instance("Ubuntu")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_instance_terminate_non_zero(self):
        """Test instance restart when terminate returns non-zero."""
        mock_term_proc = Mock()
        mock_term_proc.returncode = 1
        mock_term_proc.communicate = AsyncMock(return_value=(b"error", b"error"))

        mock_start_proc = Mock()
        mock_start_proc.returncode = 0
        mock_start_proc.communicate = AsyncMock(return_value=(b"Started", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            side_effect=[mock_term_proc, mock_start_proc],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await self.ops.restart_instance("Ubuntu")

        # Should still succeed because start succeeded
        assert result["success"] is True
        self.mock_decode_func.assert_called()

    @pytest.mark.asyncio
    async def test_restart_instance_terminate_timeout(self):
        """Test instance restart when terminate times out."""
        mock_term_proc = Mock()
        mock_term_proc.returncode = 0
        mock_term_proc.kill = Mock()
        mock_term_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        mock_start_proc = Mock()
        mock_start_proc.returncode = 0
        mock_start_proc.communicate = AsyncMock(return_value=(b"Started", b""))

        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            side_effect=[mock_term_proc, mock_start_proc],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await self.ops.restart_instance("Ubuntu")

        # Should still continue after terminate timeout
        assert result["success"] is True
        mock_term_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_instance_start_fails(self):
        """Test instance restart when start fails."""
        mock_term_proc = Mock()
        mock_term_proc.returncode = 0
        mock_term_proc.communicate = AsyncMock(return_value=(b"", b""))

        mock_start_proc = Mock()
        mock_start_proc.returncode = 1
        mock_start_proc.communicate = AsyncMock(return_value=(b"", b"start failed"))

        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            side_effect=[mock_term_proc, mock_start_proc],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await self.ops.restart_instance("Ubuntu")

        assert result["success"] is False
        assert "Failed to restart WSL instance" in result["error"]

    @pytest.mark.asyncio
    async def test_restart_instance_start_timeout(self):
        """Test instance restart when start times out."""
        mock_term_proc = Mock()
        mock_term_proc.returncode = 0
        mock_term_proc.communicate = AsyncMock(return_value=(b"", b""))

        mock_start_proc = Mock()
        mock_start_proc.kill = Mock()
        mock_start_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            side_effect=[mock_term_proc, mock_start_proc],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await self.ops.restart_instance("Ubuntu")

        assert result["success"] is False
        assert "timed out" in result["error"]
        mock_start_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_instance_exception(self):
        """Test instance restart with exception."""
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("Test error"),
        ):
            result = await self.ops.restart_instance("Ubuntu")

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestInstallAgent:
    """Test cases for install_agent method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    @pytest.mark.asyncio
    async def test_install_agent_success(self):
        """Test successful agent installation."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            commands = ["apt update", "apt install -y sysmanage-agent"]
            result = await self.ops.install_agent("Ubuntu", commands)

        assert result["success"] is True
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_install_agent_with_failures(self):
        """Test agent installation with some command failures."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            # First command fails, second succeeds
            mock_run.side_effect = [
                {"returncode": 1, "stdout": "", "stderr": "apt update failed"},
                {"returncode": 0, "stdout": "", "stderr": ""},
            ]

            commands = ["apt update", "apt install -y sysmanage-agent"]
            result = await self.ops.install_agent("Ubuntu", commands)

        # Still returns success (continues despite failures)
        assert result["success"] is True
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_install_agent_empty_commands(self):
        """Test agent installation with empty command list."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            result = await self.ops.install_agent("Ubuntu", [])

        assert result["success"] is True
        mock_run.assert_not_called()

    @pytest.mark.asyncio
    async def test_install_agent_exception(self):
        """Test agent installation with exception."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            side_effect=Exception("Test error"),
        ):
            commands = ["apt update"]
            result = await self.ops.install_agent("Ubuntu", commands)

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestGetFqdnHostname:
    """Test cases for get_fqdn_hostname method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    def test_get_fqdn_hostname_already_fqdn(self):
        """Test hostname that already has a domain."""
        result = self.ops.get_fqdn_hostname("myhost.example.com", "server.example.com")
        assert result == "myhost.example.com"

    def test_get_fqdn_hostname_derives_domain(self):
        """Test hostname derivation from server URL."""
        result = self.ops.get_fqdn_hostname("myhost", "server.example.com")
        assert result == "myhost.example.com"

    def test_get_fqdn_hostname_server_without_domain(self):
        """Test when server URL has no domain to extract."""
        result = self.ops.get_fqdn_hostname("myhost", "localhost")
        assert result == "myhost"

    def test_get_fqdn_hostname_empty_server(self):
        """Test with empty server URL."""
        result = self.ops.get_fqdn_hostname("myhost", "")
        assert result == "myhost"


class TestGetAllowedShellsForDistribution:
    """Test cases for _get_allowed_shells_for_distribution method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    def test_get_allowed_shells_ubuntu(self):
        """Test allowed shells for Ubuntu."""
        result = self.ops._get_allowed_shells_for_distribution("Ubuntu-24.04")
        assert "bash" in result
        assert "sh" in result
        assert "dash" in result

    def test_get_allowed_shells_debian(self):
        """Test allowed shells for Debian."""
        result = self.ops._get_allowed_shells_for_distribution("Debian")
        assert "bash" in result
        assert "sh" in result
        assert "dash" in result

    def test_get_allowed_shells_fedora(self):
        """Test allowed shells for Fedora."""
        result = self.ops._get_allowed_shells_for_distribution("FedoraLinux-43")
        assert "bash" in result
        assert "sh" in result
        assert "zsh" in result

    def test_get_allowed_shells_centos(self):
        """Test allowed shells for CentOS."""
        result = self.ops._get_allowed_shells_for_distribution("CentOS-8")
        assert "bash" in result
        assert "sh" in result
        assert "zsh" in result

    def test_get_allowed_shells_rhel(self):
        """Test allowed shells for RHEL."""
        result = self.ops._get_allowed_shells_for_distribution("RHEL-9")
        assert "bash" in result
        assert "sh" in result
        assert "zsh" in result

    def test_get_allowed_shells_opensuse(self):
        """Test allowed shells for openSUSE."""
        result = self.ops._get_allowed_shells_for_distribution("openSUSE-Tumbleweed")
        assert "bash" in result
        assert "sh" in result
        assert "zsh" in result

    def test_get_allowed_shells_suse(self):
        """Test allowed shells for SUSE."""
        result = self.ops._get_allowed_shells_for_distribution("SUSE-15")
        assert "bash" in result
        assert "sh" in result
        assert "zsh" in result

    def test_get_allowed_shells_alpine(self):
        """Test allowed shells for Alpine."""
        result = self.ops._get_allowed_shells_for_distribution("Alpine")
        assert "bash" in result
        assert "sh" in result
        assert "ash" in result

    def test_get_allowed_shells_unknown(self):
        """Test allowed shells for unknown distribution."""
        result = self.ops._get_allowed_shells_for_distribution("UnknownDistro")
        assert "bash" in result
        assert "sh" in result
        assert len(result) == 2


class TestConfigureAgent:
    """Test cases for configure_agent method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    @pytest.mark.asyncio
    async def test_configure_agent_success(self):
        """Test successful agent configuration."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            result = await self.ops.configure_agent(
                "Ubuntu",
                "server.example.com",
                "myhost.example.com",
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_configure_agent_derives_fqdn(self):
        """Test agent configuration with FQDN derivation."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            result = await self.ops.configure_agent(
                "Ubuntu",
                "server.example.com",
                "myhost",  # Short hostname
            )

        assert result["success"] is True
        # Check that command was called with config content
        call_args = mock_run.call_args[0]
        assert "myhost.example.com" in call_args[1]

    @pytest.mark.asyncio
    async def test_configure_agent_with_auto_approve_token(self):
        """Test agent configuration with auto-approve token."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            result = await self.ops.configure_agent(
                "Ubuntu",
                "server.example.com",
                "myhost.example.com",
                auto_approve_token="test-token-123",
            )

        assert result["success"] is True
        call_args = mock_run.call_args[0]
        assert "test-token-123" in call_args[1]

    @pytest.mark.asyncio
    async def test_configure_agent_custom_port(self):
        """Test agent configuration with custom port."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            result = await self.ops.configure_agent(
                "Ubuntu",
                "server.example.com",
                "myhost.example.com",
                server_port=9443,
            )

        assert result["success"] is True
        call_args = mock_run.call_args[0]
        assert "9443" in call_args[1]

    @pytest.mark.asyncio
    async def test_configure_agent_no_https(self):
        """Test agent configuration without HTTPS."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            result = await self.ops.configure_agent(
                "Ubuntu",
                "server.example.com",
                "myhost.example.com",
                use_https=False,
            )

        assert result["success"] is True
        call_args = mock_run.call_args[0]
        assert "use_https: false" in call_args[1]

    @pytest.mark.asyncio
    async def test_configure_agent_write_fails(self):
        """Test agent configuration when config write fails."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {
                "returncode": 1,
                "stdout": "",
                "stderr": "permission denied",
            }

            result = await self.ops.configure_agent(
                "Ubuntu",
                "server.example.com",
                "myhost.example.com",
            )

        assert result["success"] is False
        assert "Failed to write agent config" in result["error"]

    @pytest.mark.asyncio
    async def test_configure_agent_exception(self):
        """Test agent configuration with exception."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            side_effect=Exception("Test error"),
        ):
            result = await self.ops.configure_agent(
                "Ubuntu",
                "server.example.com",
                "myhost.example.com",
            )

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestStartAgentService:
    """Test cases for start_agent_service method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    @pytest.mark.asyncio
    async def test_start_agent_service_success(self):
        """Test successful agent service start."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {"returncode": 0, "stdout": "", "stderr": ""}

            result = await self.ops.start_agent_service("Ubuntu")

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_start_agent_service_failure(self):
        """Test agent service start failure."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            new_callable=AsyncMock,
        ) as mock_run:
            mock_run.return_value = {
                "returncode": 1,
                "stdout": "",
                "stderr": "service failed",
            }

            result = await self.ops.start_agent_service("Ubuntu")

        # Returns success even on failure (logs warning)
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_start_agent_service_exception(self):
        """Test agent service start with exception."""
        with patch.object(
            self.ops,
            "_run_wsl_command",
            side_effect=Exception("Test error"),
        ):
            result = await self.ops.start_agent_service("Ubuntu")

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestGetWindowsUserProfiles:
    """Test cases for _get_windows_user_profiles method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    def test_get_windows_user_profiles_no_users_dir(self):
        """Test when C:/Users doesn't exist."""
        with patch.object(Path, "exists", return_value=False):
            result = self.ops._get_windows_user_profiles()
        assert not result

    def test_get_windows_user_profiles_with_valid_profiles(self, tmp_path):
        """Test finding valid user profiles."""
        # Create mock user profiles
        user1 = tmp_path / "user1"
        user1.mkdir()
        (user1 / "Desktop").mkdir()

        user2 = tmp_path / "user2"
        user2.mkdir()
        (user2 / "Documents").mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_setup.Path"
        ) as mock_path_class:
            mock_users_dir = MagicMock()
            mock_users_dir.exists.return_value = True
            mock_users_dir.iterdir.return_value = [user1, user2]
            mock_path_class.return_value = mock_users_dir

            result = self.ops._get_windows_user_profiles()

        assert len(result) == 2
        assert user1 in result
        assert user2 in result

    def test_get_windows_user_profiles_skips_system_profiles(self, tmp_path):
        """Test skipping system profiles."""
        # Create mock profiles (some system, some user)
        default_user = tmp_path / "Default"
        default_user.mkdir()
        (default_user / "Desktop").mkdir()

        public = tmp_path / "Public"
        public.mkdir()
        (public / "Desktop").mkdir()

        real_user = tmp_path / "john"
        real_user.mkdir()
        (real_user / "Desktop").mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_setup.Path"
        ) as mock_path_class:
            mock_users_dir = MagicMock()
            mock_users_dir.exists.return_value = True
            mock_users_dir.iterdir.return_value = [default_user, public, real_user]
            mock_path_class.return_value = mock_users_dir

            result = self.ops._get_windows_user_profiles()

        assert len(result) == 1
        assert real_user in result

    def test_get_windows_user_profiles_skips_defaultapp(self, tmp_path):
        """Test skipping DefaultAppPool profiles."""
        default_app = tmp_path / "DefaultAppPool"
        default_app.mkdir()
        (default_app / "Desktop").mkdir()

        real_user = tmp_path / "jane"
        real_user.mkdir()
        (real_user / "Documents").mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_setup.Path"
        ) as mock_path_class:
            mock_users_dir = MagicMock()
            mock_users_dir.exists.return_value = True
            mock_users_dir.iterdir.return_value = [default_app, real_user]
            mock_path_class.return_value = mock_users_dir

            result = self.ops._get_windows_user_profiles()

        assert len(result) == 1
        assert real_user in result

    def test_get_windows_user_profiles_permission_error(self):
        """Test handling permission error."""
        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_setup.Path"
        ) as mock_path_class:
            mock_users_dir = MagicMock()
            mock_users_dir.exists.return_value = True
            mock_users_dir.iterdir.side_effect = PermissionError()
            mock_path_class.return_value = mock_users_dir

            result = self.ops._get_windows_user_profiles()

        assert not result

    def test_get_windows_user_profiles_other_error(self):
        """Test handling other errors."""
        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_setup.Path"
        ) as mock_path_class:
            mock_users_dir = MagicMock()
            mock_users_dir.exists.return_value = True
            mock_users_dir.iterdir.side_effect = OSError("Test error")
            mock_path_class.return_value = mock_users_dir

            result = self.ops._get_windows_user_profiles()

        assert not result

    def test_get_windows_user_profiles_skips_files(self, tmp_path):
        """Test skipping files (not directories) in users dir."""
        # Create a file instead of a directory
        file_in_users = tmp_path / "some_file.txt"
        file_in_users.touch()

        # Create a real user directory
        real_user = tmp_path / "realuser"
        real_user.mkdir()
        (real_user / "Desktop").mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_setup.Path"
        ) as mock_path_class:
            mock_users_dir = MagicMock()
            mock_users_dir.exists.return_value = True
            mock_users_dir.iterdir.return_value = [file_in_users, real_user]
            mock_path_class.return_value = mock_users_dir

            result = self.ops._get_windows_user_profiles()

        # Only the directory should be included
        assert len(result) == 1
        assert real_user in result

    def test_get_windows_user_profiles_skips_defaultapppool_variants(self, tmp_path):
        """Test skipping DefaultAppPool and similar names."""
        # Create DefaultAppPool variant
        default_app_custom = tmp_path / "DefaultAppCustom"
        default_app_custom.mkdir()
        (default_app_custom / "Desktop").mkdir()

        real_user = tmp_path / "normaluser"
        real_user.mkdir()
        (real_user / "Desktop").mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_setup.Path"
        ) as mock_path_class:
            mock_users_dir = MagicMock()
            mock_users_dir.exists.return_value = True
            mock_users_dir.iterdir.return_value = [default_app_custom, real_user]
            mock_path_class.return_value = mock_users_dir

            result = self.ops._get_windows_user_profiles()

        # Only real_user should be included
        assert len(result) == 1
        assert real_user in result

    def test_get_windows_user_profiles_skips_no_desktop_or_documents(self, tmp_path):
        """Test skipping directories without Desktop or Documents."""
        # Create directory without Desktop or Documents
        empty_user = tmp_path / "emptyuser"
        empty_user.mkdir()

        real_user = tmp_path / "normaluser"
        real_user.mkdir()
        (real_user / "Desktop").mkdir()

        with patch(
            "src.sysmanage_agent.operations.child_host_wsl_setup.Path"
        ) as mock_path_class:
            mock_users_dir = MagicMock()
            mock_users_dir.exists.return_value = True
            mock_users_dir.iterdir.return_value = [empty_user, real_user]
            mock_path_class.return_value = mock_users_dir

            result = self.ops._get_windows_user_profiles()

        # Only real_user should be included
        assert len(result) == 1
        assert real_user in result


class TestConfigureWslconfig:
    """Test cases for configure_wslconfig method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    def test_configure_wslconfig_no_profiles(self):
        """Test when no user profiles found."""
        with patch.object(
            self.ops,
            "_get_windows_user_profiles",
            return_value=[],
        ):
            result = self.ops.configure_wslconfig()

        assert result["success"] is False
        assert "No user profiles found" in result["error"]

    def test_configure_wslconfig_success(self, tmp_path):
        """Test successful wslconfig configuration."""
        profile1 = tmp_path / "user1"
        profile1.mkdir()

        with patch.object(
            self.ops,
            "_get_windows_user_profiles",
            return_value=[profile1],
        ):
            with patch.object(
                self.ops,
                "_update_wslconfig",
                return_value={"success": True},
            ) as mock_update:
                result = self.ops.configure_wslconfig()

        assert result["success"] is True
        assert result["profiles_configured"] == 1
        mock_update.assert_called_once_with(profile1 / ".wslconfig")

    def test_configure_wslconfig_already_configured(self, tmp_path):
        """Test wslconfig already configured (success=True case)."""
        profile1 = tmp_path / "user1"
        profile1.mkdir()

        with patch.object(
            self.ops,
            "_get_windows_user_profiles",
            return_value=[profile1],
        ):
            with patch.object(
                self.ops,
                "_update_wslconfig",
                return_value={"success": True, "already_configured": True},
            ):
                result = self.ops.configure_wslconfig()

        assert result["success"] is True
        assert result["profiles_configured"] == 1

    def test_configure_wslconfig_already_configured_no_success_key(self, tmp_path):
        """Test wslconfig already configured when success is False but already_configured is True."""
        profile1 = tmp_path / "user1"
        profile1.mkdir()

        with patch.object(
            self.ops,
            "_get_windows_user_profiles",
            return_value=[profile1],
        ):
            with patch.object(
                self.ops,
                "_update_wslconfig",
                return_value={"success": False, "already_configured": True},
            ):
                result = self.ops.configure_wslconfig()

        assert result["success"] is True
        assert result["profiles_configured"] == 1

    def test_configure_wslconfig_partial_failure(self, tmp_path):
        """Test wslconfig with partial failure."""
        profile1 = tmp_path / "user1"
        profile1.mkdir()
        profile2 = tmp_path / "user2"
        profile2.mkdir()

        with patch.object(
            self.ops,
            "_get_windows_user_profiles",
            return_value=[profile1, profile2],
        ):
            with patch.object(
                self.ops,
                "_update_wslconfig",
                side_effect=[
                    {"success": True},
                    {"success": False, "error": "permission denied"},
                ],
            ):
                result = self.ops.configure_wslconfig()

        assert result["success"] is True
        assert result["profiles_configured"] == 1
        assert len(result["errors"]) == 1

    def test_configure_wslconfig_all_fail(self, tmp_path):
        """Test wslconfig when all profiles fail."""
        profile1 = tmp_path / "user1"
        profile1.mkdir()

        with patch.object(
            self.ops,
            "_get_windows_user_profiles",
            return_value=[profile1],
        ):
            with patch.object(
                self.ops,
                "_update_wslconfig",
                return_value={"success": False, "error": "permission denied"},
            ):
                result = self.ops.configure_wslconfig()

        assert result["success"] is False
        assert "Failed to configure any user profiles" in result["error"]

    def test_configure_wslconfig_exception_in_update(self, tmp_path):
        """Test wslconfig with exception in update."""
        profile1 = tmp_path / "user1"
        profile1.mkdir()

        with patch.object(
            self.ops,
            "_get_windows_user_profiles",
            return_value=[profile1],
        ):
            with patch.object(
                self.ops,
                "_update_wslconfig",
                side_effect=Exception("Test error"),
            ):
                result = self.ops.configure_wslconfig()

        assert result["success"] is False
        assert len(result["errors"]) == 1

    def test_configure_wslconfig_exception(self):
        """Test wslconfig with exception."""
        with patch.object(
            self.ops,
            "_get_windows_user_profiles",
            side_effect=Exception("Test error"),
        ):
            result = self.ops.configure_wslconfig()

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestUpdateWslconfig:
    """Test cases for _update_wslconfig method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = Mock()
        self.mock_decode_func = Mock()
        self.ops = WslSetupOperations(self.mock_logger, self.mock_decode_func)

    def test_update_wslconfig_creates_new(self, tmp_path):
        """Test creating new .wslconfig file."""
        wslconfig_path = tmp_path / ".wslconfig"

        result = self.ops._update_wslconfig(wslconfig_path)

        assert result["success"] is True
        assert wslconfig_path.exists()

        # Verify content
        config = configparser.ConfigParser()
        config.read(str(wslconfig_path))
        assert config.get("wsl2", "vmIdleTimeout") == "-1"

    def test_update_wslconfig_updates_existing(self, tmp_path):
        """Test updating existing .wslconfig file."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create existing config with wrong value
        config = configparser.ConfigParser()
        config.add_section("wsl2")
        config.set("wsl2", "vmIdleTimeout", "300")
        with open(wslconfig_path, "w", encoding="utf-8") as file_handle:
            config.write(file_handle)

        result = self.ops._update_wslconfig(wslconfig_path)

        assert result["success"] is True

        # Verify updated content
        config = configparser.ConfigParser()
        config.read(str(wslconfig_path))
        assert config.get("wsl2", "vmIdleTimeout") == "-1"

    def test_update_wslconfig_already_configured(self, tmp_path):
        """Test .wslconfig already has correct value."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create config with correct value
        config = configparser.ConfigParser()
        config.add_section("wsl2")
        config.set("wsl2", "vmIdleTimeout", "-1")
        with open(wslconfig_path, "w", encoding="utf-8") as file_handle:
            config.write(file_handle)

        result = self.ops._update_wslconfig(wslconfig_path)

        assert result["success"] is True
        assert result.get("already_configured") is True

    def test_update_wslconfig_malformed_config(self, tmp_path):
        """Test updating malformed .wslconfig file."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create malformed config
        with open(wslconfig_path, "w", encoding="utf-8") as file_handle:
            file_handle.write("this is not valid ini format [[\n")

        result = self.ops._update_wslconfig(wslconfig_path)

        # Should still succeed by overwriting
        assert result["success"] is True

    def test_update_wslconfig_permission_denied(self, tmp_path):
        """Test .wslconfig with permission denied."""
        wslconfig_path = tmp_path / ".wslconfig"

        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            result = self.ops._update_wslconfig(wslconfig_path)

        assert result["success"] is False
        assert "Permission denied" in result["error"]

    def test_update_wslconfig_other_exception(self, tmp_path):
        """Test .wslconfig with other exception."""
        wslconfig_path = tmp_path / ".wslconfig"

        with patch("builtins.open", side_effect=OSError("Disk error")):
            result = self.ops._update_wslconfig(wslconfig_path)

        assert result["success"] is False
        assert "Disk error" in result["error"]

    def test_update_wslconfig_no_wsl2_section(self, tmp_path):
        """Test updating .wslconfig without wsl2 section."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create config without wsl2 section
        config = configparser.ConfigParser()
        config.add_section("experimental")
        config.set("experimental", "someOption", "value")
        with open(wslconfig_path, "w", encoding="utf-8") as file_handle:
            config.write(file_handle)

        result = self.ops._update_wslconfig(wslconfig_path)

        assert result["success"] is True

        # Verify wsl2 section was added
        config = configparser.ConfigParser()
        config.read(str(wslconfig_path))
        assert config.has_section("wsl2")
        assert config.get("wsl2", "vmIdleTimeout") == "-1"
