"""
Comprehensive unit tests for WSL child host operations.

Tests cover:
- WslOperations initialization
- Input validation
- WSL checking and enabling
- Distribution installation and detection
- User setup and systemd configuration
- Agent installation and configuration
- Progress reporting
- Control operations (start, stop, restart, delete)
- Output decoding
- Error handling
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-public-methods

import asyncio
import logging
import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.child_host_wsl import WslOperations


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return logging.getLogger("test_wsl")


@pytest.fixture
def mock_virtualization_checks():
    """Create mock virtualization checks."""
    mock_checks = Mock()
    mock_checks.check_wsl_support = Mock(
        return_value={
            "available": True,
            "needs_enable": False,
        }
    )
    return mock_checks


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    mock = Mock()
    mock.send_message = AsyncMock()
    mock.create_message = Mock(return_value={"type": "test"})
    return mock


@pytest.fixture
def wsl_ops(mock_agent, logger, mock_virtualization_checks):
    """Create a WslOperations instance for testing."""
    return WslOperations(mock_agent, logger, mock_virtualization_checks)


class TestWslOperationsInit:
    """Tests for WslOperations initialization."""

    def test_init_sets_agent(self, wsl_ops, mock_agent):
        """Test that __init__ sets agent."""
        assert wsl_ops.agent == mock_agent

    def test_init_sets_logger(self, wsl_ops, logger):
        """Test that __init__ sets logger."""
        assert wsl_ops.logger == logger

    def test_init_sets_virtualization_checks(self, wsl_ops, mock_virtualization_checks):
        """Test that __init__ sets virtualization_checks."""
        assert wsl_ops.virtualization_checks == mock_virtualization_checks

    def test_init_creates_control_ops(self, wsl_ops):
        """Test that __init__ creates control operations."""
        assert wsl_ops._control_ops is not None

    def test_init_creates_setup_ops(self, wsl_ops):
        """Test that __init__ creates setup operations."""
        assert wsl_ops._setup_ops is not None


class TestGetCreationFlags:
    """Tests for _get_creationflags method."""

    def test_get_creationflags_with_create_no_window(self, wsl_ops):
        """Test getting creation flags when CREATE_NO_WINDOW is available."""
        with patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True):
            result = wsl_ops._get_creationflags()
        assert result == 0x08000000

    def test_get_creationflags_without_create_no_window(self, wsl_ops):
        """Test getting creation flags when CREATE_NO_WINDOW is not available."""
        # On Linux, CREATE_NO_WINDOW doesn't exist
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            delattr(subprocess, "CREATE_NO_WINDOW")
        result = wsl_ops._get_creationflags()
        assert result == 0


class TestValidateWslInputs:
    """Tests for _validate_wsl_inputs method."""

    def test_validate_missing_distribution(self, wsl_ops):
        """Test validation fails when distribution is missing."""
        result = wsl_ops._validate_wsl_inputs("", "hostname", "user", "hash")
        assert result["success"] is False
        assert "Distribution" in result["error"]

    def test_validate_missing_hostname(self, wsl_ops):
        """Test validation fails when hostname is missing."""
        result = wsl_ops._validate_wsl_inputs("Ubuntu", "", "user", "hash")
        assert result["success"] is False
        assert "Hostname" in result["error"]

    def test_validate_missing_username(self, wsl_ops):
        """Test validation fails when username is missing."""
        result = wsl_ops._validate_wsl_inputs("Ubuntu", "hostname", "", "hash")
        assert result["success"] is False
        assert "Username" in result["error"]

    def test_validate_missing_password_hash(self, wsl_ops):
        """Test validation fails when password_hash is missing."""
        result = wsl_ops._validate_wsl_inputs("Ubuntu", "hostname", "user", "")
        assert result["success"] is False
        assert "Password hash" in result["error"]

    def test_validate_all_valid(self, wsl_ops):
        """Test validation succeeds with all valid inputs."""
        result = wsl_ops._validate_wsl_inputs("Ubuntu", "hostname", "user", "hash")
        assert result["success"] is True


class TestCheckAndEnableWsl:
    """Tests for _check_and_enable_wsl method."""

    @pytest.mark.asyncio
    async def test_wsl_not_available(self, wsl_ops, mock_virtualization_checks):
        """Test when WSL is not available."""
        mock_virtualization_checks.check_wsl_support.return_value = {"available": False}
        result = await wsl_ops._check_and_enable_wsl()
        assert result["success"] is False
        assert "not available" in result["error"]

    @pytest.mark.asyncio
    async def test_wsl_needs_enable_success(self, wsl_ops, mock_virtualization_checks):
        """Test when WSL needs to be enabled and succeeds."""
        mock_virtualization_checks.check_wsl_support.return_value = {
            "available": True,
            "needs_enable": True,
        }
        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "reboot_required": False}
            result = await wsl_ops._check_and_enable_wsl()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_wsl_needs_enable_reboot_required(
        self, wsl_ops, mock_virtualization_checks
    ):
        """Test when WSL needs to be enabled and requires reboot."""
        mock_virtualization_checks.check_wsl_support.return_value = {
            "available": True,
            "needs_enable": True,
        }
        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "reboot_required": True}
            result = await wsl_ops._check_and_enable_wsl()

        assert result["success"] is False
        assert "reboot" in result["error"].lower()
        assert result["reboot_required"] is True

    @pytest.mark.asyncio
    async def test_wsl_needs_enable_failure(self, wsl_ops, mock_virtualization_checks):
        """Test when enabling WSL fails."""
        mock_virtualization_checks.check_wsl_support.return_value = {
            "available": True,
            "needs_enable": True,
        }
        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": False, "error": "Enable failed"}
            result = await wsl_ops._check_and_enable_wsl()

        assert result["success"] is False
        assert result["error"] == "Enable failed"

    @pytest.mark.asyncio
    async def test_wsl_already_enabled(self, wsl_ops, mock_virtualization_checks):
        """Test when WSL is already enabled."""
        mock_virtualization_checks.check_wsl_support.return_value = {
            "available": True,
            "needs_enable": False,
        }
        result = await wsl_ops._check_and_enable_wsl()
        assert result["success"] is True


class TestConfigureWslconfig:
    """Tests for _configure_wslconfig method."""

    @pytest.mark.asyncio
    async def test_configure_wslconfig_success_already_configured(self, wsl_ops):
        """Test when .wslconfig is already configured."""
        with patch.object(wsl_ops._setup_ops, "configure_wslconfig") as mock_configure:
            mock_configure.return_value = {
                "success": True,
                "already_configured": True,
                "profiles_configured": 1,
            }
            await wsl_ops._configure_wslconfig()

        mock_configure.assert_called_once()

    @pytest.mark.asyncio
    async def test_configure_wslconfig_success_needs_restart(self, wsl_ops):
        """Test when .wslconfig is configured and needs restart."""
        with patch.object(wsl_ops._setup_ops, "configure_wslconfig") as mock_configure:
            mock_configure.return_value = {
                "success": True,
                "already_configured": False,
                "profiles_configured": 2,
            }
            with patch.object(
                wsl_ops, "_restart_wsl_for_config", new_callable=AsyncMock
            ) as mock_restart:
                await wsl_ops._configure_wslconfig()

        mock_restart.assert_called_once()

    @pytest.mark.asyncio
    async def test_configure_wslconfig_failure(self, wsl_ops):
        """Test when .wslconfig configuration fails."""
        with patch.object(wsl_ops._setup_ops, "configure_wslconfig") as mock_configure:
            mock_configure.return_value = {
                "success": False,
                "error": "Permission denied",
            }
            # Should not raise, just log warning
            await wsl_ops._configure_wslconfig()


class TestRestartWslForConfig:
    """Tests for _restart_wsl_for_config method."""

    @pytest.mark.asyncio
    async def test_restart_wsl_success(self, wsl_ops):
        """Test successful WSL restart."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            await wsl_ops._restart_wsl_for_config()

    @pytest.mark.asyncio
    async def test_restart_wsl_timeout(self, wsl_ops):
        """Test WSL restart with timeout."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            # Should not raise, just log warning
            await wsl_ops._restart_wsl_for_config()

    @pytest.mark.asyncio
    async def test_restart_wsl_exception(self, wsl_ops):
        """Test WSL restart with exception."""
        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            # Should not raise, just log warning
            await wsl_ops._restart_wsl_for_config()


class TestDecodeWslOutput:
    """Tests for _decode_wsl_output method."""

    def test_decode_empty_output(self, wsl_ops):
        """Test decoding empty output."""
        result = wsl_ops._decode_wsl_output(b"", b"")
        assert result == ""

    def test_decode_utf16le_with_bom(self, wsl_ops):
        """Test decoding UTF-16LE output with BOM."""
        # UTF-16LE BOM + "Hello" encoded as UTF-16LE
        stdout = b"\xff\xfeH\x00e\x00l\x00l\x00o\x00"
        result = wsl_ops._decode_wsl_output(stdout, b"")
        assert "Hello" in result

    def test_decode_utf16le_without_bom(self, wsl_ops):
        """Test decoding UTF-16LE output without BOM."""
        # "Test" encoded as UTF-16LE without BOM
        stdout = b"T\x00e\x00s\x00t\x00"
        result = wsl_ops._decode_wsl_output(stdout, b"")
        assert "Test" in result

    def test_decode_utf8_fallback(self, wsl_ops):
        """Test decoding falls back to UTF-8."""
        stdout = b"Hello UTF-8"
        result = wsl_ops._decode_wsl_output(stdout, b"")
        assert result == "Hello UTF-8"

    def test_decode_latin1_fallback(self, wsl_ops):
        """Test decoding falls back to Latin-1 for invalid UTF-8."""
        # Invalid UTF-8 sequence
        stdout = b"\xff\xfe\xfd"
        result = wsl_ops._decode_wsl_output(stdout, b"")
        # Should not raise, should return something
        assert isinstance(result, str)

    def test_decode_combined_stdout_stderr(self, wsl_ops):
        """Test decoding combines stdout and stderr."""
        stdout = b"stdout "
        stderr = b"stderr"
        result = wsl_ops._decode_wsl_output(stdout, stderr)
        assert "stdout" in result or "stderr" in result


class TestEnableWslInternal:
    """Tests for enable_wsl_internal method."""

    @pytest.mark.asyncio
    async def test_enable_wsl_timeout(self, wsl_ops):
        """Test WSL enable with timeout."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_proc.kill = Mock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is False
        assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_wsl_reboot_required_exit_code(self, wsl_ops):
        """Test WSL enable with reboot required exit code."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 3010

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is True
        assert result["reboot_required"] is True

    @pytest.mark.asyncio
    async def test_enable_wsl_reboot_in_output(self, wsl_ops):
        """Test WSL enable with reboot indicator in output."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"Please reboot your system", b"")
        )
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch.object(
                wsl_ops, "_decode_wsl_output", return_value="please reboot your system"
            ):
                result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is True
        assert result["reboot_required"] is True

    @pytest.mark.asyncio
    async def test_enable_wsl_failure(self, wsl_ops):
        """Test WSL enable failure."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"Error message"))
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch.object(
                wsl_ops, "_decode_wsl_output", return_value="error message"
            ):
                result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_enable_wsl_success_verified(self, wsl_ops):
        """Test WSL enable success with verification."""
        mock_install_proc = Mock()
        mock_install_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_install_proc.returncode = 0

        mock_status_proc = Mock()
        mock_status_proc.communicate = AsyncMock(return_value=(b"WSL version: 2", b""))
        mock_status_proc.returncode = 0

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_install_proc, mock_status_proc],
        ):
            with patch.object(
                wsl_ops, "_decode_wsl_output", side_effect=["", "wsl version: 2"]
            ):
                result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_wsl_exception(self, wsl_ops):
        """Test WSL enable with exception."""
        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestCheckWslStatusOutput:
    """Tests for _check_wsl_status_output method."""

    def test_status_requires_bios_virtualization(self, wsl_ops):
        """Test status output requiring BIOS virtualization."""
        status_output = "please enable virtualization in bios"
        result = wsl_ops._check_wsl_status_output(status_output, b"", b"")

        assert result["success"] is False
        assert result["requires_bios_change"] is True

    def test_status_requires_additional_setup(self, wsl_ops):
        """Test status output requiring additional setup."""
        status_output = "please enable virtual machine platform"
        result = wsl_ops._check_wsl_status_output(status_output, b"", b"")

        assert result["success"] is True
        assert result["reboot_required"] is True

    def test_status_not_supported(self, wsl_ops):
        """Test status output when not supported."""
        status_output = "wsl 2 is not supported on this version"
        result = wsl_ops._check_wsl_status_output(status_output, b"", b"")

        assert result["success"] is True
        assert result["reboot_required"] is True

    def test_status_success(self, wsl_ops):
        """Test successful status check."""
        status_output = "default distribution: ubuntu"
        result = wsl_ops._check_wsl_status_output(status_output, b"", b"")

        assert result["success"] is True
        assert result["reboot_required"] is False


class TestCheckDistributionExists:
    """Tests for _check_distribution_exists method."""

    def test_distribution_exists(self, wsl_ops):
        """Test when distribution exists."""
        mock_helper = Mock()
        mock_helper.list_wsl_instances.return_value = [
            {"child_name": "Ubuntu-24.04"},
            {"child_name": "Debian"},
        ]

        result = wsl_ops._check_distribution_exists("Ubuntu-24.04", mock_helper)
        assert result is True

    def test_distribution_exists_case_insensitive(self, wsl_ops):
        """Test case-insensitive distribution check."""
        mock_helper = Mock()
        mock_helper.list_wsl_instances.return_value = [
            {"child_name": "ubuntu-24.04"},
        ]

        result = wsl_ops._check_distribution_exists("Ubuntu-24.04", mock_helper)
        assert result is True

    def test_distribution_not_exists(self, wsl_ops):
        """Test when distribution does not exist."""
        mock_helper = Mock()
        mock_helper.list_wsl_instances.return_value = [
            {"child_name": "Debian"},
        ]

        result = wsl_ops._check_distribution_exists("Ubuntu-24.04", mock_helper)
        assert result is False

    def test_distribution_check_exception(self, wsl_ops):
        """Test distribution check with exception."""
        mock_helper = Mock()
        mock_helper.list_wsl_instances.side_effect = Exception("Error")

        result = wsl_ops._check_distribution_exists("Ubuntu-24.04", mock_helper)
        assert result is False


class TestInstallDistribution:
    """Tests for _install_distribution method."""

    @pytest.mark.asyncio
    async def test_install_distribution_success(self, wsl_ops):
        """Test successful distribution installation."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch.object(
                wsl_ops, "_detect_actual_wsl_name", return_value="Ubuntu-24.04"
            ):
                result = await wsl_ops._install_distribution("Ubuntu-24.04")

        assert result["success"] is True
        assert result["actual_name"] == "Ubuntu-24.04"

    @pytest.mark.asyncio
    async def test_install_distribution_timeout(self, wsl_ops):
        """Test distribution installation timeout."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_proc.kill = Mock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await wsl_ops._install_distribution("Ubuntu-24.04")

        assert result["success"] is False
        assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_install_distribution_failure(self, wsl_ops):
        """Test failed distribution installation."""
        mock_proc = Mock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"Installation failed"))
        mock_proc.returncode = 1

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with patch.object(
                wsl_ops, "_decode_wsl_output", return_value="Installation failed"
            ):
                result = await wsl_ops._install_distribution("Ubuntu-24.04")

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_install_distribution_exception(self, wsl_ops):
        """Test distribution installation with exception."""
        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await wsl_ops._install_distribution("Ubuntu-24.04")

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestDetectActualWslName:
    """Tests for _detect_actual_wsl_name method."""

    def test_detect_exact_match(self, wsl_ops):
        """Test detecting exact name match."""
        wsl_output = """  NAME            STATE           VERSION
* Ubuntu-24.04    Running         2
  Debian          Stopped         2
"""
        mock_result = Mock()
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(wsl_ops, "_decode_wsl_output", return_value=wsl_output):
                result = wsl_ops._detect_actual_wsl_name("Ubuntu-24.04")

        assert result == "Ubuntu-24.04"

    def test_detect_partial_match(self, wsl_ops):
        """Test detecting partial name match (e.g., Fedora -> FedoraLinux-43)."""
        wsl_output = """  NAME              STATE           VERSION
  FedoraLinux-43    Running         2
"""
        mock_result = Mock()
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(wsl_ops, "_decode_wsl_output", return_value=wsl_output):
                result = wsl_ops._detect_actual_wsl_name("Fedora")

        assert result == "FedoraLinux-43"

    def test_detect_no_output(self, wsl_ops):
        """Test detection with no output."""
        mock_result = Mock()
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(wsl_ops, "_decode_wsl_output", return_value=""):
                result = wsl_ops._detect_actual_wsl_name("Ubuntu-24.04")

        assert result == "Ubuntu-24.04"

    def test_detect_exception(self, wsl_ops):
        """Test detection with exception."""
        with patch("subprocess.run", side_effect=Exception("Error")):
            result = wsl_ops._detect_actual_wsl_name("Ubuntu-24.04")

        assert result == "Ubuntu-24.04"


class TestParseWslListOutput:
    """Tests for _parse_wsl_list_output method."""

    def test_parse_single_line(self, wsl_ops):
        """Test parsing single line output."""
        output = "  NAME           STATE"
        result = wsl_ops._parse_wsl_list_output(output, "Ubuntu")
        assert result == "Ubuntu"

    def test_parse_with_asterisk_default(self, wsl_ops):
        """Test parsing output with asterisk for default."""
        output = """  NAME           STATE
* Ubuntu         Running
"""
        result = wsl_ops._parse_wsl_list_output(output, "Ubuntu")
        assert result == "Ubuntu"

    def test_parse_no_match(self, wsl_ops):
        """Test parsing when no distribution matches."""
        output = """  NAME           STATE
  Debian         Running
"""
        result = wsl_ops._parse_wsl_list_output(output, "Ubuntu")
        assert result == "Ubuntu"


class TestExtractDistroNameFromLine:
    """Tests for _extract_distro_name_from_line method."""

    def test_extract_normal_line(self, wsl_ops):
        """Test extracting name from normal line."""
        line = "  Ubuntu-24.04    Running    2"
        result = wsl_ops._extract_distro_name_from_line(line)
        assert result == "Ubuntu-24.04"

    def test_extract_default_line(self, wsl_ops):
        """Test extracting name from line with default asterisk."""
        line = "* Ubuntu-24.04    Running    2"
        result = wsl_ops._extract_distro_name_from_line(line)
        assert result == "Ubuntu-24.04"

    def test_extract_empty_line(self, wsl_ops):
        """Test extracting name from empty line."""
        line = "   "
        result = wsl_ops._extract_distro_name_from_line(line)
        assert result == ""


class TestCheckDistroNameMatch:
    """Tests for _check_distro_name_match method."""

    def test_exact_match(self, wsl_ops):
        """Test exact name match."""
        result = wsl_ops._check_distro_name_match(
            "Ubuntu-24.04", "ubuntu-24.04", "Ubuntu-24.04"
        )
        assert result == "Ubuntu-24.04"

    def test_partial_match(self, wsl_ops):
        """Test partial name match."""
        result = wsl_ops._check_distro_name_match("FedoraLinux-43", "fedora", "Fedora")
        assert result == "FedoraLinux-43"

    def test_base_match(self, wsl_ops):
        """Test base name match."""
        result = wsl_ops._check_distro_name_match("fedoralinux-43", "fedora", "Fedora")
        assert result == "fedoralinux-43"

    def test_no_match(self, wsl_ops):
        """Test no name match."""
        result = wsl_ops._check_distro_name_match("Debian", "ubuntu", "Ubuntu")
        assert result == ""


class TestSendProgress:
    """Tests for _send_progress method."""

    @pytest.mark.asyncio
    async def test_send_progress_success(self, wsl_ops, mock_agent):
        """Test successful progress sending."""
        await wsl_ops._send_progress("installing", "Installing...")

        mock_agent.create_message.assert_called_once_with(
            "child_host_creation_progress",
            {"step": "installing", "message": "Installing..."},
        )
        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_progress_no_send_method(self, wsl_ops):
        """Test progress sending when agent has no send_message."""
        wsl_ops.agent = Mock(spec=[])
        # Should not raise
        await wsl_ops._send_progress("test", "Test")

    @pytest.mark.asyncio
    async def test_send_progress_exception(self, wsl_ops, mock_agent):
        """Test progress sending with exception."""
        mock_agent.send_message.side_effect = Exception("Send failed")
        # Should not raise
        await wsl_ops._send_progress("test", "Test")


class TestSetupWslUserAndSystemd:
    """Tests for _setup_wsl_user_and_systemd method."""

    @pytest.mark.asyncio
    async def test_setup_success(self, wsl_ops):
        """Test successful user and systemd setup."""
        with patch.object(
            wsl_ops, "_send_progress", new_callable=AsyncMock
        ) as mock_progress:
            with patch.object(
                wsl_ops._setup_ops, "configure_default_user", new_callable=AsyncMock
            ) as mock_config_user:
                mock_config_user.return_value = {"success": True}
                with patch.object(
                    wsl_ops._setup_ops, "create_user", new_callable=AsyncMock
                ) as mock_create:
                    mock_create.return_value = {"success": True}
                    with patch.object(
                        wsl_ops._setup_ops, "enable_systemd", new_callable=AsyncMock
                    ) as mock_systemd:
                        mock_systemd.return_value = {"success": True}
                        with patch.object(
                            wsl_ops._setup_ops, "set_hostname", new_callable=AsyncMock
                        ) as mock_hostname:
                            mock_hostname.return_value = {"success": True}

                            result = await wsl_ops._setup_wsl_user_and_systemd(
                                "Ubuntu-24.04",
                                "ubuntu2404.exe",
                                "testuser",
                                "$6$hash",
                                "test.example.com",
                            )

        assert result["success"] is True
        assert mock_progress.call_count >= 4

    @pytest.mark.asyncio
    async def test_setup_root_config_fails(self, wsl_ops):
        """Test when root configuration fails."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "configure_default_user", new_callable=AsyncMock
            ) as mock_config:
                mock_config.return_value = {"success": False, "error": "Failed"}

                result = await wsl_ops._setup_wsl_user_and_systemd(
                    "Ubuntu-24.04",
                    "ubuntu2404.exe",
                    "testuser",
                    "$6$hash",
                    "test.example.com",
                )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_setup_create_user_fails(self, wsl_ops):
        """Test when user creation fails."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "configure_default_user", new_callable=AsyncMock
            ) as mock_config:
                mock_config.return_value = {"success": True}
                with patch.object(
                    wsl_ops._setup_ops, "create_user", new_callable=AsyncMock
                ) as mock_create:
                    mock_create.return_value = {"success": False, "error": "Failed"}

                    result = await wsl_ops._setup_wsl_user_and_systemd(
                        "Ubuntu-24.04",
                        "ubuntu2404.exe",
                        "testuser",
                        "$6$hash",
                        "test.example.com",
                    )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_setup_hostname_failure_continues(self, wsl_ops):
        """Test that hostname failure is logged but doesn't fail the setup."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "configure_default_user", new_callable=AsyncMock
            ) as mock_config:
                mock_config.return_value = {"success": True}
                with patch.object(
                    wsl_ops._setup_ops, "create_user", new_callable=AsyncMock
                ) as mock_create:
                    mock_create.return_value = {"success": True}
                    with patch.object(
                        wsl_ops._setup_ops, "enable_systemd", new_callable=AsyncMock
                    ) as mock_systemd:
                        mock_systemd.return_value = {"success": True}
                        with patch.object(
                            wsl_ops._setup_ops, "set_hostname", new_callable=AsyncMock
                        ) as mock_hostname:
                            mock_hostname.return_value = {
                                "success": False,
                                "error": "Failed",
                            }

                            result = await wsl_ops._setup_wsl_user_and_systemd(
                                "Ubuntu-24.04",
                                "ubuntu2404.exe",
                                "testuser",
                                "$6$hash",
                                "test.example.com",
                            )

        assert result["success"] is True


class TestInstallAndConfigureAgent:
    """Tests for _install_and_configure_agent method."""

    @pytest.mark.asyncio
    async def test_install_and_configure_success(self, wsl_ops):
        """Test successful agent installation and configuration."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "install_agent", new_callable=AsyncMock
            ) as mock_install:
                mock_install.return_value = {"success": True}
                with patch.object(
                    wsl_ops._setup_ops, "configure_agent", new_callable=AsyncMock
                ) as mock_config:
                    mock_config.return_value = {"success": True}
                    with patch.object(
                        wsl_ops._setup_ops,
                        "start_agent_service",
                        new_callable=AsyncMock,
                    ) as mock_start:
                        mock_start.return_value = {"success": True}

                        await wsl_ops._install_and_configure_agent(
                            "Ubuntu-24.04",
                            ["apt install sysmanage-agent"],
                            "server.example.com",
                            "test.example.com",
                            8443,
                            True,
                            "token123",
                        )

        mock_install.assert_called_once()
        mock_config.assert_called_once()
        mock_start.assert_called_once()

    @pytest.mark.asyncio
    async def test_install_agent_failure_continues(self, wsl_ops):
        """Test that agent installation failure logs warning but continues."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "install_agent", new_callable=AsyncMock
            ) as mock_install:
                mock_install.return_value = {"success": False, "error": "Failed"}
                with patch.object(
                    wsl_ops._setup_ops, "configure_agent", new_callable=AsyncMock
                ) as mock_config:
                    mock_config.return_value = {"success": True}
                    with patch.object(
                        wsl_ops._setup_ops,
                        "start_agent_service",
                        new_callable=AsyncMock,
                    ) as mock_start:
                        mock_start.return_value = {"success": True}
                        await wsl_ops._install_and_configure_agent(
                            "Ubuntu-24.04",
                            ["apt install sysmanage-agent"],
                            "server.example.com",
                            "test.example.com",
                            8443,
                            True,
                            None,
                        )

        mock_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_install_commands(self, wsl_ops):
        """Test when no install commands are provided."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "install_agent", new_callable=AsyncMock
            ) as mock_install:
                with patch.object(
                    wsl_ops._setup_ops, "configure_agent", new_callable=AsyncMock
                ) as mock_config:
                    mock_config.return_value = {"success": True}
                    with patch.object(
                        wsl_ops._setup_ops,
                        "start_agent_service",
                        new_callable=AsyncMock,
                    ) as mock_start:
                        mock_start.return_value = {"success": True}
                        await wsl_ops._install_and_configure_agent(
                            "Ubuntu-24.04",
                            [],
                            "server.example.com",
                            "test.example.com",
                            8443,
                            True,
                            None,
                        )

        mock_install.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_server_url(self, wsl_ops):
        """Test when no server URL is provided."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "configure_agent", new_callable=AsyncMock
            ) as mock_config:
                with patch.object(
                    wsl_ops._setup_ops, "start_agent_service", new_callable=AsyncMock
                ) as mock_start:
                    mock_start.return_value = {"success": True}
                    await wsl_ops._install_and_configure_agent(
                        "Ubuntu-24.04",
                        [],
                        "",
                        "test.example.com",
                        8443,
                        True,
                        None,
                    )

        mock_config.assert_not_called()


class TestCreateWslInstance:
    """Tests for create_wsl_instance method."""

    @pytest.mark.asyncio
    async def test_create_instance_validation_fails(self, wsl_ops):
        """Test instance creation with validation failure."""
        mock_helper = Mock()

        result = await wsl_ops.create_wsl_instance(
            "",
            "hostname",
            "user",
            "hash",
            "server",
            [],
            mock_helper,
        )

        assert result["success"] is False
        assert "Distribution" in result["error"]

    @pytest.mark.asyncio
    async def test_create_instance_wsl_not_available(self, wsl_ops):
        """Test instance creation when WSL is not available."""
        mock_helper = Mock()

        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops, "_check_and_enable_wsl", new_callable=AsyncMock
            ) as mock_check:
                mock_check.return_value = {"success": False, "error": "Not available"}

                result = await wsl_ops.create_wsl_instance(
                    "Ubuntu-24.04",
                    "hostname",
                    "user",
                    "hash",
                    "server",
                    [],
                    mock_helper,
                )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_instance_already_exists(self, wsl_ops):
        """Test instance creation when distribution already exists."""
        mock_helper = Mock()

        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops, "_check_and_enable_wsl", new_callable=AsyncMock
            ) as mock_check:
                mock_check.return_value = {"success": True}
                with patch.object(
                    wsl_ops, "_configure_wslconfig", new_callable=AsyncMock
                ):
                    with patch.object(
                        wsl_ops, "_check_distribution_exists", return_value=True
                    ):
                        result = await wsl_ops.create_wsl_instance(
                            "Ubuntu-24.04",
                            "hostname",
                            "user",
                            "hash",
                            "server",
                            [],
                            mock_helper,
                        )

        assert result["success"] is False
        assert "already installed" in result["error"]

    @pytest.mark.asyncio
    async def test_create_instance_success(self, wsl_ops):
        """Test successful instance creation."""
        mock_helper = Mock()

        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops, "_check_and_enable_wsl", new_callable=AsyncMock
            ) as mock_check:
                mock_check.return_value = {"success": True}
                with patch.object(
                    wsl_ops, "_configure_wslconfig", new_callable=AsyncMock
                ):
                    with patch.object(
                        wsl_ops, "_check_distribution_exists", return_value=False
                    ):
                        with patch.object(
                            wsl_ops, "_install_distribution", new_callable=AsyncMock
                        ) as mock_install:
                            mock_install.return_value = {
                                "success": True,
                                "actual_name": "Ubuntu-24.04",
                            }
                            with patch.object(
                                wsl_ops._setup_ops,
                                "get_executable_name",
                                return_value="ubuntu2404.exe",
                            ):
                                with patch.object(
                                    wsl_ops._setup_ops,
                                    "get_fqdn_hostname",
                                    return_value="hostname.example.com",
                                ):
                                    with patch.object(
                                        wsl_ops,
                                        "_setup_wsl_user_and_systemd",
                                        new_callable=AsyncMock,
                                    ) as mock_setup:
                                        mock_setup.return_value = {"success": True}
                                        with patch.object(
                                            wsl_ops._setup_ops,
                                            "restart_instance",
                                            new_callable=AsyncMock,
                                        ) as mock_restart:
                                            mock_restart.return_value = {
                                                "success": True
                                            }
                                            with patch.object(
                                                wsl_ops,
                                                "_install_and_configure_agent",
                                                new_callable=AsyncMock,
                                            ):
                                                result = (
                                                    await wsl_ops.create_wsl_instance(
                                                        "Ubuntu-24.04",
                                                        "hostname",
                                                        "user",
                                                        "hash",
                                                        "server",
                                                        [],
                                                        mock_helper,
                                                    )
                                                )

        assert result["success"] is True
        assert result["child_name"] == "Ubuntu-24.04"
        assert result["child_type"] == "wsl"

    @pytest.mark.asyncio
    async def test_create_instance_exception(self, wsl_ops):
        """Test instance creation with exception."""
        mock_helper = Mock()

        with patch.object(
            wsl_ops, "_validate_wsl_inputs", side_effect=Exception("Test error")
        ):
            result = await wsl_ops.create_wsl_instance(
                "Ubuntu-24.04",
                "hostname",
                "user",
                "hash",
                "server",
                [],
                mock_helper,
            )

        assert result["success"] is False
        assert "Test error" in result["error"]


class TestEnableWsl:
    """Tests for enable_wsl method."""

    @pytest.mark.asyncio
    async def test_enable_wsl_success(self, wsl_ops, mock_agent):
        """Test successful WSL enabling."""
        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "reboot_required": False}

            result = await wsl_ops.enable_wsl({})

        assert result["success"] is True
        mock_agent.send_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_enable_wsl_reboot_required(self, wsl_ops, mock_agent):
        """Test WSL enabling with reboot required."""
        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "reboot_required": True}

            result = await wsl_ops.enable_wsl({})

        assert result["success"] is True
        assert result["reboot_required"] is True
        mock_agent.create_message.assert_called_once_with(
            "reboot_status_update",
            {
                "reboot_required": True,
                "reboot_required_reason": "WSL feature enablement pending",
            },
        )
        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_wsl_reboot_send_fails(self, wsl_ops, mock_agent):
        """Test WSL enabling when reboot message send fails."""
        mock_agent.send_message.side_effect = Exception("Send failed")

        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "reboot_required": True}

            result = await wsl_ops.enable_wsl({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_wsl_no_send_method(self, wsl_ops):
        """Test WSL enabling when agent has no send_message."""
        wsl_ops.agent = Mock(spec=[])

        with patch.object(
            wsl_ops, "enable_wsl_internal", new_callable=AsyncMock
        ) as mock_enable:
            mock_enable.return_value = {"success": True, "reboot_required": True}

            result = await wsl_ops.enable_wsl({})

        assert result["success"] is True


class TestControlOperationsDelegation:
    """Tests for control operation delegation methods."""

    @pytest.mark.asyncio
    async def test_start_child_host_delegated(self, wsl_ops):
        """Test that start_child_host delegates to control_ops."""
        with patch.object(
            wsl_ops._control_ops, "start_child_host", new_callable=AsyncMock
        ) as mock_start:
            mock_start.return_value = {"success": True}

            result = await wsl_ops.start_child_host({"child_name": "Ubuntu"})

        mock_start.assert_called_once_with({"child_name": "Ubuntu"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_stop_child_host_delegated(self, wsl_ops):
        """Test that stop_child_host delegates to control_ops."""
        with patch.object(
            wsl_ops._control_ops, "stop_child_host", new_callable=AsyncMock
        ) as mock_stop:
            mock_stop.return_value = {"success": True}

            result = await wsl_ops.stop_child_host({"child_name": "Ubuntu"})

        mock_stop.assert_called_once_with({"child_name": "Ubuntu"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_restart_child_host_delegated(self, wsl_ops):
        """Test that restart_child_host delegates to control_ops."""
        with patch.object(
            wsl_ops._control_ops, "restart_child_host", new_callable=AsyncMock
        ) as mock_restart:
            mock_restart.return_value = {"success": True}

            result = await wsl_ops.restart_child_host({"child_name": "Ubuntu"})

        mock_restart.assert_called_once_with({"child_name": "Ubuntu"})
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_delete_child_host_delegated(self, wsl_ops):
        """Test that delete_child_host delegates to control_ops."""
        with patch.object(
            wsl_ops._control_ops, "delete_child_host", new_callable=AsyncMock
        ) as mock_delete:
            mock_delete.return_value = {"success": True}

            result = await wsl_ops.delete_child_host({"child_name": "Ubuntu"})

        mock_delete.assert_called_once_with({"child_name": "Ubuntu"})
        assert result["success"] is True


class TestSetupWslUserAndSystemdEdgeCases:
    """Additional tests for _setup_wsl_user_and_systemd edge cases."""

    @pytest.mark.asyncio
    async def test_setup_systemd_fails(self, wsl_ops):
        """Test when systemd enablement fails."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "configure_default_user", new_callable=AsyncMock
            ) as mock_config:
                mock_config.return_value = {"success": True}
                with patch.object(
                    wsl_ops._setup_ops, "create_user", new_callable=AsyncMock
                ) as mock_create:
                    mock_create.return_value = {"success": True}
                    with patch.object(
                        wsl_ops._setup_ops, "enable_systemd", new_callable=AsyncMock
                    ) as mock_systemd:
                        mock_systemd.return_value = {
                            "success": False,
                            "error": "Failed",
                        }

                        result = await wsl_ops._setup_wsl_user_and_systemd(
                            "Ubuntu-24.04",
                            "ubuntu2404.exe",
                            "testuser",
                            "$6$hash",
                            "test.example.com",
                        )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_setup_final_default_user_fails(self, wsl_ops):
        """Test when setting final default user fails."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "configure_default_user", new_callable=AsyncMock
            ) as mock_config:
                # First call succeeds (root), second call fails (testuser)
                mock_config.side_effect = [
                    {"success": True},
                    {"success": False, "error": "Failed"},
                ]
                with patch.object(
                    wsl_ops._setup_ops, "create_user", new_callable=AsyncMock
                ) as mock_create:
                    mock_create.return_value = {"success": True}
                    with patch.object(
                        wsl_ops._setup_ops, "enable_systemd", new_callable=AsyncMock
                    ) as mock_systemd:
                        mock_systemd.return_value = {"success": True}
                        with patch.object(
                            wsl_ops._setup_ops, "set_hostname", new_callable=AsyncMock
                        ) as mock_hostname:
                            mock_hostname.return_value = {"success": True}

                            result = await wsl_ops._setup_wsl_user_and_systemd(
                                "Ubuntu-24.04",
                                "ubuntu2404.exe",
                                "testuser",
                                "$6$hash",
                                "test.example.com",
                            )

        assert result["success"] is False


class TestInstallAndConfigureAgentEdgeCases:
    """Additional tests for _install_and_configure_agent edge cases."""

    @pytest.mark.asyncio
    async def test_configure_agent_failure(self, wsl_ops):
        """Test when agent configuration fails."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "configure_agent", new_callable=AsyncMock
            ) as mock_config:
                mock_config.return_value = {"success": False, "error": "Config failed"}
                with patch.object(
                    wsl_ops._setup_ops, "start_agent_service", new_callable=AsyncMock
                ) as mock_start:
                    mock_start.return_value = {"success": True}
                    # Call with server_url but no install commands
                    await wsl_ops._install_and_configure_agent(
                        "Ubuntu-24.04",
                        [],
                        "server.example.com",
                        "test.example.com",
                        8443,
                        True,
                        None,
                    )

        # Should have called configure_agent and logged warning
        mock_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_agent_service_failure(self, wsl_ops):
        """Test when agent service start fails."""
        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops._setup_ops, "start_agent_service", new_callable=AsyncMock
            ) as mock_start:
                mock_start.return_value = {"success": False, "error": "Start failed"}
                # Call without install commands or server_url
                await wsl_ops._install_and_configure_agent(
                    "Ubuntu-24.04",
                    [],
                    "",
                    "test.example.com",
                    8443,
                    True,
                    None,
                )

        # Should have called start_agent_service and logged warning
        mock_start.assert_called_once()


class TestCreateWslInstanceEdgeCases:
    """Additional tests for create_wsl_instance edge cases."""

    @pytest.mark.asyncio
    async def test_create_instance_install_fails(self, wsl_ops):
        """Test instance creation when distribution installation fails."""
        mock_helper = Mock()

        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops, "_check_and_enable_wsl", new_callable=AsyncMock
            ) as mock_check:
                mock_check.return_value = {"success": True}
                with patch.object(
                    wsl_ops, "_configure_wslconfig", new_callable=AsyncMock
                ):
                    with patch.object(
                        wsl_ops, "_check_distribution_exists", return_value=False
                    ):
                        with patch.object(
                            wsl_ops, "_install_distribution", new_callable=AsyncMock
                        ) as mock_install:
                            mock_install.return_value = {
                                "success": False,
                                "error": "Install failed",
                            }

                            result = await wsl_ops.create_wsl_instance(
                                "Ubuntu-24.04",
                                "hostname",
                                "user",
                                "hash",
                                "server",
                                [],
                                mock_helper,
                            )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_instance_actual_name_differs(self, wsl_ops):
        """Test instance creation when actual WSL name differs from requested."""
        mock_helper = Mock()

        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops, "_check_and_enable_wsl", new_callable=AsyncMock
            ) as mock_check:
                mock_check.return_value = {"success": True}
                with patch.object(
                    wsl_ops, "_configure_wslconfig", new_callable=AsyncMock
                ):
                    with patch.object(
                        wsl_ops, "_check_distribution_exists", return_value=False
                    ):
                        with patch.object(
                            wsl_ops, "_install_distribution", new_callable=AsyncMock
                        ) as mock_install:
                            # Simulate Fedora -> FedoraLinux-43 renaming
                            mock_install.return_value = {
                                "success": True,
                                "actual_name": "FedoraLinux-43",
                            }
                            with patch.object(
                                wsl_ops._setup_ops,
                                "get_executable_name",
                                return_value="fedora.exe",
                            ):
                                with patch.object(
                                    wsl_ops._setup_ops,
                                    "get_fqdn_hostname",
                                    return_value="hostname.example.com",
                                ):
                                    with patch.object(
                                        wsl_ops,
                                        "_setup_wsl_user_and_systemd",
                                        new_callable=AsyncMock,
                                    ) as mock_setup:
                                        mock_setup.return_value = {"success": True}
                                        with patch.object(
                                            wsl_ops._setup_ops,
                                            "restart_instance",
                                            new_callable=AsyncMock,
                                        ) as mock_restart:
                                            mock_restart.return_value = {
                                                "success": True
                                            }
                                            with patch.object(
                                                wsl_ops,
                                                "_install_and_configure_agent",
                                                new_callable=AsyncMock,
                                            ):
                                                result = (
                                                    await wsl_ops.create_wsl_instance(
                                                        "Fedora",
                                                        "hostname",
                                                        "user",
                                                        "hash",
                                                        "server",
                                                        [],
                                                        mock_helper,
                                                    )
                                                )

        assert result["success"] is True
        assert result["child_name"] == "FedoraLinux-43"

    @pytest.mark.asyncio
    async def test_create_instance_setup_fails(self, wsl_ops):
        """Test instance creation when user setup fails."""
        mock_helper = Mock()

        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops, "_check_and_enable_wsl", new_callable=AsyncMock
            ) as mock_check:
                mock_check.return_value = {"success": True}
                with patch.object(
                    wsl_ops, "_configure_wslconfig", new_callable=AsyncMock
                ):
                    with patch.object(
                        wsl_ops, "_check_distribution_exists", return_value=False
                    ):
                        with patch.object(
                            wsl_ops, "_install_distribution", new_callable=AsyncMock
                        ) as mock_install:
                            mock_install.return_value = {
                                "success": True,
                                "actual_name": "Ubuntu-24.04",
                            }
                            with patch.object(
                                wsl_ops._setup_ops,
                                "get_executable_name",
                                return_value="ubuntu2404.exe",
                            ):
                                with patch.object(
                                    wsl_ops._setup_ops,
                                    "get_fqdn_hostname",
                                    return_value="hostname.example.com",
                                ):
                                    with patch.object(
                                        wsl_ops,
                                        "_setup_wsl_user_and_systemd",
                                        new_callable=AsyncMock,
                                    ) as mock_setup:
                                        mock_setup.return_value = {
                                            "success": False,
                                            "error": "Setup failed",
                                        }

                                        result = await wsl_ops.create_wsl_instance(
                                            "Ubuntu-24.04",
                                            "hostname",
                                            "user",
                                            "hash",
                                            "server",
                                            [],
                                            mock_helper,
                                        )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_instance_restart_fails(self, wsl_ops):
        """Test instance creation when WSL restart fails."""
        mock_helper = Mock()

        with patch.object(wsl_ops, "_send_progress", new_callable=AsyncMock):
            with patch.object(
                wsl_ops, "_check_and_enable_wsl", new_callable=AsyncMock
            ) as mock_check:
                mock_check.return_value = {"success": True}
                with patch.object(
                    wsl_ops, "_configure_wslconfig", new_callable=AsyncMock
                ):
                    with patch.object(
                        wsl_ops, "_check_distribution_exists", return_value=False
                    ):
                        with patch.object(
                            wsl_ops, "_install_distribution", new_callable=AsyncMock
                        ) as mock_install:
                            mock_install.return_value = {
                                "success": True,
                                "actual_name": "Ubuntu-24.04",
                            }
                            with patch.object(
                                wsl_ops._setup_ops,
                                "get_executable_name",
                                return_value="ubuntu2404.exe",
                            ):
                                with patch.object(
                                    wsl_ops._setup_ops,
                                    "get_fqdn_hostname",
                                    return_value="hostname.example.com",
                                ):
                                    with patch.object(
                                        wsl_ops,
                                        "_setup_wsl_user_and_systemd",
                                        new_callable=AsyncMock,
                                    ) as mock_setup:
                                        mock_setup.return_value = {"success": True}
                                        with patch.object(
                                            wsl_ops._setup_ops,
                                            "restart_instance",
                                            new_callable=AsyncMock,
                                        ) as mock_restart:
                                            mock_restart.return_value = {
                                                "success": False,
                                                "error": "Restart failed",
                                            }

                                            result = await wsl_ops.create_wsl_instance(
                                                "Ubuntu-24.04",
                                                "hostname",
                                                "user",
                                                "hash",
                                                "server",
                                                [],
                                                mock_helper,
                                            )

        assert result["success"] is False


class TestEnableWslInternalEdgeCases:
    """Additional tests for enable_wsl_internal edge cases."""

    @pytest.mark.asyncio
    async def test_enable_wsl_status_check_timeout(self, wsl_ops):
        """Test when WSL status check times out."""
        mock_install_proc = Mock()
        mock_install_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_install_proc.returncode = 0

        mock_status_proc = Mock()
        mock_status_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_status_proc.kill = Mock()

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=[mock_install_proc, mock_status_proc],
        ):
            with patch.object(wsl_ops, "_decode_wsl_output", return_value=""):
                result = await wsl_ops.enable_wsl_internal()

        assert result["success"] is False
        assert "timed out" in result["error"]


class TestParseWslListOutputEdgeCases:
    """Additional tests for _parse_wsl_list_output edge cases."""

    def test_parse_output_with_empty_lines(self, wsl_ops):
        """Test parsing output with empty distro name lines."""
        output = """  NAME           STATE

  Ubuntu         Running
"""
        result = wsl_ops._parse_wsl_list_output(output, "Ubuntu")
        assert result == "Ubuntu"

    def test_parse_output_skips_empty_distro_name(self, wsl_ops):
        """Test that parsing skips lines where distro name extraction returns empty."""
        output = """  NAME           STATE

  Debian         Running
"""
        result = wsl_ops._parse_wsl_list_output(output, "Ubuntu")
        # Should return the requested distribution since "Ubuntu" wasn't found
        assert result == "Ubuntu"
