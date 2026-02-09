"""
Security-focused unit tests for src.sysmanage_agent.operations.script_operations module.
Tests security validations, shell detection edge cases, and script handling.
"""

# pylint: disable=protected-access,attribute-defined-outside-init,unused-argument

import asyncio
import stat
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.script_operations import (
    ScriptOperations,
    _find_unix_shell,
    _find_windows_shell,
    _DEFAULT_SHELLS,
    _UNIX_SHELL_PATHS,
    _WINDOWS_SHELL_PATHS,
)


class TestShellDetectionHelpers:
    """Test cases for shell detection helper functions."""

    def test_find_unix_shell_exists(self):
        """Test finding Unix shell that exists."""
        with patch("os.path.exists", return_value=True), patch(
            "os.access", return_value=True
        ):
            result = _find_unix_shell("bash", _UNIX_SHELL_PATHS)
            assert result == "/bin/bash"

    def test_find_unix_shell_not_exists(self):
        """Test finding Unix shell that doesn't exist."""
        with patch("os.path.exists", return_value=False), patch(
            "os.access", return_value=False
        ):
            result = _find_unix_shell("bash", _UNIX_SHELL_PATHS)
            assert result is None

    def test_find_unix_shell_exists_not_executable(self):
        """Test finding Unix shell that exists but is not executable."""
        with patch("os.path.exists", return_value=True), patch(
            "os.access", return_value=False
        ):
            result = _find_unix_shell("bash", _UNIX_SHELL_PATHS)
            assert result is None

    def test_find_unix_shell_unknown_shell(self):
        """Test finding unknown Unix shell uses default paths."""
        with patch("os.path.exists", return_value=True), patch(
            "os.access", return_value=True
        ):
            result = _find_unix_shell("fish", _UNIX_SHELL_PATHS)
            # Should try /bin/fish first
            assert result == "/bin/fish"

    def test_find_unix_shell_second_path(self):
        """Test finding Unix shell at second path location."""

        def exists_side_effect(path):
            return path == "/usr/bin/bash"

        def access_side_effect(path, mode):
            return path == "/usr/bin/bash"

        with patch("os.path.exists", side_effect=exists_side_effect), patch(
            "os.access", side_effect=access_side_effect
        ):
            result = _find_unix_shell("bash", _UNIX_SHELL_PATHS)
            assert result == "/usr/bin/bash"

    def test_find_windows_shell_exists(self):
        """Test finding Windows shell that exists."""
        with patch("shutil.which", return_value="powershell.exe"):
            result = _find_windows_shell("powershell", _WINDOWS_SHELL_PATHS)
            assert result == "powershell.exe"

    def test_find_windows_shell_not_exists(self):
        """Test finding Windows shell that doesn't exist."""
        with patch("shutil.which", return_value=None):
            result = _find_windows_shell("powershell", _WINDOWS_SHELL_PATHS)
            assert result is None

    def test_find_windows_shell_pwsh(self):
        """Test finding pwsh (PowerShell Core)."""

        def which_side_effect(cmd):
            if cmd == "pwsh.exe":
                return "pwsh.exe"
            return None

        with patch("shutil.which", side_effect=which_side_effect):
            result = _find_windows_shell("powershell", _WINDOWS_SHELL_PATHS)
            assert result == "pwsh.exe"

    def test_find_windows_shell_unknown(self):
        """Test finding unknown Windows shell."""
        with patch("shutil.which", return_value="custom"):
            result = _find_windows_shell("custom", _WINDOWS_SHELL_PATHS)
            assert result == "custom"


class TestDefaultShellsConfiguration:
    """Test cases for default shell configurations."""

    def test_linux_default_shells(self):
        """Test Linux default shells."""
        assert "bash" in _DEFAULT_SHELLS["linux"]
        assert "sh" in _DEFAULT_SHELLS["linux"]

    def test_darwin_default_shells(self):
        """Test macOS (Darwin) default shells."""
        assert "bash" in _DEFAULT_SHELLS["darwin"]
        assert "zsh" in _DEFAULT_SHELLS["darwin"]

    def test_openbsd_default_shells(self):
        """Test OpenBSD default shells."""
        assert "ksh" in _DEFAULT_SHELLS["openbsd"]
        assert _DEFAULT_SHELLS["openbsd"][0] == "ksh"  # ksh should be first

    def test_freebsd_default_shells(self):
        """Test FreeBSD default shells."""
        assert "bash" in _DEFAULT_SHELLS["freebsd"]
        assert "sh" in _DEFAULT_SHELLS["freebsd"]

    def test_netbsd_default_shells(self):
        """Test NetBSD default shells."""
        assert "sh" in _DEFAULT_SHELLS["netbsd"]

    def test_windows_default_shells(self):
        """Test Windows default shells."""
        assert "powershell" in _DEFAULT_SHELLS["windows"]
        assert "cmd" in _DEFAULT_SHELLS["windows"]


class TestGetShellsToTry:
    """Test cases for _get_shells_to_try method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_allowed_shells.return_value = ["bash", "sh", "ksh"]
        self.mock_agent.config.is_script_execution_enabled.return_value = True
        self.mock_agent.config.get_script_execution_timeout.return_value = 300
        self.mock_agent.config.get_max_script_timeout.return_value = 3600
        self.script_ops = ScriptOperations(self.mock_agent)

    def test_specific_shell_allowed(self):
        """Test with specific allowed shell."""
        result = self.script_ops._get_shells_to_try("bash", ["bash", "sh"], "linux")
        assert result == ["bash"]

    def test_specific_shell_not_allowed(self):
        """Test with specific shell not in allowed list."""
        with pytest.raises(ValueError, match="Shell 'zsh' is not allowed"):
            self.script_ops._get_shells_to_try("zsh", ["bash", "sh"], "linux")

    def test_no_shell_specified_linux(self):
        """Test without specific shell on Linux."""
        result = self.script_ops._get_shells_to_try(None, ["bash", "sh"], "linux")
        assert "bash" in result
        assert all(s in ["bash", "sh"] for s in result)

    def test_no_shell_specified_openbsd(self):
        """Test without specific shell on OpenBSD."""
        result = self.script_ops._get_shells_to_try(None, ["ksh", "sh"], "openbsd")
        assert "ksh" in result

    def test_no_allowed_shells_available(self):
        """Test when no allowed shells match system defaults."""
        with pytest.raises(ValueError, match="No allowed shells available"):
            self.script_ops._get_shells_to_try(
                None, ["python"], "linux"  # Not a standard shell
            )

    def test_filtered_by_allowed_shells(self):
        """Test that system shells are filtered by allowed shells."""
        # Linux default is bash, sh, zsh - but only sh is allowed
        result = self.script_ops._get_shells_to_try(None, ["sh"], "linux")
        assert result == ["sh"]

    def test_unknown_system_fallback(self):
        """Test unknown system falls back to sh."""
        result = self.script_ops._get_shells_to_try(None, ["sh"], "unknownsystem")
        assert result == ["sh"]


class TestFindShellExecutable:
    """Test cases for _find_shell_executable method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_allowed_shells.return_value = ["bash", "sh"]
        self.mock_agent.config.is_script_execution_enabled.return_value = True
        self.mock_agent.config.get_script_execution_timeout.return_value = 300
        self.mock_agent.config.get_max_script_timeout.return_value = 3600
        self.script_ops = ScriptOperations(self.mock_agent)

    def test_find_first_available_shell(self):
        """Test finding first available shell."""
        with patch("os.path.exists", return_value=True), patch(
            "os.access", return_value=True
        ):
            result = self.script_ops._find_shell_executable(["bash", "sh"], "linux")
            assert "/bin/bash" in result

    def test_fallback_to_second_shell(self):
        """Test fallback to second shell when first unavailable."""

        def exists_side_effect(path):
            return "sh" in path

        def access_side_effect(path, mode):
            return "sh" in path

        with patch("os.path.exists", side_effect=exists_side_effect), patch(
            "os.access", side_effect=access_side_effect
        ):
            result = self.script_ops._find_shell_executable(["bash", "sh"], "linux")
            assert "sh" in result

    def test_no_shell_found_raises(self):
        """Test error when no shell is found."""
        with patch("os.path.exists", return_value=False), patch(
            "os.access", return_value=False
        ):
            with pytest.raises(ValueError, match="No suitable shell found"):
                self.script_ops._find_shell_executable(["bash", "sh"], "linux")

    def test_windows_shell_finding(self):
        """Test finding Windows shell."""
        with patch("shutil.which", return_value="cmd.exe"):
            result = self.script_ops._find_shell_executable(["cmd"], "windows")
            assert result == "cmd.exe"


class TestCreateScriptFile:
    """Test cases for _create_script_file method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.get_allowed_shells.return_value = ["bash", "sh"]
        self.mock_agent.config.is_script_execution_enabled.return_value = True
        self.script_ops = ScriptOperations(self.mock_agent)

    @patch("tempfile.NamedTemporaryFile")
    @patch("os.chmod")
    @patch("platform.system", return_value="Linux")
    def test_create_script_unix_with_shebang(
        self, mock_system, mock_chmod, mock_tempfile
    ):
        """Test Unix script creation includes shebang."""
        mock_file = Mock()
        mock_file.name = "/tmp/test_script.sh"
        mock_tempfile.return_value.__enter__.return_value = mock_file

        result = self.script_ops._create_script_file("echo hello", "/bin/bash")

        assert result == "/tmp/test_script.sh"
        # Should write shebang and content
        calls = mock_file.write.call_args_list
        assert calls[0][0][0] == "#!/bin/bash\n"
        assert calls[1][0][0] == "echo hello"
        # Should set execute permissions
        mock_chmod.assert_called_once_with(
            "/tmp/test_script.sh", stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
        )

    @patch("tempfile.NamedTemporaryFile")
    @patch("platform.system", return_value="Windows")
    def test_create_script_windows_powershell(self, mock_system, mock_tempfile):
        """Test Windows PowerShell script creation."""
        mock_file = Mock()
        mock_file.name = "C:\\temp\\test_script.ps1"
        mock_tempfile.return_value.__enter__.return_value = mock_file

        result = self.script_ops._create_script_file(
            "Write-Host 'hello'", "powershell.exe"
        )

        assert result == "C:\\temp\\test_script.ps1"
        # PowerShell suffix should be .ps1
        mock_tempfile.assert_called()
        call_kwargs = mock_tempfile.call_args[1]
        assert call_kwargs["suffix"] == ".ps1"

    @patch("tempfile.NamedTemporaryFile")
    @patch("platform.system", return_value="Windows")
    def test_create_script_windows_cmd(self, mock_system, mock_tempfile):
        """Test Windows CMD script creation."""
        mock_file = Mock()
        mock_file.name = "C:\\temp\\test_script.bat"
        mock_tempfile.return_value.__enter__.return_value = mock_file

        result = self.script_ops._create_script_file("echo hello", "cmd.exe")

        assert result == "C:\\temp\\test_script.bat"
        call_kwargs = mock_tempfile.call_args[1]
        assert call_kwargs["suffix"] == ".bat"


class TestValidateScriptParameters:
    """Test cases for _validate_script_parameters method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.is_script_execution_enabled.return_value = True
        self.script_ops = ScriptOperations(self.mock_agent)

    def test_script_execution_disabled(self):
        """Test validation when script execution is disabled."""
        self.mock_agent.config.is_script_execution_enabled.return_value = False

        result = self.script_ops._validate_script_parameters(
            {"script_content": "echo hello"}
        )

        assert result["success"] is False
        assert "disabled" in result["error"].lower()

    def test_no_script_content(self):
        """Test validation with missing script content."""
        result = self.script_ops._validate_script_parameters({})

        assert result["success"] is False
        assert "No script content" in result["error"]

    def test_empty_script_content(self):
        """Test validation with empty script content."""
        result = self.script_ops._validate_script_parameters({"script_content": ""})

        assert result["success"] is False
        assert "No script content" in result["error"]

    @patch("os.path.exists", return_value=False)
    def test_working_directory_not_exists(self, mock_exists):
        """Test validation with non-existent working directory."""
        result = self.script_ops._validate_script_parameters(
            {"script_content": "echo hello", "working_directory": "/nonexistent"}
        )

        assert result["success"] is False
        assert "does not exist" in result["error"]

    @patch("os.path.exists", return_value=True)
    @patch("os.path.isdir", return_value=False)
    def test_working_directory_not_dir(self, mock_isdir, mock_exists):
        """Test validation with working directory that's not a directory."""
        result = self.script_ops._validate_script_parameters(
            {"script_content": "echo hello", "working_directory": "/etc/passwd"}
        )

        assert result["success"] is False
        assert "not a directory" in result["error"]

    @patch("os.path.exists", return_value=True)
    @patch("os.path.isdir", return_value=True)
    def test_valid_parameters(self, mock_isdir, mock_exists):
        """Test validation with valid parameters."""
        result = self.script_ops._validate_script_parameters(
            {"script_content": "echo hello", "working_directory": "/tmp"}
        )

        assert result["success"] is True

    def test_no_working_directory(self):
        """Test validation without working directory (valid)."""
        result = self.script_ops._validate_script_parameters(
            {"script_content": "echo hello"}
        )

        assert result["success"] is True


class TestExecuteScriptFile:
    """Test cases for _execute_script_file method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.is_script_execution_enabled.return_value = True
        self.script_ops = ScriptOperations(self.mock_agent)

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("os.unlink")
    @patch("time.time")
    async def test_execute_script_success(
        self, mock_time, mock_unlink, mock_subprocess
    ):
        """Test successful script execution."""
        # Provide extra values for logging module which also calls time.time()
        mock_time.side_effect = [100.0, 101.5] + [101.5] * 20

        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"output\n", b"")
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process

        with patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/test.sh"
        ):
            result = await self.script_ops._execute_script_file(
                "echo hello", "/bin/bash", 300, None
            )

        assert result["success"] is True
        assert result["exit_code"] == 0
        assert result["stdout"] == "output\n"
        assert result["execution_time"] == 1.5
        mock_unlink.assert_called_once_with("/tmp/test.sh")

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("os.unlink")
    async def test_execute_script_nonzero_exit(self, mock_unlink, mock_subprocess):
        """Test script execution with non-zero exit code."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"", b"error occurred\n")
        mock_process.returncode = 1
        mock_subprocess.return_value = mock_process

        with patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/test.sh"
        ), patch("time.time", return_value=100.0):
            result = await self.script_ops._execute_script_file(
                "false", "/bin/bash", 300, None
            )

        assert result["success"] is True  # Execution succeeded even if script failed
        assert result["exit_code"] == 1
        assert result["stderr"] == "error occurred\n"

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("os.unlink")
    async def test_execute_script_timeout(self, mock_unlink, mock_subprocess):
        """Test script execution timeout."""
        mock_process = AsyncMock()
        mock_process.communicate.side_effect = asyncio.TimeoutError()
        mock_process.kill = Mock()
        mock_process.wait = AsyncMock()
        mock_subprocess.return_value = mock_process

        with patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/test.sh"
        ):
            result = await self.script_ops._execute_script_file(
                "sleep 1000", "/bin/bash", 1, None
            )

        assert result["success"] is False
        assert result["timeout"] is True
        assert "timed out" in result["error"]
        mock_process.kill.assert_called_once()

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("os.unlink")
    async def test_execute_script_timeout_process_already_dead(
        self, mock_unlink, mock_subprocess
    ):
        """Test script timeout when process is already terminated."""
        mock_process = AsyncMock()
        mock_process.communicate.side_effect = asyncio.TimeoutError()
        mock_process.kill = Mock(side_effect=ProcessLookupError())
        mock_subprocess.return_value = mock_process

        with patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/test.sh"
        ):
            result = await self.script_ops._execute_script_file(
                "sleep 1000", "/bin/bash", 1, None
            )

        assert result["success"] is False
        assert result["timeout"] is True

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("os.unlink")
    async def test_execute_script_cleanup_failure(self, mock_unlink, mock_subprocess):
        """Test script execution with cleanup failure."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"output\n", b"")
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process
        mock_unlink.side_effect = OSError("Permission denied")

        with patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/test.sh"
        ), patch("time.time", return_value=100.0):
            result = await self.script_ops._execute_script_file(
                "echo hello", "/bin/bash", 300, None
            )

        # Should still succeed despite cleanup failure
        assert result["success"] is True
        # Warning would be logged via the agent's logger

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("os.unlink")
    @patch("platform.system", return_value="Windows")
    async def test_execute_script_windows_powershell(
        self, mock_system, mock_unlink, mock_subprocess
    ):
        """Test Windows PowerShell execution."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"hello\n", b"")
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process

        with patch.object(
            self.script_ops, "_create_script_file", return_value="C:\\temp\\test.ps1"
        ), patch("time.time", return_value=100.0):
            result = await self.script_ops._execute_script_file(
                "Write-Host 'hello'", "powershell.exe", 300, None
            )

        assert result["success"] is True
        # Verify PowerShell execution args
        call_args = mock_subprocess.call_args[0]
        assert call_args[0] == "powershell.exe"
        assert "-ExecutionPolicy" in call_args
        assert "Bypass" in call_args
        assert "-File" in call_args

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("os.unlink")
    @patch("platform.system", return_value="Windows")
    async def test_execute_script_windows_cmd(
        self, mock_system, mock_unlink, mock_subprocess
    ):
        """Test Windows CMD execution."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"hello\n", b"")
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process

        with patch.object(
            self.script_ops, "_create_script_file", return_value="C:\\temp\\test.bat"
        ), patch("time.time", return_value=100.0):
            result = await self.script_ops._execute_script_file(
                "echo hello", "cmd.exe", 300, None
            )

        assert result["success"] is True
        # Verify CMD execution args
        call_args = mock_subprocess.call_args[0]
        assert call_args[0] == "cmd.exe"
        assert "/c" in call_args

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("os.unlink")
    async def test_execute_script_with_working_directory(
        self, mock_unlink, mock_subprocess
    ):
        """Test script execution with working directory."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"/tmp\n", b"")
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process

        with patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/test.sh"
        ), patch("time.time", return_value=100.0):
            result = await self.script_ops._execute_script_file(
                "pwd", "/bin/bash", 300, "/tmp"
            )

        assert result["success"] is True
        # Verify working directory was passed
        call_kwargs = mock_subprocess.call_args[1]
        assert call_kwargs["cwd"] == "/tmp"

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("os.unlink")
    async def test_execute_script_unicode_output(self, mock_unlink, mock_subprocess):
        """Test script execution with unicode output."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (
            "Hello \u4e16\u754c".encode("utf-8"),
            b"",
        )
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process

        with patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/test.sh"
        ), patch("time.time", return_value=100.0):
            result = await self.script_ops._execute_script_file(
                "echo test", "/bin/bash", 300, None
            )

        assert result["success"] is True
        assert "\u4e16\u754c" in result["stdout"]

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    @patch("os.unlink")
    async def test_execute_script_binary_output(self, mock_unlink, mock_subprocess):
        """Test script execution with invalid UTF-8 output."""
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (
            b"\x80\x81\x82invalid",  # Invalid UTF-8
            b"",
        )
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process

        with patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/test.sh"
        ), patch("time.time", return_value=100.0):
            result = await self.script_ops._execute_script_file(
                "echo test", "/bin/bash", 300, None
            )

        assert result["success"] is True
        # Should handle invalid UTF-8 with replacement
        assert "invalid" in result["stdout"]


class TestExecuteScript:
    """Test cases for execute_script method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.is_script_execution_enabled.return_value = True
        self.mock_agent.config.get_allowed_shells.return_value = ["bash", "sh"]
        self.mock_agent.config.get_script_execution_timeout.return_value = 300
        self.mock_agent.config.get_max_script_timeout.return_value = 3600
        self.script_ops = ScriptOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_execute_script_timeout_capped(self):
        """Test that timeout is capped at max_timeout."""
        parameters = {
            "script_content": "echo hello",
            "timeout": 5000,  # Exceeds max of 3600
        }

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(self.script_ops, "_execute_script_file") as mock_execute:
            mock_execute.return_value = {"success": True, "exit_code": 0}

            await self.script_ops.execute_script(parameters)

            # Verify timeout was capped
            call_args = mock_execute.call_args
            assert call_args[0][2] == 3600  # Capped at max

    @pytest.mark.asyncio
    async def test_execute_script_default_timeout(self):
        """Test that default timeout is used when not specified."""
        parameters = {"script_content": "echo hello"}

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(self.script_ops, "_execute_script_file") as mock_execute:
            mock_execute.return_value = {"success": True, "exit_code": 0}

            await self.script_ops.execute_script(parameters)

            # Verify default timeout was used
            call_args = mock_execute.call_args
            assert call_args[0][2] == 300  # Default from config

    @pytest.mark.asyncio
    async def test_execute_script_general_exception(self):
        """Test handling of general exceptions."""
        parameters = {"script_content": "echo hello"}

        with patch.object(
            self.script_ops,
            "_detect_shell",
            side_effect=RuntimeError("Unexpected error"),
        ):
            result = await self.script_ops.execute_script(parameters)

            assert result["success"] is False
            assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_script_with_shell_type(self):
        """Test script execution with specific shell type."""
        parameters = {"script_content": "echo hello", "shell_type": "sh"}

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/sh"
        ) as mock_detect, patch.object(
            self.script_ops, "_execute_script_file"
        ) as mock_execute:
            mock_execute.return_value = {"success": True, "exit_code": 0}

            await self.script_ops.execute_script(parameters)

            mock_detect.assert_called_once_with("sh")


class TestScriptOperationsSecurityEdgeCases:
    """Edge case security tests for script operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.config.is_script_execution_enabled.return_value = True
        self.mock_agent.config.get_allowed_shells.return_value = ["bash", "sh"]
        self.mock_agent.config.get_script_execution_timeout.return_value = 300
        self.mock_agent.config.get_max_script_timeout.return_value = 3600
        self.script_ops = ScriptOperations(self.mock_agent)

    @pytest.mark.asyncio
    async def test_path_traversal_in_working_directory(self):
        """Test handling of path traversal in working directory."""
        parameters = {"script_content": "ls", "working_directory": "/tmp/../etc"}

        with patch("os.path.exists", return_value=True), patch(
            "os.path.isdir", return_value=True
        ), patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(
            self.script_ops, "_execute_script_file"
        ) as mock_execute:
            mock_execute.return_value = {"success": True, "exit_code": 0}

            result = await self.script_ops.execute_script(parameters)

            # Path traversal is passed to _execute_script_file
            # (OS-level security should handle this)
            assert result["success"] is True

    def test_null_byte_in_shell_type(self):
        """Test handling of null bytes in shell type."""
        with pytest.raises(ValueError, match="is not allowed"):
            self.script_ops._get_shells_to_try("bash\x00evil", ["bash", "sh"], "linux")

    @pytest.mark.asyncio
    async def test_very_long_script_content(self):
        """Test handling of very long script content."""
        parameters = {"script_content": "echo " + "A" * 100000}  # Very long script

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(self.script_ops, "_execute_script_file") as mock_execute:
            mock_execute.return_value = {"success": True, "exit_code": 0}

            result = await self.script_ops.execute_script(parameters)

            # Should handle long content
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_script_with_null_bytes(self):
        """Test handling of null bytes in script content."""
        parameters = {"script_content": "echo hello\x00world"}

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(self.script_ops, "_execute_script_file") as mock_execute:
            mock_execute.return_value = {"success": True, "exit_code": 0}

            result = await self.script_ops.execute_script(parameters)

            # Should handle null bytes in content
            assert result["success"] is True
