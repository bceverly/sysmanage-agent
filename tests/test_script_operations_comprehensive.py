"""
Comprehensive unit tests for src.sysmanage_agent.operations.script_operations module.
Tests script execution operations with security and validation.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.script_operations import ScriptOperations


class TestScriptOperations:  # pylint: disable=too-many-public-methods
    """Test cases for ScriptOperations class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_config = Mock()
        self.mock_config.is_script_execution_enabled.return_value = True
        self.mock_config.get_script_execution_timeout.return_value = 300
        self.mock_config.get_allowed_shells.return_value = ["bash", "sh"]
        self.mock_config.get_max_script_timeout.return_value = 3600

        # Mock agent instance
        self.mock_agent = Mock()
        self.mock_agent.config = self.mock_config

        self.script_ops = ScriptOperations(self.mock_agent)

    def test_init(self):
        """Test ScriptOperations initialization."""
        assert self.script_ops.agent == self.mock_agent
        assert self.script_ops.logger is not None

    def test_detect_shell_specific_shell_allowed(self):
        """Test shell detection with specific allowed shell."""
        with patch("os.path.exists", return_value=True), patch(
            "os.access", return_value=True
        ):

            result = self.script_ops._detect_shell("bash")
            assert "/bin/bash" in result

    def test_detect_shell_specific_shell_not_allowed(self):
        """Test shell detection with specific shell not in allowed list."""
        with pytest.raises(ValueError, match="Shell 'python' is not allowed"):
            self.script_ops._detect_shell("python")

    @patch("platform.system", return_value="Linux")
    def test_detect_shell_default_linux(self, _mock_system):
        """Test shell detection with default for Linux."""
        with patch("os.path.exists", return_value=True), patch(
            "os.access", return_value=True
        ):

            result = self.script_ops._detect_shell()
            assert "/bin/bash" in result or "/usr/bin/bash" in result

    @patch("platform.system", return_value="Windows")
    @patch("shutil.which", return_value="powershell.exe")
    def test_detect_shell_windows(self, _mock_which, _mock_system):
        """Test shell detection on Windows."""
        self.mock_config.get_allowed_shells.return_value = ["powershell"]

        result = self.script_ops._detect_shell("powershell")
        assert result == "powershell.exe"

    def test_detect_shell_no_allowed_shells(self):
        """Test shell detection when no allowed shells are configured."""
        self.mock_config.get_allowed_shells.return_value = []

        with pytest.raises(ValueError, match="No allowed shells available"):
            self.script_ops._detect_shell()

    def test_detect_shell_no_suitable_shell_found(self):
        """Test shell detection when no suitable shell is found."""
        with patch("os.path.exists", return_value=False), patch(
            "os.access", return_value=False
        ), patch("shutil.which", return_value=None):

            with pytest.raises(ValueError, match="No suitable shell found"):
                self.script_ops._detect_shell("bash")

    @patch("platform.system", return_value="Linux")
    def test_create_script_file_unix(self, _mock_system):
        """Test script file creation on Unix systems."""
        script_content = "echo 'Hello World'"
        shell_path = "/bin/bash"

        with patch("tempfile.NamedTemporaryFile") as mock_temp, patch(
            "os.chmod"
        ) as mock_chmod:

            mock_file = Mock()
            mock_file.name = "/tmp/script12345.sh"
            mock_temp.return_value.__enter__.return_value = mock_file

            result = self.script_ops._create_script_file(script_content, shell_path)

            assert result == "/tmp/script12345.sh"
            mock_file.write.assert_any_call("#!/bin/bash\n")
            mock_file.write.assert_any_call(script_content)
            mock_chmod.assert_called_once_with("/tmp/script12345.sh", 0o700)

    @patch("platform.system", return_value="Windows")
    def test_create_script_file_windows_powershell(self, _mock_system):
        """Test script file creation on Windows with PowerShell."""
        script_content = "Write-Host 'Hello World'"
        shell_path = "powershell.exe"

        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            mock_file = Mock()
            mock_file.name = "C:\\temp\\script12345.ps1"
            mock_temp.return_value.__enter__.return_value = mock_file

            result = self.script_ops._create_script_file(script_content, shell_path)

            assert result == "C:\\temp\\script12345.ps1"
            mock_file.write.assert_called_once_with(script_content)

    @patch("platform.system", return_value="Windows")
    def test_create_script_file_windows_cmd(self, _mock_system):
        """Test script file creation on Windows with CMD."""
        script_content = "echo Hello World"
        shell_path = "cmd.exe"

        with patch("tempfile.NamedTemporaryFile") as mock_temp:
            mock_file = Mock()
            mock_file.name = "C:\\temp\\script12345.bat"
            mock_temp.return_value.__enter__.return_value = mock_file

            result = self.script_ops._create_script_file(script_content, shell_path)

            assert result == "C:\\temp\\script12345.bat"
            mock_file.write.assert_called_once_with(script_content)

    @pytest.mark.asyncio
    async def test_execute_script_disabled(self):
        """Test script execution when disabled."""
        self.mock_config.is_script_execution_enabled.return_value = False

        parameters = {"script_content": "echo 'hello'"}
        result = await self.script_ops.execute_script(parameters)

        assert result["success"] is False
        assert "disabled" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_execute_script_no_content(self):
        """Test script execution with no content."""
        parameters = {}
        result = await self.script_ops.execute_script(parameters)

        assert result["success"] is False
        assert "no script content" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_execute_script_timeout_capped(self):
        """Test script execution with timeout exceeding maximum."""
        parameters = {
            "script_content": "echo 'hello'",
            "timeout": 7200,  # Exceeds max_timeout of 3600
        }

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/script.sh"
        ), patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch(
            "os.unlink"
        ):

            # Mock successful execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"hello\n", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await self.script_ops.execute_script(parameters)

            # Should succeed but timeout should be capped
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_execute_script_working_directory_not_exists(self):
        """Test script execution with non-existent working directory."""
        parameters = {"script_content": "pwd", "working_directory": "/nonexistent/path"}

        # Need to patch shell detection first, then patch working directory check
        with patch.object(self.script_ops, "_detect_shell", return_value="/bin/bash"):
            with patch("os.path.exists") as mock_exists:
                # First call is for working directory (False), second might be for shell paths (True)
                mock_exists.side_effect = lambda path: path != "/nonexistent/path"

                result = await self.script_ops.execute_script(parameters)

                assert result["success"] is False
                assert "does not exist" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_script_working_directory_not_directory(self):
        """Test script execution with working directory that's not a directory."""
        parameters = {"script_content": "pwd", "working_directory": "/etc/passwd"}

        with patch.object(self.script_ops, "_detect_shell", return_value="/bin/bash"):
            with patch("os.path.exists", return_value=True), patch(
                "os.path.isdir", return_value=False
            ):

                result = await self.script_ops.execute_script(parameters)

                assert result["success"] is False
                assert "not a directory" in result["error"]

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Linux")
    async def test_execute_script_success_unix(self, _mock_system):
        """Test successful script execution on Unix."""
        parameters = {
            "script_content": "echo 'Hello World'",
            "shell_type": "bash",
            "timeout": 30,
        }

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/script.sh"
        ), patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch(
            "os.unlink"
        ) as mock_unlink, patch(
            "time.time", side_effect=[1000.0, 1001.0, 1002.0, 1003.0]
        ):  # Mock execution time

            # Mock successful execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"Hello World\n", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await self.script_ops.execute_script(parameters)

            assert result["success"] is True
            assert result["exit_code"] == 0
            assert result["stdout"] == "Hello World\n"
            assert result["stderr"] == ""
            assert result["execution_time"] == 1.0
            assert result["shell_used"] == "/bin/bash"

            # Verify subprocess was called correctly
            mock_subprocess.assert_called_once()
            args, _ = mock_subprocess.call_args
            assert args == ("/bin/bash", "/tmp/script.sh")

            # Verify cleanup
            mock_unlink.assert_called_once_with("/tmp/script.sh")

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_execute_script_success_windows_powershell(self, _mock_system):
        """Test successful script execution on Windows with PowerShell."""
        parameters = {
            "script_content": "Write-Host 'Hello World'",
            "shell_type": "powershell",
            "timeout": 30,
        }

        with patch.object(
            self.script_ops, "_detect_shell", return_value="powershell.exe"
        ), patch.object(
            self.script_ops, "_create_script_file", return_value="C:\\temp\\script.ps1"
        ), patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch(
            "os.unlink"
        ), patch(
            "time.time", side_effect=[1000.0, 1001.0, 1002.0, 1003.0]
        ):

            # Mock successful execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"Hello World\n", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await self.script_ops.execute_script(parameters)

            assert result["success"] is True
            assert result["exit_code"] == 0

            # Verify PowerShell command structure
            mock_subprocess.assert_called_once()
            args, _ = mock_subprocess.call_args
            assert args == (
                "powershell.exe",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                "C:\\temp\\script.ps1",
            )

    @pytest.mark.asyncio
    @patch("platform.system", return_value="Windows")
    async def test_execute_script_success_windows_cmd(self, _mock_system):
        """Test successful script execution on Windows with CMD."""
        parameters = {"script_content": "echo Hello World", "shell_type": "cmd"}

        self.mock_config.get_allowed_shells.return_value = ["cmd"]

        with patch.object(
            self.script_ops, "_detect_shell", return_value="cmd.exe"
        ), patch.object(
            self.script_ops, "_create_script_file", return_value="C:\\temp\\script.bat"
        ), patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch(
            "os.unlink"
        ), patch(
            "time.time", side_effect=[1000.0, 1001.0, 1002.0, 1003.0]
        ):

            # Mock successful execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"Hello World\n", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await self.script_ops.execute_script(parameters)

            assert result["success"] is True

            # Verify CMD command structure
            mock_subprocess.assert_called_once()
            args, _ = mock_subprocess.call_args
            assert args == ("cmd.exe", "/c", "C:\\temp\\script.bat")

    @pytest.mark.asyncio
    async def test_execute_script_timeout(self):
        """Test script execution timeout."""
        parameters = {"script_content": "sleep 100", "timeout": 1}

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/script.sh"
        ), patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch(
            "os.unlink"
        ):

            # Mock process that times out
            mock_process = AsyncMock()
            mock_process.communicate.side_effect = asyncio.TimeoutError()
            mock_process.kill = Mock()  # kill() is synchronous
            mock_process.wait = AsyncMock()
            mock_subprocess.return_value = mock_process

            result = await self.script_ops.execute_script(parameters)

            assert result["success"] is False
            assert "timed out" in result["error"]
            assert result["timeout"] is True

            # Verify process was killed
            mock_process.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_script_timeout_process_lookup_error(self):
        """Test script execution timeout with ProcessLookupError during cleanup."""
        parameters = {"script_content": "sleep 100", "timeout": 1}

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/script.sh"
        ), patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch(
            "os.unlink"
        ):

            # Mock process that times out and cleanup fails
            mock_process = AsyncMock()
            mock_process.communicate.side_effect = asyncio.TimeoutError()
            mock_process.kill = Mock()  # kill() is synchronous
            mock_process.wait.side_effect = ProcessLookupError("Process not found")
            mock_subprocess.return_value = mock_process

            result = await self.script_ops.execute_script(parameters)

            assert result["success"] is False
            assert "timed out" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_script_cleanup_failure(self):
        """Test script execution with cleanup failure."""
        parameters = {"script_content": "echo 'hello'", "timeout": 30}

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/script.sh"
        ), patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch(
            "os.unlink", side_effect=OSError("Permission denied")
        ) as mock_unlink:

            # Mock successful execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"hello\n", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await self.script_ops.execute_script(parameters)

            # Should still succeed despite cleanup failure
            assert result["success"] is True
            mock_unlink.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_script_exception(self):
        """Test script execution with exception."""
        parameters = {"script_content": "echo 'hello'"}

        with patch.object(
            self.script_ops,
            "_detect_shell",
            side_effect=Exception("Shell detection failed"),
        ):
            result = await self.script_ops.execute_script(parameters)

            assert result["success"] is False
            assert "Shell detection failed" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_script_with_working_directory(self):
        """Test script execution with working directory."""
        parameters = {"script_content": "pwd", "working_directory": "/tmp"}

        with patch.object(
            self.script_ops, "_detect_shell", return_value="/bin/bash"
        ), patch.object(
            self.script_ops, "_create_script_file", return_value="/tmp/script.sh"
        ), patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch(
            "os.unlink"
        ), patch(
            "os.path.exists", return_value=True
        ), patch(
            "os.path.isdir", return_value=True
        ), patch(
            "time.time", side_effect=[1000.0, 1001.0, 1002.0, 1003.0]
        ):

            # Mock successful execution
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"/tmp\n", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await self.script_ops.execute_script(parameters)

            assert result["success"] is True
            # Verify working directory was passed
            mock_subprocess.assert_called_once()
            _, kwargs = mock_subprocess.call_args
            assert kwargs["cwd"] == "/tmp"

    def test_detect_shell_coverage_paths(self):
        """Test different code paths in shell detection for coverage."""
        # Test OpenBSD system
        with patch("platform.system", return_value="OpenBSD"), patch(
            "os.path.exists", return_value=True
        ), patch("os.access", return_value=True):

            self.mock_config.get_allowed_shells.return_value = ["ksh"]
            result = self.script_ops._detect_shell()
            assert "/bin/ksh" in result or "/usr/bin/ksh" in result

        # Test FreeBSD system
        with patch("platform.system", return_value="FreeBSD"), patch(
            "os.path.exists", return_value=True
        ), patch("os.access", return_value=True):

            self.mock_config.get_allowed_shells.return_value = ["bash"]
            result = self.script_ops._detect_shell()
            assert "/bin/bash" in result or "/usr/bin/bash" in result

        # Test NetBSD system
        with patch("platform.system", return_value="NetBSD"), patch(
            "os.path.exists", return_value=True
        ), patch("os.access", return_value=True):

            self.mock_config.get_allowed_shells.return_value = ["sh"]
            result = self.script_ops._detect_shell()
            assert "/bin/sh" in result or "/usr/bin/sh" in result
