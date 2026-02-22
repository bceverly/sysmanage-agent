"""
Unit tests for src.sysmanage_agent.core.async_utils module.
Tests async subprocess execution and file I/O operations.
"""

# pylint: disable=protected-access

import asyncio
import subprocess
import tempfile
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.sysmanage_agent.core.async_utils import (
    AsyncProcessResult,
    run_command_async,
    read_file_async,
    write_file_async,
    _create_async_process,
    _collect_process_output,
)


class TestAsyncProcessResult:
    """Test cases for AsyncProcessResult dataclass."""

    def test_async_process_result_creation(self):
        """Test creating an AsyncProcessResult instance."""
        result = AsyncProcessResult(
            returncode=0,
            stdout="Hello World",
            stderr="",
        )

        assert result.returncode == 0
        assert result.stdout == "Hello World"
        assert result.stderr == ""

    def test_async_process_result_with_error(self):
        """Test AsyncProcessResult with non-zero return code and stderr."""
        result = AsyncProcessResult(
            returncode=1,
            stdout="",
            stderr="Command not found",
        )

        assert result.returncode == 1
        assert result.stdout == ""
        assert result.stderr == "Command not found"

    def test_async_process_result_equality(self):
        """Test AsyncProcessResult equality comparison."""
        result1 = AsyncProcessResult(returncode=0, stdout="test", stderr="")
        result2 = AsyncProcessResult(returncode=0, stdout="test", stderr="")
        result3 = AsyncProcessResult(returncode=1, stdout="test", stderr="")

        assert result1 == result2
        assert result1 != result3


class TestRunCommandAsync:
    """Test cases for run_command_async function."""

    @pytest.mark.asyncio
    async def test_run_command_async_success_with_list(self):
        """Test running a command successfully with list input."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"output", b""))

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ):
            result = await run_command_async(["echo", "hello"])

            assert result.returncode == 0
            assert result.stdout == "output"
            assert result.stderr == ""

    @pytest.mark.asyncio
    async def test_run_command_async_success_with_string(self):
        """Test running a command successfully with string input."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"output", b""))

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ):
            result = await run_command_async("echo hello")

            assert result.returncode == 0
            assert result.stdout == "output"

    @pytest.mark.asyncio
    async def test_run_command_async_with_shell(self):
        """Test running a command with shell=True."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"shell output", b""))

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ) as mock_create:
            result = await run_command_async("echo hello", shell=True)

            assert result.returncode == 0
            assert result.stdout == "shell output"
            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["shell"] is True

    @pytest.mark.asyncio
    async def test_run_command_async_with_cwd(self):
        """Test running a command with custom working directory."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ) as mock_create:
            await run_command_async(["ls"], cwd="/tmp")

            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["cwd"] == "/tmp"

    @pytest.mark.asyncio
    async def test_run_command_async_with_env(self):
        """Test running a command with custom environment."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))
        custom_env = {"MY_VAR": "my_value"}

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ) as mock_create:
            await run_command_async(["env"], env=custom_env)

            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["env"] == custom_env

    @pytest.mark.asyncio
    async def test_run_command_async_with_input_data(self):
        """Test running a command with input data sent to stdin."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"processed input", b""))

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ) as mock_create:
            result = await run_command_async(["cat"], input_data="test input")

            assert result.stdout == "processed input"
            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["input_data"] == "test input"

    @pytest.mark.asyncio
    async def test_run_command_async_with_stderr(self):
        """Test running a command that produces stderr output."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"stdout", b"stderr output"))

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ):
            result = await run_command_async(["some_command"])

            assert result.stdout == "stdout"
            assert result.stderr == "stderr output"

    @pytest.mark.asyncio
    async def test_run_command_async_check_success(self):
        """Test running a command with check=True that succeeds."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"success", b""))

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ):
            result = await run_command_async(["echo", "hello"], check=True)

            assert result.returncode == 0
            assert result.stdout == "success"

    @pytest.mark.asyncio
    async def test_run_command_async_check_failure(self):
        """Test running a command with check=True that fails."""
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"error message"))

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ):
            with pytest.raises(subprocess.CalledProcessError) as exc_info:
                await run_command_async(["failing_command"], check=True)

            assert exc_info.value.returncode == 1
            assert exc_info.value.stderr == "error message"

    @pytest.mark.asyncio
    async def test_run_command_async_timeout(self):
        """Test running a command that times out."""
        mock_process = MagicMock()
        mock_process.kill = MagicMock()
        mock_process.wait = AsyncMock()
        mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ):
            with patch(
                "src.sysmanage_agent.core.async_utils._collect_process_output",
                side_effect=asyncio.TimeoutError(),
            ):
                with pytest.raises(asyncio.TimeoutError):
                    await run_command_async(["sleep", "10"], timeout=0.1)

                # Process should be killed on timeout
                mock_process.kill.assert_called_once()
                mock_process.wait.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_command_async_timeout_kill_fails(self):
        """Test timeout handling when killing the process fails."""
        mock_process = MagicMock()
        mock_process.kill = MagicMock(side_effect=ProcessLookupError())
        mock_process.wait = AsyncMock()

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ):
            with patch(
                "src.sysmanage_agent.core.async_utils._collect_process_output",
                side_effect=asyncio.TimeoutError(),
            ):
                # Should still raise TimeoutError even if kill fails
                with pytest.raises(asyncio.TimeoutError):
                    await run_command_async(["sleep", "10"], timeout=0.1)

    @pytest.mark.asyncio
    async def test_run_command_async_no_timeout(self):
        """Test running a command with no timeout (None)."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"no timeout", b""))

        with patch(
            "src.sysmanage_agent.core.async_utils._create_async_process",
            return_value=mock_process,
        ):
            result = await run_command_async(["echo", "test"], timeout=None)

            assert result.returncode == 0
            assert result.stdout == "no timeout"


class TestCreateAsyncProcess:
    """Test cases for _create_async_process function."""

    @pytest.mark.asyncio
    async def test_create_async_process_exec_with_list(self):
        """Test creating async process with list command (exec mode)."""
        mock_process = MagicMock()

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            result = await _create_async_process(["echo", "hello"])

            assert result == mock_process
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args
            assert call_args[0] == ("echo", "hello")

    @pytest.mark.asyncio
    async def test_create_async_process_exec_with_string(self):
        """Test creating async process with string command (exec mode, splits string)."""
        mock_process = MagicMock()

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            result = await _create_async_process("echo hello world")

            assert result == mock_process
            call_args = mock_exec.call_args
            # String should be split into components
            assert call_args[0] == ("echo", "hello", "world")

    @pytest.mark.asyncio
    async def test_create_async_process_shell_with_string(self):
        """Test creating async process with shell=True and string command."""
        mock_process = MagicMock()

        with patch(
            "asyncio.create_subprocess_shell", return_value=mock_process
        ) as mock_shell:
            result = await _create_async_process("echo hello", shell=True)

            assert result == mock_process
            mock_shell.assert_called_once()
            call_args = mock_shell.call_args
            assert call_args[0][0] == "echo hello"

    @pytest.mark.asyncio
    async def test_create_async_process_shell_with_list(self):
        """Test creating async process with shell=True and list command (joins list)."""
        mock_process = MagicMock()

        with patch(
            "asyncio.create_subprocess_shell", return_value=mock_process
        ) as mock_shell:
            result = await _create_async_process(["echo", "hello", "world"], shell=True)

            assert result == mock_process
            call_args = mock_shell.call_args
            # List should be joined into a string for shell
            assert call_args[0][0] == "echo hello world"

    @pytest.mark.asyncio
    async def test_create_async_process_with_cwd(self):
        """Test creating async process with custom working directory."""
        mock_process = MagicMock()

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await _create_async_process(["ls"], cwd="/home")

            call_kwargs = mock_exec.call_args[1]
            assert call_kwargs["cwd"] == "/home"

    @pytest.mark.asyncio
    async def test_create_async_process_with_env(self):
        """Test creating async process with custom environment."""
        mock_process = MagicMock()
        custom_env = {"PATH": "/usr/bin", "HOME": "/root"}

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await _create_async_process(["env"], env=custom_env)

            call_kwargs = mock_exec.call_args[1]
            assert call_kwargs["env"] == custom_env

    @pytest.mark.asyncio
    async def test_create_async_process_with_input_data(self):
        """Test creating async process with stdin pipe for input data."""
        mock_process = MagicMock()

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await _create_async_process(["cat"], input_data="test input")

            call_kwargs = mock_exec.call_args[1]
            assert call_kwargs["stdin"] == asyncio.subprocess.PIPE

    @pytest.mark.asyncio
    async def test_create_async_process_without_input_data(self):
        """Test creating async process without stdin pipe when no input data."""
        mock_process = MagicMock()

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await _create_async_process(["echo", "test"])

            call_kwargs = mock_exec.call_args[1]
            assert call_kwargs["stdin"] is None

    @pytest.mark.asyncio
    async def test_create_async_process_pipes_stdout_stderr(self):
        """Test that async process always pipes stdout and stderr."""
        mock_process = MagicMock()

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_exec:
            await _create_async_process(["echo", "test"])

            call_kwargs = mock_exec.call_args[1]
            assert call_kwargs["stdout"] == asyncio.subprocess.PIPE
            assert call_kwargs["stderr"] == asyncio.subprocess.PIPE


class TestCollectProcessOutput:
    """Test cases for _collect_process_output function."""

    @pytest.mark.asyncio
    async def test_collect_process_output_success(self):
        """Test collecting output from successful process."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(
            return_value=(b"stdout output", b"stderr output")
        )

        result = await _collect_process_output(mock_process, ["test"])

        assert result.returncode == 0
        assert result.stdout == "stdout output"
        assert result.stderr == "stderr output"

    @pytest.mark.asyncio
    async def test_collect_process_output_with_timeout(self):
        """Test collecting output with timeout."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"output", b""))

        with patch("asyncio.wait_for", return_value=(b"output", b"")) as mock_wait_for:
            result = await _collect_process_output(mock_process, ["test"], timeout=10.0)

            assert result.returncode == 0
            mock_wait_for.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_process_output_without_timeout(self):
        """Test collecting output without timeout (None)."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"no timeout output", b""))

        result = await _collect_process_output(mock_process, ["test"], timeout=None)

        assert result.returncode == 0
        assert result.stdout == "no timeout output"
        # communicate should be called directly, not through wait_for
        mock_process.communicate.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_process_output_with_input_data(self):
        """Test collecting output when input data is provided."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"processed", b""))

        result = await _collect_process_output(
            mock_process, ["cat"], input_data="input text"
        )

        assert result.stdout == "processed"
        # Check that communicate was called with encoded input
        mock_process.communicate.assert_called_once()
        call_kwargs = mock_process.communicate.call_args[1]
        assert call_kwargs["input"] == b"input text"

    @pytest.mark.asyncio
    async def test_collect_process_output_check_failure(self):
        """Test that check=True raises CalledProcessError on non-zero exit."""
        mock_process = MagicMock()
        mock_process.returncode = 127
        mock_process.communicate = AsyncMock(return_value=(b"", b"command not found"))

        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            await _collect_process_output(mock_process, ["nonexistent_cmd"], check=True)

        assert exc_info.value.returncode == 127
        assert exc_info.value.cmd == ["nonexistent_cmd"]
        assert exc_info.value.output == ""
        assert exc_info.value.stderr == "command not found"

    @pytest.mark.asyncio
    async def test_collect_process_output_check_success(self):
        """Test that check=True doesn't raise on zero exit code."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"success", b""))

        result = await _collect_process_output(
            mock_process, ["echo", "test"], check=True
        )

        assert result.returncode == 0
        assert result.stdout == "success"

    @pytest.mark.asyncio
    async def test_collect_process_output_empty_stdout(self):
        """Test handling of empty/None stdout."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(None, b"stderr"))

        result = await _collect_process_output(mock_process, ["test"])

        assert result.stdout == ""
        assert result.stderr == "stderr"

    @pytest.mark.asyncio
    async def test_collect_process_output_empty_stderr(self):
        """Test handling of empty/None stderr."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"stdout", None))

        result = await _collect_process_output(mock_process, ["test"])

        assert result.stdout == "stdout"
        assert result.stderr == ""

    @pytest.mark.asyncio
    async def test_collect_process_output_utf8_decode_errors(self):
        """Test handling of UTF-8 decode errors with replacement."""
        mock_process = MagicMock()
        mock_process.returncode = 0
        # Invalid UTF-8 sequence
        mock_process.communicate = AsyncMock(
            return_value=(b"\xff\xfe invalid utf8", b"\x80\x81 error")
        )

        result = await _collect_process_output(mock_process, ["test"])

        # Should decode with replacement characters, not raise exception
        assert isinstance(result.stdout, str)
        assert isinstance(result.stderr, str)
        assert result.returncode == 0

    @pytest.mark.asyncio
    async def test_collect_process_output_timeout_raises(self):
        """Test that timeout in wait_for raises TimeoutError."""
        mock_process = MagicMock()
        mock_process.communicate = AsyncMock()

        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            with pytest.raises(asyncio.TimeoutError):
                await _collect_process_output(mock_process, ["slow_cmd"], timeout=0.1)


class TestReadFileAsync:
    """Test cases for read_file_async function."""

    @pytest.mark.asyncio
    async def test_read_file_async_success(self):
        """Test reading a file successfully."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as temp_file:
            temp_file.write("Hello, World!")
            temp_path = temp_file.name

        try:
            result = await read_file_async(temp_path)
            assert result == "Hello, World!"
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_read_file_async_with_encoding(self):
        """Test reading a file with specific encoding."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write("Unicode: \u00e9\u00e8\u00ea")
            temp_path = temp_file.name

        try:
            result = await read_file_async(temp_path, encoding="utf-8")
            assert result == "Unicode: \u00e9\u00e8\u00ea"
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_read_file_async_empty_file(self):
        """Test reading an empty file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as temp_file:
            temp_path = temp_file.name

        try:
            result = await read_file_async(temp_path)
            assert result == ""
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_read_file_async_multiline(self):
        """Test reading a multiline file."""
        content = "Line 1\nLine 2\nLine 3\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            result = await read_file_async(temp_path)
            assert result == content
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_read_file_async_file_not_found(self):
        """Test reading a non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            await read_file_async("/nonexistent/path/file.txt")

    @pytest.mark.asyncio
    async def test_read_file_async_with_aiofiles_mock(self):
        """Test read_file_async with mocked aiofiles."""
        mock_file = AsyncMock()
        mock_file.read = AsyncMock(return_value="mocked content")
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("aiofiles.open", return_value=mock_file):
            result = await read_file_async("/some/path.txt")
            assert result == "mocked content"


class TestWriteFileAsync:
    """Test cases for write_file_async function."""

    @pytest.mark.asyncio
    async def test_write_file_async_success(self):
        """Test writing a file successfully."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as temp_file:
            temp_path = temp_file.name

        try:
            await write_file_async(temp_path, "Test content")

            # Verify the file was written
            with open(temp_path, "r", encoding="utf-8") as read_file:
                assert read_file.read() == "Test content"
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_write_file_async_overwrite(self):
        """Test that write mode overwrites existing content."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as temp_file:
            temp_file.write("Original content")
            temp_path = temp_file.name

        try:
            await write_file_async(temp_path, "New content")

            with open(temp_path, "r", encoding="utf-8") as read_file:
                assert read_file.read() == "New content"
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_write_file_async_append_mode(self):
        """Test writing a file in append mode."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as temp_file:
            temp_file.write("Original")
            temp_path = temp_file.name

        try:
            await write_file_async(temp_path, " Appended", mode="a")

            with open(temp_path, "r", encoding="utf-8") as read_file:
                assert read_file.read() == "Original Appended"
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_write_file_async_with_encoding(self):
        """Test writing a file with specific encoding."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as temp_file:
            temp_path = temp_file.name

        try:
            await write_file_async(
                temp_path, "Unicode: \u00e9\u00e8\u00ea", encoding="utf-8"
            )

            with open(temp_path, "r", encoding="utf-8") as read_file:
                assert read_file.read() == "Unicode: \u00e9\u00e8\u00ea"
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_write_file_async_empty_content(self):
        """Test writing empty content to a file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as temp_file:
            temp_file.write("Existing content")
            temp_path = temp_file.name

        try:
            await write_file_async(temp_path, "")

            with open(temp_path, "r", encoding="utf-8") as read_file:
                assert read_file.read() == ""
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_write_file_async_multiline(self):
        """Test writing multiline content."""
        content = "Line 1\nLine 2\nLine 3\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as temp_file:
            temp_path = temp_file.name

        try:
            await write_file_async(temp_path, content)

            with open(temp_path, "r", encoding="utf-8") as read_file:
                assert read_file.read() == content
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_write_file_async_creates_file(self):
        """Test that write_file_async creates a new file."""
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, "new_file.txt")

        try:
            assert not os.path.exists(temp_path)

            await write_file_async(temp_path, "New file content")

            assert os.path.exists(temp_path)
            with open(temp_path, "r", encoding="utf-8") as read_file:
                assert read_file.read() == "New file content"
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            os.rmdir(temp_dir)

    @pytest.mark.asyncio
    async def test_write_file_async_with_aiofiles_mock(self):
        """Test write_file_async with mocked aiofiles."""
        mock_file = AsyncMock()
        mock_file.write = AsyncMock()
        mock_file.__aenter__ = AsyncMock(return_value=mock_file)
        mock_file.__aexit__ = AsyncMock(return_value=None)

        with patch("aiofiles.open", return_value=mock_file):
            await write_file_async("/some/path.txt", "content to write")
            mock_file.write.assert_called_once_with("content to write")


class TestIntegration:
    """Integration tests for async_utils module."""

    @pytest.mark.asyncio
    async def test_run_command_echo_integration(self):
        """Integration test: run echo command and capture output."""
        result = await run_command_async(["echo", "integration test"])

        assert result.returncode == 0
        assert "integration test" in result.stdout

    @pytest.mark.asyncio
    async def test_run_command_with_pipe_input_integration(self):
        """Integration test: run command with stdin input."""
        result = await run_command_async(["cat"], input_data="piped input data")

        assert result.returncode == 0
        assert result.stdout == "piped input data"

    @pytest.mark.asyncio
    async def test_run_command_shell_integration(self):
        """Integration test: run shell command."""
        result = await run_command_async(
            "echo 'shell test' && echo 'second line'", shell=True
        )

        assert result.returncode == 0
        assert "shell test" in result.stdout
        assert "second line" in result.stdout

    @pytest.mark.asyncio
    async def test_file_read_write_integration(self):
        """Integration test: write and read file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as temp_file:
            temp_path = temp_file.name

        try:
            test_content = "Integration test content\nWith multiple lines\n"

            # Write content
            await write_file_async(temp_path, test_content)

            # Read it back
            result = await read_file_async(temp_path)

            assert result == test_content
        finally:
            os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_run_command_failing_integration(self):
        """Integration test: command that fails."""
        result = await run_command_async(["false"])  # 'false' returns exit code 1

        assert result.returncode == 1

    @pytest.mark.asyncio
    async def test_run_command_check_failing_integration(self):
        """Integration test: failing command with check=True."""
        with pytest.raises(subprocess.CalledProcessError):
            await run_command_async(["false"], check=True)

    @pytest.mark.asyncio
    async def test_run_command_with_env_integration(self):
        """Integration test: command with custom environment variable."""
        custom_env = os.environ.copy()
        custom_env["TEST_VAR"] = "test_value_12345"

        result = await run_command_async("echo $TEST_VAR", shell=True, env=custom_env)

        assert result.returncode == 0
        assert "test_value_12345" in result.stdout

    @pytest.mark.asyncio
    async def test_run_command_cwd_integration(self):
        """Integration test: command with custom working directory."""
        result = await run_command_async(["pwd"], cwd="/tmp")

        assert result.returncode == 0
        assert "/tmp" in result.stdout or "tmp" in result.stdout
