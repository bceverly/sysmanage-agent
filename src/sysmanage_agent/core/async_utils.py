"""
Async utility functions for non-blocking subprocess and file operations.

These utilities should be used in async functions instead of their
synchronous equivalents (subprocess.run, open()) to avoid blocking
the event loop.
"""

import asyncio
import subprocess  # nosec B404 # Required for CalledProcessError
from dataclasses import dataclass
from typing import Dict, List, Optional, Union

import aiofiles


@dataclass
class AsyncProcessResult:
    """Result from async subprocess execution, mimics subprocess.CompletedProcess."""

    returncode: int
    stdout: str
    stderr: str


async def run_command_async(
    cmd: Union[List[str], str],
    timeout: Optional[
        float
    ] = 30.0,  # NOSONAR - timeout parameter is passed to asyncio.wait_for, not used for manual sleep-based polling
    check: bool = False,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False,
    input_data: Optional[str] = None,
) -> AsyncProcessResult:
    """
    Run a command asynchronously without blocking the event loop.

    This is the async equivalent of subprocess.run() and should be used
    in async functions instead of the synchronous subprocess.run().

    Args:
        cmd: Command to run as list of strings or string (if shell=True)
        timeout: Timeout in seconds (default 30)
        check: If True, raise CalledProcessError on non-zero return code
        cwd: Working directory for the command
        env: Environment variables for the command
        shell: If True, run command through shell
        input_data: Optional string to send to stdin

    Returns:
        AsyncProcessResult with returncode, stdout, stderr

    Raises:
        asyncio.TimeoutError: If command times out
        subprocess.CalledProcessError: If check=True and command fails
    """
    try:
        process = (
            await _create_async_process(  # nosec B604 # shell param passed through
                cmd, shell=shell, cwd=cwd, env=env, input_data=input_data
            )
        )
        return await _collect_process_output(
            process, cmd, timeout=timeout, check=check, input_data=input_data
        )

    except asyncio.TimeoutError:
        # Try to kill the process if it timed out
        try:
            process.kill()
            await process.wait()
        except Exception:  # nosec B110 # Ignore errors killing timed-out process
            pass
        raise


async def _create_async_process(
    cmd: Union[List[str], str],
    shell: bool = False,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    input_data: Optional[str] = None,
) -> asyncio.subprocess.Process:
    """Create an async subprocess in shell or exec mode.

    Args:
        cmd: Command to run as list of strings or string (if shell=True)
        shell: If True, run command through shell
        cwd: Working directory for the command
        env: Environment variables for the command
        input_data: If provided, stdin pipe is opened

    Returns:
        The created async subprocess Process
    """
    stdin_pipe = asyncio.subprocess.PIPE if input_data else None

    if shell:
        if isinstance(cmd, list):
            cmd = " ".join(cmd)
        return await asyncio.create_subprocess_shell(
            cmd,
            stdin=stdin_pipe,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )

    if isinstance(cmd, str):
        cmd = cmd.split()
    return await asyncio.create_subprocess_exec(
        *cmd,
        stdin=stdin_pipe,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )


async def _collect_process_output(
    process: asyncio.subprocess.Process,
    cmd: Union[List[str], str],
    timeout: Optional[float] = None,
    check: bool = False,
    input_data: Optional[str] = None,
) -> AsyncProcessResult:
    """Collect stdout/stderr from an async subprocess and optionally check return code.

    Args:
        process: The async subprocess to collect output from
        cmd: Original command (used for CalledProcessError if check=True)
        timeout: Timeout in seconds for process.communicate, or None for no timeout
        check: If True, raise CalledProcessError on non-zero return code
        input_data: Optional string to send to stdin

    Returns:
        AsyncProcessResult with returncode, stdout, stderr

    Raises:
        asyncio.TimeoutError: If command times out
        subprocess.CalledProcessError: If check=True and command fails
    """
    input_bytes = input_data.encode("utf-8") if input_data else None

    if timeout is not None:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(input=input_bytes), timeout=timeout
        )
    else:
        stdout_bytes, stderr_bytes = await process.communicate(input=input_bytes)

    stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
    stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

    result = AsyncProcessResult(
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )

    if check and process.returncode != 0:
        raise subprocess.CalledProcessError(
            process.returncode,
            cmd,
            output=stdout,
            stderr=stderr,
        )

    return result


async def read_file_async(filepath: str, encoding: str = "utf-8") -> str:
    """
    Read a file asynchronously without blocking the event loop.

    Args:
        filepath: Path to file to read
        encoding: File encoding (default utf-8)

    Returns:
        File contents as string
    """
    async with aiofiles.open(filepath, mode="r", encoding=encoding) as file_handle:
        return await file_handle.read()


async def write_file_async(
    filepath: str, content: str, encoding: str = "utf-8", mode: str = "w"
) -> None:
    """
    Write to a file asynchronously without blocking the event loop.

    Args:
        filepath: Path to file to write
        content: Content to write
        encoding: File encoding (default utf-8)
        mode: File mode ('w' for write, 'a' for append)
    """
    async with aiofiles.open(filepath, mode=mode, encoding=encoding) as file_handle:
        await file_handle.write(content)
