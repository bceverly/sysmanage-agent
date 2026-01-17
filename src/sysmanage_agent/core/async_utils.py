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
    timeout: Optional[float] = 30.0,
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
        # Determine stdin pipe based on whether we have input
        stdin_pipe = asyncio.subprocess.PIPE if input_data else None

        if shell:
            # Shell mode - cmd should be a string
            if isinstance(cmd, list):
                cmd = " ".join(cmd)
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdin=stdin_pipe,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
        else:
            # Non-shell mode - cmd should be a list
            if isinstance(cmd, str):
                cmd = cmd.split()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=stdin_pipe,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )

        # Prepare input bytes if provided
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

    except asyncio.TimeoutError:
        # Try to kill the process if it timed out
        try:
            process.kill()
            await process.wait()
        except Exception:  # nosec B110 # Ignore errors killing timed-out process
            pass
        raise


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
