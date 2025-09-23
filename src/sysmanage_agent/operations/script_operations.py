"""
Script execution operations module for SysManage agent.
Handles script execution with proper shell detection and security controls.
"""

import asyncio
import logging
import os
import platform
import shutil
import stat
import tempfile
import time
from typing import Any, Dict, Optional

from src.i18n import _


class ScriptOperations:
    """Handles script execution operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize script operations with agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

    def _detect_shell(self, shell_type: Optional[str] = None) -> str:
        """
        Detect the appropriate shell to use for script execution.

        Args:
            shell_type: Preferred shell type from request

        Returns:
            Path to shell executable

        Raises:
            ValueError: If requested shell is not available or allowed
        """
        system = platform.system().lower()

        # Get allowed shells from configuration
        allowed_shells = self.agent.config.get_allowed_shells()

        # Default shell preferences by platform
        default_shells = {
            "linux": ["bash", "sh", "zsh"],
            "darwin": ["bash", "zsh", "sh"],
            "freebsd": ["bash", "sh", "zsh", "ksh"],
            "openbsd": ["ksh", "sh", "bash"],
            "netbsd": ["sh", "bash", "ksh"],
            "windows": ["powershell", "cmd"],
        }

        # Determine shells to try
        if shell_type:
            # Specific shell requested
            if shell_type not in allowed_shells:
                raise ValueError(
                    _("Shell '%s' is not allowed by configuration") % shell_type
                )
            shells_to_try = [shell_type]
        else:
            # Use system defaults, filtered by allowed shells
            system_shells = default_shells.get(system, ["sh"])
            shells_to_try = [s for s in system_shells if s in allowed_shells]

        if not shells_to_try:
            raise ValueError(_("No allowed shells available for system '%s'") % system)

        # Find first available shell
        shell_paths = {
            "bash": ["/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"],
            "sh": ["/bin/sh", "/usr/bin/sh"],
            "zsh": ["/bin/zsh", "/usr/bin/zsh", "/usr/local/bin/zsh"],
            "ksh": ["/bin/ksh", "/usr/bin/ksh"],
            "powershell": ["powershell.exe", "pwsh.exe"],
            "cmd": ["cmd.exe"],
        }

        for shell in shells_to_try:
            if system == "windows":
                # On Windows, try to find the executable in PATH
                for shell_cmd in shell_paths.get(shell, [shell]):
                    if shutil.which(shell_cmd):
                        self.logger.info(_("Selected shell: %s"), shell_cmd)
                        return shell_cmd
            else:
                # On Unix-like systems, check specific paths
                for shell_path in shell_paths.get(
                    shell, [f"/bin/{shell}", f"/usr/bin/{shell}"]
                ):
                    if os.path.exists(shell_path) and os.access(shell_path, os.X_OK):
                        self.logger.info(_("Selected shell: %s"), shell_path)
                        return shell_path

        raise ValueError(
            _("No suitable shell found from allowed shells: %s")
            % ", ".join(allowed_shells)
        )

    def _create_script_file(self, script_content: str, shell_path: str) -> str:
        """
        Create a temporary script file with proper permissions.

        Args:
            script_content: The script content to write
            shell_path: Path to the shell executable

        Returns:
            Path to the created script file
        """
        # Determine file extension based on shell
        shell_name = os.path.basename(shell_path).lower()
        if shell_name in ["powershell.exe", "pwsh.exe"]:
            suffix = ".ps1"
        elif shell_name == "cmd.exe":
            suffix = ".bat"
        else:
            suffix = ".sh"

        # Create temporary script file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False
        ) as script_file:
            # Add shebang for Unix shells
            if not platform.system().lower() == "windows" and suffix == ".sh":
                script_file.write(f"#!{shell_path}\n")

            script_file.write(script_content)
            script_path = script_file.name

        # Set execute permissions on Unix-like systems
        if not platform.system().lower() == "windows":
            os.chmod(script_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        return script_path

    def _validate_script_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate script execution parameters."""
        # Check if script execution is enabled
        if not self.agent.config.is_script_execution_enabled():
            return {
                "success": False,
                "error": _("Script execution is disabled in agent configuration"),
            }

        # Extract and validate script content
        script_content = parameters.get("script_content")
        if not script_content:
            return {"success": False, "error": _("No script content provided")}

        # Validate working directory
        working_directory = parameters.get("working_directory")
        if working_directory:
            if not os.path.exists(working_directory):
                return {
                    "success": False,
                    "error": _("Working directory does not exist: %s")
                    % working_directory,
                }
            if not os.path.isdir(working_directory):
                return {
                    "success": False,
                    "error": _("Working directory is not a directory: %s")
                    % working_directory,
                }

        return {"success": True}

    async def _execute_script_file(
        self, script_content: str, shell_path: str, timeout: int, working_directory: str
    ) -> Dict[str, Any]:
        """Execute script file and return results."""
        # Create script file
        script_path = self._create_script_file(script_content, shell_path)

        try:
            # Prepare execution command
            if platform.system().lower() == "windows":
                if "powershell" in shell_path.lower():
                    cmd = [
                        shell_path,
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        script_path,
                    ]
                else:
                    cmd = [shell_path, "/c", script_path]
            else:
                cmd = [shell_path, script_path]

            self.logger.info(_("Executing script with shell: %s"), shell_path)
            self.logger.debug(_("Script content preview: %s..."), script_content[:100])

            # Execute script
            start_time = time.time()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_directory,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
                execution_time = time.time() - start_time

                # Decode output
                stdout_text = stdout.decode("utf-8", errors="replace")
                stderr_text = stderr.decode("utf-8", errors="replace")

                self.logger.info(
                    _("Script execution completed in %.2f seconds with exit code %d"),
                    execution_time,
                    process.returncode,
                )

                return {
                    "success": True,
                    "exit_code": process.returncode,
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "execution_time": execution_time,
                    "shell_used": shell_path,
                }

            except asyncio.TimeoutError:
                # Kill the process if it times out
                try:
                    process.kill()
                    await process.wait()
                except ProcessLookupError:
                    pass  # Process already terminated

                return {
                    "success": False,
                    "error": _("Script execution timed out after %d seconds") % timeout,
                    "timeout": True,
                }

        finally:
            # Clean up script file
            try:
                os.unlink(script_path)
            except OSError as e:
                self.logger.warning(
                    _("Failed to delete script file %s: %s"), script_path, e
                )

    async def execute_script(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a script with proper security controls.

        Args:
            parameters: Script execution parameters containing:
                - script_content: The script to execute
                - shell_type: Optional preferred shell
                - timeout: Optional execution timeout
                - working_directory: Optional working directory

        Returns:
            Execution result with output, error, and status information
        """
        try:
            # Validate parameters
            validation_result = self._validate_script_parameters(parameters)
            if not validation_result["success"]:
                return validation_result

            # Extract parameters
            script_content = parameters.get("script_content")
            shell_type = parameters.get("shell_type")
            timeout = parameters.get(
                "timeout", self.agent.config.get_script_execution_timeout()
            )
            working_directory = parameters.get("working_directory")

            # Validate timeout
            max_timeout = self.agent.config.get_max_script_timeout()
            if timeout > max_timeout:
                timeout = max_timeout
                self.logger.warning(
                    _("Script timeout capped at %d seconds"), max_timeout
                )

            # Detect shell
            shell_path = self._detect_shell(shell_type)

            # Execute the script
            return await self._execute_script_file(
                script_content, shell_path, timeout, working_directory
            )

        except Exception as e:
            self.logger.error(_("Script execution failed: %s"), e)
            return {"success": False, "error": str(e)}
