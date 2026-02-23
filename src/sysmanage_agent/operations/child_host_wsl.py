"""
WSL-specific child host operations.
"""

import asyncio
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict

from src.i18n import _

from .child_host_wsl_control import WslControlOperations


class WslOperations:
    """WSL-specific operations for child host management."""

    def __init__(self, agent_instance, logger, virtualization_checks):
        """
        Initialize WSL operations.

        Args:
            agent_instance: Reference to the main SysManageAgent instance
            logger: Logger instance
            virtualization_checks: VirtualizationChecks instance
        """
        self.agent = agent_instance
        self.logger = logger
        self.virtualization_checks = virtualization_checks

        # Initialize sub-modules with shared decode function
        self._control_ops = WslControlOperations(logger, self._decode_wsl_output)

    def _get_creationflags(self) -> int:
        """Get subprocess creation flags for Windows."""
        return (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )

    def _decode_wsl_output(self, stdout: bytes, stderr: bytes) -> str:
        """
        Decode WSL command output which may be UTF-16LE encoded.

        wsl.exe outputs UTF-16LE on Windows, but subprocess with text=True
        expects UTF-8, resulting in garbled or empty output.

        Args:
            stdout: Raw stdout bytes
            stderr: Raw stderr bytes

        Returns:
            Combined decoded output as a string
        """
        combined = stdout + stderr
        if not combined:
            return ""

        # Try UTF-16LE first (what wsl.exe actually outputs)
        try:
            # Remove BOM if present
            if combined.startswith(b"\xff\xfe"):
                combined = combined[2:]
            decoded = combined.decode("utf-16-le")
            # Filter out null characters that may appear
            decoded = decoded.replace("\x00", "")
            if decoded.strip():
                return decoded
        except (UnicodeDecodeError, LookupError):
            pass

        # Fall back to UTF-8
        try:
            return combined.decode("utf-8")
        except UnicodeDecodeError:
            pass

        # Last resort: latin-1 (never fails)
        return combined.decode("latin-1")

    async def enable_wsl_internal(self) -> Dict[str, Any]:
        """
        Enable WSL on the system using wsl --install.

        Returns:
            Dict with success status and whether reboot is required
        """
        try:
            self.logger.info("Attempting to enable WSL")

            # Use wsl --install which enables all required features
            # Note: wsl.exe outputs UTF-16LE, so we read as bytes and decode manually
            proc = await asyncio.create_subprocess_exec(
                "wsl",
                "--install",
                "--no-distribution",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=300
                )  # 5 minutes timeout
            except asyncio.TimeoutError:
                proc.kill()
                return {"success": False, "error": _("WSL installation timed out")}

            # Decode the UTF-16LE output from wsl.exe
            output = self._decode_wsl_output(stdout, stderr).lower()

            # Check for reboot required error code
            if proc.returncode == 3010:
                self.logger.info("WSL install requires reboot (exit code 3010)")
                return {"success": True, "reboot_required": True}

            # Check output for reboot indicators
            if "reboot" in output or "restart" in output:
                self.logger.info("WSL install requires reboot (found in output)")
                return {"success": True, "reboot_required": True}

            if proc.returncode != 0:
                error_msg = output or "Unknown error"
                self.logger.error("WSL install failed: %s", error_msg)
                return {"success": False, "error": error_msg}

            # The install command returned 0, but we need to verify WSL actually works
            # wsl --install can return 0 even when Virtual Machine Platform isn't enabled
            self.logger.info("WSL install command completed, verifying status...")

            status_proc = await asyncio.create_subprocess_exec(
                "wsl",
                "--status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                status_stdout, status_stderr = await asyncio.wait_for(
                    status_proc.communicate(), timeout=30
                )
            except asyncio.TimeoutError:
                status_proc.kill()
                return {"success": False, "error": _("WSL status check timed out")}

            # Decode the UTF-16LE output from wsl.exe
            status_output = self._decode_wsl_output(
                status_stdout, status_stderr
            ).lower()
            self.logger.debug("WSL status output: %s", status_output[:500])

            # Check for indicators that WSL isn't fully enabled
            return self._check_wsl_status_output(
                status_output, status_stdout, status_stderr
            )

        except Exception as error:
            return {"success": False, "error": str(error)}

    def _check_wsl_status_output(
        self, status_output: str, status_stdout: bytes, status_stderr: bytes
    ) -> Dict[str, Any]:
        """Check WSL status output for enablement issues."""
        if "please enable" in status_output or "not supported" in status_output:
            self.logger.warning(
                "WSL install completed but additional setup required: %s",
                status_stdout or status_stderr,
            )

            # Check if it's an actual BIOS virtualization issue
            if "bios" in status_output and "virtualization" in status_output:
                return {
                    "success": False,
                    "error": _(
                        "WSL requires virtualization to be enabled in BIOS/UEFI. "
                        "Please enable virtualization in your system's BIOS settings "
                        "and restart the computer."
                    ),
                    "requires_bios_change": True,
                }

            return {"success": True, "reboot_required": True}

        self.logger.info("WSL enabled and verified successfully")
        return {"success": True, "reboot_required": False}

    async def enable_wsl(self, _parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enable WSL on a Windows system.

        This is called when the user clicks "Enable WSL" in the UI.

        Args:
            _parameters: Optional parameters (unused)

        Returns:
            Dict with success status and whether reboot is required
        """
        self.logger.info(_("Enabling WSL on this system"))

        result = await self.enable_wsl_internal()

        if result.get("success") and result.get("reboot_required"):
            # Notify server that reboot is required
            try:
                if hasattr(self.agent, "send_message"):
                    reboot_message = self.agent.create_message(
                        "reboot_status_update",
                        {
                            "reboot_required": True,
                            "reboot_required_reason": "WSL feature enablement pending",
                        },
                    )
                    await self.agent.send_message(reboot_message)
            except Exception as error:
                self.logger.warning("Failed to send reboot status update: %s", error)

        return result

    # Delegate control operations to sub-module
    async def start_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Start a stopped WSL instance."""
        return await self._control_ops.start_child_host(parameters)

    async def stop_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Stop a running WSL instance."""
        return await self._control_ops.stop_child_host(parameters)

    async def restart_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restart a WSL instance (stop then start)."""
        return await self._control_ops.restart_child_host(parameters)

    async def delete_child_host(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Delete (unregister) a WSL instance."""
        return await self._control_ops.delete_child_host(parameters)
