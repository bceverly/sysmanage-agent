"""
Windows virtualization support check methods.

This module provides mixin methods for checking Windows-specific
virtualization technologies: WSL (Windows Subsystem for Linux) and Hyper-V.
"""

import os
import platform
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict


class WindowsVirtualizationMixin:
    """Mixin providing Windows virtualization check methods."""

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

    def _detect_wsl_blockers(self, output_lower: str, result: Dict[str, Any]) -> bool:
        """Detect WSL blockers like BIOS virtualization or missing platform features.

        Args:
            output_lower: Lowercased WSL status output
            result: Dict to update with blocker information

        Returns:
            True if a blocker was found and result was updated
        """
        if "bios" in output_lower and "virtualization" in output_lower:
            result["enabled"] = False
            result["needs_enable"] = False
            result["needs_bios_virtualization"] = True
            self.logger.warning("WSL requires BIOS virtualization to be enabled")
            return True

        if "virtual machine platform" in output_lower:
            result["enabled"] = False
            result["needs_enable"] = True
            self.logger.info("WSL requires Virtual Machine Platform to be enabled")
            return True

        return False

    def _parse_wsl_version(self, output: str, result: Dict[str, Any]) -> None:
        """Parse WSL version from wsl --status output.

        Args:
            output: Raw WSL status output string
            result: Dict to update with version information
        """
        if "Default Version: 2" in output or "Default Version: WSL 2" in output:
            result["default_version"] = 2
            result["version"] = "2"
        elif "Default Version: 1" in output or "Default Version: WSL 1" in output:
            result["default_version"] = 1
            result["version"] = "1"
        elif "WSL 1" in output:
            result["version"] = "1"
            result["default_version"] = 1
        else:
            # Default to WSL 2 for modern Windows when version unclear
            result["version"] = "2"
            result["default_version"] = 2

    def check_wsl_support(self) -> Dict[str, Any]:
        """
        Check WSL (Windows Subsystem for Linux) support.

        Returns:
            Dict with WSL availability and status info
        """
        result = {
            "available": False,
            "enabled": False,
            "version": None,
            "needs_enable": False,
            "needs_bios_virtualization": False,
            "default_version": None,
        }

        try:
            if platform.system().lower() != "windows":
                return result

            wsl_path = os.path.join(
                os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wsl.exe"
            )
            if not os.path.exists(wsl_path):
                self.logger.debug("WSL executable not found at %s", wsl_path)
                return result

            result["available"] = True

            try:
                status_result = subprocess.run(  # nosec B603 B607
                    ["wsl", "--status"],
                    capture_output=True,
                    timeout=30,
                    check=False,
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        if hasattr(subprocess, "CREATE_NO_WINDOW")
                        else 0
                    ),
                )

                output = self._decode_wsl_output(
                    status_result.stdout, status_result.stderr
                )
                output_lower = output.lower()

                if self._detect_wsl_blockers(output_lower, result):
                    return result

                if status_result.returncode == 0 and "default version:" in output_lower:
                    result["enabled"] = True
                    self._parse_wsl_version(output, result)
                    self.logger.info(
                        "WSL is enabled, default version: %s", result["default_version"]
                    )
                else:
                    result["enabled"] = False
                    result["needs_enable"] = True
                    self.logger.info("WSL is available but not fully enabled")

            except subprocess.TimeoutExpired:
                self.logger.warning("WSL status check timed out")
                result["enabled"] = False
                result["needs_enable"] = True

            except FileNotFoundError:
                result["enabled"] = False
                result["needs_enable"] = True

        except Exception as error:
            self.logger.error("Error checking WSL support: %s", error)

        return result

    def check_hyperv_support(self) -> Dict[str, Any]:
        """
        Check Hyper-V support on Windows.

        Returns:
            Dict with Hyper-V availability info
        """
        result = {
            "available": False,
            "enabled": False,
        }

        try:
            if platform.system().lower() != "windows":
                return result

            # Check if Hyper-V is available using PowerShell
            ps_command = (
                "Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All "
                "-Online | Select-Object -ExpandProperty State"
            )

            ps_result = subprocess.run(  # nosec B603 B607
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW")
                    else 0
                ),
            )

            if ps_result.returncode == 0:
                state = ps_result.stdout.strip()
                result["available"] = True
                result["enabled"] = state.lower() == "enabled"

        except Exception as error:
            self.logger.debug("Error checking Hyper-V support: %s", error)

        return result
