"""
Hostname operations module for SysManage agent.
Handles hostname change commands with OS-specific implementations.
"""

import logging
import platform
import re
import socket
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.core.async_utils import run_command_async


class HostnameOperations:
    """Handles hostname change operations for the agent."""

    def __init__(self, agent_instance):
        """Initialize hostname operations with agent instance."""
        self.agent_instance = agent_instance
        self.logger = logging.getLogger(__name__)

    async def change_hostname(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Change the system hostname.

        Args:
            parameters: Dict containing 'new_hostname' key

        Returns:
            Dict with success status and result/error message
        """
        new_hostname = parameters.get("new_hostname", "").strip()

        if not new_hostname:
            return {"success": False, "error": _("No hostname specified")}

        # Validate hostname format
        if not self._validate_hostname(new_hostname):
            return {"success": False, "error": _("Invalid hostname format")}

        try:
            system = platform.system().lower()

            if system == "linux":
                result = await self._change_linux_hostname(new_hostname)
            elif system == "darwin":
                result = await self._change_macos_hostname(new_hostname)
            elif system == "windows":
                result = await self._change_windows_hostname(new_hostname)
            elif system == "freebsd":
                result = await self._change_freebsd_hostname(new_hostname)
            elif system in ("openbsd", "netbsd"):
                result = await self._change_bsd_hostname(new_hostname)
            else:
                return {
                    "success": False,
                    "error": _("Unsupported operating system: %s") % system,
                }

            if result["success"]:
                # Send the hostname update to the server
                await self._send_hostname_update(new_hostname)

            return result

        except Exception as error:
            self.logger.error(_("Failed to change hostname: %s"), error)
            return {"success": False, "error": str(error)}

    def _validate_hostname(self, hostname: str) -> bool:
        """
        Validate hostname format.

        Hostnames must:
        - Be 1-253 characters
        - Contain only alphanumeric, hyphens, and dots (for FQDN)
        - Not start or end with a hyphen
        - Not have consecutive dots
        """
        if not hostname or len(hostname) > 253:
            return False

        # RFC 1123 compliant hostname regex
        # Allows FQDN format (hostname.domain.tld)
        pattern = r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$"
        return bool(re.match(pattern, hostname))

    async def _change_linux_hostname(self, hostname: str) -> Dict[str, Any]:
        """
        Change hostname on Linux systems using hostnamectl.

        Updates:
        - Transient hostname (runtime)
        - Static hostname (/etc/hostname)
        - Pretty hostname
        """
        self.logger.info(_("Changing Linux hostname to: %s"), hostname)

        # Try hostnamectl first (systemd systems)
        result = await run_command_async(
            ["sudo", "hostnamectl", "set-hostname", hostname],
            timeout=30.0,
        )

        if result.returncode == 0:
            self.logger.info(_("Successfully changed hostname using hostnamectl"))
            return {
                "success": True,
                "result": _("Hostname changed to %s") % hostname,
            }

        # Fallback: manually update /etc/hostname and run hostname command
        self.logger.warning(
            _("hostnamectl failed, trying manual hostname change: %s"),
            result.stderr,
        )

        # Write to /etc/hostname
        try:
            write_result = await run_command_async(
                ["sudo", "tee", "/etc/hostname"],
                timeout=10.0,
                input_data=f"{hostname}\n",
            )
            if write_result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to update /etc/hostname: %s")
                    % write_result.stderr,
                }
        except Exception as error:
            return {
                "success": False,
                "error": _("Failed to update /etc/hostname: %s") % str(error),
            }

        # Set runtime hostname
        hostname_result = await run_command_async(
            ["sudo", "hostname", hostname],
            timeout=10.0,
        )

        if hostname_result.returncode != 0:
            return {
                "success": False,
                "error": _("Failed to set runtime hostname: %s")
                % hostname_result.stderr,
            }

        return {
            "success": True,
            "result": _("Hostname changed to %s") % hostname,
        }

    async def _change_macos_hostname(self, hostname: str) -> Dict[str, Any]:
        """
        Change hostname on macOS using scutil.

        Sets:
        - ComputerName (user-friendly name)
        - LocalHostName (Bonjour name, no dots allowed)
        - HostName (DNS hostname)
        """
        self.logger.info(_("Changing macOS hostname to: %s"), hostname)

        # Extract short hostname (without domain) for LocalHostName
        short_hostname = hostname.split(".")[0]

        # Set ComputerName
        result = await run_command_async(
            ["sudo", "scutil", "--set", "ComputerName", hostname],
            timeout=10.0,
        )
        if result.returncode != 0:
            return {
                "success": False,
                "error": _("Failed to set ComputerName: %s") % result.stderr,
            }

        # Set LocalHostName (Bonjour, no dots)
        result = await run_command_async(
            ["sudo", "scutil", "--set", "LocalHostName", short_hostname],
            timeout=10.0,
        )
        if result.returncode != 0:
            return {
                "success": False,
                "error": _("Failed to set LocalHostName: %s") % result.stderr,
            }

        # Set HostName
        result = await run_command_async(
            ["sudo", "scutil", "--set", "HostName", hostname],
            timeout=10.0,
        )
        if result.returncode != 0:
            return {
                "success": False,
                "error": _("Failed to set HostName: %s") % result.stderr,
            }

        return {
            "success": True,
            "result": _("Hostname changed to %s") % hostname,
        }

    async def _change_windows_hostname(self, hostname: str) -> Dict[str, Any]:
        """
        Change hostname on Windows using PowerShell Rename-Computer.

        Note: This requires a reboot to take full effect.
        """
        self.logger.info(_("Changing Windows hostname to: %s"), hostname)

        # Use PowerShell Rename-Computer
        ps_command = f'Rename-Computer -NewName "{hostname}" -Force'

        result = await run_command_async(
            ["powershell", "-Command", ps_command],
            timeout=60.0,
        )

        if result.returncode != 0:
            return {
                "success": False,
                "error": _("Failed to rename computer: %s") % result.stderr,
            }

        return {
            "success": True,
            "result": _(
                "Hostname changed to %s. A reboot is required for the change to take effect."
            )
            % hostname,
        }

    async def _change_freebsd_hostname(self, hostname: str) -> Dict[str, Any]:
        """
        Change hostname on FreeBSD.

        Updates:
        - Runtime hostname via hostname command
        - Persistent hostname in /etc/rc.conf
        """
        self.logger.info(_("Changing FreeBSD hostname to: %s"), hostname)

        # Set runtime hostname
        result = await run_command_async(
            ["sudo", "hostname", hostname],
            timeout=10.0,
        )
        if result.returncode != 0:
            return {
                "success": False,
                "error": _("Failed to set runtime hostname: %s") % result.stderr,
            }

        # Update /etc/rc.conf for persistence
        # Use sysrc if available, otherwise sed
        sysrc_result = await run_command_async(
            ["sudo", "sysrc", f"hostname={hostname}"],
            timeout=10.0,
        )

        if sysrc_result.returncode != 0:
            # Fallback to sed
            self.logger.warning(_("sysrc failed, trying sed: %s"), sysrc_result.stderr)
            sed_result = await run_command_async(
                [
                    "sudo",
                    "sed",
                    "-i",
                    "",
                    f's/^hostname=.*/hostname="{hostname}"/',
                    "/etc/rc.conf",
                ],
                timeout=10.0,
            )
            if sed_result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to update /etc/rc.conf: %s") % sed_result.stderr,
                }

        return {
            "success": True,
            "result": _("Hostname changed to %s") % hostname,
        }

    async def _change_bsd_hostname(self, hostname: str) -> Dict[str, Any]:
        """
        Change hostname on OpenBSD/NetBSD.

        Updates:
        - Runtime hostname via hostname command
        - Persistent hostname in /etc/myname
        """
        self.logger.info(_("Changing BSD hostname to: %s"), hostname)

        # Set runtime hostname
        result = await run_command_async(
            ["sudo", "hostname", hostname],
            timeout=10.0,
        )
        if result.returncode != 0:
            return {
                "success": False,
                "error": _("Failed to set runtime hostname: %s") % result.stderr,
            }

        # Update /etc/myname for persistence
        try:
            write_result = await run_command_async(
                ["sudo", "tee", "/etc/myname"],
                timeout=10.0,
                input_data=f"{hostname}\n",
            )
            if write_result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to update /etc/myname: %s")
                    % write_result.stderr,
                }
        except Exception as error:
            return {
                "success": False,
                "error": _("Failed to update /etc/myname: %s") % str(error),
            }

        return {
            "success": True,
            "result": _("Hostname changed to %s") % hostname,
        }

    async def _send_hostname_update(self, new_hostname: str):
        """
        Send hostname change confirmation to server.

        Args:
            new_hostname: The new hostname that was set
        """
        try:
            system_info = self.agent_instance.registration.get_system_info()
            message = self.agent_instance.create_message(
                "hostname_changed",
                {
                    "hostname": system_info.get("hostname") or socket.gethostname(),
                    "new_hostname": new_hostname,
                    "success": True,
                },
            )
            await self.agent_instance.send_message(message)
            self.logger.info(_("Sent hostname change confirmation to server"))
        except Exception as error:
            self.logger.error(
                _("Failed to send hostname change confirmation: %s"), error
            )
