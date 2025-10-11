"""
Linux-specific firewall operations for SysManage Agent.
Supports ufw (Ubuntu/Debian) and firewalld (RHEL/CentOS/Fedora).

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _
from src.sysmanage_agent.operations.firewall_base import FirewallBase


class LinuxFirewallOperations(FirewallBase):
    """Manages firewall operations on Linux systems."""

    async def enable_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable firewall on Linux systems.

        Tries ufw first (Ubuntu/Debian), then firewalld (RHEL/CentOS/Fedora).

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        # Try ufw first (Ubuntu/Debian)
        try:
            # Check if ufw is installed
            result = subprocess.run(  # nosec B603 B607
                ["which", "ufw"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Detected ufw firewall")

                # Always ensure SSH (port 22) is allowed to prevent lockout
                self.logger.info("Adding ufw rule: allow 22/tcp (SSH)")
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "ufw", "allow", "22/tcp"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode != 0:
                    self.logger.warning(
                        "Failed to add ufw rule for SSH port 22: %s",
                        result.stderr,
                    )

                # Add rules for agent communication ports
                for port in ports:
                    self.logger.info("Adding ufw rule: allow %d/%s", port, protocol)
                    result = subprocess.run(  # nosec B603 B607
                        ["sudo", "ufw", "allow", f"{port}/{protocol}"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode != 0:
                        self.logger.warning(
                            "Failed to add ufw rule for port %d: %s",
                            port,
                            result.stderr,
                        )

                # Enable ufw
                self.logger.info("Enabling ufw firewall")
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "ufw", "--force", "enable"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("UFW firewall enabled successfully")
                    # Send updated firewall status
                    await self._send_firewall_status_update()
                    return {
                        "success": True,
                        "message": _("UFW firewall enabled successfully"),
                    }
                return {
                    "success": False,
                    "error": f"Failed to enable ufw: {result.stderr}",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try firewalld (RHEL/CentOS/Fedora)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "firewall-cmd"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Detected firewalld")

                # Always ensure SSH (port 22) is allowed to prevent lockout
                self.logger.info("Adding firewalld rule: allow 22/tcp (SSH)")
                result = subprocess.run(  # nosec B603 B607
                    [
                        "sudo",
                        "firewall-cmd",
                        "--permanent",
                        "--add-port=22/tcp",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode != 0:
                    self.logger.warning(
                        "Failed to add firewalld rule for SSH port 22: %s",
                        result.stderr,
                    )

                # Add rules for agent communication ports
                for port in ports:
                    self.logger.info(
                        "Adding firewalld rule: allow %d/%s", port, protocol
                    )
                    result = subprocess.run(  # nosec B603 B607
                        [
                            "sudo",
                            "firewall-cmd",
                            "--permanent",
                            f"--add-port={port}/{protocol}",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode != 0:
                        self.logger.warning(
                            "Failed to add firewalld rule for port %d: %s",
                            port,
                            result.stderr,
                        )

                # Reload firewalld to apply changes
                subprocess.run(  # nosec B603 B607
                    ["sudo", "firewall-cmd", "--reload"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                # Start/enable firewalld service
                self.logger.info("Enabling firewalld service")
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "systemctl", "enable", "--now", "firewalld"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Firewalld enabled successfully")
                    await self._send_firewall_status_update()
                    return {
                        "success": True,
                        "message": _("Firewalld enabled successfully"),
                    }
                return {
                    "success": False,
                    "error": f"Failed to enable firewalld: {result.stderr}",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return {
            "success": False,
            "error": _("No supported firewall found on this system"),
        }

    async def disable_firewall(self) -> Dict:
        """
        Disable firewall on Linux systems.

        Tries ufw first (Ubuntu/Debian), then firewalld (RHEL/CentOS/Fedora).

        Returns:
            Dict with success status and message
        """
        # Try ufw first (Ubuntu/Debian)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "ufw"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Detected ufw firewall, disabling")
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "ufw", "disable"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("UFW firewall disabled successfully")
                    await self._send_firewall_status_update()
                    return {
                        "success": True,
                        "message": _("UFW firewall disabled successfully"),
                    }
                return {
                    "success": False,
                    "error": f"Failed to disable ufw: {result.stderr}",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try firewalld (RHEL/CentOS/Fedora)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "firewall-cmd"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Detected firewalld, disabling")
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "systemctl", "stop", "firewalld"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Firewalld disabled successfully")
                    await self._send_firewall_status_update()
                    return {
                        "success": True,
                        "message": _("Firewalld disabled successfully"),
                    }
                return {
                    "success": False,
                    "error": f"Failed to disable firewalld: {result.stderr}",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return {
            "success": False,
            "error": _("No supported firewall found on this system"),
        }

    async def restart_firewall(self) -> Dict:
        """
        Restart firewall on Linux systems.

        Tries ufw first (Ubuntu/Debian), then firewalld (RHEL/CentOS/Fedora).

        Returns:
            Dict with success status and message
        """
        # Try ufw first (Ubuntu/Debian)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "ufw"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Detected ufw firewall, restarting")
                # UFW doesn't have a restart command, but we can reload it
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "ufw", "reload"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("UFW firewall restarted successfully")
                    await self._send_firewall_status_update()
                    return {
                        "success": True,
                        "message": _("UFW firewall restarted successfully"),
                    }
                return {
                    "success": False,
                    "error": f"Failed to restart ufw: {result.stderr}",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try firewalld (RHEL/CentOS/Fedora)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "firewall-cmd"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Detected firewalld, restarting")
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "systemctl", "restart", "firewalld"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Firewalld restarted successfully")
                    await self._send_firewall_status_update()
                    return {
                        "success": True,
                        "message": _("Firewalld restarted successfully"),
                    }
                return {
                    "success": False,
                    "error": f"Failed to restart firewalld: {result.stderr}",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return {
            "success": False,
            "error": _("No supported firewall found on this system"),
        }

    async def deploy_firewall(self) -> Dict:
        """Deploy (enable) firewall on Linux systems."""
        try:
            self.logger.info("Deploying firewall on Linux system")
            ports, protocol = self._get_agent_communication_ports()
            server_ports = self._get_local_server_ports()
            all_ports = list(set(ports + server_ports))
            return await self.enable_firewall(all_ports, protocol)
        except Exception as exc:
            self.logger.error("Error deploying firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}
