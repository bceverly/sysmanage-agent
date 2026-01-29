"""
Firewalld-specific firewall operations for Linux systems.
Used by LinuxFirewallOperations for RHEL/CentOS/Fedora systems.

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

import logging
import re
import subprocess  # nosec B404
from typing import Callable, Dict, List, Tuple

from src.i18n import _  # pylint: disable=not-callable

# Log message constants for firewalld rule operations
LOG_REMOVE_TCP_RULE = "Removing firewalld rule: remove-port %d/tcp"
LOG_REMOVE_UDP_RULE = "Removing firewalld rule: remove-port %d/udp"


class FirewalldOperations:
    """Handles firewalld firewall operations on RHEL/CentOS/Fedora systems."""

    def __init__(
        self,
        logger: logging.Logger,
        get_agent_ports_func: Callable[[], Tuple[List[int], str]],
        send_status_func: Callable,
    ):
        """
        Initialize firewalld operations.

        Args:
            logger: Logger instance
            get_agent_ports_func: Function to get agent communication ports
            send_status_func: Async function to send firewall status update
        """
        self.logger = logger
        self._get_agent_communication_ports = get_agent_ports_func
        self._send_firewall_status_update = send_status_func

    @staticmethod
    def is_available() -> bool:
        """Check if firewalld is available on this system."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "firewall-cmd"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    async def enable_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable firewalld.

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        self.logger.info("Detected firewalld")

        # Always ensure SSH (port 22) is allowed to prevent lockout
        self.logger.info("Adding firewalld rule: allow 22/tcp (SSH)")
        result = subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
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
            self.logger.info("Adding firewalld rule: allow %d/%s", port, protocol)
            result = subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
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
        subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
            ["sudo", "firewall-cmd", "--reload"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        # Start/enable firewalld service
        self.logger.info("Enabling firewalld service")
        result = subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
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

    async def disable_firewall(self) -> Dict:
        """
        Disable firewalld.

        Returns:
            Dict with success status and message
        """
        self.logger.info("Detected firewalld, disabling")
        result = subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
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

    async def restart_firewall(self) -> Dict:
        """
        Restart firewalld.

        Returns:
            Dict with success status and message
        """
        self.logger.info("Detected firewalld, restarting")
        result = subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
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

    def get_current_ports(self) -> Dict[int, Dict[str, bool]]:
        """Get current open ports from firewalld."""
        current_ports = {}
        try:
            result = subprocess.run(  # nosec B603 B607
                ["sudo", "firewall-cmd", "--list-ports"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                # Parse firewalld output: "22/tcp 80/tcp 443/tcp 53/udp"
                for port_spec in result.stdout.strip().split():
                    match = re.match(r"(\d+)/(tcp|udp)", port_spec)
                    if match:
                        port = int(match.group(1))
                        protocol = match.group(2)
                        if port not in current_ports:
                            current_ports[port] = {"tcp": False, "udp": False}
                        current_ports[port][protocol] = True
        except Exception as exc:
            self.logger.warning("Failed to get current firewalld ports: %s", exc)
        return current_ports

    async def apply_firewall_roles(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """Apply firewall roles using firewalld (synchronize - add and remove)."""
        self.logger.info("Synchronizing firewall roles using firewalld")

        errors = []

        # Get agent communication ports (must always be preserved)
        agent_ports, _ = self._get_agent_communication_ports()
        # Also preserve SSH port 22
        preserved_ports = set(agent_ports + [22])

        # Build desired port configuration from both IPv4 and IPv6
        desired_ports = {}
        for port_config in ipv4_ports + ipv6_ports:
            port = port_config.get("port")
            tcp = port_config.get("tcp", False)
            udp = port_config.get("udp", False)

            if port not in desired_ports:
                desired_ports[port] = {"tcp": False, "udp": False}
            if tcp:
                desired_ports[port]["tcp"] = True
            if udp:
                desired_ports[port]["udp"] = True

        # Get current open ports
        current_ports = self.get_current_ports()

        self.logger.info(
            "Current ports: %s, Desired ports: %s, Preserved: %s",
            list(current_ports.keys()),
            list(desired_ports.keys()),
            list(preserved_ports),
        )

        # Remove ports that are no longer needed
        self._remove_unneeded_ports(current_ports, desired_ports, preserved_ports)

        # Add new ports
        errors = self._add_new_ports(desired_ports, current_ports)

        # Reload firewalld to apply changes
        self._reload_firewalld()

        # Send updated firewall status
        await self._send_firewall_status_update()

        if errors:
            return {
                "success": False,
                "error": "; ".join(errors),
                "message": _(  # pylint: disable=not-callable
                    "Some firewall rules failed to apply"
                ),
            }

        return {
            "success": True,
            "message": _(  # pylint: disable=not-callable
                "Firewall roles synchronized successfully via firewalld"
            ),
        }

    def _remove_port_rule(self, port: int, protocol: str) -> None:
        """Remove a single firewalld port rule."""
        self.logger.info("Removing firewalld rule: remove-port %d/%s", port, protocol)
        result = subprocess.run(  # nosec B603 B607
            [
                "sudo",
                "firewall-cmd",
                "--permanent",
                f"--remove-port={port}/{protocol}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            self.logger.warning(
                "Failed to remove firewalld rule for port %d/%s: %s",
                port,
                protocol,
                result.stderr,
            )

    def _remove_port_protocols(
        self, port: int, protocols: Dict[str, bool], desired: Dict[str, bool] = None
    ) -> None:
        """Remove TCP and/or UDP rules for a port based on desired state."""
        if desired is None:
            if protocols.get("tcp"):
                self._remove_port_rule(port, "tcp")
            if protocols.get("udp"):
                self._remove_port_rule(port, "udp")
        else:
            if protocols.get("tcp") and not desired.get("tcp"):
                self._remove_port_rule(port, "tcp")
            if protocols.get("udp") and not desired.get("udp"):
                self._remove_port_rule(port, "udp")

    def _remove_unneeded_ports(
        self,
        current_ports: Dict[int, Dict[str, bool]],
        desired_ports: Dict[int, Dict[str, bool]],
        preserved_ports: set,
    ) -> None:
        """Remove ports that are no longer needed."""
        for port, protocols in current_ports.items():
            if port in preserved_ports:
                continue

            if port not in desired_ports:
                self._remove_port_protocols(port, protocols)
            else:
                self._remove_port_protocols(port, protocols, desired_ports[port])

    def _add_new_ports(
        self,
        desired_ports: Dict[int, Dict[str, bool]],
        current_ports: Dict[int, Dict[str, bool]],
    ) -> List[str]:
        """Add new ports and return list of errors."""
        errors = []
        for port, protocols in desired_ports.items():
            current = current_ports.get(port, {"tcp": False, "udp": False})

            if protocols.get("tcp") and not current.get("tcp"):
                self.logger.info("Adding firewalld rule: add-port %d/tcp", port)
                result = subprocess.run(  # nosec B603 B607
                    [
                        "sudo",
                        "firewall-cmd",
                        "--permanent",
                        f"--add-port={port}/tcp",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append(f"Failed to add TCP port {port}: {result.stderr}")
                    self.logger.warning(
                        "Failed to add firewalld rule for port %d/tcp: %s",
                        port,
                        result.stderr,
                    )

            if protocols.get("udp") and not current.get("udp"):
                self.logger.info("Adding firewalld rule: add-port %d/udp", port)
                result = subprocess.run(  # nosec B603 B607
                    [
                        "sudo",
                        "firewall-cmd",
                        "--permanent",
                        f"--add-port={port}/udp",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append(f"Failed to add UDP port {port}: {result.stderr}")
                    self.logger.warning(
                        "Failed to add firewalld rule for port %d/udp: %s",
                        port,
                        result.stderr,
                    )
        return errors

    def _reload_firewalld(self) -> None:
        """Reload firewalld to apply changes."""
        self.logger.info("Reloading firewalld to apply changes")
        result = subprocess.run(  # nosec B603 B607
            ["sudo", "firewall-cmd", "--reload"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0:
            self.logger.warning("Failed to reload firewalld: %s", result.stderr)

    def _remove_port_with_error_tracking(
        self, port: int, protocol: str, errors: List[str]
    ) -> None:
        """Remove a firewalld port rule with error tracking for removal operations."""
        self.logger.info("Removing firewalld rule: remove-port %d/%s", port, protocol)
        result = subprocess.run(  # nosec B603 B607
            [
                "sudo",
                "firewall-cmd",
                "--permanent",
                f"--remove-port={port}/{protocol}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0 and "NOT_ENABLED" not in result.stderr:
            errors.append(
                f"Failed to remove {protocol.upper()} port {port}: {result.stderr}"
            )
            self.logger.warning(
                "Failed to remove firewalld rule for port %d/%s: %s",
                port,
                protocol,
                result.stderr,
            )

    def _build_ports_dict(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict[int, Dict[str, bool]]:
        """Build a consolidated ports dictionary from IPv4 and IPv6 port lists."""
        ports = {}
        for port_config in ipv4_ports + ipv6_ports:
            port = port_config.get("port")
            tcp = port_config.get("tcp", False)
            udp = port_config.get("udp", False)

            if port not in ports:
                ports[port] = {"tcp": False, "udp": False}
            if tcp:
                ports[port]["tcp"] = True
            if udp:
                ports[port]["udp"] = True
        return ports

    async def remove_firewall_ports(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """Remove specific firewall ports using firewalld."""
        self.logger.info("Removing specific firewall ports using firewalld")

        errors: List[str] = []

        agent_ports, _ = self._get_agent_communication_ports()
        preserved_ports = set(agent_ports + [22])

        ports_to_remove = self._build_ports_dict(ipv4_ports, ipv6_ports)

        self.logger.info(
            "Ports to remove: %s, Preserved (will not remove): %s",
            list(ports_to_remove.keys()),
            list(preserved_ports),
        )

        for port, protocols in ports_to_remove.items():
            if port in preserved_ports:
                self.logger.info(
                    "Skipping removal of preserved port %d (agent/SSH)", port
                )
                continue

            if protocols.get("tcp"):
                self._remove_port_with_error_tracking(port, "tcp", errors)
            if protocols.get("udp"):
                self._remove_port_with_error_tracking(port, "udp", errors)

        self._reload_firewalld()
        await self._send_firewall_status_update()

        if errors:
            return {
                "success": False,
                "error": "; ".join(errors),
                "message": _(  # pylint: disable=not-callable
                    "Some firewall rules failed to remove"
                ),
            }

        return {
            "success": True,
            "message": _(  # pylint: disable=not-callable
                "Firewall ports removed successfully via firewalld"
            ),
        }
