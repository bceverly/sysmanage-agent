"""
Firewall operations for SysManage Agent.
Manages firewall configuration including enabling, disabling, and modifying rules.

This module acts as an orchestrator that delegates to OS-specific firewall implementations.
"""

import logging
import platform
from typing import Dict, Optional

from src.i18n import _


class FirewallOperations:
    """Manages firewall operations across different operating systems."""

    def __init__(self, agent, logger: Optional[logging.Logger] = None):
        """Initialize the firewall operations manager."""
        self.agent = agent
        self.logger = logger or logging.getLogger(__name__)
        self.system = platform.system()
        self._os_handler = None

    def _get_os_handler(self):
        """
        Get the appropriate OS-specific firewall handler.

        Returns:
            OS-specific firewall operations instance
        """
        if self._os_handler is None:
            if self.system == "Linux":
                # pylint: disable=import-outside-toplevel
                from src.sysmanage_agent.operations.firewall_linux import (
                    LinuxFirewallOperations,
                )

                self._os_handler = LinuxFirewallOperations(self.agent, self.logger)
            elif self.system == "Windows":
                # pylint: disable=import-outside-toplevel
                from src.sysmanage_agent.operations.firewall_windows import (
                    WindowsFirewallOperations,
                )

                self._os_handler = WindowsFirewallOperations(self.agent, self.logger)
            elif self.system == "Darwin":  # macOS
                # pylint: disable=import-outside-toplevel
                from src.sysmanage_agent.operations.firewall_macos import (
                    MacOSFirewallOperations,
                )

                self._os_handler = MacOSFirewallOperations(self.agent, self.logger)
            elif self.system in ["FreeBSD", "OpenBSD", "NetBSD"]:
                # pylint: disable=import-outside-toplevel
                from src.sysmanage_agent.operations.firewall_bsd import (
                    BSDFirewallOperations,
                )

                self._os_handler = BSDFirewallOperations(self.agent, self.logger)
            else:
                raise ValueError(
                    _("Unsupported operating system for firewall operations")
                )

        return self._os_handler

    async def enable_firewall(self, _parameters: Dict) -> Dict:
        """
        Enable firewall and ensure agent communication ports are open.

        This will:
        1. Detect the firewall software on the system
        2. Dynamically determine which ports are needed for agent communication
        3. Add those ports to the firewall configuration
        4. Enable the firewall service
        5. Send updated firewall status back to server

        Args:
            parameters: Command parameters (unused for enable)

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Starting firewall enable operation")

            # Get the OS-specific handler
            handler = self._get_os_handler()

            # Get agent communication ports
            # pylint: disable=protected-access
            ports, protocol = handler._get_agent_communication_ports()

            # Check if SysManage server is running locally and add its ports
            # pylint: disable=protected-access
            server_ports = handler._get_local_server_ports()
            if server_ports:
                self.logger.info(
                    "SysManage server detected on this host, adding ports: %s",
                    server_ports,
                )
                # Combine agent and server ports
                all_ports = list(set(ports + server_ports))
            else:
                all_ports = ports

            # Delegate to OS-specific handler
            return await handler.enable_firewall(all_ports, protocol)

        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        except Exception as exc:
            self.logger.error("Error enabling firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def disable_firewall(self, _parameters: Dict) -> Dict:
        """
        Disable firewall on the system.

        Args:
            parameters: Command parameters (unused)

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Starting firewall disable operation")

            # Get the OS-specific handler
            handler = self._get_os_handler()

            # Delegate to OS-specific handler
            return await handler.disable_firewall()

        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        except Exception as exc:
            self.logger.error("Error disabling firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def restart_firewall(self, _parameters: Dict) -> Dict:
        """
        Restart firewall service on the system.

        Args:
            parameters: Command parameters (unused)

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Starting firewall restart operation")

            # Get the OS-specific handler
            handler = self._get_os_handler()

            # Delegate to OS-specific handler
            return await handler.restart_firewall()

        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        except Exception as exc:
            self.logger.error("Error restarting firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def deploy_firewall(self, _parameters: Dict) -> Dict:
        """
        Deploy (install and enable) firewall on the system.

        Args:
            _parameters: Command parameters (unused)

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Starting firewall deploy operation")

            # Get the appropriate firewall handler for the OS
            handler = self._get_os_handler()

            # Deploy the firewall
            return await handler.deploy_firewall()

        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        except Exception as exc:
            self.logger.error("Error deploying firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def apply_firewall_roles(self, parameters: Dict) -> Dict:
        """
        Apply firewall roles by configuring open ports based on assigned roles.

        This will:
        1. Parse the list of IPv4 and IPv6 ports to open
        2. Clear existing role-based ports
        3. Add the new ports to the firewall
        4. Send updated firewall status back to server

        Args:
            parameters: Command parameters containing:
                - ipv4_ports: List of {port, tcp, udp} for IPv4
                - ipv6_ports: List of {port, tcp, udp} for IPv6

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Starting apply firewall roles operation")

            ipv4_ports = parameters.get("ipv4_ports", [])
            ipv6_ports = parameters.get("ipv6_ports", [])

            self.logger.info(
                "Applying firewall roles: %d IPv4 ports, %d IPv6 ports",
                len(ipv4_ports),
                len(ipv6_ports),
            )

            # Get the OS-specific handler
            handler = self._get_os_handler()

            # Delegate to OS-specific handler
            return await handler.apply_firewall_roles(ipv4_ports, ipv6_ports)

        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        except Exception as exc:
            self.logger.error("Error applying firewall roles: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def remove_firewall_ports(self, parameters: Dict) -> Dict:
        """
        Remove specific firewall ports.

        This removes only the specified ports from the firewall, used when
        a firewall role is removed from a host. Unlike apply_firewall_roles,
        this does NOT sync to a desired state - it only removes the specified ports.

        Args:
            parameters: Command parameters containing:
                - ipv4_ports: List of {port, tcp, udp} for IPv4 to remove
                - ipv6_ports: List of {port, tcp, udp} for IPv6 to remove

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Starting remove firewall ports operation")

            ipv4_ports = parameters.get("ipv4_ports", [])
            ipv6_ports = parameters.get("ipv6_ports", [])

            self.logger.info(
                "Removing firewall ports: %d IPv4 ports, %d IPv6 ports",
                len(ipv4_ports),
                len(ipv6_ports),
            )

            # Get the OS-specific handler
            handler = self._get_os_handler()

            # Delegate to OS-specific handler
            return await handler.remove_firewall_ports(ipv4_ports, ipv6_ports)

        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        except Exception as exc:
            self.logger.error("Error removing firewall ports: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}
