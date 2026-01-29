"""
Linux-specific firewall operations for SysManage Agent.
Supports ufw (Ubuntu/Debian) and firewalld (RHEL/CentOS/Fedora).

This module delegates to specialized helper modules:
- firewall_linux_ufw.py for UFW operations
- firewall_linux_firewalld.py for firewalld operations

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

from typing import Dict, List

from src.i18n import _  # pylint: disable=not-callable
from src.sysmanage_agent.operations.firewall_base import FirewallBase
from src.sysmanage_agent.operations.firewall_linux_firewalld import FirewalldOperations
from src.sysmanage_agent.operations.firewall_linux_ufw import UfwOperations

# Constant for error message when no supported firewall is found
NO_SUPPORTED_FIREWALL_MSG = "No supported firewall found on this system"


class LinuxFirewallOperations(FirewallBase):
    """Manages firewall operations on Linux systems."""

    def __init__(self, agent, logger=None):
        """Initialize Linux firewall operations with helper modules."""
        super().__init__(agent, logger)
        self._ufw = None
        self._firewalld = None

    def _get_ufw(self) -> UfwOperations:
        """Lazy initialization of UFW operations."""
        if self._ufw is None:
            self._ufw = UfwOperations(
                logger=self.logger,
                get_agent_ports_func=self._get_agent_communication_ports,
                send_status_func=self._send_firewall_status_update,
            )
        return self._ufw

    def _get_firewalld(self) -> FirewalldOperations:
        """Lazy initialization of firewalld operations."""
        if self._firewalld is None:
            self._firewalld = FirewalldOperations(
                logger=self.logger,
                get_agent_ports_func=self._get_agent_communication_ports,
                send_status_func=self._send_firewall_status_update,
            )
        return self._firewalld

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
        if UfwOperations.is_available():
            return await self._get_ufw().enable_firewall(ports, protocol)

        # Try firewalld (RHEL/CentOS/Fedora)
        if FirewalldOperations.is_available():
            return await self._get_firewalld().enable_firewall(ports, protocol)

        return {
            "success": False,
            "error": _(NO_SUPPORTED_FIREWALL_MSG),
        }

    async def disable_firewall(self) -> Dict:
        """
        Disable firewall on Linux systems.

        Tries ufw first (Ubuntu/Debian), then firewalld (RHEL/CentOS/Fedora).

        Returns:
            Dict with success status and message
        """
        # Try ufw first (Ubuntu/Debian)
        if UfwOperations.is_available():
            return await self._get_ufw().disable_firewall()

        # Try firewalld (RHEL/CentOS/Fedora)
        if FirewalldOperations.is_available():
            return await self._get_firewalld().disable_firewall()

        return {
            "success": False,
            "error": _(NO_SUPPORTED_FIREWALL_MSG),
        }

    async def restart_firewall(self) -> Dict:
        """
        Restart firewall on Linux systems.

        Tries ufw first (Ubuntu/Debian), then firewalld (RHEL/CentOS/Fedora).

        Returns:
            Dict with success status and message
        """
        # Try ufw first (Ubuntu/Debian)
        if UfwOperations.is_available():
            return await self._get_ufw().restart_firewall()

        # Try firewalld (RHEL/CentOS/Fedora)
        if FirewalldOperations.is_available():
            return await self._get_firewalld().restart_firewall()

        return {
            "success": False,
            "error": _(NO_SUPPORTED_FIREWALL_MSG),
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

    async def apply_firewall_roles(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """
        Apply firewall roles by configuring open ports.

        This applies a default-deny policy where only the specified ports are allowed.
        Agent communication ports and SSH are always preserved to prevent lockout.

        Args:
            ipv4_ports: List of {port, tcp, udp} for IPv4
            ipv6_ports: List of {port, tcp, udp} for IPv6

        Returns:
            Dict with success status and message
        """
        # Try ufw first (Ubuntu/Debian)
        if UfwOperations.is_available():
            return await self._get_ufw().apply_firewall_roles(ipv4_ports, ipv6_ports)

        # Try firewalld (RHEL/CentOS/Fedora)
        if FirewalldOperations.is_available():
            return await self._get_firewalld().apply_firewall_roles(
                ipv4_ports, ipv6_ports
            )

        return {
            "success": False,
            "error": _(NO_SUPPORTED_FIREWALL_MSG),
        }

    async def remove_firewall_ports(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """
        Remove specific firewall ports (explicit removal, not sync).

        This removes only the specified ports from the firewall.
        Used when a firewall role is removed from a host.

        Args:
            ipv4_ports: List of {port, tcp, udp} for IPv4 to remove
            ipv6_ports: List of {port, tcp, udp} for IPv6 to remove

        Returns:
            Dict with success status and message
        """
        # Try ufw first (Ubuntu/Debian)
        if UfwOperations.is_available():
            return await self._get_ufw().remove_firewall_ports(ipv4_ports, ipv6_ports)

        # Try firewalld (RHEL/CentOS/Fedora)
        if FirewalldOperations.is_available():
            return await self._get_firewalld().remove_firewall_ports(
                ipv4_ports, ipv6_ports
            )

        return {
            "success": False,
            "error": _(NO_SUPPORTED_FIREWALL_MSG),  # pylint: disable=not-callable
        }

    def configure_lxd_firewall(self, bridge_name: str = "lxdbr0") -> Dict:
        """
        Configure firewall for LXD container networking.

        This sets up IP forwarding, NAT masquerade, and forwarding rules
        to allow LXD containers on the specified bridge to access the network.

        Args:
            bridge_name: Name of the LXD bridge (default: lxdbr0)

        Returns:
            Dict with success status and message
        """
        # Try ufw first (Ubuntu/Debian)
        if UfwOperations.is_available():
            return self._get_ufw().configure_lxd_firewall(bridge_name)

        # firewalld doesn't need special configuration for LXD
        # as it typically handles this automatically with zones
        if FirewalldOperations.is_available():
            self.logger.info(
                "firewalld detected - LXD networking should work automatically"
            )
            return {
                "success": True,
                "message": _(
                    "firewalld detected - LXD networking configured automatically"
                ),
            }

        return {
            "success": False,
            "error": _(NO_SUPPORTED_FIREWALL_MSG),
        }
