"""
UFW-specific firewall operations for Linux systems.
Used by LinuxFirewallOperations for Ubuntu/Debian systems.

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

import logging
import re
import subprocess  # nosec B404
from typing import Callable, Dict, List, Tuple

from src.i18n import _  # pylint: disable=not-callable

# Log message constants for ufw rule operations
LOG_REMOVE_TCP_RULE = "Removing ufw rule: delete allow %d/tcp"
LOG_REMOVE_UDP_RULE = "Removing ufw rule: delete allow %d/udp"


class UfwOperations:
    """Handles UFW firewall operations on Ubuntu/Debian systems."""

    def __init__(
        self,
        logger: logging.Logger,
        get_agent_ports_func: Callable[[], Tuple[List[int], str]],
        send_status_func: Callable,
    ):
        """
        Initialize UFW operations.

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
        """Check if ufw is available on this system."""
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "ufw"],
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
        Enable UFW firewall.

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        self.logger.info("Detected ufw firewall")

        # Always ensure SSH (port 22) is allowed to prevent lockout
        self.logger.info("Adding ufw rule: allow 22/tcp (SSH)")
        result = subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
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
            result = subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
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
        result = subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
            ["sudo", "ufw", "--force", "enable"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode == 0:
            self.logger.info("UFW firewall enabled successfully")
            await self._send_firewall_status_update()
            return {
                "success": True,
                "message": _("UFW firewall enabled successfully"),
            }
        return {
            "success": False,
            "error": f"Failed to enable ufw: {result.stderr}",
        }

    async def disable_firewall(self) -> Dict:
        """
        Disable UFW firewall.

        Returns:
            Dict with success status and message
        """
        self.logger.info("Detected ufw firewall, disabling")
        result = subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
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

    async def restart_firewall(self) -> Dict:
        """
        Restart (reload) UFW firewall.

        Returns:
            Dict with success status and message
        """
        self.logger.info("Detected ufw firewall, restarting")
        # UFW doesn't have a restart command, but we can reload it
        result = subprocess.run(  # nosec B603 B607  # NOSONAR - sync subprocess acceptable for quick firewall commands
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

    def get_current_ports(self) -> Dict[int, Dict[str, bool]]:
        """Get current open ports from ufw status."""
        current_ports = {}
        try:
            result = subprocess.run(  # nosec B603 B607
                ["sudo", "ufw", "status"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                # Parse ufw status output to extract open ports
                # Format: "22/tcp                     ALLOW       Anywhere"
                for line in result.stdout.split("\n"):
                    # Match port/protocol patterns
                    match = re.match(r"(\d+)/(tcp|udp)\s+ALLOW", line.strip())
                    if match:
                        port = int(match.group(1))
                        protocol = match.group(2)
                        if port not in current_ports:
                            current_ports[port] = {"tcp": False, "udp": False}
                        current_ports[port][protocol] = True
        except Exception as exc:
            self.logger.warning("Failed to get current ufw ports: %s", exc)
        return current_ports

    async def apply_firewall_roles(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """Apply firewall roles using ufw (synchronize - add and remove ports)."""
        self.logger.info("Synchronizing firewall roles using ufw")

        errors = []

        # Get agent communication ports (must always be preserved)
        agent_ports, _ = self._get_agent_communication_ports()
        # Also preserve SSH port 22 and LXD bridge ports (53=DNS, 67=DHCP)
        # LXD ports are needed for container networking on lxdbr0
        preserved_ports = set(agent_ports + [22, 53, 67])

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

        # Reload ufw to apply changes
        self._reload_ufw()

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
                "Firewall roles synchronized successfully via ufw"
            ),
        }

    def _remove_port_rule(self, port: int, protocol: str) -> None:
        """Remove a single ufw port rule."""
        self.logger.info("Removing ufw rule: delete allow %d/%s", port, protocol)
        result = subprocess.run(  # nosec B603 B607
            ["sudo", "ufw", "delete", "allow", f"{port}/{protocol}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            self.logger.warning(
                "Failed to remove ufw rule for port %d/%s: %s",
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
                self.logger.info("Adding ufw rule: allow %d/tcp", port)
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "ufw", "allow", f"{port}/tcp"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append(f"Failed to add TCP port {port}: {result.stderr}")
                    self.logger.warning(
                        "Failed to add ufw rule for port %d/tcp: %s",
                        port,
                        result.stderr,
                    )

            if protocols.get("udp") and not current.get("udp"):
                self.logger.info("Adding ufw rule: allow %d/udp", port)
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "ufw", "allow", f"{port}/udp"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append(f"Failed to add UDP port {port}: {result.stderr}")
                    self.logger.warning(
                        "Failed to add ufw rule for port %d/udp: %s",
                        port,
                        result.stderr,
                    )
        return errors

    def _reload_ufw(self) -> None:
        """Reload ufw to apply changes."""
        self.logger.info("Reloading ufw to apply changes")
        result = subprocess.run(  # nosec B603 B607
            ["sudo", "ufw", "reload"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0:
            self.logger.warning("Failed to reload ufw: %s", result.stderr)

    def _enable_ip_forwarding(self, errors: List[str]) -> None:
        """Enable IP forwarding for LXD container networking."""
        self.logger.info("Enabling IP forwarding")
        try:
            with open(
                "/proc/sys/net/ipv4/ip_forward", "r", encoding="utf-8"
            ) as file_handle:
                current_value = file_handle.read().strip()

            if current_value == "1":
                return

            result = subprocess.run(  # nosec B603 B607
                ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                errors.append(f"Failed to enable IP forwarding: {result.stderr}")

            self._persist_ip_forwarding()
        except Exception as exc:
            errors.append(f"Error configuring IP forwarding: {exc}")

    def _persist_ip_forwarding(self) -> None:
        """Persist IP forwarding setting in sysctl.conf."""
        sysctl_line = "net.ipv4.ip_forward=1"
        result = subprocess.run(  # nosec B603 B607
            [
                "sudo",
                "sh",
                "-c",
                f"grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf && "
                f"sudo sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' "
                f"/etc/sysctl.conf || echo '{sysctl_line}' >> /etc/sysctl.conf",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            self.logger.warning(
                "Could not persist IP forwarding setting: %s", result.stderr
            )

    def _set_forward_policy(self, errors: List[str]) -> None:
        """Set UFW default forward policy to ACCEPT."""
        self.logger.info("Setting UFW default forward policy to ACCEPT")
        result = subprocess.run(  # nosec B603 B607
            [
                "sudo",
                "sed",
                "-i",
                's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/',
                "/etc/default/ufw",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            errors.append(f"Failed to set forward policy: {result.stderr}")

    def _add_lxd_bridge_rules(self, bridge_name: str) -> None:
        """Add UFW rules for LXD bridge traffic."""
        self.logger.info("Adding UFW rules for LXD bridge")

        ufw_rules = [
            ["sudo", "ufw", "route", "allow", "in", "on", bridge_name],
            ["sudo", "ufw", "route", "allow", "out", "on", bridge_name],
            [
                "sudo",
                "ufw",
                "allow",
                "in",
                "on",
                bridge_name,
                "to",
                "any",
                "port",
                "67",
                "proto",
                "udp",
            ],
            [
                "sudo",
                "ufw",
                "allow",
                "in",
                "on",
                bridge_name,
                "to",
                "any",
                "port",
                "53",
            ],
        ]

        for rule in ufw_rules:
            result = subprocess.run(  # nosec B603 B607
                rule,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if (
                result.returncode != 0
                and "Skipping" not in result.stdout
                and "already exists" not in result.stderr
            ):
                self.logger.warning(
                    "UFW rule failed: %s - %s", " ".join(rule), result.stderr
                )

    def _configure_nat_masquerade(self, bridge_name: str, errors: List[str]) -> None:
        """Configure NAT masquerade for LXD containers."""
        self.logger.info("Configuring NAT masquerade for LXD")
        nat_rules = self._generate_ufw_nat_rules(bridge_name)

        try:
            with open("/etc/ufw/before.rules", "r", encoding="utf-8") as file_handle:
                before_rules_content = file_handle.read()

            if "# LXD NAT rules" in before_rules_content:
                self.logger.info("NAT rules already configured in before.rules")
                return

            result = subprocess.run(  # nosec B603 B607
                [
                    "sudo",
                    "sh",
                    "-c",
                    f"cat /etc/ufw/before.rules > /tmp/ufw_before.rules.bak && "
                    f"echo '{nat_rules}' | cat - /tmp/ufw_before.rules.bak | "
                    f"sudo tee /etc/ufw/before.rules > /dev/null",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                errors.append(f"Failed to add NAT rules: {result.stderr}")
        except Exception as exc:
            errors.append(f"Error configuring NAT rules: {exc}")

    def configure_lxd_firewall(self, bridge_name: str = "lxdbr0") -> Dict:
        """
        Configure UFW to allow LXD container networking.

        Args:
            bridge_name: Name of the LXD bridge (default: lxdbr0)

        Returns:
            Dict with success status and message
        """
        self.logger.info("Configuring UFW firewall for LXD bridge: %s", bridge_name)
        errors: List[str] = []

        self._enable_ip_forwarding(errors)
        self._set_forward_policy(errors)
        self._add_lxd_bridge_rules(bridge_name)
        self._configure_nat_masquerade(bridge_name, errors)

        self.logger.info("Reloading UFW to apply LXD firewall rules")
        result = subprocess.run(  # nosec B603 B607
            ["sudo", "ufw", "reload"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            errors.append(f"Failed to reload UFW: {result.stderr}")

        if errors:
            return {
                "success": False,
                "error": "; ".join(errors),
                "message": _("Some LXD firewall rules failed to apply"),
            }

        return {
            "success": True,
            "message": _("UFW firewall configured for LXD successfully"),
        }

    def _generate_ufw_nat_rules(self, bridge_name: str) -> str:
        """Generate NAT rules for UFW before.rules file."""
        # Get the LXD bridge subnet
        subnet = "10.0.0.0/8"  # NOSONAR - default private subnet for LXD networking

        # Try to get actual subnet from the bridge
        try:
            result = subprocess.run(  # nosec B603 B607
                ["ip", "-o", "-4", "addr", "show", bridge_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Parse output like: "382: lxdbr0 inet 10.227.191.1/24 ..."
                parts = result.stdout.split()
                for i, part in enumerate(parts):
                    if part == "inet" and i + 1 < len(parts):
                        # Get the network address from the CIDR
                        addr_cidr = parts[i + 1]
                        # Convert e.g. 10.227.191.1/24 to 10.227.191.0/24
                        import ipaddress  # pylint: disable=import-outside-toplevel

                        network = ipaddress.ip_network(addr_cidr, strict=False)
                        subnet = str(network)
                        break
        except Exception:  # nosec B110 # uses default subnet 10.0.0.0/8 on failure
            pass

        nat_rules = f"""# LXD NAT rules - added by sysmanage-agent
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s {subnet} ! -d {subnet} -j MASQUERADE
COMMIT
# End LXD NAT rules

"""
        return nat_rules

    def _remove_port_with_error_tracking(
        self, port: int, protocol: str, errors: List[str]
    ) -> None:
        """Remove a ufw port rule with error tracking for removal operations."""
        self.logger.info("Removing ufw rule: delete allow %d/%s", port, protocol)
        result = subprocess.run(  # nosec B603 B607
            ["sudo", "ufw", "delete", "allow", f"{port}/{protocol}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            if "Could not delete non-existent rule" not in result.stderr:
                errors.append(
                    f"Failed to remove {protocol.upper()} port {port}: {result.stderr}"
                )
                self.logger.warning(
                    "Failed to remove ufw rule for port %d/%s: %s",
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
        """Remove specific firewall ports using ufw."""
        self.logger.info("Removing specific firewall ports using ufw")

        errors: List[str] = []

        agent_ports, _ = self._get_agent_communication_ports()
        preserved_ports = set(agent_ports + [22, 53, 67])

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

        self._reload_ufw()
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
                "Firewall ports removed successfully via ufw"
            ),
        }
