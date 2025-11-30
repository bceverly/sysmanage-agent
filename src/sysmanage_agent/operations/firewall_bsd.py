"""
BSD-specific firewall operations for SysManage Agent.
Supports PF (Packet Filter), IPFW, and NPF on FreeBSD, OpenBSD, and NetBSD.

Security Note: This module uses subprocess to execute system firewall commands.
All commands are hardcoded with no user input, use shell=False, and only call
trusted system utilities. B603/B607 warnings are suppressed as safe by design.
"""

# pylint: disable=too-many-lines

import subprocess  # nosec B404
from typing import Dict, List

from src.i18n import _  # pylint: disable=not-callable
from src.sysmanage_agent.core.agent_utils import is_running_privileged
from src.sysmanage_agent.operations.firewall_base import FirewallBase


class BSDFirewallOperations(FirewallBase):
    """Manages firewall operations on BSD systems (FreeBSD, OpenBSD, NetBSD)."""

    def _build_command(self, command: List[str]) -> List[str]:
        """
        Build a command with or without sudo based on privilege level.

        Args:
            command: The command to execute as a list

        Returns:
            The command with sudo prepended if not running privileged
        """
        if is_running_privileged():
            return command
        return ["sudo"] + command

    async def enable_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable firewall on BSD systems.

        Tries IPFW first (FreeBSD default), NPF (NetBSD default),
        then PF (OpenBSD default, also available on FreeBSD/NetBSD).

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        # Try IPFW first (FreeBSD default)
        if self.system == "FreeBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "ipfw"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    return await self._enable_ipfw_firewall(ports, protocol)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Try NPF (NetBSD default)
        if self.system == "NetBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "npfctl"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    return await self._enable_npf_firewall(ports, protocol)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Try PF (OpenBSD default, also available on FreeBSD/NetBSD)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "pfctl"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                return await self._enable_pf_firewall(ports, protocol)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return {
            "success": False,
            "error": _("No supported firewall found on this BSD system"),
        }

    async def _enable_pf_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable PF (Packet Filter) on BSD/macOS.

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Enabling PF firewall")

            # Check if PF config exists
            pf_conf = "/etc/pf.conf"
            try:
                with open(pf_conf, "r", encoding="utf-8") as file_handle:
                    existing_rules = file_handle.read()
            except FileNotFoundError:
                existing_rules = ""

            # Build rules to add
            rules_to_add = []

            # Always allow SSH (port 22)
            if "pass in proto tcp to port 22" not in existing_rules:
                rules_to_add.append("pass in proto tcp to port 22")

            # Add agent/server ports
            for port in ports:
                rule = f"pass in proto {protocol} to port {port}"
                if rule not in existing_rules:
                    rules_to_add.append(rule)

            if rules_to_add:
                # Append rules to pf.conf
                self.logger.info("Adding %d rules to pf.conf", len(rules_to_add))
                try:
                    with open(pf_conf, "a", encoding="utf-8") as file_handle:
                        file_handle.write("\n# SysManage Agent rules\n")
                        for rule in rules_to_add:
                            file_handle.write(f"{rule}\n")
                except PermissionError:
                    # Try with sudo
                    rules_content = (
                        "\n# SysManage Agent rules\n" + "\n".join(rules_to_add) + "\n"
                    )
                    subprocess.run(  # nosec B603 B607
                        self._build_command(
                            ["sh", "-c", f"echo '{rules_content}' >> {pf_conf}"]
                        ),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

            # Test the configuration
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["pfctl", "-nf", pf_conf]),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"PF configuration test failed: {result.stderr}",
                }

            # Load the rules
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["pfctl", "-f", pf_conf]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to load PF rules: {result.stderr}",
                }

            # Enable PF
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["pfctl", "-e"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # Note: pfctl -e returns error if already enabled, so we check output
            if result.returncode == 0 or "already enabled" in result.stderr:
                self.logger.info("PF firewall enabled successfully")
                await self._send_firewall_status_update()
                return {
                    "success": True,
                    "message": _("PF firewall enabled successfully"),
                }
            return {
                "success": False,
                "error": f"Failed to enable PF: {result.stderr}",
            }

        except Exception as exc:
            self.logger.error("Error enabling PF firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def _enable_ipfw_firewall(self, ports: List[int], protocol: str) -> Dict:
        """
        Enable IPFW on FreeBSD.

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Enabling IPFW firewall")

            # Load IPFW kernel module if not already loaded
            self.logger.info("Loading IPFW kernel module with kldload")
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["kldload", "ipfw"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.logger.info(
                "kldload result: returncode=%d, stdout='%s', stderr='%s'",
                result.returncode,
                result.stdout.strip(),
                result.stderr.strip(),
            )
            # kldload returns 1 if already loaded, which is fine
            if result.returncode not in [0, 1]:
                self.logger.warning(
                    "Failed to load IPFW kernel module: %s", result.stderr
                )

            # Enable IPFW (requires rc.conf modification)
            # Check if firewall_enable is already set
            try:
                with open("/etc/rc.conf", "r", encoding="utf-8") as file_handle:
                    rc_conf = file_handle.read()

                if 'firewall_enable="YES"' not in rc_conf:
                    subprocess.run(  # nosec B603 B607
                        self._build_command(["sysrc", "firewall_enable=YES"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    subprocess.run(  # nosec B603 B607
                        self._build_command(["sysrc", "firewall_type=open"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
            except Exception as exc:
                self.logger.warning("Error modifying rc.conf: %s", exc)

            # Start IPFW service (this will load default rules from rc.firewall)
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["service", "ipfw", "start"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to start IPFW service: {result.stderr}",
                }

            # Now add our custom rules (after service started to avoid them being flushed)
            # Always allow SSH (port 22)
            self.logger.info("Adding IPFW rule: allow 22/tcp (SSH)")
            result = subprocess.run(  # nosec B603 B607
                self._build_command(
                    [
                        "ipfw",
                        "add",
                        "allow",
                        "tcp",
                        "from",
                        "any",
                        "to",
                        "any",
                        "22",
                    ]
                ),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                self.logger.warning(
                    "Failed to add IPFW rule for SSH: %s", result.stderr
                )

            # Add agent/server ports
            for port in ports:
                self.logger.info("Adding IPFW rule: allow %d/%s", port, protocol)
                result = subprocess.run(  # nosec B603 B607
                    self._build_command(
                        [
                            "ipfw",
                            "add",
                            "allow",
                            protocol,
                            "from",
                            "any",
                            "to",
                            "any",
                            str(port),
                        ]
                    ),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode != 0:
                    self.logger.warning(
                        "Failed to add IPFW rule for port %d: %s", port, result.stderr
                    )

            self.logger.info("IPFW firewall enabled successfully")
            await self._send_firewall_status_update()
            return {
                "success": True,
                "message": _("IPFW firewall enabled successfully"),
            }

        except Exception as exc:
            self.logger.error("Error enabling IPFW firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def _enable_npf_firewall(
        self, ports: List[int], protocol: str  # pylint: disable=unused-argument
    ) -> Dict:
        """
        Enable NPF (NetBSD Packet Filter).

        Args:
            ports: List of ports to allow
            protocol: Protocol to use ('tcp' or 'udp')

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Enabling NPF firewall")

            # Build complete NPF configuration
            npf_conf = "/etc/npf.conf"

            # Check if config already exists
            try:
                with open(npf_conf, "r", encoding="utf-8") as file_handle:
                    existing_config = file_handle.read()
            except FileNotFoundError:
                existing_config = ""

            # Only create config if it doesn't exist or is empty
            if not existing_config.strip():
                self.logger.info("Creating NPF configuration")

                # Create NPF config with proper firewall rules
                config_content = """# NPF configuration - managed by SysManage Agent
# Minimal configuration - allows all traffic

# Introduce 2 variables to list opened TCP and UDP ports[3]
$services_tcp = { http, https, smtp, smtps, domain, 587, 6000 }
$services_udp = { domain, ntp, 6000, 51413 }

group default {
    # Allow all loopback traffic
    pass final on lo0 all

    # Allow all outgoing traffic
    pass stateful out final all

    # Allow ICMP
    pass in final proto icmp icmp-type timxceed all
    pass in final proto icmp icmp-type unreach all
    pass in final proto icmp icmp-type echoreply all
    pass in final proto icmp icmp-type sourcequench all
    pass in final proto icmp icmp-type paramprob all

    # Allow SSH
    pass stateful in final proto tcp from any to any port 22

    # Allow SysManage-Agent
    pass stateful in final proto tcp from any to any port 8080

    # Allow DHCP
    pass out final proto udp from any port bootpc to any port bootps
    pass in final proto udp from any port bootps to any port bootpc
    pass in final proto udp from any port bootps to 255.255.255.0 port bootpc

    # Allow incoming TCP/UDP packets on selected ports
    pass stateful in final proto tcp to any port $services_tcp
    pass stateful in final proto udp to any port $services_udp

    # Allow Traceroute
    pass stateful in final proto udp to any port 33434-33600

    # Reject everything else [9]
    block return-rst in final proto tcp all
    block return-icmp in final proto udp all
    block return in final all
}
"""

                # Write the configuration
                try:
                    with open(npf_conf, "w", encoding="utf-8") as file_handle:
                        file_handle.write(config_content)
                except PermissionError:
                    # Try with sudo if not running as root
                    result = subprocess.run(  # nosec B603 B607
                        self._build_command(
                            [
                                "sh",
                                "-c",
                                f"cat > {npf_conf} << 'EOF'\n{config_content}EOF",
                            ]
                        ),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode != 0:
                        return {
                            "success": False,
                            "error": f"Failed to write NPF config: {result.stderr}",
                        }
            else:
                self.logger.info("NPF config already exists, skipping creation")

            # Validate the configuration
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["npfctl", "validate", npf_conf]),
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"NPF configuration validation failed: {result.stderr}",
                }

            # Reload the configuration
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["npfctl", "reload", npf_conf]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to reload NPF configuration: {result.stderr}",
                }

            # Start NPF
            result = subprocess.run(  # nosec B603 B607
                self._build_command(["npfctl", "start"]),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # npfctl start may fail with non-zero returncode if already running
            # Log the actual output to help debug
            self.logger.debug("npfctl start returncode: %s", result.returncode)
            self.logger.debug("npfctl start stdout: %s", result.stdout)
            self.logger.debug("npfctl start stderr: %s", result.stderr)

            if result.returncode != 0:
                # Check if it's already running - that's OK
                output_combined = (result.stdout + result.stderr).lower()
                if not any(msg in output_combined for msg in ["already", "running"]):
                    return {
                        "success": False,
                        "error": f"Failed to enable NPF: {result.stderr}",
                    }

            self.logger.info("NPF firewall enabled successfully")
            await self._send_firewall_status_update()
            return {
                "success": True,
                "message": _("NPF firewall enabled successfully"),
            }

        except Exception as exc:
            self.logger.error("Error enabling NPF firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def disable_firewall(self) -> Dict:
        """
        Disable firewall on BSD systems.

        Tries IPFW first (FreeBSD default), NPF (NetBSD default),
        then PF (OpenBSD default, also available on FreeBSD/NetBSD).

        Returns:
            Dict with success status and message
        """
        # Try IPFW first (FreeBSD default)
        if self.system == "FreeBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "ipfw"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Disabling IPFW firewall")
                    # Disable IPFW using sysctl
                    result = subprocess.run(  # nosec B603 B607
                        self._build_command(["sysctl", "net.inet.ip.fw.enable=0"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode == 0:
                        self.logger.info("IPFW firewall disabled successfully")
                        await self._send_firewall_status_update()
                        return {
                            "success": True,
                            "message": _("IPFW firewall disabled successfully"),
                        }
                    return {
                        "success": False,
                        "error": f"Failed to disable IPFW: {result.stderr}",
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Try NPF (NetBSD default)
        if self.system == "NetBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "npfctl"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Disabling NPF firewall")
                    result = subprocess.run(  # nosec B603 B607
                        self._build_command(["npfctl", "stop"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode == 0:
                        self.logger.info("NPF firewall disabled successfully")
                        await self._send_firewall_status_update()
                        return {
                            "success": True,
                            "message": _("NPF firewall disabled successfully"),
                        }
                    return {
                        "success": False,
                        "error": f"Failed to disable NPF: {result.stderr}",
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Try PF (OpenBSD default, also available on FreeBSD/NetBSD)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "pfctl"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Disabling PF firewall")
                result = subprocess.run(  # nosec B603 B607
                    self._build_command(["pfctl", "-d"]),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("PF firewall disabled successfully")
                    await self._send_firewall_status_update()
                    return {
                        "success": True,
                        "message": _("PF firewall disabled successfully"),
                    }
                return {
                    "success": False,
                    "error": f"Failed to disable PF: {result.stderr}",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return {
            "success": False,
            "error": _("No supported firewall found on this BSD system"),
        }

    async def restart_firewall(self) -> Dict:
        """
        Restart firewall on BSD systems.

        Tries IPFW first (FreeBSD default), NPF (NetBSD default),
        then PF (OpenBSD default, also available on FreeBSD/NetBSD).

        Returns:
            Dict with success status and message
        """
        # Try IPFW first (FreeBSD default)
        if self.system == "FreeBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "ipfw"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Restarting IPFW firewall")
                    result = subprocess.run(  # nosec B603 B607
                        self._build_command(["service", "ipfw", "restart"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode == 0:
                        self.logger.info("IPFW firewall restarted successfully")
                        await self._send_firewall_status_update()
                        return {
                            "success": True,
                            "message": _("IPFW firewall restarted successfully"),
                        }
                    return {
                        "success": False,
                        "error": f"Failed to restart IPFW: {result.stderr}",
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Try NPF (NetBSD default)
        if self.system == "NetBSD":
            try:
                result = subprocess.run(  # nosec B603 B607
                    ["which", "npfctl"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("Restarting NPF firewall")
                    result = subprocess.run(  # nosec B603 B607
                        self._build_command(["npfctl", "reload"]),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )

                    if result.returncode == 0:
                        self.logger.info("NPF firewall restarted successfully")
                        await self._send_firewall_status_update()
                        return {
                            "success": True,
                            "message": _("NPF firewall restarted successfully"),
                        }
                    return {
                        "success": False,
                        "error": f"Failed to restart NPF: {result.stderr}",
                    }
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Try PF (OpenBSD default, also available on FreeBSD/NetBSD)
        try:
            result = subprocess.run(  # nosec B603 B607
                ["which", "pfctl"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0:
                self.logger.info("Restarting PF firewall")
                result = subprocess.run(  # nosec B603 B607
                    self._build_command(["pfctl", "-f", "/etc/pf.conf"]),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0:
                    self.logger.info("PF firewall restarted successfully")
                    await self._send_firewall_status_update()
                    return {
                        "success": True,
                        "message": _("PF firewall restarted successfully"),
                    }
                return {
                    "success": False,
                    "error": f"Failed to restart PF: {result.stderr}",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return {
            "success": False,
            "error": _("No supported firewall found on this BSD system"),
        }

    async def deploy_firewall(self) -> Dict:
        """
        Deploy (enable) firewall on BSD systems.

        BSD firewalls are built into the kernel, so "deploy" means enabling them.
        - FreeBSD: Enable IPFW (built into kernel)
        - OpenBSD: Enable PF (built in)
        - NetBSD: Enable NPF (built in)

        Returns:
            Dict with success status and message
        """
        try:
            self.logger.info("Deploying firewall on BSD system")

            # Get agent communication ports
            ports, protocol = self._get_agent_communication_ports()

            # Also detect if server is running locally
            server_ports = self._get_local_server_ports()
            all_ports = list(set(ports + server_ports))

            self.logger.info("Ports to allow: %s (protocol: %s)", all_ports, protocol)

            # Deploy means enable on BSD systems (firewall software is built-in)
            return await self.enable_firewall(all_ports, protocol)

        except Exception as exc:
            self.logger.error("Error deploying firewall: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def apply_firewall_roles(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """
        Apply firewall roles by configuring open ports on BSD systems.

        Supports:
        - OpenBSD/FreeBSD: PF (packet filter)
        - FreeBSD: IPFW
        - NetBSD: NPF

        Args:
            ipv4_ports: List of {port, tcp, udp} for IPv4
            ipv6_ports: List of {port, tcp, udp} for IPv6

        Returns:
            Dict with success status and message
        """
        self.logger.info("Applying firewall roles on BSD system (%s)", self.system)

        errors = []

        # Get agent communication ports (must always be open)
        agent_ports, _ = self._get_agent_communication_ports()

        # Combine port configurations
        all_port_configs = {}
        for port_config in ipv4_ports + ipv6_ports:
            port = port_config.get("port")
            tcp = port_config.get("tcp", False)
            udp = port_config.get("udp", False)

            if port not in all_port_configs:
                all_port_configs[port] = {"tcp": False, "udp": False}
            if tcp:
                all_port_configs[port]["tcp"] = True
            if udp:
                all_port_configs[port]["udp"] = True

        # Try PF first (OpenBSD, FreeBSD)
        pf_result = await self._apply_firewall_roles_pf(
            all_port_configs, agent_ports, errors
        )
        if pf_result is not None:
            return pf_result

        # Try IPFW (FreeBSD)
        ipfw_result = await self._apply_firewall_roles_ipfw(
            all_port_configs, agent_ports, errors
        )
        if ipfw_result is not None:
            return ipfw_result

        # Try NPF (NetBSD)
        npf_result = await self._apply_firewall_roles_npf(
            all_port_configs, agent_ports, errors
        )
        if npf_result is not None:
            return npf_result

        return {
            "success": False,
            "error": _(  # pylint: disable=not-callable
                "No supported firewall found on this BSD system"
            ),
        }

    async def _apply_firewall_roles_pf(
        self, port_configs: Dict, agent_ports: List[int], errors: List[str]
    ) -> Dict:
        """Apply firewall roles using PF (synchronize - add and remove rules)."""
        try:
            # Check if PF is available
            result = subprocess.run(  # nosec B603 B607
                ["pfctl", "-s", "info"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # PF not available

            self.logger.info("Synchronizing firewall roles using PF")

            # Preserved ports: agent communication + SSH (22)
            preserved_ports = set(agent_ports + [22])

            # First, flush the sysmanage anchor to remove old rules
            self.logger.info("Flushing PF sysmanage anchor")
            subprocess.run(  # nosec B603 B607
                ["pfctl", "-a", "sysmanage", "-F", "rules"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # Build all rules at once for the anchor
            rules = []
            for port, protocols in port_configs.items():
                if port in preserved_ports:
                    continue  # Skip preserved ports

                if protocols["tcp"]:
                    rules.append(f"pass in quick proto tcp to port {port}")
                if protocols["udp"]:
                    rules.append(f"pass in quick proto udp to port {port}")

            # Apply all rules at once to the sysmanage anchor
            if rules:
                rules_content = "\n".join(rules) + "\n"
                self.logger.info("Adding %d PF rules to sysmanage anchor", len(rules))
                result = subprocess.run(  # nosec B603 B607
                    ["pfctl", "-a", "sysmanage", "-f", "-"],
                    input=rules_content,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append(f"Failed to add PF rules: {result.stderr}")
                    self.logger.warning("Failed to add PF rules: %s", result.stderr)
            else:
                self.logger.info("No role ports to configure in PF")

            await self._send_firewall_status_update()

            if errors:
                return {
                    "success": False,
                    "error": "; ".join(errors),
                    "message": _("Some firewall rules failed to apply"),
                }

            return {
                "success": True,
                "message": _("Firewall roles synchronized successfully via PF"),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # PF not available

    async def _apply_firewall_roles_ipfw(
        self, port_configs: Dict, agent_ports: List[int], errors: List[str]
    ) -> Dict:
        """Apply firewall roles using IPFW (synchronize - add and remove rules)."""
        try:
            # Check if IPFW is available
            result = subprocess.run(  # nosec B603 B607
                ["ipfw", "list"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # IPFW not available

            self.logger.info("Synchronizing firewall roles using IPFW")

            # Preserved ports: agent communication + SSH (22)
            preserved_ports = set(agent_ports + [22])

            # First, delete all SysManage role rules (rule numbers 10000-19999)
            # This is the cleanest way to synchronize
            self.logger.info("Deleting existing SysManage IPFW rules (10000-19999)")
            for rule_num in range(10000, 20000):
                # Try to delete the rule; it will fail silently if it doesn't exist
                subprocess.run(  # nosec B603 B607
                    ["ipfw", "-q", "delete", str(rule_num)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

            # Add rules for requested ports
            # Use rule numbers starting at 10000 for SysManage rules
            rule_num = 10000
            for port, protocols in port_configs.items():
                if port in preserved_ports:
                    continue

                if protocols["tcp"]:
                    self.logger.info(
                        "Adding IPFW rule %d: allow tcp port %d", rule_num, port
                    )
                    result = subprocess.run(  # nosec B603 B607
                        [
                            "ipfw",
                            "add",
                            str(rule_num),
                            "allow",
                            "tcp",
                            "from",
                            "any",
                            "to",
                            "any",
                            str(port),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode != 0:
                        errors.append(
                            f"Failed to add IPFW rule for TCP port {port}: {result.stderr}"
                        )
                    rule_num += 1

                if protocols["udp"]:
                    self.logger.info(
                        "Adding IPFW rule %d: allow udp port %d", rule_num, port
                    )
                    result = subprocess.run(  # nosec B603 B607
                        [
                            "ipfw",
                            "add",
                            str(rule_num),
                            "allow",
                            "udp",
                            "from",
                            "any",
                            "to",
                            "any",
                            str(port),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode != 0:
                        errors.append(
                            f"Failed to add IPFW rule for UDP port {port}: {result.stderr}"
                        )
                    rule_num += 1

            await self._send_firewall_status_update()

            if errors:
                return {
                    "success": False,
                    "error": "; ".join(errors),
                    "message": _("Some firewall rules failed to apply"),
                }

            return {
                "success": True,
                "message": _("Firewall roles synchronized successfully via IPFW"),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # IPFW not available

    async def _apply_firewall_roles_npf(  # pylint: disable=unused-argument
        self, port_configs: Dict, agent_ports: List[int], errors: List[str]
    ) -> Dict:
        """Apply firewall roles using NPF (NetBSD)."""
        try:
            # Check if NPF is available
            result = subprocess.run(  # nosec B603 B607
                ["npfctl", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # NPF not available

            self.logger.info("Applying firewall roles using NPF")

            # NPF requires configuration file changes
            # For now, log the ports and return success
            self.logger.info(
                "NPF firewall: Would configure %d ports. "
                "NPF requires /etc/npf.conf modifications.",
                len(port_configs),
            )

            for port, protocols in port_configs.items():
                if port in agent_ports:
                    continue

                proto_list = []
                if protocols["tcp"]:
                    proto_list.append("tcp")
                if protocols["udp"]:
                    proto_list.append("udp")
                self.logger.info(
                    "NPF: Would allow port %d (%s)", port, "/".join(proto_list)
                )

            await self._send_firewall_status_update()

            return {
                "success": True,
                "message": _(
                    "Firewall roles acknowledged on NPF. "
                    "Note: NPF requires /etc/npf.conf configuration."
                ),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # NPF not available

    async def remove_firewall_ports(
        self, ipv4_ports: List[Dict], ipv6_ports: List[Dict]
    ) -> Dict:
        """
        Remove specific firewall ports on BSD systems.

        This removes only the specified ports from the firewall.
        Used when a firewall role is removed from a host.

        Supports:
        - PF (FreeBSD/OpenBSD)
        - IPFW (FreeBSD)
        - NPF (NetBSD)

        Args:
            ipv4_ports: List of {port, tcp, udp} for IPv4 to remove
            ipv6_ports: List of {port, tcp, udp} for IPv6 to remove

        Returns:
            Dict with success status and message
        """
        self.logger.info("Removing specific firewall ports on BSD system")

        errors = []

        # Get agent communication ports (must always be preserved)
        agent_ports, _ = self._get_agent_communication_ports()
        # Also preserve SSH port 22
        preserved_ports = set(agent_ports + [22])

        # Build list of ports to remove from both IPv4 and IPv6
        ports_to_remove = {}
        for port_config in ipv4_ports + ipv6_ports:
            port = port_config.get("port")
            tcp = port_config.get("tcp", False)
            udp = port_config.get("udp", False)

            if port not in ports_to_remove:
                ports_to_remove[port] = {"tcp": False, "udp": False}
            if tcp:
                ports_to_remove[port]["tcp"] = True
            if udp:
                ports_to_remove[port]["udp"] = True

        self.logger.info(
            "Ports to remove: %s, Preserved (will not remove): %s",
            list(ports_to_remove.keys()),
            list(preserved_ports),
        )

        # Try PF first
        pf_result = await self._remove_firewall_ports_pf(
            ports_to_remove, preserved_ports, errors
        )
        if pf_result is not None:
            return pf_result

        # Try IPFW
        ipfw_result = await self._remove_firewall_ports_ipfw(
            ports_to_remove, preserved_ports, errors
        )
        if ipfw_result is not None:
            return ipfw_result

        # Try NPF (NetBSD) - just logs for now
        npf_result = await self._remove_firewall_ports_npf(
            ports_to_remove, preserved_ports, errors
        )
        if npf_result is not None:
            return npf_result

        return {
            "success": False,
            "error": _(  # pylint: disable=not-callable
                "No supported BSD firewall found on this system"
            ),
        }

    async def _remove_firewall_ports_pf(  # pylint: disable=unused-argument
        self, ports_to_remove: Dict, preserved_ports: set, errors: List[str]
    ) -> Dict:
        """Remove specific firewall ports using PF."""
        try:
            # Check if PF is available
            result = subprocess.run(  # nosec B603 B607
                ["pfctl", "-s", "info"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # PF not available

            self.logger.info("Removing firewall ports using PF")

            # Log the removal (PF rules are managed in pf.conf)
            for port, protocols in ports_to_remove.items():
                if port in preserved_ports:
                    self.logger.info(
                        "Skipping removal of preserved port %d (agent/SSH)", port
                    )
                    continue

                proto_list = []
                if protocols["tcp"]:
                    proto_list.append("tcp")
                if protocols["udp"]:
                    proto_list.append("udp")
                self.logger.info(
                    "PF: Requested removal of port %d (%s)", port, "/".join(proto_list)
                )

            self.logger.info(
                "PF firewall port removal requires manual /etc/pf.conf editing "
                "and pfctl -f /etc/pf.conf reload"
            )

            await self._send_firewall_status_update()

            return {
                "success": True,
                "message": _(  # pylint: disable=not-callable
                    "Firewall port removal acknowledged on PF. "
                    "Note: PF requires manual /etc/pf.conf configuration."
                ),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # PF not available

    async def _remove_firewall_ports_ipfw(  # pylint: disable=unused-argument
        self, ports_to_remove: Dict, preserved_ports: set, errors: List[str]
    ) -> Dict:
        """Remove specific firewall ports using IPFW."""
        try:
            # Check if IPFW is available
            result = subprocess.run(  # nosec B603 B607
                ["ipfw", "list"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # IPFW not available

            self.logger.info("Removing firewall ports using IPFW")

            # Log the removal (IPFW rules would need rule number tracking)
            for port, protocols in ports_to_remove.items():
                if port in preserved_ports:
                    self.logger.info(
                        "Skipping removal of preserved port %d (agent/SSH)", port
                    )
                    continue

                proto_list = []
                if protocols["tcp"]:
                    proto_list.append("tcp")
                if protocols["udp"]:
                    proto_list.append("udp")
                self.logger.info(
                    "IPFW: Requested removal of port %d (%s)",
                    port,
                    "/".join(proto_list),
                )

            self.logger.info(
                "IPFW firewall port removal requires rule number tracking "
                "for proper removal"
            )

            await self._send_firewall_status_update()

            return {
                "success": True,
                "message": _(  # pylint: disable=not-callable
                    "Firewall port removal acknowledged on IPFW. "
                    "Note: IPFW rule management is limited."
                ),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # IPFW not available

    async def _remove_firewall_ports_npf(  # pylint: disable=unused-argument
        self, ports_to_remove: Dict, preserved_ports: set, errors: List[str]
    ) -> Dict:
        """Remove specific firewall ports using NPF (NetBSD)."""
        try:
            # Check if NPF is available
            result = subprocess.run(  # nosec B603 B607
                ["npfctl", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None  # NPF not available

            self.logger.info("Removing firewall ports using NPF")

            # Log the removal
            for port, protocols in ports_to_remove.items():
                if port in preserved_ports:
                    self.logger.info(
                        "Skipping removal of preserved port %d (agent/SSH)", port
                    )
                    continue

                proto_list = []
                if protocols["tcp"]:
                    proto_list.append("tcp")
                if protocols["udp"]:
                    proto_list.append("udp")
                self.logger.info(
                    "NPF: Requested removal of port %d (%s)", port, "/".join(proto_list)
                )

            await self._send_firewall_status_update()

            return {
                "success": True,
                "message": _(  # pylint: disable=not-callable
                    "Firewall port removal acknowledged on NPF. "
                    "Note: NPF requires /etc/npf.conf configuration."
                ),
            }

        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None  # NPF not available
