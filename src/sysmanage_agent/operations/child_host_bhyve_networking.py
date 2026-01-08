"""
bhyve NAT networking operations for FreeBSD hosts.

This module handles bhyve network configuration including NAT bridge setup,
pf firewall rules, and dhcpd configuration for VM DHCP.
"""

import os
import subprocess  # nosec B404 # Required for system command execution
from typing import Any, Dict, Optional

from src.i18n import _

# Default bhyve network configuration
BHYVE_BRIDGE_NAME = "bhyve0"
BHYVE_SUBNET = "10.0.100"  # Will use 10.0.100.0/24
BHYVE_GATEWAY_IP = f"{BHYVE_SUBNET}.1"
BHYVE_NETMASK = "255.255.255.0"
BHYVE_DHCP_START = f"{BHYVE_SUBNET}.10"
BHYVE_DHCP_END = f"{BHYVE_SUBNET}.254"


class BhyveNetworking:
    """bhyve NAT networking operations for FreeBSD."""

    def __init__(self, logger):
        """
        Initialize bhyve networking operations.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def get_host_dns_server(self) -> Optional[str]:
        """
        Get the DNS server from the host's /etc/resolv.conf.

        Returns:
            First nameserver IP address or None if not found
        """
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as resolv_file:
                for line in resolv_file:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            dns_server = parts[1]
                            if "#" in dns_server:
                                dns_server = dns_server.split("#")[0].strip()
                            self.logger.info(
                                _("Detected host DNS server: %s"), dns_server
                            )
                            return dns_server
            return None
        except Exception as error:
            self.logger.warning(_("Error reading /etc/resolv.conf: %s"), error)
            return None

    def get_egress_interface(self) -> Optional[str]:
        """
        Get the primary egress interface (interface with default route).

        Returns:
            Interface name or None if not found
        """
        try:
            # Get default route
            result = subprocess.run(  # nosec B603 B607
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "interface:" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            return parts[1].strip()
            return None
        except Exception as error:
            self.logger.warning(_("Error getting egress interface: %s"), error)
            return None

    async def setup_nat_bridge(self, run_subprocess) -> Dict[str, Any]:
        """
        Set up the NAT bridge for bhyve VMs.

        Creates bhyve0 bridge interface with gateway IP.

        Args:
            run_subprocess: Async function to run subprocess commands

        Returns:
            Dict with success status and message
        """
        try:
            # Check if bridge already exists
            result = await run_subprocess(
                ["ifconfig", BHYVE_BRIDGE_NAME],
                timeout=10,
            )

            if result.returncode == 0:
                self.logger.info(_("bhyve bridge %s already exists"), BHYVE_BRIDGE_NAME)
            else:
                # Create the bridge
                self.logger.info(_("Creating bhyve bridge %s"), BHYVE_BRIDGE_NAME)
                create_result = await run_subprocess(
                    ["ifconfig", BHYVE_BRIDGE_NAME, "create"],
                    timeout=10,
                )
                if create_result.returncode != 0:
                    return {
                        "success": False,
                        "error": _("Failed to create bridge %s: %s")
                        % (BHYVE_BRIDGE_NAME, create_result.stderr),
                    }

            # Configure the bridge with gateway IP
            self.logger.info(
                _("Configuring bridge %s with IP %s"),
                BHYVE_BRIDGE_NAME,
                BHYVE_GATEWAY_IP,
            )
            config_result = await run_subprocess(
                [
                    "ifconfig",
                    BHYVE_BRIDGE_NAME,
                    "inet",
                    BHYVE_GATEWAY_IP,
                    "netmask",
                    BHYVE_NETMASK,
                    "up",
                ],
                timeout=10,
            )
            if config_result.returncode != 0:
                self.logger.warning(
                    _("Failed to configure bridge IP: %s"), config_result.stderr
                )

            # Make bridge persistent in /etc/rc.conf
            await self._add_rc_conf_entry(
                f'cloned_interfaces="${{cloned_interfaces}} {BHYVE_BRIDGE_NAME}"',
                "cloned_interfaces",
                run_subprocess,
            )
            await self._add_rc_conf_entry(
                f'ifconfig_{BHYVE_BRIDGE_NAME}="inet {BHYVE_GATEWAY_IP} netmask {BHYVE_NETMASK}"',
                f"ifconfig_{BHYVE_BRIDGE_NAME}",
                run_subprocess,
            )

            return {
                "success": True,
                "message": _("NAT bridge %s configured") % BHYVE_BRIDGE_NAME,
                "bridge": BHYVE_BRIDGE_NAME,
                "gateway_ip": BHYVE_GATEWAY_IP,
            }

        except Exception as error:
            self.logger.error(_("Error setting up NAT bridge: %s"), error)
            return {"success": False, "error": str(error)}

    async def setup_ip_forwarding(self, run_subprocess) -> Dict[str, Any]:
        """
        Enable IP forwarding for NAT.

        Args:
            run_subprocess: Async function to run subprocess commands

        Returns:
            Dict with success status
        """
        try:
            # Enable IP forwarding immediately
            self.logger.info(_("Enabling IP forwarding"))
            await run_subprocess(
                ["sysctl", "net.inet.ip.forwarding=1"],
                timeout=10,
            )

            # Make persistent in /etc/sysctl.conf
            sysctl_conf = "/etc/sysctl.conf"
            sysctl_line = "net.inet.ip.forwarding=1"

            try:
                content = ""
                if os.path.exists(sysctl_conf):
                    with open(sysctl_conf, "r", encoding="utf-8") as conf_file:
                        content = conf_file.read()

                if sysctl_line not in content:
                    with open(sysctl_conf, "a", encoding="utf-8") as conf_file:
                        conf_file.write(
                            f"\n# bhyve NAT - added by sysmanage\n{sysctl_line}\n"
                        )
                    self.logger.info(_("Added IP forwarding to %s"), sysctl_conf)
            except PermissionError:
                self.logger.warning(
                    _("Cannot write to %s - IP forwarding may not persist"),
                    sysctl_conf,
                )

            return {"success": True, "message": _("IP forwarding enabled")}

        except Exception as error:
            self.logger.error(_("Error enabling IP forwarding: %s"), error)
            return {"success": False, "error": str(error)}

    async def setup_pf_nat(self, run_subprocess) -> Dict[str, Any]:
        """
        Set up pf NAT rules for bhyve VMs.

        Args:
            run_subprocess: Async function to run subprocess commands

        Returns:
            Dict with success status
        """
        try:
            egress_iface = self.get_egress_interface()
            if not egress_iface:
                egress_iface = "egress"  # pf macro for default route interface

            pf_conf = "/etc/pf.conf"

            # NAT rule for bhyve subnet
            nat_rule = f"nat on {egress_iface} from {BHYVE_SUBNET}.0/24 to any -> ({egress_iface})"

            # Check if pf.conf exists and read it
            pf_content = ""
            if os.path.exists(pf_conf):
                with open(pf_conf, "r", encoding="utf-8") as conf_file:
                    pf_content = conf_file.read()

            # Check if our NAT rule already exists
            if "bhyve NAT" in pf_content or nat_rule in pf_content:
                self.logger.info(_("pf NAT rules already configured"))
                # Just reload pf
                await run_subprocess(["pfctl", "-f", pf_conf], timeout=30)
                return {"success": True, "message": _("pf NAT rules already present")}

            # Add NAT rule to pf.conf
            self.logger.info(_("Adding NAT rules to %s"), pf_conf)

            # Build new pf.conf content
            # We need to add the NAT rule before any other rules
            new_content = pf_content

            # Add our NAT section if not present
            nat_section = f"""
# bhyve NAT - added by sysmanage
nat on {egress_iface} from {BHYVE_SUBNET}.0/24 to any -> ({egress_iface})
# Allow traffic from bhyve VMs
pass in on {BHYVE_BRIDGE_NAME} from {BHYVE_SUBNET}.0/24 to any
pass out on {egress_iface} from {BHYVE_SUBNET}.0/24 to any
"""

            # If pf.conf is empty or minimal, create a basic config
            if not pf_content.strip() or len(pf_content.strip()) < 50:
                new_content = f"""# pf.conf - FreeBSD packet filter configuration
# Modified by sysmanage for bhyve NAT

# Macros
ext_if = "{egress_iface}"
bhyve_net = "{BHYVE_SUBNET}.0/24"

# Options
set skip on lo0

# NAT for bhyve VMs
nat on $ext_if from $bhyve_net to any -> ($ext_if)

# Default rules
pass in all
pass out all
"""
            else:
                # Append our NAT rules
                new_content = pf_content.rstrip() + "\n" + nat_section

            # Write updated pf.conf
            try:
                with open(pf_conf, "w", encoding="utf-8") as conf_file:
                    conf_file.write(new_content)
            except PermissionError:
                return {
                    "success": False,
                    "error": _("Permission denied writing to %s") % pf_conf,
                }

            # Enable pf if not enabled
            await run_subprocess(["sysrc", "pf_enable=YES"], timeout=10)

            # Load the new rules
            self.logger.info(_("Loading pf rules"))
            load_result = await run_subprocess(
                ["pfctl", "-f", pf_conf],
                timeout=30,
            )

            if load_result.returncode != 0:
                self.logger.warning(
                    _("pf rule load returned non-zero: %s"),
                    load_result.stderr or load_result.stdout,
                )

            # Enable pf
            await run_subprocess(["pfctl", "-e"], timeout=10)

            return {"success": True, "message": _("pf NAT rules configured")}

        except Exception as error:
            self.logger.error(_("Error setting up pf NAT: %s"), error)
            return {"success": False, "error": str(error)}

    async def setup_dhcpd(self, run_subprocess) -> Dict[str, Any]:
        """
        Install and configure dhcpd for bhyve VMs.

        Args:
            run_subprocess: Async function to run subprocess commands

        Returns:
            Dict with success status
        """
        try:
            # Get host DNS server
            dns_server = self.get_host_dns_server()
            if not dns_server:
                dns_server = "8.8.8.8"  # Fallback to Google DNS
                self.logger.warning(
                    _("Could not detect host DNS, using %s"), dns_server
                )

            # Check if dhcpd is installed
            result = await run_subprocess(["which", "dhcpd"], timeout=10)

            if result.returncode != 0:
                # Install ISC DHCP server
                self.logger.info(_("Installing dhcpd"))
                install_result = await run_subprocess(
                    ["pkg", "install", "-y", "isc-dhcp44-server"],
                    timeout=300,
                )
                if install_result.returncode != 0:
                    return {
                        "success": False,
                        "error": _("Failed to install dhcpd: %s")
                        % (install_result.stderr or install_result.stdout),
                    }

            # Create dhcpd.conf
            dhcpd_conf = "/usr/local/etc/dhcpd.conf"
            dhcpd_config = f"""# bhyve DHCP server configuration - generated by sysmanage
# DO NOT EDIT - this file is managed by sysmanage

option domain-name-servers {dns_server};

default-lease-time 600;
max-lease-time 7200;

authoritative;

subnet {BHYVE_SUBNET}.0 netmask {BHYVE_NETMASK} {{
    range {BHYVE_DHCP_START} {BHYVE_DHCP_END};
    option routers {BHYVE_GATEWAY_IP};
    option domain-name-servers {dns_server};
}}
"""

            self.logger.info(_("Creating dhcpd configuration"))
            try:
                with open(dhcpd_conf, "w", encoding="utf-8") as conf_file:
                    conf_file.write(dhcpd_config)
            except PermissionError:
                return {
                    "success": False,
                    "error": _("Permission denied writing to %s") % dhcpd_conf,
                }

            # Configure dhcpd to listen only on bhyve bridge
            await run_subprocess(
                ["sysrc", f"dhcpd_ifaces={BHYVE_BRIDGE_NAME}"],
                timeout=10,
            )
            await run_subprocess(
                ["sysrc", "dhcpd_enable=YES"],
                timeout=10,
            )

            # Start/restart dhcpd
            self.logger.info(_("Starting dhcpd service"))
            # Try to restart first (in case it's already running)
            restart_result = await run_subprocess(
                ["service", "isc-dhcpd", "restart"],
                timeout=60,
            )

            if restart_result.returncode != 0:
                # Try to start fresh
                start_result = await run_subprocess(
                    ["service", "isc-dhcpd", "start"],
                    timeout=60,
                )
                if start_result.returncode != 0:
                    self.logger.warning(
                        _("dhcpd start returned non-zero: %s"),
                        start_result.stderr or start_result.stdout,
                    )

            return {
                "success": True,
                "message": _("dhcpd configured for bhyve VMs"),
                "dns_server": dns_server,
            }

        except Exception as error:
            self.logger.error(_("Error setting up dhcpd: %s"), error)
            return {"success": False, "error": str(error)}

    async def setup_nat_networking(self, run_subprocess) -> Dict[str, Any]:
        """
        Complete NAT networking setup for bhyve.

        This sets up:
        1. bhyve0 bridge with gateway IP
        2. IP forwarding
        3. pf NAT rules
        4. dhcpd for DHCP

        Args:
            run_subprocess: Async function to run subprocess commands

        Returns:
            Dict with success status and details
        """
        results = {}

        # Step 1: Create NAT bridge
        bridge_result = await self.setup_nat_bridge(run_subprocess)
        results["bridge"] = bridge_result
        if not bridge_result.get("success"):
            return {
                "success": False,
                "error": _("Failed to set up NAT bridge: %s")
                % bridge_result.get("error"),
                "results": results,
            }

        # Step 2: Enable IP forwarding
        forwarding_result = await self.setup_ip_forwarding(run_subprocess)
        results["forwarding"] = forwarding_result
        if not forwarding_result.get("success"):
            self.logger.warning(
                _("IP forwarding setup had issues: %s"),
                forwarding_result.get("error"),
            )

        # Step 3: Set up pf NAT
        pf_result = await self.setup_pf_nat(run_subprocess)
        results["pf"] = pf_result
        if not pf_result.get("success"):
            self.logger.warning(
                _("pf NAT setup had issues: %s"), pf_result.get("error")
            )

        # Step 4: Set up dhcpd
        dhcpd_result = await self.setup_dhcpd(run_subprocess)
        results["dhcpd"] = dhcpd_result
        if not dhcpd_result.get("success"):
            self.logger.warning(
                _("dhcpd setup had issues: %s"), dhcpd_result.get("error")
            )

        return {
            "success": True,
            "message": _("NAT networking configured for bhyve"),
            "bridge": BHYVE_BRIDGE_NAME,
            "gateway": BHYVE_GATEWAY_IP,
            "subnet": f"{BHYVE_SUBNET}.0/24",
            "dhcp_range": f"{BHYVE_DHCP_START} - {BHYVE_DHCP_END}",
            "results": results,
        }

    async def _add_rc_conf_entry(self, entry: str, key: str, run_subprocess) -> bool:
        """
        Add an entry to /etc/rc.conf if not present.

        Args:
            entry: The full line to add
            key: The key to check for (to avoid duplicates)
            run_subprocess: Async function to run subprocess commands

        Returns:
            True if successful
        """
        try:
            rc_conf = "/etc/rc.conf"
            content = ""
            if os.path.exists(rc_conf):
                with open(rc_conf, "r", encoding="utf-8") as conf_file:
                    content = conf_file.read()

            if key in content:
                self.logger.info(_("%s already in rc.conf"), key)
                return True

            # Use sysrc for safer rc.conf management
            # Extract the key=value from the entry
            if "=" in entry:
                await run_subprocess(["sysrc", entry.strip('"')], timeout=10)
            return True
        except Exception as error:
            self.logger.warning(_("Error adding rc.conf entry: %s"), error)
            return False

    def get_bridge_name(self) -> str:
        """Get the bhyve bridge name."""
        return BHYVE_BRIDGE_NAME

    def get_gateway_ip(self) -> str:
        """Get the bhyve gateway IP."""
        return BHYVE_GATEWAY_IP

    def get_subnet(self) -> str:
        """Get the bhyve subnet."""
        return f"{BHYVE_SUBNET}.0/24"
