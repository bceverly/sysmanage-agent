"""
OpenBSD autoinstall infrastructure setup and teardown.

This module handles setting up and cleaning up the infrastructure needed for
OpenBSD autoinstall: network interfaces, DHCP, TFTP, and VMD configuration.

Extracted from child_host_vmm_autoinstall.py to provide standalone functions
for infrastructure management.
"""

import hashlib
import os
import re
import shutil
import subprocess  # nosec B404 # Required for system command execution
import time
import urllib.request
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.operations import (
    child_host_vmm_network_helpers as network_helpers,
)

# Default autoinstall HTTP server settings
AUTOINSTALL_BIND = "100.64.0.1"  # vmd local network address (matches pf.conf vm_net)

# PXE boot settings
PXE_CACHE_DIR = "/var/vmm/pxeboot"  # Cache for downloaded PXE boot files
TFTP_DIR = "/tftpboot"  # TFTP server root directory (OpenBSD default)
OPENBSD_MIRROR = "https://ftp.openbsd.org/pub/OpenBSD"  # OpenBSD mirror


def _generate_mac_address(vm_name: str) -> str:
    """
    Generate a deterministic MAC address for a VM based on its name.

    Uses the fe:e1:bb prefix (locally administered, unicast)
    followed by 3 bytes derived from the VM name.

    Args:
        vm_name: Name of the VM

    Returns:
        MAC address string (e.g., "fe:e1:bb:d1:2d:93")
    """
    # Hash the VM name to get deterministic bytes
    hash_bytes = hashlib.sha256(vm_name.encode()).digest()

    # Use first 3 bytes of hash for the last 3 octets of MAC
    # Use fe:e1:bb prefix (locally administered)
    mac = f"fe:e1:bb:{hash_bytes[0]:02x}:{hash_bytes[1]:02x}:{hash_bytes[2]:02x}"

    return mac


def _parse_openbsd_version(iso_url: str) -> Optional[str]:
    """
    Parse OpenBSD version from ISO URL.

    Args:
        iso_url: URL to OpenBSD ISO (e.g., .../install77.iso)

    Returns:
        Version string (e.g., "7.7") or None if can't parse
    """
    # Match install<version>.iso pattern (e.g., install77.iso -> 7.7)
    match = re.search(r"install(\d)(\d)\.iso", iso_url)
    if match:
        major = match.group(1)
        minor = match.group(2)
        return f"{major}.{minor}"
    return None


def _download_pxe_files(version: str, logger, arch: str = "amd64") -> Dict[str, Any]:
    """
    Download and cache OpenBSD PXE boot files.

    Args:
        version: OpenBSD version (e.g., "7.7")
        logger: Logger instance
        arch: Architecture (default: "amd64")

    Returns:
        Dict with success status and file paths
    """
    cache_dir = os.path.join(PXE_CACHE_DIR, version, arch)
    pxeboot_path = os.path.join(cache_dir, "pxeboot")
    bsd_rd_path = os.path.join(cache_dir, "bsd.rd")

    # Check if already cached
    if os.path.exists(pxeboot_path) and os.path.exists(bsd_rd_path):
        logger.info(_("PXE files for OpenBSD %s %s already cached"), version, arch)
        return {
            "success": True,
            "pxeboot": pxeboot_path,
            "bsd_rd": bsd_rd_path,
            "cached": True,
        }

    # Create cache directory
    try:
        os.makedirs(cache_dir, mode=0o755, exist_ok=True)

        # Download pxeboot
        pxeboot_url = f"{OPENBSD_MIRROR}/{version}/{arch}/pxeboot"
        logger.info(_("Downloading %s"), pxeboot_url)
        urllib.request.urlretrieve(pxeboot_url, pxeboot_path)  # nosec B310

        # Download bsd.rd
        bsd_rd_url = f"{OPENBSD_MIRROR}/{version}/{arch}/bsd.rd"
        logger.info(_("Downloading %s"), bsd_rd_url)
        urllib.request.urlretrieve(bsd_rd_url, bsd_rd_path)  # nosec B310

        logger.info(_("Downloaded PXE files for OpenBSD %s %s"), version, arch)

        return {
            "success": True,
            "pxeboot": pxeboot_path,
            "bsd_rd": bsd_rd_path,
            "cached": False,
        }

    except Exception as error:
        logger.error(_("Failed to download PXE files: %s"), error)
        return {
            "success": False,
            "error": str(error),
        }


def _setup_tftp_server(state: Dict[str, Any], logger) -> None:
    """
    Set up TFTP server for PXE boot.

    Args:
        state: State dict to track TFTP configuration
        logger: Logger instance

    Raises:
        Exception: If TFTP setup fails
    """
    # Create TFTP directory
    if not os.path.exists(TFTP_DIR):
        os.makedirs(TFTP_DIR, mode=0o755)
        state["tftp_dir_created"] = True
        logger.info(_("Created TFTP directory: %s"), TFTP_DIR)
    else:
        state["tftp_dir_created"] = False

    # Check if tftpd is already running
    result = subprocess.run(  # nosec B603 B607
        ["rcctl", "check", "tftpd"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    state["tftpd_was_running"] = result.returncode == 0

    # Configure tftpd to serve from TFTP_DIR
    subprocess.run(  # nosec B603 B607
        ["rcctl", "set", "tftpd", "flags", TFTP_DIR],
        check=True,
        timeout=10,
    )

    # Enable tftpd
    subprocess.run(  # nosec B603 B607
        ["rcctl", "enable", "tftpd"],
        check=True,
        timeout=10,
    )

    # Start or restart tftpd
    if state["tftpd_was_running"]:
        subprocess.run(  # nosec B603 B607
            ["rcctl", "restart", "tftpd"],
            check=True,
            timeout=30,
        )
        logger.info(_("Restarted tftpd"))
    else:
        subprocess.run(  # nosec B603 B607
            ["rcctl", "start", "tftpd"],
            check=True,
            timeout=30,
        )
        logger.info(_("Started tftpd"))


def setup_autoinstall_infrastructure(
    vm_name: str,
    hostname: str,
    logger,
    iso_url: str = None,
    use_pxe: bool = True,
) -> Dict[str, Any]:
    """
    Set up complete autoinstall infrastructure: network, DHCP, TFTP, and HTTP.

    This follows the approach from obtusenet.com/blog/openbsd-vmd-autoinstall/

    Args:
        vm_name: Name of the VM
        hostname: Hostname for the VM
        logger: Logger instance
        iso_url: URL to OpenBSD ISO (for version detection)
        use_pxe: If True, set up PXE boot; if False, use ISO boot

    Returns:
        Dict with success status and cleanup state
    """
    state = {
        "dhcpd_was_enabled": False,
        "dhcpd_was_running": False,
        "dhcpd_original_flags": None,
        "dhcpd_conf_existed": False,
        "dhcpd_conf_backup": None,
        "vm_conf_existed": False,
        "vm_conf_backup": None,
        "vmd_was_running": False,
        "bridge0_created": False,
        "vether0_created": False,
        "tftpd_was_running": False,
        "tftp_dir_created": False,
        "use_pxe": use_pxe,
    }

    try:
        # Step 1: Use fixed subnet from AUTOINSTALL_BIND constant (matches pf.conf NAT)
        # Extract network from gateway IP (e.g., "100.64.0.1" -> "100.64.0.0")
        gateway_parts = AUTOINSTALL_BIND.split(".")
        subnet_network = f"{gateway_parts[0]}.{gateway_parts[1]}.{gateway_parts[2]}.0"
        subnet_info = network_helpers.format_subnet_info(subnet_network)

        logger.info(
            _("Using fixed subnet %s for VM network (matches pf.conf)"),
            subnet_info["network"],
        )
        state["subnet_info"] = subnet_info

        # Step 2: Create bridge0 and vether0 interfaces if needed
        for iface, state_key in [
            ("bridge0", "bridge0_created"),
            ("vether0", "vether0_created"),
        ]:
            result = subprocess.run(  # nosec B603 B607
                ["ifconfig", iface],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                subprocess.run(  # nosec B603 B607
                    ["ifconfig", iface, "create"],
                    check=True,
                    timeout=10,
                )
                state[state_key] = True
                logger.info(_("Created %s interface"), iface)
            else:
                state[state_key] = False
                logger.info(_("%s already exists"), iface)

        # Assign IP address to vether0
        subprocess.run(  # nosec B603 B607
            [
                "ifconfig",
                "vether0",
                "inet",
                subnet_info["gateway_ip"],
                "netmask",
                subnet_info["netmask"],
                "up",
            ],
            check=True,
            timeout=10,
        )
        logger.info(_("Assigned IP %s to vether0"), subnet_info["gateway_ip"])

        # Add vether0 to bridge0
        subprocess.run(  # nosec B603 B607
            ["ifconfig", "bridge0", "add", "vether0", "up"],
            check=True,
            timeout=10,
        )
        logger.info(_("Added vether0 to bridge0"))

        # Step 3: Enable IP forwarding
        subprocess.run(  # nosec B603 B607
            ["sysctl", "net.inet.ip.forwarding=1"],
            check=True,
            timeout=10,
        )
        logger.info(_("Enabled IP forwarding"))

        # Step 4: Generate MAC address for VM
        mac_address = _generate_mac_address(vm_name)
        state["mac_address"] = mac_address
        logger.info(_("Generated MAC address %s for VM"), mac_address)

        # Step 5: Set up /etc/vm.conf with a switch and VM definition
        vm_conf_path = "/etc/vm.conf"
        if os.path.exists(vm_conf_path):
            state["vm_conf_existed"] = True
            # Back up existing config
            backup_path = f"{vm_conf_path}.sysmanage-backup"
            subprocess.run(  # nosec B603 B607
                ["cp", vm_conf_path, backup_path],
                check=True,
                timeout=10,
            )
            state["vm_conf_backup"] = backup_path
            logger.info(_("Backed up existing vm.conf to %s"), backup_path)

        # Create vm.conf with switch definition only
        # VM will be launched via vmctl with MAC specified via -i interface config
        vm_conf_content = """# SysManage vmd config for autoinstall
switch "local" {
    interface bridge0
}
"""

        with open(vm_conf_path, "w", encoding="utf-8") as conf_file:
            conf_file.write(vm_conf_content)

        logger.info(_("Created vm.conf with local switch and VM definition"))

        # Step 3: Check if vmd is running and restart it
        result = subprocess.run(  # nosec B603 B607
            ["rcctl", "check", "vmd"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        state["vmd_was_running"] = result.returncode == 0

        if state["vmd_was_running"]:
            # Restart vmd to pick up new vm.conf
            subprocess.run(  # nosec B603 B607
                ["rcctl", "restart", "vmd"],
                check=True,
                timeout=30,
            )
            logger.info(_("Restarted vmd with new vm.conf"))
            # Wait for vmd to settle
            time.sleep(2)

        # Step 3: Check if dhcpd is already configured
        result = subprocess.run(  # nosec B603 B607
            ["rcctl", "get", "dhcpd", "status"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        state["dhcpd_was_running"] = (
            result.returncode == 0 and "running" in result.stdout
        )

        result = subprocess.run(  # nosec B603 B607
            ["rcctl", "get", "dhcpd", "flags"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            state["dhcpd_was_enabled"] = True
            state["dhcpd_original_flags"] = result.stdout.strip()

        # Step 4: Check if dhcpd.conf exists
        dhcpd_conf_path = "/etc/dhcpd.conf"
        if os.path.exists(dhcpd_conf_path):
            state["dhcpd_conf_existed"] = True
            # Back up existing config
            backup_path = f"{dhcpd_conf_path}.sysmanage-backup"
            subprocess.run(  # nosec B603 B607
                ["cp", dhcpd_conf_path, backup_path],
                check=True,
                timeout=10,
            )
            state["dhcpd_conf_backup"] = backup_path
            logger.info(_("Backed up existing dhcpd.conf to %s"), backup_path)

        # Step 5: Set up PXE boot if enabled
        if use_pxe:
            # Parse OpenBSD version from ISO URL
            if not iso_url:
                raise RuntimeError(_("ISO URL required for PXE boot"))

            version = _parse_openbsd_version(iso_url)
            if not version:
                raise RuntimeError(
                    _("Could not parse OpenBSD version from ISO URL: %s") % iso_url
                )

            logger.info(_("Setting up PXE boot for OpenBSD %s"), version)

            # Download PXE boot files
            pxe_result = _download_pxe_files(version, logger)
            if not pxe_result.get("success"):
                raise RuntimeError(
                    _("Failed to download PXE files: %s") % pxe_result.get("error")
                )

            state["pxe_files"] = pxe_result

            # Copy PXE files to TFTP directory
            _setup_tftp_server(state, logger)

            # Copy pxeboot and bsd.rd to TFTP directory
            pxeboot_src = pxe_result["pxeboot"]
            bsd_rd_src = pxe_result["bsd_rd"]
            pxeboot_dst = os.path.join(TFTP_DIR, "pxeboot")
            auto_install_dst = os.path.join(TFTP_DIR, "auto_install")

            shutil.copy2(pxeboot_src, pxeboot_dst)
            shutil.copy2(bsd_rd_src, auto_install_dst)

            logger.info(_("Copied PXE files to TFTP directory"))

        # Step 6: Generate dhcpd.conf for autoinstall
        # Serve autoinstall to any VM on the isolated virtual network
        # For PXE boot, filename is "pxeboot"; for ISO boot, "install.conf"
        boot_filename = "pxeboot" if use_pxe else "install.conf"
        dhcpd_conf_content = f"""# SysManage dhcpd config for autoinstall
# Auto-generated for VM: {vm_name}

subnet {subnet_info['network']} netmask {subnet_info['netmask']} {{
    range {subnet_info['dhcp_start']} {subnet_info['dhcp_end']};
    option routers {subnet_info['gateway_ip']};
    option domain-name-servers 1.1.1.1;
    option host-name "{hostname}";
    filename "{boot_filename}";
    next-server {subnet_info['gateway_ip']};
}}
"""

        with open(dhcpd_conf_path, "w", encoding="utf-8") as conf_file:
            conf_file.write(dhcpd_conf_content)

        logger.info(_("Created dhcpd.conf for autoinstall"))

        # Step 6: Configure and start dhcpd on vether0
        # Use default lease file location /var/db/dhcpd.leases (OpenBSD default)
        # Set flags to listen only on vether0 interface
        dhcpd_flags = "vether0"
        subprocess.run(  # nosec B603 B607
            ["rcctl", "set", "dhcpd", "flags", dhcpd_flags],
            check=True,
            timeout=10,
        )

        # Explicitly enable dhcpd
        subprocess.run(  # nosec B603 B607
            ["rcctl", "enable", "dhcpd"],
            check=True,
            timeout=10,
        )

        # Start or restart dhcpd
        if state["dhcpd_was_running"]:
            subprocess.run(  # nosec B603 B607
                ["rcctl", "restart", "dhcpd"],
                check=True,
                timeout=30,
            )
            logger.info(_("Restarted dhcpd with autoinstall config"))
        else:
            subprocess.run(  # nosec B603 B607
                ["rcctl", "start", "dhcpd"],
                check=True,
                timeout=30,
            )
            logger.info(_("Started dhcpd for autoinstall"))

        # Verify dhcpd is actually running (catches immediate crashes)
        time.sleep(2)  # Give dhcpd time to start and stabilize
        result = subprocess.run(  # nosec B603 B607
            ["rcctl", "check", "dhcpd"],
            capture_output=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            # dhcpd crashed or failed to start
            logger.error(_("dhcpd failed to start or crashed immediately"))
            # Check for error messages in system logs
            log_result = subprocess.run(  # nosec B603 B607
                ["tail", "-20", "/var/log/messages"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if "dhcpd" in log_result.stdout:
                logger.error(_("Recent dhcpd errors: %s"), log_result.stdout)
            raise RuntimeError(_("dhcpd failed to start - check /var/log/messages"))

        logger.info(_("Verified dhcpd is running"))

        return {
            "success": True,
            "state": state,
        }

    except Exception as error:
        logger.error(_("Failed to setup autoinstall infrastructure: %s"), error)
        # Attempt to restore state
        _restore_infrastructure_state(state, logger)
        return {
            "success": False,
            "error": str(error),
        }


def cleanup_autoinstall_infrastructure(state: Dict[str, Any], logger) -> Dict[str, Any]:
    """
    Clean up autoinstall infrastructure and restore original state.

    Args:
        state: State dict from setup_autoinstall_infrastructure
        logger: Logger instance

    Returns:
        Dict with success status
    """
    try:
        _restore_infrastructure_state(state, logger)
        return {"success": True}
    except Exception as error:
        logger.error(_("Failed to cleanup autoinstall infrastructure: %s"), error)
        return {
            "success": False,
            "error": str(error),
        }


def _restore_infrastructure_state(state: Dict[str, Any], logger) -> None:
    """
    Restore dhcpd to its original state.

    Note: bridge0 and vm.conf are permanent infrastructure and are NOT cleaned up.

    Args:
        state: State dict containing original configuration
        logger: Logger instance
    """
    try:
        # Restore dhcpd.conf
        if state.get("dhcpd_conf_backup"):
            backup_path = state["dhcpd_conf_backup"]
            if os.path.exists(backup_path):
                subprocess.run(  # nosec B603 B607
                    ["mv", backup_path, "/etc/dhcpd.conf"],
                    check=True,
                    timeout=10,
                )
                logger.info(_("Restored original dhcpd.conf"))
        elif not state.get("dhcpd_conf_existed"):
            # Remove the config we created
            if os.path.exists("/etc/dhcpd.conf"):
                os.remove("/etc/dhcpd.conf")
                logger.info(_("Removed temporary dhcpd.conf"))

        # Restore dhcpd flags
        if state.get("dhcpd_original_flags") is not None:
            subprocess.run(  # nosec B603 B607
                ["rcctl", "set", "dhcpd", "flags", state["dhcpd_original_flags"]],
                check=True,
                timeout=10,
            )

        # Restore dhcpd running state
        if state.get("dhcpd_was_running"):
            subprocess.run(  # nosec B603 B607
                ["rcctl", "restart", "dhcpd"],
                check=True,
                timeout=30,
            )
            logger.info(_("Restarted dhcpd with original config"))
        else:
            subprocess.run(  # nosec B603 B607
                ["rcctl", "stop", "dhcpd"],
                check=False,
                timeout=30,
            )
            if not state.get("dhcpd_was_enabled"):
                subprocess.run(  # nosec B603 B607
                    ["rcctl", "disable", "dhcpd"],
                    check=False,
                    timeout=10,
                )
            logger.info(_("Stopped dhcpd and restored original state"))

        # Restore dhcpleased state (DHCP client daemon)
        if state.get("dhcpleased_was_running"):
            subprocess.run(  # nosec B603 B607
                ["rcctl", "start", "dhcpleased"],
                check=False,
                timeout=30,
            )
            logger.info(_("Restarted dhcpleased"))

        # Clean up TFTP server if it was set up
        if state.get("use_pxe") and state.get("tftpd_was_running") is not None:
            if state["tftpd_was_running"]:
                # Restart tftpd with original config (don't stop it)
                subprocess.run(  # nosec B603 B607
                    ["rcctl", "restart", "tftpd"],
                    check=False,
                    timeout=30,
                )
                logger.info(_("Restarted tftpd"))
            else:
                # Stop tftpd since it wasn't running before
                subprocess.run(  # nosec B603 B607
                    ["rcctl", "stop", "tftpd"],
                    check=False,
                    timeout=30,
                )
                subprocess.run(  # nosec B603 B607
                    ["rcctl", "disable", "tftpd"],
                    check=False,
                    timeout=10,
                )
                logger.info(_("Stopped tftpd"))

            # Clean up TFTP directory files (but keep the directory)
            if os.path.exists(TFTP_DIR):
                for file in ["pxeboot", "auto_install"]:
                    file_path = os.path.join(TFTP_DIR, file)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                logger.info(_("Cleaned up TFTP files"))

    except Exception as error:
        logger.warning(_("Error restoring infrastructure state: %s"), error)
