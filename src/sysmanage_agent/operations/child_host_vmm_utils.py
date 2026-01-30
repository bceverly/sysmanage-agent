"""
VMM utility functions for VM creation.

This module contains utility functions used during VMM VM creation,
including VM existence checks, metadata handling, and hostname parsing.
"""

import json
import os
import re
import subprocess  # nosec B404
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from src.i18n import _

# VMM directories
VMM_DISK_DIR = "/var/vmm"
VMM_METADATA_DIR = "/var/vmm/metadata"


def vm_exists(vm_name: str, logger) -> bool:
    """
    Check if a VM already exists.

    Checks:
    1. Metadata file exists
    2. VM.conf contains VM definition
    3. vmctl status shows the VM

    Args:
        vm_name: Name of the VM to check
        logger: Logger instance

    Returns:
        True if VM exists, False otherwise
    """
    logger.info("🔍 [VM_EXISTS_CHECK] Checking if VM '%s' exists...", vm_name)

    # Check metadata file
    metadata_path = Path(VMM_METADATA_DIR) / f"{vm_name}.json"
    logger.info("🔍 [VM_EXISTS_CHECK] Checking metadata file: %s", metadata_path)
    if metadata_path.exists():
        logger.info(
            "✅ [VM_EXISTS_CHECK] VM '%s' exists (metadata file found)", vm_name
        )
        return True
    logger.info("❌ [VM_EXISTS_CHECK] Metadata file not found")

    # Check vm.conf
    logger.info("🔍 [VM_EXISTS_CHECK] Checking /etc/vm.conf...")
    try:
        with open("/etc/vm.conf", "r", encoding="utf-8") as file_handle:
            vm_conf_content = file_handle.read()
            # Look for 'vm "vm_name" {' pattern
            if f'vm "{vm_name}"' in vm_conf_content:
                logger.info(
                    "✅ [VM_EXISTS_CHECK] VM '%s' exists (found in /etc/vm.conf)",
                    vm_name,
                )
                return True
        logger.info("❌ [VM_EXISTS_CHECK] VM not found in /etc/vm.conf")
    except FileNotFoundError:
        logger.info("❌ [VM_EXISTS_CHECK] /etc/vm.conf doesn't exist")
    except Exception as error:
        logger.warning("⚠️ [VM_EXISTS_CHECK] Error reading /etc/vm.conf: %s", error)

    # Check vmctl status
    logger.info("🔍 [VM_EXISTS_CHECK] Checking vmctl status...")
    try:
        result = subprocess.run(  # nosec B603 B607
            ["vmctl", "status", vm_name],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        logger.info("🔍 [VM_EXISTS_CHECK] vmctl returncode: %d", result.returncode)
        logger.info("🔍 [VM_EXISTS_CHECK] vmctl stdout: %s", repr(result.stdout))
        # vmctl status returns 0 even if VM doesn't exist (just shows empty list)
        # So we need to check if the output contains the VM name
        if result.returncode == 0 and vm_name in result.stdout:
            logger.info(
                "✅ [VM_EXISTS_CHECK] VM '%s' exists (found in vmctl status)",
                vm_name,
            )
            return True
        logger.info("❌ [VM_EXISTS_CHECK] VM not found in vmctl status")
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        logger.warning("⚠️ [VM_EXISTS_CHECK] Error checking vmctl status: %s", error)

    logger.info("✅ [VM_EXISTS_CHECK] VM '%s' does NOT exist", vm_name)
    return False


def extract_openbsd_version(distribution: str, logger) -> Optional[str]:
    """
    Extract OpenBSD version from distribution string.

    Args:
        distribution: Distribution string (e.g., "OpenBSD 7.7")
        logger: Logger instance

    Returns:
        Version string (e.g., "7.7") or None if not found
    """
    try:
        match = re.search(r"(\d+\.\d+)", distribution)  # NOSONAR
        if match:
            return match.group(1)
        return None
    except Exception as error:
        logger.error(_("Error parsing OpenBSD version: %s"), error)
        return None


def get_fqdn_hostname(hostname: str, server_url: str) -> str:
    """
    Derive FQDN hostname from server URL if not already FQDN.

    Args:
        hostname: Hostname (may be short or FQDN)
        server_url: Server URL to derive domain from

    Returns:
        FQDN hostname
    """
    if "." in hostname:
        return hostname

    try:
        parsed = urlparse(server_url)
        server_host = parsed.hostname or ""
        if "." in server_host:
            parts = server_host.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])
                return f"{hostname}.{domain}"
    except Exception:  # nosec B110
        pass

    return hostname


def ensure_vmm_directories(logger):
    """
    Ensure VMM directories exist.

    Args:
        logger: Logger instance
    """
    for dir_path in [VMM_DISK_DIR]:
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, mode=0o755)
            logger.info(_("Created VMM directory: %s"), dir_path)


def save_vm_metadata(
    vm_name: str,
    hostname: str,
    distribution: str,
    openbsd_version: str,
    vm_ip: str,
    logger,
) -> bool:
    """
    Save VM metadata to JSON file for listing.

    Args:
        vm_name: Name of the VM
        hostname: VM hostname
        distribution: Distribution string
        openbsd_version: OpenBSD version
        vm_ip: VM IP address
        logger: Logger instance

    Returns:
        True if successful, False otherwise
    """
    try:
        metadata_dir = Path(VMM_METADATA_DIR)
        metadata_dir.mkdir(parents=True, exist_ok=True)

        metadata = {
            "vm_name": vm_name,
            "hostname": hostname,
            "vm_ip": vm_ip,
            "distribution": {
                "distribution_name": "OpenBSD",
                "distribution_version": openbsd_version,
            },
            "distribution_string": distribution,
        }

        metadata_file = metadata_dir / f"{vm_name}.json"
        with open(metadata_file, "w", encoding="utf-8") as metadata_fp:
            json.dump(metadata, metadata_fp, indent=2)

        logger.info(_("Saved VM metadata for '%s' to %s"), vm_name, metadata_file)
        return True

    except Exception as error:
        logger.error(_("Error saving VM metadata for '%s': %s"), vm_name, error)
        return False
