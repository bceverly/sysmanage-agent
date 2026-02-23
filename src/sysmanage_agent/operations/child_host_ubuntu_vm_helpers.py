"""
Ubuntu VM creation helper functions.

Pure utility functions extracted from UbuntuVmCreator to keep the
orchestration module under 1000 lines.  Every function that previously
lived as a method on the class but only needed a logger (or nothing at
all) is collected here.
"""

import json
import shutil
import subprocess  # nosec B404
import time
from pathlib import Path
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.operations.child_host_vmm_utils import VMM_METADATA_DIR


def parse_memory_gb(memory_str: str) -> float:
    """
    Parse memory string to GB value.

    Args:
        memory_str: Memory string like "1G", "2G", "512M"

    Returns:
        Memory in GB as float
    """
    memory_str = memory_str.upper().strip()
    try:
        if memory_str.endswith("G"):
            return float(memory_str[:-1])
        if memory_str.endswith("M"):
            return float(memory_str[:-1]) / 1024
        if memory_str.endswith("K"):
            return float(memory_str[:-1]) / (1024 * 1024)
        # Assume bytes, convert to GB
        return float(memory_str) / (1024 * 1024 * 1024)
    except ValueError:
        return 0.0


def get_gateway_ip(logger) -> Optional[str]:
    """Get gateway IP from vether0 interface."""
    try:
        result = subprocess.run(  # nosec B603 B607
            ["ifconfig", "vether0"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        for line in result.stdout.split("\n"):
            if "inet " in line and "netmask" in line:
                return line.split()[1]
        return None
    except Exception as error:
        logger.error(_("Failed to get vether0 IP: %s"), error)
        return None


def get_next_vm_ip(gateway_ip: str) -> str:
    """Get the next available VM IP address."""
    parts = gateway_ip.rsplit(".", 1)
    subnet_prefix = parts[0]

    # Find used IPs from metadata
    used_ips: set = set()
    metadata_dir = Path(VMM_METADATA_DIR)
    if metadata_dir.exists():
        for metadata_file in metadata_dir.glob("*.json"):
            try:
                with open(metadata_file, "r", encoding="utf-8") as file_handle:
                    metadata = json.load(file_handle)
                    if "vm_ip" in metadata:
                        used_ips.add(metadata["vm_ip"])
            except (OSError, json.JSONDecodeError):
                pass

    # Find next available IP starting from .100
    for i in range(100, 255):
        candidate_ip = f"{subnet_prefix}.{i}"
        if candidate_ip not in used_ips:
            return candidate_ip

    return f"{subnet_prefix}.100"


def get_disk_size(disk_path: str, logger) -> int:
    """
    Get the actual size of a disk image (not sparse size).

    Args:
        disk_path: Path to the disk image
        logger: Logger instance

    Returns:
        Actual disk size in bytes (not virtual size)
    """
    try:
        # Use 'du -k' for OpenBSD compatibility (returns size in KB)
        # OpenBSD du doesn't have -b flag
        result = subprocess.run(  # nosec B603 B607
            ["du", "-k", disk_path],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            # Output format: "size_in_kb\tpath"
            size_kb_str = result.stdout.strip().split()[0]
            return int(size_kb_str) * 1024  # Convert KB to bytes
    except Exception as error:
        logger.warning(_("Failed to get disk size: %s"), error)

    # Fallback to stat if du fails
    try:
        return Path(disk_path).stat().st_size
    except Exception:
        return 0


def validate_vm_config(config) -> Dict[str, Any]:
    """Validate VM configuration."""
    if not config.distribution:
        return {"success": False, "error": _("Distribution is required")}
    if not config.vm_name:
        return {"success": False, "error": _("VM name is required")}
    if not config.hostname:
        return {"success": False, "error": _("Hostname is required")}
    if not config.username:
        return {"success": False, "error": _("Username is required")}
    if not config.password_hash:
        return {"success": False, "error": _("Password is required")}
    if not config.server_config.server_url:
        return {"success": False, "error": _("Server URL is required")}
    return {"success": True}


def save_vm_metadata(
    vm_name: str,
    hostname: str,
    distribution: str,
    ubuntu_version: str,
    vm_ip: str,
    logger,
) -> None:
    """Save VM metadata to JSON file."""
    metadata_dir = Path(VMM_METADATA_DIR)
    metadata_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "vm_name": vm_name,
        "hostname": hostname,
        "vm_ip": vm_ip,
        "distribution": {
            "distribution_name": "Ubuntu",
            "distribution_version": ubuntu_version,
        },
        "distribution_string": distribution,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    metadata_path = metadata_dir / f"{vm_name}.json"
    with open(metadata_path, "w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=2)

    logger.info(_("Saved VM metadata to %s"), metadata_path)


def cleanup_installation_artifacts(serial_iso_path: str, vm_name: str, logger) -> None:
    """
    Clean up installation artifacts after successful VM creation.

    Removes:
    - Serial console ISO (large file, no longer needed after install)
    - Cidata ISO (small, no longer needed after install)
    - Optionally the ubuntu-data directory (keeps for debugging by default)

    Args:
        serial_iso_path: Path to the serial console ISO
        vm_name: Name of the VM
        logger: Logger instance
    """
    # Remove serial console ISO (typically ~3GB for Ubuntu)
    try:
        iso_path = Path(serial_iso_path)
        if iso_path.exists():
            iso_size_mb = iso_path.stat().st_size // (1024 * 1024)
            iso_path.unlink()
            logger.info(
                _("Removed serial console ISO: %s (%d MB freed)"),
                serial_iso_path,
                iso_size_mb,
            )
    except Exception as error:
        logger.warning(
            _("Failed to remove serial console ISO %s: %s"),
            serial_iso_path,
            error,
        )

    # Remove cidata ISO (small, ~365KB)
    cidata_iso_path = Path(f"/var/vmm/cidata/cidata-{vm_name}.iso")
    try:
        if cidata_iso_path.exists():
            cidata_iso_path.unlink()
            logger.info(_("Removed cidata ISO: %s"), cidata_iso_path)
    except Exception as error:
        logger.warning(
            _("Failed to remove cidata ISO %s: %s"),
            cidata_iso_path,
            error,
        )

    # Remove httpd autoinstall directory (no longer needed after install)
    httpd_dir = Path(f"/var/www/htdocs/ubuntu/{vm_name}")
    try:
        if httpd_dir.exists():
            shutil.rmtree(httpd_dir)
            logger.info(_("Removed httpd autoinstall directory: %s"), httpd_dir)
    except Exception as error:
        logger.warning(_("Failed to remove httpd directory %s: %s"), httpd_dir, error)

    # Keep ubuntu-data directory for debugging/reference
    # It's small and useful for troubleshooting
    logger.info(
        _("Keeping ubuntu-data directory for reference: /var/vmm/ubuntu-data/%s"),
        vm_name,
    )
