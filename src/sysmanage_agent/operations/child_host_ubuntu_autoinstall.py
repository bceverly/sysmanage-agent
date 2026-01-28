"""
Ubuntu VMM autoinstall module.

This module implements the automated installation of Ubuntu VMs:
- Downloads Ubuntu Server ISO
- Creates autoinstall YAML files for automated installation
- Modifies ISO for serial console boot on OpenBSD VMM
- Manages configuration files for firstboot setup

Key differences from Debian:
- Uses Subiquity installer with autoinstall (YAML format) instead of preseed
- Uses GRUB bootloader instead of ISOLINUX
- Uses netplan for network configuration
- Requires kernel ip= parameter for static IP during autoinstall
- ISO is larger (~3.1GB vs ~650MB)
"""

import logging
import os
import shutil
import subprocess  # nosec B404
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.operations.child_host_ubuntu_packages import (
    UBUNTU_CODENAMES,
    UBUNTU_ISO_INITRD_PATH,
    UBUNTU_ISO_KERNEL_PATH,
    UBUNTU_ISO_URLS,
)
from src.sysmanage_agent.operations.child_host_ubuntu_scripts import (
    generate_agent_config,
    generate_autoinstall_file,
    generate_autoinstall_with_agent,
    generate_firstboot_script,
    generate_firstboot_systemd_service,
    generate_kernel_boot_params,
)

# Module-level constants for duplicate string literals
_UNSUPPORTED_UBUNTU_VERSION = "Unsupported Ubuntu version: %s"


class UbuntuAutoinstallSetup:
    """Ubuntu automated installation setup for VMM VMs."""

    ISO_CACHE_DIR = "/var/vmm/iso-cache"
    UBUNTU_DATA_BASE = "/var/vmm/ubuntu-data"
    HTTPD_ROOT = "/var/www/htdocs"  # OpenBSD httpd document root
    CIDATA_ISO_DIR = "/var/vmm/cidata"  # Directory for cidata ISOs

    def __init__(self, logger: logging.Logger):
        """Initialize Ubuntu autoinstall setup."""
        self.logger = logger

    def _check_cached_iso(self, iso_path: Path) -> Dict[str, Any]:
        """
        Check if a valid cached ISO exists.

        Args:
            iso_path: Path to the ISO file

        Returns:
            Dict with 'found' bool and optional 'iso_path' if valid cache exists
        """
        if not iso_path.exists():
            return {"found": False}

        file_size = iso_path.stat().st_size
        if file_size > 2 * 1024 * 1024 * 1024:  # > 2GB
            self.logger.info(
                _("Using cached Ubuntu ISO: %s (%d MB)"),
                iso_path,
                file_size // (1024 * 1024),
            )
            return {"found": True, "iso_path": str(iso_path)}

        # File is too small, likely corrupted - remove it
        self.logger.warning(
            _("Cached ISO is incomplete (%d bytes), re-downloading"),
            file_size,
        )
        iso_path.unlink()
        return {"found": False}

    def _download_iso_with_progress(
        self, iso_url: str, temp_path: Path
    ) -> Dict[str, Any]:
        """
        Download ISO file with progress logging.

        Args:
            iso_url: URL to download from
            temp_path: Temporary path to save the download

        Returns:
            Dict with 'success' bool, 'total_size' int, and optional 'error'
        """
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(iso_url, timeout=3600) as response:  # nosec B310
            total_size = int(response.headers.get("content-length", 0))
            downloaded = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            last_logged_mb = 0  # Track last logged MB for progress

            # Download to temp file first
            with open(temp_path, "wb") as iso_file:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    iso_file.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        # Log progress every 100MB (larger file)
                        current_mb = downloaded // (1024 * 1024)
                        if current_mb >= last_logged_mb + 100:
                            last_logged_mb = current_mb
                            self.logger.info(
                                _("Download progress: %.1f%% (%d MB)"),
                                progress,
                                current_mb,
                            )

        return {"success": True, "total_size": total_size}

    def _validate_and_finalize_download(
        self, temp_path: Path, iso_path: Path, total_size: int
    ) -> Dict[str, Any]:
        """
        Validate downloaded file size and move to final location.

        Args:
            temp_path: Temporary download path
            iso_path: Final ISO path
            total_size: Expected file size (0 if unknown)

        Returns:
            Dict with 'success' bool and optional 'error'
        """
        if total_size > 0:
            actual_size = temp_path.stat().st_size
            if actual_size != total_size:
                temp_path.unlink()
                return {
                    "success": False,
                    "error": _("Download incomplete: expected %d bytes, got %d bytes")
                    % (total_size, actual_size),
                }

        # Atomically rename temp file to final path
        temp_path.rename(iso_path)

        self.logger.info(
            _("Downloaded Ubuntu ISO: %s (%d MB)"),
            iso_path,
            iso_path.stat().st_size // (1024 * 1024),
        )
        return {"success": True, "iso_path": str(iso_path)}

    def download_ubuntu_iso(self, version: str) -> Dict[str, Any]:
        """
        Download Ubuntu Server ISO.

        Args:
            version: Ubuntu version (e.g., "24.04")

        Returns:
            Dict with success status and ISO path
        """
        temp_path = None
        try:
            # Ensure cache directory exists
            Path(self.ISO_CACHE_DIR).mkdir(parents=True, exist_ok=True)

            # Get ISO URL for this version
            if version not in UBUNTU_ISO_URLS:
                return {
                    "success": False,
                    "iso_path": None,
                    "error": _(_UNSUPPORTED_UBUNTU_VERSION) % version,
                }

            iso_url = UBUNTU_ISO_URLS[version]
            iso_filename = os.path.basename(iso_url)
            iso_path = Path(self.ISO_CACHE_DIR) / iso_filename
            temp_path = Path(self.ISO_CACHE_DIR) / f"{iso_filename}.downloading"

            # Clean up any leftover temp file from previous failed download
            if temp_path.exists():
                self.logger.info(_("Removing incomplete download: %s"), temp_path)
                temp_path.unlink()

            # Check if already downloaded and validate size
            cache_result = self._check_cached_iso(iso_path)
            if cache_result.get("found"):
                return {"success": True, "iso_path": cache_result["iso_path"]}

            # Download ISO (Ubuntu Server is ~3.1GB, will take a while)
            self.logger.info(_("Downloading Ubuntu %s ISO from %s"), version, iso_url)
            self.logger.info(_("This may take several minutes (ISO is ~3.1GB)..."))

            download_result = self._download_iso_with_progress(iso_url, temp_path)
            if not download_result.get("success"):
                return {
                    "success": False,
                    "iso_path": None,
                    "error": download_result.get("error", "Download failed"),
                }

            # Validate and finalize download
            finalize_result = self._validate_and_finalize_download(
                temp_path, iso_path, download_result["total_size"]
            )
            if not finalize_result.get("success"):
                return {
                    "success": False,
                    "iso_path": None,
                    "error": finalize_result.get("error"),
                }

            temp_path = None  # Clear so we don't try to delete in finally
            return {"success": True, "iso_path": finalize_result["iso_path"]}

        except Exception as error:  # pylint: disable=broad-except
            # Clean up partial download on failure
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                    self.logger.info(_("Cleaned up partial download: %s"), temp_path)
                except OSError:
                    pass
            return {"success": False, "iso_path": None, "error": str(error)}

    def create_serial_console_iso(
        self,
        original_iso_path: str,
        vm_name: str,
        vm_ip: str,
        gateway_ip: str,
    ) -> Dict[str, Any]:
        """
        Create a modified Ubuntu ISO with serial console boot for autoinstall.

        Uses xorriso modify mode to preserve the original ISO's boot structure
        (GRUB2 MBR, El Torito boot sectors, GPT partition table) while:
        1. Updating grub.cfg for serial console boot
        2. Adding kernel ip= parameter for static networking

        The autoinstall config is provided via a separate cidata ISO which
        cloud-init auto-detects. This avoids the GRUB semicolon parsing issue
        with ds=nocloud-net;s=... kernel parameters.

        Args:
            original_iso_path: Path to original Ubuntu ISO
            vm_name: Name of the VM (for unique ISO naming)
            vm_ip: Static IP address for the VM
            gateway_ip: Gateway IP address

        Returns:
            Dict with success status and modified ISO path
        """
        temp_dir = None
        try:
            # Create output path for modified ISO
            modified_iso_path = (
                Path(self.ISO_CACHE_DIR) / f"ubuntu-serial-{vm_name}.iso"
            )

            # Create temp directory for files to add to ISO
            temp_dir = tempfile.mkdtemp(prefix="ubuntu-iso-")

            # Extract short hostname from vm_name (remove domain if present)
            short_hostname = vm_name.split(".")[0]

            # Generate boot parameters (no ds= param needed with cidata ISO)
            boot_params = generate_kernel_boot_params(
                vm_ip=vm_ip,
                gateway_ip=gateway_ip,
                hostname=short_hostname,
            )

            # Create modified grub.cfg
            grub_cfg_path = Path(temp_dir) / "grub.cfg"
            self._modify_grub_cfg(grub_cfg_path, boot_params)

            self.logger.info(
                _("Modifying ISO for serial console: %s"), modified_iso_path
            )

            # Use xorriso in modify mode to preserve boot structure
            # Only update grub.cfg (autoinstall served via HTTP)
            xorriso_cmd = [
                "xorriso",
                "-indev",
                str(original_iso_path),
                "-outdev",
                str(modified_iso_path),
                # Update grub.cfg
                "-update",
                str(grub_cfg_path),
                "/boot/grub/grub.cfg",
                # Preserve boot structure
                "-boot_image",
                "any",
                "replay",
                "-end",
            ]

            result = subprocess.run(  # nosec B603 B607
                xorriso_cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes for larger ISO
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to create ISO: {result.stderr}",
                }

            self.logger.info(
                _("Created serial console ISO: %s (%d MB)"),
                modified_iso_path,
                modified_iso_path.stat().st_size // (1024 * 1024),
            )

            return {"success": True, "iso_path": str(modified_iso_path)}

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": str(error)}

        finally:
            # Clean up temp directory
            if temp_dir and Path(temp_dir).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    def create_cidata_iso(
        self,
        vm_name: str,
        user_data_content: str,
        meta_data_content: str = "",
    ) -> Dict[str, Any]:
        """
        Create a cidata ISO for cloud-init NoCloud datasource.

        Cloud-init auto-detects filesystems labeled 'cidata' or 'CIDATA' and
        reads user-data/meta-data from them. This bypasses the need for
        ds=nocloud-net;s=... kernel parameters which have GRUB semicolon issues.

        Args:
            vm_name: Name of the VM (for unique ISO naming)
            user_data_content: Content for user-data file (autoinstall YAML)
            meta_data_content: Content for meta-data file (can be empty)

        Returns:
            Dict with success status and cidata ISO path
        """
        temp_dir = None
        try:
            # Ensure cidata ISO directory exists
            Path(self.CIDATA_ISO_DIR).mkdir(parents=True, exist_ok=True)

            # Create output path for cidata ISO
            cidata_iso_path = Path(self.CIDATA_ISO_DIR) / f"cidata-{vm_name}.iso"

            # Create temp directory for cidata files
            temp_dir = tempfile.mkdtemp(prefix="cidata-")

            # Write user-data file
            user_data_path = Path(temp_dir) / "user-data"
            user_data_path.write_text(user_data_content)
            self.logger.info(_("Created user-data file for cidata ISO"))

            # Write meta-data file (can be empty but must exist)
            meta_data_path = Path(temp_dir) / "meta-data"
            meta_data_path.write_text(meta_data_content)
            self.logger.info(_("Created meta-data file for cidata ISO"))

            # Create cidata ISO using mkisofs
            # -V sets the volume label to 'cidata' which cloud-init auto-detects
            # -J enables Joliet extensions (for longer filenames)
            # -R enables Rock Ridge extensions (for Unix permissions)
            mkisofs_cmd = [
                "mkisofs",
                "-output",
                str(cidata_iso_path),
                "-volid",
                "cidata",  # Volume label - cloud-init looks for this
                "-joliet",
                "-rock",
                temp_dir,
            ]

            self.logger.info(_("Creating cidata ISO: %s"), cidata_iso_path)
            result = subprocess.run(  # nosec B603 B607
                mkisofs_cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to create cidata ISO: {result.stderr}",
                }

            iso_size = cidata_iso_path.stat().st_size
            self.logger.info(
                _("Created cidata ISO: %s (%d bytes)"),
                cidata_iso_path,
                iso_size,
            )

            return {"success": True, "cidata_iso_path": str(cidata_iso_path)}

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": str(error)}

        finally:
            # Clean up temp directory
            if temp_dir and Path(temp_dir).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _modify_grub_cfg(self, cfg_path: Path, boot_params: str) -> None:
        """
        Modify grub.cfg for serial console and autoinstall boot.

        Args:
            cfg_path: Path to grub.cfg
            boot_params: Kernel boot parameters string
        """
        # Create a new grub.cfg optimized for serial console autoinstall
        # This bypasses the graphical menu entirely
        kernel_path = UBUNTU_ISO_KERNEL_PATH
        initrd_path = UBUNTU_ISO_INITRD_PATH

        new_content = f"""# Serial console configuration for OpenBSD VMM
# Auto-generated for autoinstall

# Serial console setup
serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1
terminal_input serial console
terminal_output serial console

set timeout=3
set default=0

menuentry "Install Ubuntu Server (autoinstall)" {{
    linux {kernel_path} {boot_params}
    initrd {initrd_path}
}}

menuentry "Install Ubuntu Server (manual)" {{
    linux {kernel_path} console=ttyS0,115200n8 ---
    initrd {initrd_path}
}}
"""
        cfg_path.write_text(new_content)
        self.logger.info(_("Modified grub.cfg for serial console autoinstall"))

    def _modify_loopback_cfg(self, cfg_path: Path, boot_params: str) -> None:
        """Modify loopback.cfg for serial console (used when booting from ISO file)."""
        kernel_path = UBUNTU_ISO_KERNEL_PATH
        initrd_path = UBUNTU_ISO_INITRD_PATH

        new_content = f"""# Loopback configuration for serial console
menuentry "Install Ubuntu Server (autoinstall)" {{
    linux {kernel_path} {boot_params}
    initrd {initrd_path}
}}
"""
        cfg_path.write_text(new_content)
        self.logger.info(_("Modified loopback.cfg for serial console"))

    def create_autoinstall_file(  # pylint: disable=too-many-arguments
        self,
        hostname: str,
        username: str,
        password_hash: str,
        gateway_ip: str,
        vm_ip: str,
        dns_server: str,
        ubuntu_version: str = "24.04",
    ) -> Dict[str, Any]:
        """
        Create Ubuntu autoinstall YAML file.

        Args:
            hostname: VM hostname (FQDN)
            username: User to create
            password_hash: SHA-512 hashed password for user
            gateway_ip: Gateway IP address
            vm_ip: Static IP address for the VM
            dns_server: DNS server (must be actual DNS, not gateway!)
            ubuntu_version: Ubuntu version (e.g., "24.04")

        Returns:
            Dict with success status and autoinstall content
        """
        try:
            if ubuntu_version not in UBUNTU_CODENAMES:
                return {
                    "success": False,
                    "autoinstall": None,
                    "error": _(_UNSUPPORTED_UBUNTU_VERSION) % ubuntu_version,
                }

            autoinstall_content = generate_autoinstall_file(
                hostname=hostname,
                username=username,
                password_hash=password_hash,
                gateway_ip=gateway_ip,
                vm_ip=vm_ip,
                dns_server=dns_server,
                ubuntu_version=ubuntu_version,
            )

            return {"success": True, "autoinstall": autoinstall_content}

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "autoinstall": None, "error": str(error)}

    def create_ubuntu_data_dir(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        vm_name: str,
        autoinstall_content: str,
        server_hostname: str,
        server_port: int,
        use_https: bool,
        auto_approve_token: str = None,
        ubuntu_version: str = "24.04",
    ) -> Dict[str, Any]:
        """
        Create data directory with all Ubuntu setup files.

        This directory contains the autoinstall file, agent configuration,
        firstboot script, and systemd service for automated setup.

        Args:
            vm_name: Name of the VM
            autoinstall_content: Autoinstall YAML content
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS
            auto_approve_token: Optional auto-approval token
            ubuntu_version: Ubuntu version (default: "24.04")

        Returns:
            Dict with success status and data directory path
        """
        try:
            data_dir = Path(self.UBUNTU_DATA_BASE)
            data_dir.mkdir(parents=True, exist_ok=True)

            # Create VM-specific directory
            vm_data_dir = data_dir / vm_name
            vm_data_dir.mkdir(exist_ok=True)

            # Write autoinstall file (user-data)
            userdata_path = vm_data_dir / "user-data"
            userdata_path.write_text(autoinstall_content)
            self.logger.info(_("Created autoinstall file: %s"), userdata_path)

            # Create empty meta-data (required by cloud-init)
            metadata_path = vm_data_dir / "meta-data"
            metadata_path.write_text("")
            self.logger.info(_("Created meta-data file: %s"), metadata_path)

            # Generate and write agent configuration
            agent_config = generate_agent_config(
                hostname=server_hostname,
                port=server_port,
                use_https=use_https,
                auto_approve_token=auto_approve_token,
            )
            config_path = vm_data_dir / "sysmanage-agent.yaml"
            config_path.write_text(agent_config)
            self.logger.info(_("Created agent config: %s"), config_path)

            # Generate and write firstboot script
            firstboot_script = generate_firstboot_script(
                ubuntu_version=ubuntu_version,
                server_hostname=server_hostname,
                server_port=server_port,
                use_https=use_https,
                auto_approve_token=auto_approve_token,
            )
            firstboot_path = vm_data_dir / "sysmanage-firstboot.sh"
            firstboot_path.write_text(firstboot_script)
            firstboot_path.chmod(0o755)
            self.logger.info(_("Created firstboot script: %s"), firstboot_path)

            # Generate and write systemd service
            systemd_service = generate_firstboot_systemd_service()
            service_path = vm_data_dir / "sysmanage-firstboot.service"
            service_path.write_text(systemd_service)
            self.logger.info(_("Created systemd service: %s"), service_path)

            # Also copy autoinstall to httpd document root for serving via HTTP
            # The OpenBSD httpd serves files from /var/www/htdocs on 100.64.0.1:80
            httpd_ubuntu_dir = Path(self.HTTPD_ROOT) / "ubuntu" / vm_name
            httpd_ubuntu_dir.mkdir(parents=True, exist_ok=True)

            # user-data (the autoinstall config)
            httpd_userdata_path = httpd_ubuntu_dir / "user-data"
            httpd_userdata_path.write_text(autoinstall_content)
            httpd_userdata_path.chmod(0o644)
            self.logger.info(_("Created httpd user-data file: %s"), httpd_userdata_path)

            # meta-data (empty, required by cloud-init)
            httpd_metadata_path = httpd_ubuntu_dir / "meta-data"
            httpd_metadata_path.write_text("")
            httpd_metadata_path.chmod(0o644)
            self.logger.info(_("Created httpd meta-data file: %s"), httpd_metadata_path)

            # vendor-data (empty, required by cloud-init nocloud datasource)
            httpd_vendordata_path = httpd_ubuntu_dir / "vendor-data"
            httpd_vendordata_path.write_text("")
            httpd_vendordata_path.chmod(0o644)
            self.logger.info(
                _("Created httpd vendor-data file: %s"), httpd_vendordata_path
            )

            # Build the autoinstall URL (served by httpd on VMM network)
            # Note: trailing slash is important for cloud-init
            autoinstall_url = (
                f"http://100.64.0.1/ubuntu/{vm_name}/"  # NOSONAR - internal VM network
            )

            self.logger.info(_("Created Ubuntu setup data in %s"), vm_data_dir)

            return {
                "success": True,
                "data_dir": str(vm_data_dir),
                "userdata_path": str(userdata_path),
                "autoinstall_url": autoinstall_url,
                "config_path": str(config_path),
                "firstboot_path": str(firstboot_path),
                "service_path": str(service_path),
            }

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": str(error)}

    def generate_enhanced_autoinstall(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        hostname: str,
        username: str,
        password_hash: str,
        gateway_ip: str,
        vm_ip: str,
        ubuntu_version: str,
        server_hostname: str,
        server_port: int,
        use_https: bool,
        auto_approve_token: str = None,
        dns_server: str = None,
        agent_deb_url: str = None,
    ) -> Dict[str, Any]:
        """
        Generate enhanced autoinstall YAML with embedded agent setup.

        This creates a complete autoinstall file that includes all necessary
        late-commands to set up sysmanage-agent without needing external files.

        Args:
            hostname: VM hostname (FQDN)
            username: User to create
            password_hash: SHA-512 hashed password for user
            gateway_ip: Gateway IP address
            vm_ip: Static IP address for the VM
            ubuntu_version: Ubuntu version (e.g., "24.04")
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS
            auto_approve_token: Optional auto-approval token
            dns_server: DNS server (defaults to actual DNS lookup)
            agent_deb_url: Optional URL to download agent .deb during install

        Returns:
            Dict with success status and complete autoinstall content
        """
        try:
            if ubuntu_version not in UBUNTU_CODENAMES:
                return {
                    "success": False,
                    "autoinstall": None,
                    "error": _(_UNSUPPORTED_UBUNTU_VERSION) % ubuntu_version,
                }

            # DNS server is critical - must be actual DNS, not gateway
            if not dns_server:
                return {
                    "success": False,
                    "autoinstall": None,
                    "error": _("DNS server is required for Ubuntu autoinstall"),
                }

            autoinstall_content = generate_autoinstall_with_agent(
                hostname=hostname,
                username=username,
                password_hash=password_hash,
                gateway_ip=gateway_ip,
                vm_ip=vm_ip,
                dns_server=dns_server,
                server_hostname=server_hostname,
                server_port=server_port,
                use_https=use_https,
                auto_approve_token=auto_approve_token,
                ubuntu_version=ubuntu_version,
                agent_deb_url=agent_deb_url,
            )

            return {"success": True, "autoinstall": autoinstall_content}

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "autoinstall": None, "error": str(error)}
