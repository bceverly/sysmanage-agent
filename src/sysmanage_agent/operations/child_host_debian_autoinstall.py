"""
Debian VMM autoinstall module.

This module implements the automated installation of Debian VMs:
- Downloads Debian netinst ISO
- Creates preseed files for automated installation
- Manages configuration files for firstboot setup
"""

from __future__ import annotations

import base64
import logging
import os
import shutil
import subprocess  # nosec B404
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict

from src.i18n import _
from src.sysmanage_agent.operations.child_host_debian_agent_download import (
    AgentPackageDownloader,
)
from src.sysmanage_agent.operations.child_host_debian_packages import (
    DEBIAN_CODENAMES,
    DEBIAN_ISO_URLS,
    DEBIAN_MIRROR_URLS,
)
from src.sysmanage_agent.operations.child_host_debian_scripts import (
    generate_agent_config,
    generate_firstboot_script,
    generate_firstboot_systemd_service,
    generate_preseed_file,
)


class DebianAutoinstallSetup:
    """Debian automated installation setup for VMM VMs."""

    ISO_CACHE_DIR = "/var/vmm/iso-cache"
    DEBIAN_DATA_BASE = "/var/vmm/debian-data"
    HTTPD_ROOT = "/var/www/htdocs"  # OpenBSD httpd document root

    def __init__(self, logger: logging.Logger):
        """Initialize Debian autoinstall setup."""
        self.logger = logger
        self.agent_downloader = AgentPackageDownloader(logger)

    def download_agent_deb(self, debian_version: str) -> Dict[str, Any]:
        """Delegate to agent_downloader."""
        return self.agent_downloader.download_agent_deb(debian_version)

    def serve_agent_deb_via_httpd(self, deb_path: str, vm_name: str) -> Dict[str, Any]:
        """Delegate to agent_downloader."""
        return self.agent_downloader.serve_agent_deb_via_httpd(deb_path, vm_name)

    def download_debian_iso(self, version: str) -> Dict[str, Any]:
        """
        Download Debian netinst ISO.

        Args:
            version: Debian version (e.g., "12")

        Returns:
            Dict with success status and ISO path
        """
        temp_path = None
        try:
            # Ensure cache directory exists
            Path(self.ISO_CACHE_DIR).mkdir(parents=True, exist_ok=True)

            # Get ISO URL for this version
            if version not in DEBIAN_ISO_URLS:
                return {
                    "success": False,
                    "iso_path": None,
                    "error": _("Unsupported Debian version: %s") % version,
                }

            iso_url = DEBIAN_ISO_URLS[version]
            iso_filename = os.path.basename(iso_url)
            iso_path = Path(self.ISO_CACHE_DIR) / iso_filename
            temp_path = Path(self.ISO_CACHE_DIR) / f"{iso_filename}.downloading"

            # Clean up any leftover temp file from previous failed download
            if temp_path.exists():
                self.logger.info(_("Removing incomplete download: %s"), temp_path)
                temp_path.unlink()

            # Check if already downloaded and validate size
            cached_result = self._check_cached_iso(iso_path)
            if cached_result is not None:
                return cached_result

            # Download ISO (Debian netinst is ~600MB, may take a while)
            self.logger.info(_("Downloading Debian %s ISO from %s"), version, iso_url)
            self.logger.info(_("This may take several minutes (ISO is ~600MB)..."))

            total_size = self._download_iso_to_temp(iso_url, temp_path)

            # Validate downloaded size
            validation_error = self._validate_downloaded_iso(temp_path, total_size)
            if validation_error is not None:
                return validation_error

            # Atomically rename temp file to final path
            temp_path.rename(iso_path)
            temp_path = None  # Clear so we don't try to delete in finally

            self.logger.info(
                _("Downloaded Debian ISO: %s (%d MB)"),
                iso_path,
                iso_path.stat().st_size // (1024 * 1024),
            )
            return {"success": True, "iso_path": str(iso_path)}

        except Exception as error:  # pylint: disable=broad-except
            # Clean up partial download on failure
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                    self.logger.info(_("Cleaned up partial download: %s"), temp_path)
                except OSError:
                    pass
            return {"success": False, "iso_path": None, "error": str(error)}

    def _check_cached_iso(self, iso_path: Path) -> Dict[str, Any] | None:
        """Check if a cached ISO exists and is valid.

        Returns:
            Success dict if cached ISO is valid, None if download is needed.
        """
        if not iso_path.exists():
            return None

        file_size = iso_path.stat().st_size
        if file_size > 500 * 1024 * 1024:  # > 500MB
            self.logger.info(
                _("Using cached Debian ISO: %s (%d MB)"),
                iso_path,
                file_size // (1024 * 1024),
            )
            return {"success": True, "iso_path": str(iso_path)}

        # File is too small, likely corrupted - remove it
        self.logger.warning(
            _("Cached ISO is incomplete (%d bytes), re-downloading"),
            file_size,
        )
        iso_path.unlink()
        return None

    def _download_iso_to_temp(self, iso_url: str, temp_path: Path) -> int:
        """Download ISO from URL to a temporary file.

        Returns:
            Total expected size from content-length header (0 if unknown).
        """
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(iso_url, timeout=1800) as response:  # nosec B310
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
                        # Log progress every 50MB
                        current_mb = downloaded // (1024 * 1024)
                        if current_mb >= last_logged_mb + 50:
                            last_logged_mb = current_mb
                            self.logger.info(
                                _("Download progress: %.1f%% (%d MB)"),
                                progress,
                                current_mb,
                            )

        return total_size

    def _validate_downloaded_iso(
        self, temp_path: Path, total_size: int
    ) -> Dict[str, Any] | None:
        """Validate downloaded ISO size matches expected.

        Returns:
            Error dict if validation fails, None if valid.
        """
        if total_size <= 0:
            return None

        actual_size = temp_path.stat().st_size
        if actual_size == total_size:
            return None

        temp_path.unlink()
        return {
            "success": False,
            "iso_path": None,
            "error": _("Download incomplete: expected %d bytes, got %d bytes")
            % (total_size, actual_size),
        }

    def create_serial_console_iso(
        self,
        original_iso_path: str,
        vm_name: str,
        preseed_url: str,
        vm_ip: str,
        gateway_ip: str,
        dns_server: str,
    ) -> Dict[str, Any]:
        """
        Create a modified ISO with serial console boot enabled.

        This repackages the Debian netinst ISO to:
        1. Enable serial console in ISOLINUX
        2. Set default boot to text install with all parameters
        3. No keyboard interaction required

        Args:
            original_iso_path: Path to original Debian ISO
            vm_name: Name of the VM (for unique ISO naming)
            preseed_url: URL to preseed file
            vm_ip: Static IP for the VM
            gateway_ip: Gateway IP
            dns_server: DNS server

        Returns:
            Dict with success status and modified ISO path
        """
        temp_dir = None
        try:
            # Create output path for modified ISO
            modified_iso_path = (
                Path(self.ISO_CACHE_DIR) / f"debian-serial-{vm_name}.iso"
            )

            # Create temp directory for extraction
            temp_dir = tempfile.mkdtemp(prefix="debian-iso-")
            self.logger.info(_("Extracting ISO to %s"), temp_dir)

            # Extract ISO using bsdtar (available on OpenBSD)
            result = subprocess.run(  # nosec B603 B607
                ["bsdtar", "-C", temp_dir, "-xf", original_iso_path],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to extract ISO: {result.stderr}",
                }

            # Make isolinux directory writable
            isolinux_dir = Path(temp_dir) / "isolinux"
            if not isolinux_dir.exists():
                return {
                    "success": False,
                    "error": "No isolinux directory found in ISO",
                }

            # Make files writable
            for iso_file in isolinux_dir.iterdir():
                iso_file.chmod(0o644)

            # Modify isolinux.cfg for serial console
            isolinux_cfg = isolinux_dir / "isolinux.cfg"
            self._modify_isolinux_cfg(isolinux_cfg)

            # Modify txt.cfg with boot parameters
            txt_cfg = isolinux_dir / "txt.cfg"
            self._modify_txt_cfg(txt_cfg, preseed_url, vm_ip, gateway_ip, dns_server)

            # Also modify gtk.cfg to prevent graphical install from being default
            gtk_cfg = isolinux_dir / "gtk.cfg"
            if gtk_cfg.exists():
                self._disable_gtk_default(gtk_cfg)

            # Regenerate md5sum.txt
            self._regenerate_checksums(temp_dir)

            # Extract MBR template from original ISO for hybrid boot support
            # This is required for the ISO to boot under OpenBSD VMM
            mbr_template = Path(temp_dir) / "isohdpfx.bin"
            result = subprocess.run(  # nosec B603 B607
                [
                    "dd",
                    f"if={original_iso_path}",
                    "bs=1",
                    "count=432",
                    f"of={mbr_template}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                self.logger.warning(
                    _("Failed to extract MBR template: %s"), result.stderr
                )

            # Build new ISO using xorriso (preserves boot records properly)
            # See: https://wiki.debian.org/RepackBootableISO
            self.logger.info(_("Building modified ISO: %s"), modified_iso_path)

            xorriso_cmd = [
                "xorriso",
                "-as",
                "mkisofs",
                "-r",  # Rock Ridge extensions
                "-V",
                "Debian Serial",  # Volume ID
                "-J",
                "-joliet-long",  # Joliet extensions
                "-cache-inodes",
                "-b",
                "isolinux/isolinux.bin",
                "-c",
                "isolinux/boot.cat",
                "-boot-load-size",
                "4",
                "-boot-info-table",
                "-no-emul-boot",
            ]

            # Add hybrid MBR if we extracted it successfully
            if mbr_template.exists():
                xorriso_cmd.extend(["-isohybrid-mbr", str(mbr_template)])

            # Check if EFI boot image exists and include it
            efi_img = Path(temp_dir) / "boot" / "grub" / "efi.img"
            if efi_img.exists():
                xorriso_cmd.extend(
                    [
                        "-eltorito-alt-boot",
                        "-e",
                        "boot/grub/efi.img",
                        "-no-emul-boot",
                        "-isohybrid-gpt-basdat",
                    ]
                )

            xorriso_cmd.extend(["-o", str(modified_iso_path), temp_dir])

            result = subprocess.run(  # nosec B603 B607
                xorriso_cmd,
                capture_output=True,
                text=True,
                timeout=300,
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

    def _modify_isolinux_cfg(self, cfg_path: Path) -> None:
        """Modify isolinux.cfg to enable serial console and auto-boot."""
        # Completely replace isolinux.cfg for serial console boot
        # Don't use menu system at all - just boot directly
        # Must include txt.cfg which defines the "install" label
        new_content = """# Serial console configuration for OpenBSD VMM
# Bypass graphical menu entirely for headless install
SERIAL 0 115200
CONSOLE 0
DEFAULT install
PROMPT 0
TIMEOUT 1
include txt.cfg
"""
        cfg_path.write_text(new_content)
        self.logger.info(_("Modified isolinux.cfg for serial console"))

    def _modify_txt_cfg(
        self,
        cfg_path: Path,
        preseed_url: str,
        vm_ip: str,
        gateway_ip: str,
        dns_server: str,
    ) -> None:
        """Modify txt.cfg with serial console boot parameters."""
        # Build the boot parameters
        params = [
            "console=ttyS0,115200n8",
            "vga=off",
            "DEBIAN_FRONTEND=text",
            "auto=true",
            "priority=critical",
            "net.ifnames=0",
            "biosdevname=0",
        ]

        if preseed_url:
            params.append(f"url={preseed_url}")

        if vm_ip and gateway_ip:
            hostname = vm_ip.replace(".", "-")
            params.append(f"ip={vm_ip}::{gateway_ip}:255.255.255.0:{hostname}:eth0:off")
            params.append("netcfg/choose_interface=eth0")
            params.append(f"netcfg/get_ipaddress={vm_ip}")
            params.append("netcfg/get_netmask=255.255.255.0")
            params.append(f"netcfg/get_gateway={gateway_ip}")
            if dns_server:
                params.append(f"netcfg/get_nameservers={dns_server}")
            params.append("netcfg/disable_dhcp=true")
            params.append("netcfg/confirm_static=true")

        boot_params = " ".join(params)

        # Create new txt.cfg content
        new_content = f"""default install
label install
    menu label ^Install
    kernel /install.amd/vmlinuz
    append initrd=/install.amd/initrd.gz {boot_params} --- quiet
"""

        cfg_path.write_text(new_content)
        self.logger.info(_("Modified txt.cfg with boot parameters"))

    def _disable_gtk_default(self, cfg_path: Path) -> None:
        """Disable graphical install as default."""
        content = cfg_path.read_text()
        # Comment out the default line if present
        content = content.replace("default installgui", "# default installgui")
        # NOSONAR - path is constructed from a known temp directory with a fixed filename
        cfg_path.write_text(content)
        self.logger.info(_("Disabled GTK installer default"))

    def _regenerate_checksums(self, iso_dir: str) -> None:
        """Regenerate md5sum.txt for the ISO."""
        md5_path = Path(iso_dir) / "md5sum.txt"
        if md5_path.exists():
            md5_path.chmod(0o644)
            # Use find and md5 to regenerate checksums
            result = subprocess.run(  # nosec B603 B607
                [
                    "sh",
                    "-c",
                    f"cd {iso_dir} && find . -type f ! -name md5sum.txt -exec md5 -r {{}} \\; > md5sum.txt",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode == 0:
                self.logger.info(_("Regenerated md5sum.txt"))

    def create_preseed_file(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        hostname: str,
        username: str,
        user_password_hash: str,
        root_password_hash: str,
        gateway_ip: str,
        vm_ip: str,
        debian_version: str,
        dns_server: str = None,
        disk: str = "vda",
        timezone: str = "UTC",
    ) -> Dict[str, Any]:
        """
        Create Debian preseed file.

        Args:
            hostname: VM hostname (FQDN)
            username: User to create
            user_password_hash: SHA-512 hashed password for user
            root_password_hash: SHA-512 hashed password for root
            gateway_ip: Gateway IP address
            vm_ip: Static IP address for the VM
            debian_version: Debian version (e.g., "12")
            dns_server: DNS server (defaults to gateway_ip)
            disk: Target disk device (default: vda)
            timezone: Timezone (default: UTC)

        Returns:
            Dict with success status and preseed content
        """
        try:
            if debian_version not in DEBIAN_CODENAMES:
                return {
                    "success": False,
                    "preseed": None,
                    "error": _("Unsupported Debian version: %s") % debian_version,
                }

            codename = DEBIAN_CODENAMES[debian_version]
            mirror_url = DEBIAN_MIRROR_URLS.get(debian_version, "deb.debian.org")
            # Extract just the hostname from the URL if it's a full URL
            if mirror_url.startswith("https://"):
                mirror_url = mirror_url.replace("https://", "").split("/")[0]
            elif mirror_url.startswith("http://"):  # NOSONAR - mirrors may use http
                mirror_url = mirror_url.replace("http://", "").split("/")[0]

            preseed_content = generate_preseed_file(
                hostname=hostname,
                username=username,
                user_password_hash=user_password_hash,
                root_password_hash=root_password_hash,
                gateway_ip=gateway_ip,
                vm_ip=vm_ip,
                dns_server=dns_server,
                disk=disk,
                timezone=timezone,
                debian_version=debian_version,
                debian_codename=codename,
                mirror_url=mirror_url,
            )

            return {"success": True, "preseed": preseed_content}

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "preseed": None, "error": str(error)}

    def create_debian_data_dir(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        vm_name: str,
        preseed_content: str,
        server_hostname: str,
        server_port: int,
        use_https: bool,
        auto_approve_token: str = None,
        debian_version: str = "12",
    ) -> Dict[str, Any]:
        """
        Create data directory with all Debian setup files.

        This directory contains the preseed file, agent configuration,
        firstboot script, and systemd service for automated setup.

        Args:
            vm_name: Name of the VM
            preseed_content: Preseed file content
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS
            auto_approve_token: Optional auto-approval token
            debian_version: Debian version (default: "12")

        Returns:
            Dict with success status and data directory path
        """
        try:
            data_dir = Path(self.DEBIAN_DATA_BASE)
            data_dir.mkdir(parents=True, exist_ok=True)

            # Create VM-specific directory
            vm_data_dir = data_dir / vm_name
            vm_data_dir.mkdir(exist_ok=True)

            # Write preseed file
            preseed_path = vm_data_dir / "preseed.cfg"
            preseed_path.write_text(preseed_content)
            self.logger.info(_("Created preseed file: %s"), preseed_path)

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
                debian_version=debian_version,
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

            # Also copy preseed to httpd document root for serving via HTTP
            # The OpenBSD httpd serves files from /var/www/htdocs on 100.64.0.1:80
            httpd_debian_dir = Path(self.HTTPD_ROOT) / "debian" / vm_name
            httpd_debian_dir.mkdir(parents=True, exist_ok=True)
            httpd_preseed_path = httpd_debian_dir / "preseed.cfg"
            httpd_preseed_path.write_text(preseed_content)
            # Make readable by httpd (runs as www user)
            httpd_preseed_path.chmod(0o644)
            self.logger.info(_("Created httpd preseed file: %s"), httpd_preseed_path)

            # Build the preseed URL (served by httpd on VMM network)
            preseed_url = f"http://100.64.0.1/debian/{vm_name}/preseed.cfg"  # NOSONAR - internal VM network

            self.logger.info(_("Created Debian setup data in %s"), vm_data_dir)

            return {
                "success": True,
                "data_dir": str(vm_data_dir),
                "preseed_path": str(preseed_path),
                "preseed_url": preseed_url,
                "config_path": str(config_path),
                "firstboot_path": str(firstboot_path),
                "service_path": str(service_path),
            }

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": str(error)}

    def create_late_command_script(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        hostname: str,
        server_hostname: str,
        server_port: int,
        use_https: bool,
        vm_ip: str,
        gateway_ip: str,
        dns_server: str,
        auto_approve_token: str = None,
        debian_version: str = "12",
        agent_deb_url: str = None,
    ) -> str:
        """
        Generate shell commands for preseed late_command.

        These commands are run at the end of the Debian installation
        to set up the sysmanage-agent configuration, network, and firstboot.

        Args:
            hostname: Full hostname/FQDN of the VM (e.g., deb12.example.com)
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS
            vm_ip: Static IP address for the VM
            gateway_ip: Gateway IP address
            dns_server: DNS server IP address
            auto_approve_token: Optional auto-approval token
            debian_version: Debian version
            agent_deb_url: Optional URL to download agent .deb from httpd

        Returns:
            Shell commands for late_command
        """
        # Extract short hostname from FQDN
        short_hostname = hostname.split(".")[0]
        # Generate agent config
        agent_config = generate_agent_config(
            hostname=server_hostname,
            port=server_port,
            use_https=use_https,
            auto_approve_token=auto_approve_token,
        )

        # Generate firstboot script with server config (writes config AFTER .deb install)
        firstboot_script = generate_firstboot_script(
            debian_version=debian_version,
            server_hostname=server_hostname,
            server_port=server_port,
            use_https=use_https,
            auto_approve_token=auto_approve_token,
        )

        # Generate systemd service
        systemd_service = generate_firstboot_systemd_service()

        # Escape the content for shell (use base64 to avoid escaping issues)
        config_b64 = base64.b64encode(agent_config.encode()).decode()
        firstboot_b64 = base64.b64encode(firstboot_script.encode()).decode()
        service_b64 = base64.b64encode(systemd_service.encode()).decode()

        # Build late command that decodes base64 and writes files
        # Use setsid to fully detach poweroff - prevents installer from waiting
        # 120 seconds allows finishing phase to complete before auto-poweroff

        # Optionally download agent .deb from httpd during installation
        agent_download_cmd = ""
        if agent_deb_url:
            agent_download_cmd = f"wget -q -O /target/root/sysmanage-agent.deb '{agent_deb_url}' || true; \\\n"

        # Network interface config using echo (more reliable than cat heredoc)
        # Debian on VMM uses enp0s2 as the virtio network interface
        network_config = f"""echo 'auto enp0s2' > /target/etc/network/interfaces.d/enp0s2; \\
echo 'iface enp0s2 inet static' >> /target/etc/network/interfaces.d/enp0s2; \\
echo '    address {vm_ip}' >> /target/etc/network/interfaces.d/enp0s2; \\
echo '    netmask 255.255.255.0' >> /target/etc/network/interfaces.d/enp0s2; \\
echo '    gateway {gateway_ip}' >> /target/etc/network/interfaces.d/enp0s2; \\
echo '    dns-nameservers {dns_server}' >> /target/etc/network/interfaces.d/enp0s2; \\
"""

        late_command = f"""
mkdir -p /target/etc/sysmanage-agent; \\
mkdir -p /target/var/log/sysmanage-agent; \\
mkdir -p /target/var/lib/sysmanage-agent; \\
mkdir -p /target/etc/network/interfaces.d; \\
mkdir -p /target/etc/systemd/system/multi-user.target.wants; \\
echo '{short_hostname}' > /target/etc/hostname; \\
echo '127.0.0.1 localhost' > /target/etc/hosts; \\
echo '{vm_ip} {hostname} {short_hostname}' >> /target/etc/hosts; \\
{network_config}echo '{config_b64}' | base64 -d > /target/etc/sysmanage-agent.yaml; \\
echo '{firstboot_b64}' | base64 -d > /target/root/sysmanage-firstboot.sh; \\
chmod 755 /target/root/sysmanage-firstboot.sh; \\
echo '{service_b64}' | base64 -d > /target/etc/systemd/system/sysmanage-firstboot.service; \\
ln -sf /etc/systemd/system/sysmanage-firstboot.service /target/etc/systemd/system/multi-user.target.wants/sysmanage-firstboot.service; \\
{agent_download_cmd}setsid sh -c "sleep 120; /sbin/poweroff -f" >/dev/null 2>&1 &
"""
        return late_command.strip()

    def generate_enhanced_preseed(  # NOSONAR - 15 params required: each param maps to a distinct preseed/late_command field; grouping would obscure the 1:1 mapping to Debian installer config  # pylint: disable=too-many-arguments,too-many-locals
        self,
        hostname: str,
        username: str,
        user_password_hash: str,
        root_password_hash: str,
        gateway_ip: str,
        vm_ip: str,
        debian_version: str,
        server_hostname: str,
        server_port: int,
        use_https: bool,
        auto_approve_token: str = None,
        dns_server: str = None,
        disk: str = "vda",
        timezone: str = "UTC",
        agent_deb_url: str = None,
    ) -> Dict[str, Any]:
        """
        Generate enhanced preseed with embedded late_command for agent setup.

        This creates a complete preseed file that includes all necessary
        commands to set up sysmanage-agent without needing external files.

        Args:
            hostname: VM hostname (FQDN)
            username: User to create
            user_password_hash: SHA-512 hashed password for user
            root_password_hash: SHA-512 hashed password for root
            gateway_ip: Gateway IP address
            vm_ip: Static IP address for the VM
            debian_version: Debian version (e.g., "12")
            server_hostname: SysManage server hostname
            server_port: SysManage server port
            use_https: Whether to use HTTPS
            auto_approve_token: Optional auto-approval token
            dns_server: DNS server (defaults to gateway_ip)
            disk: Target disk device (default: vda)
            timezone: Timezone (default: UTC)
            agent_deb_url: Optional URL to download agent .deb during install

        Returns:
            Dict with success status and complete preseed content
        """
        try:
            # First get the base preseed
            result = self.create_preseed_file(
                hostname=hostname,
                username=username,
                user_password_hash=user_password_hash,
                root_password_hash=root_password_hash,
                gateway_ip=gateway_ip,
                vm_ip=vm_ip,
                debian_version=debian_version,
                dns_server=dns_server,
                disk=disk,
                timezone=timezone,
            )

            if not result["success"]:
                return result

            base_preseed = result["preseed"]

            # Generate the late command with embedded config
            # Use dns_server or fall back to gateway_ip
            effective_dns = dns_server if dns_server else gateway_ip
            late_command = self.create_late_command_script(
                hostname=hostname,
                server_hostname=server_hostname,
                server_port=server_port,
                use_https=use_https,
                vm_ip=vm_ip,
                gateway_ip=gateway_ip,
                dns_server=effective_dns,
                auto_approve_token=auto_approve_token,
                debian_version=debian_version,
                agent_deb_url=agent_deb_url,
            )

            # Replace the basic late_command in the preseed with our enhanced one
            # Find and replace the late_command section
            enhanced_preseed = base_preseed.replace(
                "d-i preseed/late_command string \\",
                f"d-i preseed/late_command string {late_command}",
            )

            # Remove the old late_command continuation lines that follow our new command
            # The old lines start with whitespace and contain mkdir, echo hostname, etc.
            lines = enhanced_preseed.split("\n")
            filtered_lines = []
            skip_old_late_cmd = False
            for line in lines:
                # Our new late_command ends with the poweroff & - after that, skip old lines
                if "setsid sh -c" in line and "poweroff" in line:
                    filtered_lines.append(line)
                    skip_old_late_cmd = True
                    continue
                # Skip old late_command continuation lines (start with spaces, contain old patterns)
                if skip_old_late_cmd:
                    stripped = line.strip()
                    # Old late_command lines we need to skip
                    if (
                        stripped.startswith("mkdir -p /target/")
                        or stripped.startswith('echo "')
                        or "in-target systemctl enable" in stripped
                        or (stripped.startswith("setsid") and "poweroff" in stripped)
                    ):
                        continue
                    # Empty line or non-late_command line ends the skip
                    skip_old_late_cmd = False
                filtered_lines.append(line)

            enhanced_preseed = "\n".join(filtered_lines)

            return {"success": True, "preseed": enhanced_preseed}

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "preseed": None, "error": str(error)}
