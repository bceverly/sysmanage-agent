"""
OpenBSD VMM autoinstall using httpd approach.

This module implements the httpd-based autoinstall that mirrors test_pxe_boot.sh:
- Sets up httpd to serve OpenBSD sets
- Downloads OpenBSD sets to /var/www/htdocs
- Embeds install.conf into bsd.rd ramdisk
- Serves site.tgz via HTTP (not embedded)
"""

import logging
import subprocess  # nosec B404
import urllib.request
from pathlib import Path
from typing import Any, Dict

from src.i18n import _


class HttpdAutoinstallSetup:
    """Httpd-based autoinstall setup for VMM VMs."""

    OPENBSD_MIRROR = "https://ftp.openbsd.org/pub/OpenBSD"
    SETS_BASE = "/var/www/htdocs/pub/OpenBSD"

    # Sets to download for autoinstall
    REQUIRED_SETS = [
        "bsd",
        "bsd.rd",
        "base{version}.tgz",
        "comp{version}.tgz",
        "man{version}.tgz",
        "game{version}.tgz",
        "xbase{version}.tgz",
        "xshare{version}.tgz",
        "xfont{version}.tgz",
        "xserv{version}.tgz",
        "SHA256",
        "SHA256.sig",
        "index.txt",
        "BUILDINFO",
        "INSTALL.amd64",
    ]

    def __init__(self, logger: logging.Logger):
        """Initialize httpd autoinstall setup."""
        self.logger = logger

    def setup_httpd(self, gateway_ip: str) -> Dict[str, Any]:
        """
        Setup httpd.conf to serve OpenBSD sets.

        Args:
            gateway_ip: Gateway IP address (e.g., "10.1.0.1")

        Returns:
            Dict with success status
        """
        try:
            httpd_conf = f"""server "autoinstall" {{
    listen on {gateway_ip} port 80
    root "/htdocs"
}}
"""
            self.logger.info(_("Creating httpd.conf for %s"), gateway_ip)

            # Write httpd.conf
            result = subprocess.run(  # nosec B603 B607
                ["sh", "-c", f"echo '{httpd_conf}' | tee /etc/httpd.conf"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to write httpd.conf: {result.stderr}",
                }

            # Enable and restart httpd
            self.logger.info(_("Enabling and starting httpd"))
            result = subprocess.run(  # nosec B603 B607
                ["rcctl", "enable", "httpd"],
                capture_output=True,
                timeout=30,
                check=False,
            )

            result = subprocess.run(  # nosec B603 B607
                ["rcctl", "restart", "httpd"],
                capture_output=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to start httpd: {result.stderr.decode()}",
                }

            return {"success": True}

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": str(error)}

    def download_openbsd_sets(self, version: str) -> Dict[str, Any]:
        """
        Download OpenBSD installation sets to /var/www/htdocs.

        Args:
            version: OpenBSD version (e.g., "7.7")

        Returns:
            Dict with success status
        """
        try:
            version_nodot = version.replace(".", "")
            sets_dir = Path(self.SETS_BASE) / version / "amd64"

            self.logger.info(_("Creating sets directory: %s"), sets_dir)
            sets_dir.mkdir(parents=True, exist_ok=True)

            # Download each set
            for set_template in self.REQUIRED_SETS:
                set_name = set_template.format(version=version_nodot)
                dest_path = sets_dir / set_name

                # Skip if already downloaded
                if dest_path.exists():
                    self.logger.debug(_("Set already downloaded: %s"), set_name)
                    continue

                url = f"{self.OPENBSD_MIRROR}/{version}/amd64/{set_name}"
                self.logger.info(_("Downloading %s"), set_name)

                try:
                    with urllib.request.urlopen(
                        url, timeout=300
                    ) as response:  # nosec B310
                        with open(dest_path, "wb") as file:
                            file.write(response.read())
                    self.logger.debug(_("Downloaded: %s"), set_name)
                except Exception as dl_error:
                    # Some sets might not exist (like INSTALL.amd64), that's ok
                    self.logger.warning(
                        _("Could not download %s: %s"), set_name, dl_error
                    )

            return {"success": True, "sets_dir": str(sets_dir)}

        except Exception as error:  # pylint: disable=broad-except
            return {"success": False, "error": str(error)}

    def embed_install_conf_in_bsdrd(
        self,
        install_conf_content: str,
        openbsd_version: str,
        sets_dir: Path,
    ) -> Dict[str, Any]:
        """
        Embed install.conf into bsd.rd ramdisk.

        This follows the exact approach from test_pxe_boot.sh:
        1. Decompress bsd.rd from sets (it's gzipped)
        2. Extract ramdisk with rdsetroot
        3. Mount ramdisk
        4. Copy install.conf as auto_install.conf
        5. Unmount and repack

        Args:
            install_conf_content: Content of install.conf file
            openbsd_version: OpenBSD version (e.g., "7.7")
            sets_dir: Path to sets directory

        Returns:
            Dict with success status and path to modified bsd.rd
        """
        try:
            self.logger.info(_("Embedding install.conf into bsd.rd"))

            # Paths
            bsdrd_gz = sets_dir / "bsd.rd"
            bsdrd_decompressed = Path("/var/vmm/bsd.rd")
            bsdrd_autoinstall = Path(f"/var/vmm/bsd.rd.autoinstall.{openbsd_version}")

            # Step 1: Decompress bsd.rd
            self.logger.info(_("Decompressing bsd.rd"))
            result = subprocess.run(  # nosec B603 B607
                ["sh", "-c", f"gzcat {bsdrd_gz} > {bsdrd_decompressed}"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to decompress bsd.rd: {result.stderr}",
                }

            # Step 2: Extract ramdisk
            ramdisk_img = "/tmp/ramdisk.img"
            self.logger.info(_("Extracting ramdisk from bsd.rd"))
            result = subprocess.run(  # nosec B603 B607
                ["rdsetroot", "-x", str(bsdrd_decompressed), ramdisk_img],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"rdsetroot extraction failed: {result.stderr}",
                }

            # Step 3: Mount ramdisk
            mount_point = "/tmp/ramdisk_mount"
            Path(mount_point).mkdir(parents=True, exist_ok=True)

            result = subprocess.run(  # nosec B603 B607
                ["vnconfig", "vnd0", ramdisk_img],
                capture_output=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"vnconfig failed: {result.stderr.decode()}",
                }

            result = subprocess.run(  # nosec B603 B607
                ["mount", "/dev/vnd0a", mount_point],
                capture_output=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                # Cleanup vnd
                subprocess.run(
                    ["vnconfig", "-u", "vnd0"], check=False
                )  # nosec B603 B607
                return {
                    "success": False,
                    "error": f"mount failed: {result.stderr.decode()}",
                }

            # Step 4: Copy install.conf
            self.logger.info(_("Copying install.conf to ramdisk"))
            install_conf_path = Path(mount_point) / "auto_install.conf"

            try:
                with open(install_conf_path, "w", encoding="utf-8") as file:
                    file.write(install_conf_content)
            except Exception as write_error:
                # Cleanup
                subprocess.run(["umount", mount_point], check=False)  # nosec B603 B607
                subprocess.run(
                    ["vnconfig", "-u", "vnd0"], check=False
                )  # nosec B603 B607
                return {
                    "success": False,
                    "error": f"Failed to write install.conf: {write_error}",
                }

            # Step 5: Unmount and cleanup
            subprocess.run(  # nosec B603 B607
                ["umount", mount_point],
                capture_output=True,
                timeout=30,
                check=False,
            )

            subprocess.run(  # nosec B603 B607
                ["vnconfig", "-u", "vnd0"],
                capture_output=True,
                timeout=30,
                check=False,
            )

            # Step 6: Create modified bsd.rd
            result = subprocess.run(  # nosec B603 B607
                ["cp", str(bsdrd_decompressed), str(bsdrd_autoinstall)],
                capture_output=True,
                timeout=30,
                check=False,
            )

            result = subprocess.run(  # nosec B603 B607
                ["rdsetroot", str(bsdrd_autoinstall), ramdisk_img],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"rdsetroot insertion failed: {result.stderr}",
                }

            # Cleanup temporary files
            Path(ramdisk_img).unlink(missing_ok=True)
            Path(mount_point).rmdir()

            self.logger.info(_("Created modified bsd.rd: %s"), bsdrd_autoinstall)

            return {
                "success": True,
                "bsdrd_path": str(bsdrd_autoinstall),
            }

        except Exception as error:  # pylint: disable=broad-except
            # Best effort cleanup
            subprocess.run(["umount", mount_point], check=False)  # nosec B603 B607
            subprocess.run(["vnconfig", "-u", "vnd0"], check=False)  # nosec B603 B607
            return {"success": False, "error": str(error)}

    def create_install_conf_content(
        self,
        hostname: str,
        username: str,
        _password: str,
        gateway_ip: str,
        _openbsd_version: str,
    ) -> str:
        """
        Create install.conf content for httpd-based autoinstall.

        Args:
            hostname: VM hostname
            username: User to create
            _password: Password (currently unused, using pre-generated hash for testing)
            gateway_ip: Gateway IP for HTTP server and network
            _openbsd_version: OpenBSD version (currently unused, using wildcards)

        Returns:
            install.conf content as string
        """
        # Use bcrypt hashed password (pre-generated for consistency)
        # This is bcrypt hash of "mar2000x" for testing
        # In production, you'd want to hash the actual password
        bcrypt_hash = "$2b$08$1Q9ZP0pPhaRxEJMLkNjZ6umCl/brYuFoQLCT7hkb8igVU5.dfJv1K"

        # Get parent DNS from /etc/resolv.conf
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as file_handle:
                for line in file_handle:
                    if line.strip().startswith("nameserver"):
                        parent_dns = line.strip().split()[1]
                        break
                else:
                    parent_dns = "8.8.8.8"  # Fallback
        except Exception:
            parent_dns = "8.8.8.8"  # Fallback

        # Create install.conf content using DHCP for networking
        # DHCP will be provided by dhcpd configured on the host
        install_conf = f"""System hostname = {hostname}
Which disk is the root disk = sd0
Use (W)hole disk MBR, whole disk (G)PT, (O)penBSD area or (E)dit = whole
Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = a
Password for root account = {bcrypt_hash}
Setup a user = {username}
Password for user {username} = {bcrypt_hash}
Allow root ssh login = no
What timezone are you in = US/Eastern
Network interfaces = vio0
IPv4 address for vio0 = 100.64.0.100
Netmask for vio0 = 255.255.255.0
Default IPv4 route = 100.64.0.1
DNS nameservers = {parent_dns}
Location of sets = http
HTTP Server = {gateway_ip}
Set name(s) = -game* -x* +site*
Continue without verification = yes
Reboot after install = no
"""
        # DEBUG: Log the exact install.conf content being generated
        self.logger.info(_("=== GENERATED INSTALL.CONF CONTENT ==="))
        for line in install_conf.split("\n"):
            if line.strip():
                self.logger.info(_("  %s"), line)
        self.logger.info(_("=== END INSTALL.CONF ==="))

        return install_conf
