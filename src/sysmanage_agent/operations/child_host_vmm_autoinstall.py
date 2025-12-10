"""
OpenBSD autoinstall support for VMM VMs.

This module handles generating and serving install.conf response files
for automated OpenBSD installations.
"""

import hashlib
import http.server
import os
import re
import shutil
import socketserver
import subprocess  # nosec B404 # Required for system command execution
import threading
import time
import urllib.request
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.operations import (
    child_host_vmm_network_helpers as network_helpers,
)

# Default autoinstall HTTP server settings
AUTOINSTALL_DIR = "/var/vmm/autoinstall"
AUTOINSTALL_PORT = 80  # OpenBSD autoinstall looks for HTTP on port 80
AUTOINSTALL_BIND = "10.0.0.1"  # vmd local network address when using -L

# PXE boot settings
PXE_CACHE_DIR = "/var/vmm/pxeboot"  # Cache for downloaded PXE boot files
TFTP_DIR = "/tftpboot"  # TFTP server root directory (OpenBSD default)
OPENBSD_MIRROR = "https://ftp.openbsd.org/pub/OpenBSD"  # OpenBSD mirror


class AutoinstallHttpHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler for serving autoinstall files."""

    def __init__(self, *args, directory=None, logger=None, **kwargs):
        self.logger = logger
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        """Log HTTP requests."""
        if self.logger:
            self.logger.debug("Autoinstall HTTP: %s", format % args)

    def do_GET(self):
        """Handle GET requests."""
        if self.logger:
            self.logger.info(
                _("Autoinstall HTTP request: %s from %s"),
                self.path,
                self.client_address[0],
            )
        super().do_GET()


class VmmAutoinstallOperations:
    """Autoinstall operations for VMM VMs."""

    def __init__(self, logger):
        """
        Initialize autoinstall operations.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        self._http_server = None
        self._http_thread = None

    @staticmethod
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

    def generate_install_conf(
        self,
        hostname: str,
        username: str,
        password: str,
        timezone: str = "US/Eastern",
        dns_nameservers: str = "1.1.1.1",
        sets: str = "-game* -x*",
        public_key: Optional[str] = None,
    ) -> str:
        """
        Generate an OpenBSD install.conf response file.

        See autoinstall(8) for format details.

        Args:
            hostname: System hostname for the VM
            username: Non-root user to create
            password: Password for root and user (will be encrypted)
            timezone: Timezone for the system
            dns_nameservers: DNS nameserver(s) to use
            sets: Sets to install (- prefix excludes)
            public_key: Optional SSH public key for roo

        Returns:
            install.conf content as string
        """
        # Encrypt password using OpenBSD's encrypt(1) or Python's cryp
        encrypted_password = self._encrypt_password(password)

        lines = [
            f"System hostname = {hostname}",
            "Which disk is the root disk = sd0",
            "Use (W)hole disk MBR, whole disk (G)PT, (O)penBSD area or (E)dit = whole",
            "Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = a",
            f"Password for root account = {encrypted_password}",
            f"Setup a user = {username}",
            f"Password for user {username} = {encrypted_password}",
            "Allow root ssh login = yes",
            f"What timezone are you in = {timezone}",
            f"DNS nameservers = {dns_nameservers}",
            "Network interfaces = vio0",
            "IPv4 address for vio0 = dhcp",
            "Location of sets = http",
            "HTTP Server = cdn.openbsd.org",
            f"Set name(s) = {sets}",
            "Continue without verification = yes",
        ]

        # Add SSH public key if provided
        if public_key:
            lines.append(f"Public ssh key for root account = {public_key}")

        return "\n".join(lines) + "\n"

    def _encrypt_password(self, password: str) -> str:
        """
        Encrypt password using bcrypt for OpenBSD.

        Args:
            password: Plain text password

        Returns:
            Encrypted password hash
        """
        try:
            # Try to use OpenBSD's encrypt(1) command
            result = subprocess.run(  # nosec B603 B607
                ["encrypt", "-b", "8"],
                input=password,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Fallback: use Python's hashlib with a simple hash
        # Note: crypt module is deprecated, so we use a simpler approach
        # On OpenBSD, encrypt(1) should always work, so this is just a fallback
        try:
            # Generate a simple hash as fallback (not ideal for production)
            hash_obj = hashlib.sha256(password.encode())
            return hash_obj.hexdigest()
        except AttributeError:
            pass

        # Last resort: return a known hash format that OpenBSD will accep
        # This is a placeholder - in practice encrypt(1) should always work
        self.logger.warning(
            _("Could not encrypt password, using plain text (NOT RECOMMENDED)")
        )
        return password

    def write_install_conf(
        self,
        vm_name: str,
        hostname: str,
        username: str,
        password: str,
        timezone: str = "US/Eastern",
    ) -> Dict[str, Any]:
        """
        Write install.conf file for a VM.

        Creates the file at /var/vmm/autoinstall/<mac-address>-install.conf
        or just install.conf for the default.

        Args:
            vm_name: Name of the VM (used for logging)
            hostname: System hostname
            username: Non-root user to create
            password: Password for accounts
            timezone: Timezone

        Returns:
            Dict with success status and file path
        """
        try:
            # Ensure autoinstall directory exists
            if not os.path.exists(AUTOINSTALL_DIR):
                os.makedirs(AUTOINSTALL_DIR, mode=0o755)
                self.logger.info(
                    _("Created autoinstall directory: %s"), AUTOINSTALL_DIR
                )

            # Generate install.conf conten
            content = self.generate_install_conf(
                hostname=hostname,
                username=username,
                password=password,
                timezone=timezone,
            )

            # Write to file
            # OpenBSD autoinstall looks for install.conf in web roo
            conf_path = os.path.join(AUTOINSTALL_DIR, "install.conf")

            with open(conf_path, "w", encoding="utf-8") as conf_file:
                conf_file.write(content)

            os.chmod(conf_path, 0o644)

            self.logger.info(
                _("Generated install.conf for VM %s at %s"), vm_name, conf_path
            )

            return {
                "success": True,
                "conf_path": conf_path,
            }

        except Exception as error:
            self.logger.error(_("Failed to write install.conf: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }

    def start_http_server(
        self, bind_address: str = None, port: int = None
    ) -> Dict[str, Any]:
        """
        Start HTTP server to serve autoinstall files.

        Args:
            bind_address: Address to bind to (default: 10.0.0.1)
            port: Port to listen on (default: 80)

        Returns:
            Dict with success status
        """
        if self._http_server is not None:
            return {
                "success": True,
                "message": _("HTTP server already running"),
            }

        bind_addr = bind_address or AUTOINSTALL_BIND
        listen_port = port or AUTOINSTALL_PORT

        try:
            # Ensure autoinstall directory exists
            if not os.path.exists(AUTOINSTALL_DIR):
                os.makedirs(AUTOINSTALL_DIR, mode=0o755)

            # Create handler with directory
            def handler(*args, **kwargs):
                return AutoinstallHttpHandler(
                    *args,
                    directory=AUTOINSTALL_DIR,
                    logger=self.logger,
                    **kwargs,
                )

            # Allow address reuse
            socketserver.TCPServer.allow_reuse_address = True

            self._http_server = socketserver.TCPServer(
                (bind_addr, listen_port), handler
            )

            # Start in background thread
            self._http_thread = threading.Thread(
                target=self._http_server.serve_forever,
                daemon=True,
            )
            self._http_thread.start()

            self.logger.info(
                _("Started autoinstall HTTP server on %s:%d"), bind_addr, listen_port
            )

            return {
                "success": True,
                "address": bind_addr,
                "port": listen_port,
            }

        except OSError as error:
            if error.errno == 98:  # Address already in use
                # Another process might be serving on this address
                # That's OK, autoinstall should still work
                self.logger.warning(
                    _("HTTP port %d already in use, autoinstall may still work"),
                    listen_port,
                )
                return {
                    "success": True,
                    "warning": _("Port already in use"),
                }

            self.logger.error(_("Failed to start HTTP server: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }
        except Exception as error:
            self.logger.error(_("Failed to start HTTP server: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }

    def stop_http_server(self) -> Dict[str, Any]:
        """
        Stop the autoinstall HTTP server.

        Returns:
            Dict with success status
        """
        if self._http_server is None:
            return {
                "success": True,
                "message": _("HTTP server not running"),
            }

        try:
            self._http_server.shutdown()
            self._http_server = None
            self._http_thread = None

            self.logger.info(_("Stopped autoinstall HTTP server"))

            return {"success": True}

        except Exception as error:
            self.logger.error(_("Failed to stop HTTP server: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }

    def cleanup_install_conf(self, _vm_name: str = None) -> Dict[str, Any]:
        """
        Clean up install.conf files after installation.

        Args:
            _vm_name: Optional VM name (for future per-VM configs)

        Returns:
            Dict with success status
        """
        try:
            conf_path = os.path.join(AUTOINSTALL_DIR, "install.conf")
            if os.path.exists(conf_path):
                os.remove(conf_path)
                self.logger.info(_("Cleaned up install.conf"))

            return {"success": True}

        except Exception as error:
            self.logger.warning(_("Failed to cleanup install.conf: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }

    def wait_for_autoinstall_fetch(
        self, timeout: int = 300, check_interval: int = 5
    ) -> Dict[str, Any]:
        """
        Wait for the VM to fetch install.conf (indicates autoinstall started).

        This monitors the install.conf file access time.

        Args:
            timeout: Maximum time to wait in seconds
            check_interval: Time between checks in seconds

        Returns:
            Dict with success status
        """
        conf_path = os.path.join(AUTOINSTALL_DIR, "install.conf")

        if not os.path.exists(conf_path):
            return {
                "success": False,
                "error": _("install.conf not found"),
            }

        # Get initial access time
        try:
            initial_atime = os.path.getatime(conf_path)
        except Exception:
            initial_atime = 0

        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                current_atime = os.path.getatime(conf_path)
                if current_atime > initial_atime:
                    self.logger.info(
                        _("Autoinstall detected: install.conf was accessed")
                    )
                    return {"success": True}
            except Exception as error:  # nosec B110
                self.logger.debug("Error checking file access time: %s", error)

            time.sleep(check_interval)

        return {
            "success": False,
            "error": _("Timeout waiting for autoinstall to fetch install.conf"),
        }

    def _parse_openbsd_version(self, iso_url: str) -> Optional[str]:
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

    def _download_pxe_files(self, version: str, arch: str = "amd64") -> Dict[str, Any]:
        """
        Download and cache OpenBSD PXE boot files.

        Args:
            version: OpenBSD version (e.g., "7.7")
            arch: Architecture (default: "amd64")

        Returns:
            Dict with success status and file paths
        """
        cache_dir = os.path.join(PXE_CACHE_DIR, version, arch)
        pxeboot_path = os.path.join(cache_dir, "pxeboot")
        bsd_rd_path = os.path.join(cache_dir, "bsd.rd")

        # Check if already cached
        if os.path.exists(pxeboot_path) and os.path.exists(bsd_rd_path):
            self.logger.info(
                _("PXE files for OpenBSD %s %s already cached"), version, arch
            )
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
            self.logger.info(_("Downloading %s"), pxeboot_url)
            urllib.request.urlretrieve(pxeboot_url, pxeboot_path)  # nosec B310

            # Download bsd.rd
            bsd_rd_url = f"{OPENBSD_MIRROR}/{version}/{arch}/bsd.rd"
            self.logger.info(_("Downloading %s"), bsd_rd_url)
            urllib.request.urlretrieve(bsd_rd_url, bsd_rd_path)  # nosec B310

            self.logger.info(_("Downloaded PXE files for OpenBSD %s %s"), version, arch)

            return {
                "success": True,
                "pxeboot": pxeboot_path,
                "bsd_rd": bsd_rd_path,
                "cached": False,
            }

        except Exception as error:
            self.logger.error(_("Failed to download PXE files: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }

    def _setup_tftp_server(self, state: Dict[str, Any]) -> None:
        """
        Set up TFTP server for PXE boot.

        Args:
            state: State dict to track TFTP configuration

        Raises:
            Exception: If TFTP setup fails
        """
        # Create TFTP directory
        if not os.path.exists(TFTP_DIR):
            os.makedirs(TFTP_DIR, mode=0o755)
            state["tftp_dir_created"] = True
            self.logger.info(_("Created TFTP directory: %s"), TFTP_DIR)
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

        # Enable tftpd (uses default /tftpboot directory from rc.d/tftpd)
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
            self.logger.info(_("Restarted tftpd"))
        else:
            subprocess.run(  # nosec B603 B607
                ["rcctl", "start", "tftpd"],
                check=True,
                timeout=30,
            )
            self.logger.info(_("Started tftpd"))

    def setup_autoinstall_infrastructure(
        self,
        vm_name: str,
        hostname: str,
        iso_url: str = None,
        use_pxe: bool = True,
    ) -> Dict[str, Any]:
        """
        Set up complete autoinstall infrastructure: network, DHCP, TFTP, and HTTP.

        This follows the approach from obtusenet.com/blog/openbsd-vmd-autoinstall/

        Args:
            vm_name: Name of the VM
            hostname: Hostname for the VM
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
            # Step 1: Select unused subnet for VM network
            subnet_info = network_helpers.select_unused_subnet(self.logger)
            if not subnet_info:
                raise RuntimeError(_("Failed to select unused subnet"))

            self.logger.info(
                _("Selected subnet %s for VM network"), subnet_info["network"]
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
                    self.logger.info(_("Created %s interface"), iface)
                else:
                    state[state_key] = False
                    self.logger.info(_("%s already exists"), iface)

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
            self.logger.info(_("Assigned IP %s to vether0"), subnet_info["gateway_ip"])

            # Add vether0 to bridge0
            subprocess.run(  # nosec B603 B607
                ["ifconfig", "bridge0", "add", "vether0", "up"],
                check=True,
                timeout=10,
            )
            self.logger.info(_("Added vether0 to bridge0"))

            # Step 3: Enable IP forwarding
            subprocess.run(  # nosec B603 B607
                ["sysctl", "net.inet.ip.forwarding=1"],
                check=True,
                timeout=10,
            )
            self.logger.info(_("Enabled IP forwarding"))

            # Step 4: Generate MAC address for VM
            mac_address = self._generate_mac_address(vm_name)
            state["mac_address"] = mac_address
            self.logger.info(_("Generated MAC address %s for VM"), mac_address)

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
                self.logger.info(_("Backed up existing vm.conf to %s"), backup_path)

            # Create vm.conf with switch definition only
            # VM will be launched via vmctl with MAC specified via -i interface config
            vm_conf_content = """# SysManage vmd config for autoinstall
switch "local" {
    interface bridge0
}
"""

            with open(vm_conf_path, "w", encoding="utf-8") as conf_file:
                conf_file.write(vm_conf_content)

            self.logger.info(_("Created vm.conf with local switch and VM definition"))

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
                self.logger.info(_("Restarted vmd with new vm.conf"))
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
                self.logger.info(_("Backed up existing dhcpd.conf to %s"), backup_path)

            # Step 5: Set up PXE boot if enabled
            if use_pxe:
                # Parse OpenBSD version from ISO URL
                if not iso_url:
                    raise RuntimeError(_("ISO URL required for PXE boot"))

                version = self._parse_openbsd_version(iso_url)
                if not version:
                    raise RuntimeError(
                        _("Could not parse OpenBSD version from ISO URL: %s") % iso_url
                    )

                self.logger.info(_("Setting up PXE boot for OpenBSD %s"), version)

                # Download PXE boot files
                pxe_result = self._download_pxe_files(version)
                if not pxe_result.get("success"):
                    raise RuntimeError(
                        _("Failed to download PXE files: %s") % pxe_result.get("error")
                    )

                state["pxe_files"] = pxe_result

                # Copy PXE files to TFTP directory
                self._setup_tftp_server(state)

                # Copy pxeboot and bsd.rd to TFTP directory
                pxeboot_src = pxe_result["pxeboot"]
                bsd_rd_src = pxe_result["bsd_rd"]
                pxeboot_dst = os.path.join(TFTP_DIR, "pxeboot")
                auto_install_dst = os.path.join(TFTP_DIR, "auto_install")

                shutil.copy2(pxeboot_src, pxeboot_dst)
                shutil.copy2(bsd_rd_src, auto_install_dst)

                self.logger.info(_("Copied PXE files to TFTP directory"))

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

            self.logger.info(_("Created dhcpd.conf for autoinstall"))

            # Step 6: Configure and start dhcpd on vether0
            # Set flags first (this also enables the service)
            subprocess.run(  # nosec B603 B607
                ["rcctl", "set", "dhcpd", "flags", "vether0"],
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
                self.logger.info(_("Restarted dhcpd with autoinstall config"))
            else:
                subprocess.run(  # nosec B603 B607
                    ["rcctl", "start", "dhcpd"],
                    check=True,
                    timeout=30,
                )
                self.logger.info(_("Started dhcpd for autoinstall"))

            return {
                "success": True,
                "state": state,
            }

        except Exception as error:
            self.logger.error(
                _("Failed to setup autoinstall infrastructure: %s"), error
            )
            # Attempt to restore state
            self._restore_infrastructure_state(state)
            return {
                "success": False,
                "error": str(error),
            }

    def cleanup_autoinstall_infrastructure(
        self, state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Clean up autoinstall infrastructure and restore original state.

        Args:
            state: State dict from setup_autoinstall_infrastructure

        Returns:
            Dict with success status
        """
        try:
            self._restore_infrastructure_state(state)
            return {"success": True}
        except Exception as error:
            self.logger.error(
                _("Failed to cleanup autoinstall infrastructure: %s"), error
            )
            return {
                "success": False,
                "error": str(error),
            }

    def _restore_infrastructure_state(self, state: Dict[str, Any]) -> None:
        """
        Restore dhcpd to its original state.

        Note: bridge0 and vm.conf are permanent infrastructure and are NOT cleaned up.

        Args:
            state: State dict containing original configuration
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
                    self.logger.info(_("Restored original dhcpd.conf"))
            elif not state.get("dhcpd_conf_existed"):
                # Remove the config we created
                if os.path.exists("/etc/dhcpd.conf"):
                    os.remove("/etc/dhcpd.conf")
                    self.logger.info(_("Removed temporary dhcpd.conf"))

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
                self.logger.info(_("Restarted dhcpd with original config"))
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
                self.logger.info(_("Stopped dhcpd and restored original state"))

            # Clean up TFTP server if it was set up
            if state.get("use_pxe") and state.get("tftpd_was_running") is not None:
                if state["tftpd_was_running"]:
                    # Restart tftpd with original config (don't stop it)
                    subprocess.run(  # nosec B603 B607
                        ["rcctl", "restart", "tftpd"],
                        check=False,
                        timeout=30,
                    )
                    self.logger.info(_("Restarted tftpd"))
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
                    self.logger.info(_("Stopped tftpd"))

                # Clean up TFTP directory files (but keep the directory)
                if os.path.exists(TFTP_DIR):
                    for file in ["pxeboot", "auto_install"]:
                        file_path = os.path.join(TFTP_DIR, file)
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    self.logger.info(_("Cleaned up TFTP files"))

        except Exception as error:
            self.logger.warning(_("Error restoring infrastructure state: %s"), error)
