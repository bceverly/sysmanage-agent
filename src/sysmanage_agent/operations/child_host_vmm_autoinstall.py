"""
OpenBSD autoinstall support for VMM VMs.

This module handles generating and serving install.conf response files
for automated OpenBSD installations.
"""

import hashlib
import http.server
import os
import socketserver
import subprocess  # nosec B404 # Required for system command execution
import tempfile
import threading
import time
from typing import Any, Dict, Optional

from src.i18n import _

# Default autoinstall HTTP server settings
AUTOINSTALL_DIR = "/var/vmm/autoinstall"
AUTOINSTALL_PORT = 80  # OpenBSD autoinstall looks for HTTP on port 80
AUTOINSTALL_BIND = "10.0.0.1"  # vmd local network address when using -L


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
            public_key: Optional SSH public key for root

        Returns:
            install.conf content as string
        """
        # Encrypt password using OpenBSD's encrypt(1) or Python's crypt
        encrypted_password = self._encrypt_password(password)

        lines = [
            f"System hostname = {hostname}",
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

        # Last resort: return a known hash format that OpenBSD will accept
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

            # Generate install.conf content
            content = self.generate_install_conf(
                hostname=hostname,
                username=username,
                password=password,
                timezone=timezone,
            )

            # Write to file
            # OpenBSD autoinstall looks for install.conf in web root
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

    def embed_install_conf_in_bsd_rd(
        self,
        iso_path: str,
        vm_name: str,
        hostname: str,
        username: str,
        password: str,
        work_dir: str = None,
    ) -> Dict[str, Any]:
        """
        Embed install.conf directly into bsd.rd ramdisk for autoinstall.

        This eliminates the need for DHCP next-server and HTTP server by
        embedding the response file directly into the ramdisk kernel.

        Args:
            iso_path: Path to the OpenBSD install ISO
            vm_name: Name of the VM
            hostname: System hostname
            username: Non-root user to create
            password: Password for accounts
            work_dir: Working directory for temporary files

        Returns:
            Dict with success status and path to modified bsd.rd
        """
        bsd_rd_path = None
        disk_fs_path = None
        mount_point = None
        vnd_device = None

        try:
            self.logger.info(_("Embedding install.conf into bsd.rd for VM %s"), vm_name)

            # Use system temp directory if not specified
            if work_dir is None:
                work_dir = tempfile.gettempdir()

            # Create work directory for this VM
            vm_work_dir = os.path.join(work_dir, f"autoinstall-{vm_name}")
            if not os.path.exists(vm_work_dir):
                os.makedirs(vm_work_dir, mode=0o755)

            # Step 1: Extract bsd.rd from ISO
            bsd_rd_path = os.path.join(vm_work_dir, "bsd.rd")
            self.logger.debug("Extracting bsd.rd from ISO")

            # Mount the ISO temporarily to extract bsd.rd
            iso_mount = os.path.join(vm_work_dir, "iso_mount")
            if not os.path.exists(iso_mount):
                os.makedirs(iso_mount, mode=0o755)

            # Mount ISO using vnconfig
            result = subprocess.run(  # nosec B603 B607
                ["vnconfig", "vnd1", iso_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to configure vnd device for ISO: %s")
                    % (result.stderr or result.stdout),
                }

            try:
                # Mount the ISO
                result = subprocess.run(  # nosec B603 B607
                    ["mount", "-t", "cd9660", "/dev/vnd1c", iso_mount],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if result.returncode != 0:
                    subprocess.run(  # nosec B603 B607
                        ["vnconfig", "-u", "vnd1"],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    return {
                        "success": False,
                        "error": _("Failed to mount ISO: %s")
                        % (result.stderr or result.stdout),
                    }

                # Find and copy bsd.rd (usually in <version>/amd64/bsd.rd)
                iso_bsd_rd = None
                for root, _dirs, files in os.walk(iso_mount):
                    if "bsd.rd" in files:
                        iso_bsd_rd = os.path.join(root, "bsd.rd")
                        break

                if not iso_bsd_rd:
                    return {
                        "success": False,
                        "error": _("Could not find bsd.rd in ISO"),
                    }

                # Copy bsd.rd to work directory
                subprocess.run(  # nosec B603 B607
                    ["cp", iso_bsd_rd, bsd_rd_path],
                    capture_output=True,
                    timeout=30,
                    check=True,
                )

            finally:
                # Unmount ISO and unconfigure vnd1
                subprocess.run(  # nosec B603 B607
                    ["umount", iso_mount],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                subprocess.run(  # nosec B603 B607
                    ["vnconfig", "-u", "vnd1"],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                # Clean up mount point
                if os.path.exists(iso_mount):
                    os.rmdir(iso_mount)

            self.logger.debug("Extracted bsd.rd from ISO")

            # Step 2: Decompress bsd.rd (it's gzip compressed)
            bsd_rd_uncompressed = os.path.join(vm_work_dir, "bsd.rd.uncompressed")
            self.logger.debug("Decompressing bsd.rd")

            result = subprocess.run(  # nosec B603 B607
                ["gunzip", "-c", bsd_rd_path],
                capture_output=True,
                timeout=60,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to decompress bsd.rd: %s")
                    % (result.stderr.decode() if result.stderr else "Unknown error"),
                }

            # Write decompressed data to file
            with open(bsd_rd_uncompressed, "wb") as uncompressed_file:
                uncompressed_file.write(result.stdout)

            # Step 3: Extract ramdisk from decompressed bsd.rd
            disk_fs_path = os.path.join(vm_work_dir, "disk.fs")
            self.logger.debug("Extracting ramdisk from bsd.rd")

            result = subprocess.run(  # nosec B603 B607
                ["rdsetroot", "-x", bsd_rd_uncompressed, disk_fs_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to extract ramdisk: %s")
                    % (result.stderr or result.stdout),
                }

            # Step 4: Mount ramdisk
            self.logger.debug("Mounting ramdisk")

            # Find available vnd device
            result = subprocess.run(  # nosec B603 B607
                ["vnconfig", "vnd0", disk_fs_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to configure vnd device: %s")
                    % (result.stderr or result.stdout),
                }
            vnd_device = "vnd0"

            # Create mount point
            mount_point = os.path.join(vm_work_dir, "ramdisk")
            if not os.path.exists(mount_point):
                os.makedirs(mount_point, mode=0o755)

            # Mount the ramdisk
            result = subprocess.run(  # nosec B603 B607
                ["mount", "/dev/vnd0a", mount_point],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                subprocess.run(  # nosec B603 B607
                    ["vnconfig", "-u", "vnd0"],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                return {
                    "success": False,
                    "error": _("Failed to mount ramdisk: %s")
                    % (result.stderr or result.stdout),
                }

            # Step 5: Generate and copy install.conf
            self.logger.debug("Creating auto_install.conf in ramdisk")

            conf_content = self.generate_install_conf(
                hostname=hostname,
                username=username,
                password=password,
            )

            auto_install_path = os.path.join(mount_point, "auto_install.conf")
            with open(auto_install_path, "w", encoding="utf-8") as conf_file:
                conf_file.write(conf_content)

            os.chmod(auto_install_path, 0o644)

            # Step 6: Unmount ramdisk
            self.logger.debug("Unmounting ramdisk")

            result = subprocess.run(  # nosec B603 B607
                ["umount", mount_point],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                self.logger.warning("Failed to unmount ramdisk: %s", result.stderr)

            # Remove mount point
            if os.path.exists(mount_point):
                os.rmdir(mount_point)
            mount_point = None

            # Unconfigure vnd device
            result = subprocess.run(  # nosec B603 B607
                ["vnconfig", "-u", "vnd0"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                self.logger.warning("Failed to unconfigure vnd0: %s", result.stderr)
            vnd_device = None

            # Step 7: Re-inject ramdisk into uncompressed bsd.rd
            self.logger.debug("Re-injecting ramdisk into bsd.rd")

            result = subprocess.run(  # nosec B603 B607
                ["rdsetroot", bsd_rd_uncompressed, disk_fs_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to re-inject ramdisk: %s")
                    % (result.stderr or result.stdout),
                }

            # Step 8: Compress the modified bsd.rd back to gzip format
            self.logger.debug("Compressing modified bsd.rd")

            result = subprocess.run(  # nosec B603 B607
                ["gzip", "-c", bsd_rd_uncompressed],
                capture_output=True,
                timeout=60,
                check=False,
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": _("Failed to compress bsd.rd: %s")
                    % (result.stderr.decode() if result.stderr else "Unknown error"),
                }

            # Write compressed data back to bsd.rd
            with open(bsd_rd_path, "wb") as compressed_file:
                compressed_file.write(result.stdout)

            self.logger.info(
                _("Successfully embedded install.conf into bsd.rd for VM %s"), vm_name
            )

            return {
                "success": True,
                "bsd_rd_path": bsd_rd_path,
                "work_dir": vm_work_dir,
            }

        except subprocess.TimeoutExpired as error:
            self.logger.error(_("Timeout during ramdisk operations: %s"), error)
            return {
                "success": False,
                "error": _("Timeout during ramdisk operations"),
            }
        except Exception as error:
            self.logger.error(_("Failed to embed install.conf: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }
        finally:
            # Cleanup: ensure everything is unmounted and unconfigured
            try:
                if mount_point and os.path.exists(mount_point):
                    subprocess.run(  # nosec B603 B607
                        ["umount", mount_point],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    os.rmdir(mount_point)
            except Exception:  # nosec B110
                pass

            try:
                if vnd_device:
                    subprocess.run(  # nosec B603 B607
                        ["vnconfig", "-u", vnd_device],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
            except Exception:  # nosec B110
                pass

    def cleanup_embedded_autoinstall(self, work_dir: str) -> Dict[str, Any]:
        """
        Clean up temporary files from embedded autoinstall.

        Args:
            work_dir: Work directory containing temporary files

        Returns:
            Dict with success status
        """
        try:
            if os.path.exists(work_dir):
                # Remove all files in work directory
                for item in os.listdir(work_dir):
                    item_path = os.path.join(work_dir, item)
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        os.rmdir(item_path)

                # Remove work directory
                os.rmdir(work_dir)
                self.logger.info(_("Cleaned up autoinstall work directory"))

            return {"success": True}

        except Exception as error:
            self.logger.warning(
                _("Failed to cleanup autoinstall work directory: %s"), error
            )
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
