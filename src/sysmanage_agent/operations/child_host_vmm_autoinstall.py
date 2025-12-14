"""
OpenBSD autoinstall support for VMM VMs.

This module handles generating and serving install.conf response files
for automated OpenBSD installations.

This is a compatibility wrapper that delegates to the specialized modules:
- child_host_vmm_autoinstall_config: install.conf generation
- child_host_vmm_autoinstall_http: HTTP server management
- child_host_vmm_autoinstall_infra: Infrastructure setup/cleanup
"""

import os
import shutil
import time
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.operations import child_host_vmm_autoinstall_config as config
from src.sysmanage_agent.operations import (
    child_host_vmm_autoinstall_http as http_module,
)
from src.sysmanage_agent.operations import child_host_vmm_autoinstall_infra as infra

# Re-export constants for backward compatibility
from src.sysmanage_agent.operations.child_host_vmm_autoinstall_http import (
    AUTOINSTALL_BIND,
    AUTOINSTALL_DIR,
    AUTOINSTALL_PORT,
)

# PXE boot settings (for backward compatibility)
PXE_CACHE_DIR = "/var/vmm/pxeboot"
TFTP_DIR = "/tftpboot"
OPENBSD_MIRROR = "https://ftp.openbsd.org/pub/OpenBSD"


class VmmAutoinstallOperations:
    """Autoinstall operations for VMM VMs."""

    def __init__(self, logger):
        """
        Initialize autoinstall operations.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        self._http_server_manager = http_module.AutoinstallHttpServer(logger)

    @staticmethod
    def _generate_mac_address(vm_name: str) -> str:
        """
        Generate a deterministic MAC address for a VM based on its name.

        Args:
            vm_name: Name of the VM

        Returns:
            MAC address string
        """
        return config.generate_mac_address(vm_name)

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
        return config.generate_install_conf(
            hostname=hostname,
            username=username,
            password=password,
            logger=self.logger,
            timezone=timezone,
            dns_nameservers=dns_nameservers,
            sets=sets,
            public_key=public_key,
        )

    def _encrypt_password(self, password: str) -> str:
        """
        Encrypt password using bcrypt for OpenBSD.

        Args:
            password: Plain text password

        Returns:
            Encrypted password hash
        """
        return config.encrypt_password(password, self.logger)

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

        Args:
            vm_name: Name of the VM (used for logging)
            hostname: System hostname
            username: Non-root user to create
            password: Password for accounts
            timezone: Timezone

        Returns:
            Dict with success status and file path
        """
        content = self.generate_install_conf(
            hostname=hostname,
            username=username,
            password=password,
            timezone=timezone,
        )
        return http_module.write_install_conf(vm_name, content, self.logger)

    def start_http_server(
        self, bind_address: Optional[str] = None, port: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Start HTTP server to serve autoinstall files.

        Args:
            bind_address: Address to bind to (default: 100.64.0.1)
            port: Port to listen on (default: 80)

        Returns:
            Dict with success status
        """
        return self._http_server_manager.start(bind_address, port)

    def stop_http_server(self) -> Dict[str, Any]:
        """
        Stop the autoinstall HTTP server.

        Returns:
            Dict with success status
        """
        return self._http_server_manager.stop()

    def cleanup_install_conf(self, _vm_name: Optional[str] = None) -> Dict[str, Any]:
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
                self.logger.info(_("Removed install.conf: %s"), conf_path)

            return {"success": True}

        except Exception as error:
            self.logger.error(_("Failed to cleanup install.conf: %s"), error)
            return {
                "success": False,
                "error": str(error),
            }

    def wait_for_autoinstall_fetch(
        self,
        timeout: int = 300,
        check_interval: int = 5,
    ) -> Dict[str, Any]:
        """
        Wait for VM to fetch install.conf via HTTP.

        Args:
            timeout: Maximum time to wait in seconds
            check_interval: How often to check in seconds

        Returns:
            Dict with success status
        """
        start_time = time.time()
        conf_path = os.path.join(AUTOINSTALL_DIR, "install.conf")

        self.logger.info(_("Waiting for VM to fetch install.conf..."))

        while time.time() - start_time < timeout:
            # Check if file still exists (would be fetched/removed if accessed)
            if not os.path.exists(conf_path):
                self.logger.info(_("install.conf was fetched"))
                return {"success": True}

            # TODO: Better detection - check HTTP server logs or access time
            time.sleep(check_interval)

        self.logger.warning(
            _("Timeout waiting for install.conf fetch after %d seconds"), timeout
        )
        return {
            "success": False,
            "error": _("Timeout waiting for autoinstall fetch"),
        }

    def _parse_openbsd_version(self, iso_url: str) -> Optional[str]:
        """
        Parse OpenBSD version from ISO URL.

        Args:
            iso_url: URL to OpenBSD ISO

        Returns:
            Version string (e.g., "7.4") or None
        """
        return infra._parse_openbsd_version(iso_url)

    def _download_pxe_files(self, version: str, arch: str = "amd64") -> Dict[str, Any]:
        """
        Download PXE boot files for a specific OpenBSD version.

        Args:
            version: OpenBSD version (e.g., "7.4")
            arch: Architecture (default: amd64)

        Returns:
            Dict with success status and file paths
        """
        return infra._download_pxe_files(version, self.logger, arch)

    def _setup_tftp_server(self, state: Dict[str, Any]) -> None:
        """
        Set up TFTP server for PXE boot.

        Args:
            state: Infrastructure state dict to update
        """
        infra._setup_tftp_server(state, self.logger)

    def setup_autoinstall_infrastructure(
        self,
        vm_name: str,
        hostname: str,
        iso_url: Optional[str] = None,
        use_pxe: bool = True,
    ) -> Dict[str, Any]:
        """
        Set up complete autoinstall infrastructure.

        Args:
            vm_name: Name of the VM
            hostname: Hostname for the VM
            iso_url: Optional ISO URL for version detection
            use_pxe: Whether to set up PXE boot infrastructure

        Returns:
            Dict with success status and state for cleanup
        """
        return infra.setup_autoinstall_infrastructure(
            vm_name, hostname, self.logger, iso_url, use_pxe
        )

    def cleanup_autoinstall_infrastructure(
        self, state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Clean up autoinstall infrastructure and restore original state.

        Args:
            state: Infrastructure state from setup

        Returns:
            Dict with success status
        """
        return infra.cleanup_autoinstall_infrastructure(state, self.logger)

    def _restore_infrastructure_state(self, state: Dict[str, Any]) -> None:
        """
        Restore infrastructure to original state.

        Args:
            state: Infrastructure state to restore
        """
        infra._restore_infrastructure_state(state, self.logger)
