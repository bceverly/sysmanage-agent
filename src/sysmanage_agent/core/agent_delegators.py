"""
Agent delegator mixin classes.

This module contains mixin classes that provide delegator methods for the
SysManageAgent class. These methods simply forward calls to the appropriate
operations handler, providing a unified interface.

Extracted from main.py to reduce file size while maintaining API compatibility.
"""

from typing import Any, Dict


class SystemOperationsDelegator:
    """Mixin providing system operations delegators."""

    async def execute_shell_command(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a shell command."""
        return await self.system_ops.execute_shell_command(parameters)

    async def get_detailed_system_info(self) -> Dict[str, Any]:
        """Get detailed system information."""
        return await self.system_ops.get_detailed_system_info()

    async def install_package(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Install a package using the appropriate package manager."""
        return await self.system_ops.install_package(parameters)

    async def install_packages(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Install multiple packages using the appropriate package manager."""
        return await self.system_ops.install_packages(parameters)

    async def uninstall_packages(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Uninstall multiple packages using the appropriate package manager."""
        return await self.system_ops.uninstall_packages(parameters)

    async def update_system(self) -> Dict[str, Any]:
        """Update the system using the default package manager."""
        return await self.system_ops.update_system()

    async def restart_service(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restart a system service."""
        return await self.system_ops.restart_service(parameters)

    async def reboot_system(self) -> Dict[str, Any]:
        """Reboot the system."""
        return await self.system_ops.reboot_system()

    async def shutdown_system(self) -> Dict[str, Any]:
        """Shutdown the system."""
        return await self.system_ops.shutdown_system()

    async def ubuntu_pro_attach(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Attach Ubuntu Pro subscription using provided token."""
        return await self.system_ops.ubuntu_pro_attach(parameters)

    async def ubuntu_pro_detach(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Detach Ubuntu Pro subscription."""
        return await self.system_ops.ubuntu_pro_detach(parameters)

    async def ubuntu_pro_enable_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable Ubuntu Pro service."""
        return await self.system_ops.ubuntu_pro_enable_service(parameters)

    async def ubuntu_pro_disable_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disable Ubuntu Pro service."""
        return await self.system_ops.ubuntu_pro_disable_service(parameters)

    async def deploy_files(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy files to the filesystem."""
        return await self.system_ops.deploy_files(parameters)

    async def execute_command_sequence(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a sequence of commands."""
        return await self.system_ops.execute_command_sequence(parameters)

    async def deploy_opentelemetry(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy OpenTelemetry collector to the system."""
        return await self.system_ops.deploy_opentelemetry(parameters)

    async def remove_opentelemetry(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove OpenTelemetry collector from the system."""
        return await self.system_ops.remove_opentelemetry(parameters)

    async def list_third_party_repositories(
        self, parameters: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """List all third-party repositories on the system."""
        return await self.system_ops.list_third_party_repositories(parameters or {})

    async def add_third_party_repository(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a third-party repository to the system."""
        return await self.system_ops.add_third_party_repository(parameters)

    async def delete_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Delete third-party repositories from the system."""
        return await self.system_ops.delete_third_party_repositories(parameters)

    async def enable_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable third-party repositories on the system."""
        return await self.system_ops.enable_third_party_repositories(parameters)

    async def disable_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disable third-party repositories on the system."""
        return await self.system_ops.disable_third_party_repositories(parameters)

    async def deploy_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy antivirus software to the system."""
        return await self.system_ops.deploy_antivirus(parameters)

    async def enable_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enable antivirus service(s)."""
        return await self.system_ops.enable_antivirus(parameters)

    async def disable_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Disable antivirus service(s)."""
        return await self.system_ops.disable_antivirus(parameters)

    async def remove_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove antivirus software from the system."""
        return await self.system_ops.remove_antivirus(parameters)

    async def create_host_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user account on the host."""
        return await self.system_ops.create_host_user(parameters)

    async def create_host_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new group on the host."""
        return await self.system_ops.create_host_group(parameters)

    async def delete_host_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Delete a user account from the host."""
        return await self.system_ops.delete_host_user(parameters)

    async def delete_host_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Delete a group from the host."""
        return await self.system_ops.delete_host_group(parameters)

    async def change_hostname(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Change the system hostname."""
        return await self.system_ops.change_hostname(parameters)


class DataCollectorDelegator:
    """Mixin providing data collector delegators."""

    async def send_initial_data_updates(self):
        """Send initial data updates after WebSocket connection."""
        await self.data_collector.send_initial_data_updates()

    async def update_os_version(self) -> Dict[str, Any]:
        """Gather and send updated OS version information to the server."""
        return await self.data_collector.update_os_version()

    async def update_hardware(self) -> Dict[str, Any]:
        """Gather and send updated hardware information to the server."""
        return await self.data_collector.update_hardware()

    async def update_user_access(self) -> Dict[str, Any]:
        """Gather and send updated user access information to the server."""
        return await self.data_collector.update_user_access()

    async def update_checker(self):
        """Periodically check for updates."""
        await self.data_collector.update_checker()

    async def _send_software_inventory_update(self):
        """Send software inventory update."""
        await self.data_collector._send_software_inventory_update()  # pylint: disable=protected-access

    async def _send_user_access_update(self):
        """Send user access update."""
        await self.data_collector._send_user_access_update()  # pylint: disable=protected-access

    async def _send_hardware_update(self):
        """Send hardware update."""
        await self.data_collector._send_hardware_update()  # pylint: disable=protected-access

    async def _send_certificate_update(self):
        """Send certificate update."""
        await self.data_collector._send_certificate_update()  # pylint: disable=protected-access

    async def _send_role_update(self):
        """Send role update."""
        await self.data_collector._send_role_update()  # pylint: disable=protected-access

    async def _send_os_version_update(self):
        """Send OS version update."""
        await self.data_collector._send_os_version_update()  # pylint: disable=protected-access

    async def _send_reboot_status_update(self):
        """Send reboot status update."""
        await self.data_collector._send_reboot_status_update()  # pylint: disable=protected-access

    async def _send_third_party_repository_update(self):
        """Send third-party repository update."""
        await self.data_collector._send_third_party_repository_update()  # pylint: disable=protected-access

    async def _send_antivirus_status_update(self):
        """Send antivirus status update."""
        await self.data_collector._send_antivirus_status_update()  # pylint: disable=protected-access

    async def _collect_and_send_periodic_data(self):
        """Collect and send all periodic data."""
        await self.data_collector._collect_and_send_periodic_data()  # pylint: disable=protected-access

    async def package_collector(self):
        """Periodically collect and send package information."""
        return await self.data_collector.package_collector()

    async def child_host_heartbeat(self):
        """Delegate to data_collector for frequent child host status updates."""
        return await self.data_collector.child_host_heartbeat()

    async def collect_available_packages(self) -> Dict[str, Any]:
        """Delegate to data_collector."""
        return await self.data_collector.collect_available_packages()

    async def _send_available_packages_paginated(
        self,
        package_managers: Dict[str, list],
        os_name: str,
        os_version: str,
        total_packages: int,
    ) -> bool:
        """Send available packages using pagination to avoid large message issues."""
        return await self.data_collector._send_available_packages_paginated(  # pylint: disable=protected-access
            package_managers, os_name, os_version, total_packages
        )

    async def collect_certificates(self) -> Dict[str, Any]:
        """Delegate to data_collector."""
        return await self.data_collector.collect_certificates()

    async def collect_roles(self) -> Dict[str, Any]:
        """Delegate to data_collector."""
        return await self.data_collector.collect_roles()


class RegistrationDelegator:
    """Mixin providing registration manager delegators."""

    async def get_auth_token(self) -> str:
        """Get authentication token for WebSocket connection."""
        return await self.registration_manager.get_auth_token()

    async def fetch_certificates(self, host_id: str) -> bool:
        """Fetch certificates from server after approval."""
        return await self.registration_manager.fetch_certificates(host_id)

    async def ensure_certificates(self) -> bool:
        """Ensure agent has valid certificates for mTLS."""
        return await self.registration_manager.ensure_certificates()

    async def handle_host_approval(self, message: Dict[str, Any]) -> None:
        """Handle host approval notification from server."""
        await self.registration_manager.handle_host_approval(message)

    async def clear_host_approval(self) -> None:
        """Clear all host approval records from local database."""
        await self.registration_manager.clear_host_approval()

    async def store_host_approval(
        self,
        host_id: str,
        approval_status: str,
        certificate: str = None,
        host_token: str = None,
    ) -> None:
        """Store host approval information in local database."""
        await self.registration_manager.store_host_approval(
            host_id, approval_status, certificate, host_token
        )

    async def handle_registration_success(self, message: Dict[str, Any]) -> None:
        """Handle registration success notification from server."""
        await self.registration_manager.handle_registration_success(message)

    async def get_stored_host_id(self) -> str:
        """Get the stored host_id from local database."""
        return await self.registration_manager.get_stored_host_id()

    async def get_stored_host_token(self) -> str:
        """Get the stored host_token from local database."""
        return await self.registration_manager.get_stored_host_token()

    def get_stored_host_token_sync(self) -> str:
        """Get the stored host_token from local database synchronously."""
        return self.registration_manager.get_stored_host_token_sync()

    async def call_server_api(
        self, endpoint: str, method: str = "POST", data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Centralized method for making API calls to the server.

        Args:
            endpoint: API endpoint (without /api prefix)
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request payload (for POST/PUT requests)

        Returns:
            Response data as dictionary, or None if request failed
        """
        return await self.registration_manager.call_server_api(endpoint, method, data)

    def get_host_approval_from_db(self):
        """Get the host approval record from local database."""
        return self.registration_manager.get_host_approval_from_db()

    def get_stored_host_id_sync(self) -> str:
        """Get the stored host_id from local database synchronously."""
        return self.registration_manager.get_stored_host_id_sync()

    def cleanup_corrupt_database_entries(self) -> None:
        """Clean up any corrupt entries from database (e.g., invalid UUIDs)."""
        self.registration_manager.cleanup_corrupt_database_entries()

    async def clear_stored_host_id(self) -> None:
        """Clear the stored host_id from local database and related data."""
        await self.registration_manager.clear_stored_host_id()


class UpdateManagerDelegator:
    """Mixin providing update manager delegators."""

    async def check_updates(self) -> Dict[str, Any]:
        """Check for available updates for installed packages."""
        return await self.update_manager.check_updates()

    async def apply_updates(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Apply updates for specified packages."""
        return await self.update_manager.apply_updates(parameters)

    async def check_reboot_status(self) -> Dict[str, Any]:
        """Check if the system requires a reboot."""
        return await self.update_manager.check_reboot_status()

    async def send_reboot_status_update(self, requires_reboot: bool) -> None:
        """Send reboot status update to server."""
        await self.update_manager.send_reboot_status_update(requires_reboot)


class FirewallDelegator:
    """Mixin providing firewall operations delegators."""

    async def deploy_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy (install and enable) firewall on the system."""
        return await self.firewall_ops.deploy_firewall(parameters)

    async def enable_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enable firewall and ensure agent communication ports are open."""
        return await self.firewall_ops.enable_firewall(parameters)

    async def disable_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Disable firewall on the system."""
        return await self.firewall_ops.disable_firewall(parameters)

    async def restart_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restart firewall service on the system."""
        return await self.firewall_ops.restart_firewall(parameters)

    async def apply_firewall_roles(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Apply firewall roles by setting open ports based on assigned roles."""
        return await self.firewall_ops.apply_firewall_roles(parameters)

    async def remove_firewall_ports(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove specific firewall ports (used when a firewall role is removed)."""
        return await self.firewall_ops.remove_firewall_ports(parameters)


class MiscDelegator:
    """Mixin providing miscellaneous operation delegators."""

    async def handle_command(self, message: Dict[str, Any]):
        """Handle command from server."""
        await self.message_processor.handle_command(message)

    async def execute_script(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a script with proper security controls."""
        return await self.script_ops.execute_script(parameters)

    async def collect_diagnostics(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Collect system diagnostics and send to server."""
        return await self.diagnostic_collector.collect_diagnostics(parameters)

    async def attach_to_graylog(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Attach host to Graylog log aggregation server."""
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.operations.graylog_attachment import (
            GraylogAttachmentOperations,
        )

        graylog_ops = GraylogAttachmentOperations(self, self.logger)
        return await graylog_ops.attach_to_graylog(parameters)

    async def enable_package_manager(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable an additional package manager on this host."""
        # pylint: disable=import-outside-toplevel
        from src.sysmanage_agent.operations.package_manager_operations import (
            PackageManagerOperations,
        )

        pm_ops = PackageManagerOperations(self, self.logger)
        return await pm_ops.enable_package_manager(parameters)


class AgentDelegatorMixin(
    SystemOperationsDelegator,
    DataCollectorDelegator,
    RegistrationDelegator,
    UpdateManagerDelegator,
    FirewallDelegator,
    MiscDelegator,
):
    """Combined mixin providing all delegator methods for SysManageAgent."""
