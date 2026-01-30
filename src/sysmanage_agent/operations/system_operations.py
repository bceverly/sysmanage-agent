"""
System operations module for SysManage agent.
Handles system-level commands and operations.

This is a facade class that delegates to specialized operation classes.
"""

import logging
from typing import Any, Dict

from src.sysmanage_agent.operations.antivirus_operations import AntivirusOperations
from src.sysmanage_agent.operations.certificate_operations import CertificateOperations
from src.sysmanage_agent.operations.firewall_operations import FirewallOperations
from src.sysmanage_agent.operations.hostname_operations import HostnameOperations
from src.sysmanage_agent.operations.opentelemetry_operations import (
    OpenTelemetryOperations,
)
from src.sysmanage_agent.operations.package_operations import PackageOperations
from src.sysmanage_agent.operations.repository_operations import (
    ThirdPartyRepositoryOperations,
)
from src.sysmanage_agent.operations.ssh_key_operations import SSHKeyOperations
from src.sysmanage_agent.operations.system_control import SystemControl
from src.sysmanage_agent.operations.ubuntu_pro_operations import UbuntuProOperations
from src.sysmanage_agent.operations.user_account_operations import UserAccountOperations


class SystemOperations:  # pylint: disable=too-many-instance-attributes
    """Handles system-level operations for the agent via delegation to specialized handlers."""

    def __init__(self, agent_instance):
        """Initialize system operations with agent instance."""
        self.agent = agent_instance
        self.logger = logging.getLogger(__name__)

        # Initialize specialized operation handlers
        self.certificate_ops = CertificateOperations(agent_instance)
        self.system_control = SystemControl(agent_instance)
        self.package_ops = PackageOperations(agent_instance)
        self.otel_ops = OpenTelemetryOperations(agent_instance)
        self.antivirus_ops = AntivirusOperations(agent_instance)
        self.firewall_ops = FirewallOperations(agent_instance)
        self.repo_ops = ThirdPartyRepositoryOperations(agent_instance)
        self.ssh_ops = SSHKeyOperations(agent_instance)
        self.ubuntu_pro_ops = UbuntuProOperations(agent_instance)
        self.user_account_ops = UserAccountOperations(agent_instance)
        self.hostname_ops = HostnameOperations(agent_instance)

    # ========== System Control Delegation ==========

    async def execute_shell_command(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a shell command."""
        return await self.system_control.execute_shell_command(parameters)

    async def get_detailed_system_info(self) -> Dict[str, Any]:
        """Get detailed system information and send all data to server."""
        return await self.system_control.get_detailed_system_info()

    async def update_system(self) -> Dict[str, Any]:
        """Update the system packages."""
        return await self.system_control.update_system()

    async def restart_service(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restart a system service."""
        return await self.system_control.restart_service(parameters)

    async def reboot_system(self) -> Dict[str, Any]:
        """Reboot the system."""
        return await self.system_control.reboot_system()

    async def shutdown_system(self) -> Dict[str, Any]:
        """Shutdown the system."""
        return await self.system_control.shutdown_system()

    # ========== Package Operations Delegation ==========

    async def install_package(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Install a package using the appropriate package manager."""
        return await self.package_ops.install_package(parameters)

    async def install_packages(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Install multiple packages using UUID-based grouping."""
        return await self.package_ops.install_packages(parameters)

    async def uninstall_packages(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Uninstall multiple packages using UUID-based grouping."""
        return await self.package_ops.uninstall_packages(parameters)

    async def _install_packages_with_apt(self, package_names: list) -> Dict[str, Any]:
        """Install multiple packages with a single apt-get command."""
        return await self.package_ops._install_packages_with_apt(  # pylint: disable=protected-access
            package_names
        )

    async def _uninstall_packages_with_apt(self, package_names: list) -> Dict[str, Any]:
        """Uninstall multiple packages with a single apt-get command."""
        return await self.package_ops._uninstall_packages_with_apt(  # pylint: disable=protected-access
            package_names
        )

    async def _send_installation_completion(
        self, request_id: str, success: bool, result_log: str
    ):
        """Send completion notification to the server."""
        return await self.package_ops._send_installation_completion(  # pylint: disable=protected-access
            request_id, success, result_log
        )

    async def _send_installation_status_update(
        self,
        installation_id: str,
        status: str,
        package_name: str,
        requested_by: str,
        error_message: str = None,
        installed_version: str = None,
        installation_log: str = None,
    ):
        """Send status update during installation."""
        return await self.package_ops._send_installation_status_update(  # pylint: disable=protected-access
            installation_id,
            status,
            package_name,
            requested_by,
            error_message,
            installed_version,
            installation_log,
        )

    async def _run_package_update(self) -> None:
        """Run package update command."""
        return (
            await self.package_ops._run_package_update()  # pylint: disable=protected-access
        )

    async def _trigger_update_detection(self):
        """Trigger update detection after package installation."""
        return (
            await self.package_ops._trigger_update_detection()  # pylint: disable=protected-access
        )

    async def _get_package_versions(self, package_names: list) -> dict:
        """Get installed versions for a list of package names."""
        return await self.package_ops._get_package_versions(  # pylint: disable=protected-access
            package_names
        )

    # ========== Ubuntu Pro Operations Delegation ==========

    async def ubuntu_pro_attach(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Attach system to Ubuntu Pro."""
        return await self.ubuntu_pro_ops.ubuntu_pro_attach(parameters)

    async def ubuntu_pro_detach(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Detach system from Ubuntu Pro."""
        return await self.ubuntu_pro_ops.ubuntu_pro_detach(parameters)

    async def ubuntu_pro_enable_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable an Ubuntu Pro service."""
        return await self.ubuntu_pro_ops.ubuntu_pro_enable_service(parameters)

    async def ubuntu_pro_disable_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disable an Ubuntu Pro service."""
        return await self.ubuntu_pro_ops.ubuntu_pro_disable_service(parameters)

    async def _send_os_update_after_pro_change(self):
        """Send OS update after Ubuntu Pro configuration change."""
        return (
            await self.ubuntu_pro_ops._send_os_update_after_pro_change()  # pylint: disable=protected-access
        )

    # ========== SSH Key Operations Delegation ==========

    async def deploy_ssh_keys(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy SSH keys to a user's .ssh directory with proper permissions."""
        return await self.ssh_ops.deploy_ssh_keys(parameters)

    def _validate_ssh_key_inputs(self, username: str, ssh_keys: list) -> dict:
        """Validate SSH key deployment inputs."""
        return (
            self.ssh_ops._validate_ssh_key_inputs(  # pylint: disable=protected-access
                username, ssh_keys
            )
        )

    def _setup_ssh_environment(self, username: str) -> Dict[str, Any]:
        """Setup SSH environment for a user."""
        return self.ssh_ops._setup_ssh_environment(  # pylint: disable=protected-access
            username
        )

    # ========== Certificate Operations Delegation ==========

    async def deploy_certificates(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy SSL certificates to the appropriate system directory."""
        return await self.certificate_ops.deploy_certificates(parameters)

    # ========== OpenTelemetry Operations Delegation ==========

    async def deploy_opentelemetry(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy OpenTelemetry collector to the system."""
        return await self.otel_ops.deploy_opentelemetry(parameters)

    async def remove_opentelemetry(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove OpenTelemetry collector from the system."""
        return await self.otel_ops.remove_opentelemetry(parameters)

    async def start_opentelemetry_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Start the OpenTelemetry collector service."""
        return await self.otel_ops.start_opentelemetry_service(parameters)

    async def stop_opentelemetry_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Stop the OpenTelemetry collector service."""
        return await self.otel_ops.stop_opentelemetry_service(parameters)

    async def restart_opentelemetry_service(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Restart the OpenTelemetry collector service."""
        return await self.otel_ops.restart_opentelemetry_service(parameters)

    async def connect_opentelemetry_grafana(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Connect OpenTelemetry to a Grafana instance."""
        return await self.otel_ops.connect_opentelemetry_grafana(parameters)

    async def disconnect_opentelemetry_grafana(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disconnect OpenTelemetry from Grafana."""
        return await self.otel_ops.disconnect_opentelemetry_grafana(parameters)

    # ========== Antivirus Operations Delegation ==========

    async def deploy_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy antivirus software (ClamAV)."""
        return await self.antivirus_ops.deploy_antivirus(parameters)

    async def enable_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enable antivirus software (ClamAV)."""
        return await self.antivirus_ops.enable_antivirus(parameters)

    async def disable_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Disable antivirus software (ClamAV)."""
        return await self.antivirus_ops.disable_antivirus(parameters)

    async def remove_antivirus(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Remove antivirus software (ClamAV)."""
        return await self.antivirus_ops.remove_antivirus(parameters)

    async def _send_antivirus_status_update(self, antivirus_status: Dict[str, Any]):
        """Send antivirus status update to server."""
        return await self.antivirus_ops._send_antivirus_status_update(  # pylint: disable=protected-access
            antivirus_status
        )

    # ========== Repository Operations Delegation ==========

    async def list_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """List third-party repositories on the system."""
        return await self.repo_ops.list_third_party_repositories(parameters)

    async def add_third_party_repository(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a third-party repository to the system."""
        return await self.repo_ops.add_third_party_repository(parameters)

    async def delete_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Delete third-party repositories from the system."""
        return await self.repo_ops.delete_third_party_repositories(parameters)

    async def enable_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enable third-party repositories."""
        return await self.repo_ops.enable_third_party_repositories(parameters)

    async def disable_third_party_repositories(
        self, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disable third-party repositories."""
        return await self.repo_ops.disable_third_party_repositories(parameters)

    async def _trigger_third_party_repository_rescan(self):
        """Trigger a rescan of third-party repositories."""
        return (
            await self.repo_ops._trigger_third_party_repository_rescan()  # pylint: disable=protected-access
        )

    def _check_obs_url(self, url: str) -> bool:
        """Check if URL is a valid OpenBuildService URL."""
        return self.repo_ops._check_obs_url(url)  # pylint: disable=protected-access

    # ========== Firewall Operations Delegation ==========

    async def deploy_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy (install and enable) firewall."""
        return await self.firewall_ops.deploy_firewall(parameters)

    async def enable_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Enable firewall."""
        return await self.firewall_ops.enable_firewall(parameters)

    async def disable_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Disable firewall."""
        return await self.firewall_ops.disable_firewall(parameters)

    async def restart_firewall(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Restart firewall."""
        return await self.firewall_ops.restart_firewall(parameters)

    # ========== User Account Operations Delegation ==========

    async def create_host_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user account on the host."""
        return await self.user_account_ops.create_host_user(parameters)

    async def create_host_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new group on the host."""
        return await self.user_account_ops.create_host_group(parameters)

    async def delete_host_user(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Delete a user account from the host."""
        return await self.user_account_ops.delete_host_user(parameters)

    async def delete_host_group(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Delete a group from the host."""
        return await self.user_account_ops.delete_host_group(parameters)

    # ========== Hostname Operations Delegation ==========

    async def change_hostname(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Change the system hostname."""
        return await self.hostname_ops.change_hostname(parameters)
