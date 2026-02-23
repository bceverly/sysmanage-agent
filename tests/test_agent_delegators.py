"""
Comprehensive unit tests for agent_delegators.py module.

Tests the delegator mixin classes that forward calls to appropriate handlers:
- SystemOperationsDelegator
- DataCollectorDelegator
- RegistrationDelegator
- UpdateManagerDelegator
- FirewallDelegator
- MiscDelegator
- AgentDelegatorMixin
"""

# pylint: disable=protected-access,too-many-public-methods

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.core.agent_delegators import (
    AgentDelegatorMixin,
    DataCollectorDelegator,
    FirewallDelegator,
    MiscDelegator,
    RegistrationDelegator,
    SystemOperationsDelegator,
    UpdateManagerDelegator,
)


class MockDelegatorClass(AgentDelegatorMixin):
    """Mock class that uses all delegator mixins for testing."""

    def __init__(self):
        """Initialize mock delegator with all required handlers."""
        self.system_ops = Mock()
        self.data_collector = Mock()
        self.registration_manager = Mock()
        self.update_manager = Mock()
        self.firewall_ops = Mock()
        self.message_processor = Mock()
        self.script_ops = Mock()
        self.diagnostic_collector = Mock()
        self.logger = Mock()


class TestSystemOperationsDelegator:
    """Test SystemOperationsDelegator mixin class."""

    @pytest.fixture
    def delegator(self):
        """Create a mock delegator instance."""
        return MockDelegatorClass()

    @pytest.mark.asyncio
    async def test_execute_shell_command(self, delegator):
        """Test execute_shell_command delegation."""
        delegator.system_ops.execute_shell_command = AsyncMock(
            return_value={"success": True, "result": {"stdout": "output"}}
        )
        parameters = {"command": "echo hello"}

        result = await delegator.execute_shell_command(parameters)

        assert result["success"] is True
        delegator.system_ops.execute_shell_command.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_get_detailed_system_info(self, delegator):
        """Test get_detailed_system_info delegation."""
        delegator.system_ops.get_detailed_system_info = AsyncMock(
            return_value={"success": True, "result": "System info collected"}
        )

        result = await delegator.get_detailed_system_info()

        assert result["success"] is True
        delegator.system_ops.get_detailed_system_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_install_package(self, delegator):
        """Test install_package delegation."""
        delegator.system_ops.install_package = AsyncMock(
            return_value={"success": True, "result": "Package installed"}
        )
        parameters = {"package_name": "vim", "package_manager": "apt"}

        result = await delegator.install_package(parameters)

        assert result["success"] is True
        delegator.system_ops.install_package.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_install_packages(self, delegator):
        """Test install_packages delegation."""
        delegator.system_ops.install_packages = AsyncMock(
            return_value={"success": True, "result": "Packages installed"}
        )
        parameters = {"packages": ["vim", "git"], "package_manager": "apt"}

        result = await delegator.install_packages(parameters)

        assert result["success"] is True
        delegator.system_ops.install_packages.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_uninstall_packages(self, delegator):
        """Test uninstall_packages delegation."""
        delegator.system_ops.uninstall_packages = AsyncMock(
            return_value={"success": True, "result": "Packages uninstalled"}
        )
        parameters = {"packages": ["vim"], "package_manager": "apt"}

        result = await delegator.uninstall_packages(parameters)

        assert result["success"] is True
        delegator.system_ops.uninstall_packages.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_update_system(self, delegator):
        """Test update_system delegation."""
        delegator.system_ops.update_system = AsyncMock(
            return_value={"success": True, "result": "System updated"}
        )

        result = await delegator.update_system()

        assert result["success"] is True
        delegator.system_ops.update_system.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_service(self, delegator):
        """Test restart_service delegation."""
        delegator.system_ops.restart_service = AsyncMock(
            return_value={"success": True, "result": "Service restarted"}
        )
        parameters = {"service_name": "nginx"}

        result = await delegator.restart_service(parameters)

        assert result["success"] is True
        delegator.system_ops.restart_service.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_reboot_system(self, delegator):
        """Test reboot_system delegation."""
        delegator.system_ops.reboot_system = AsyncMock(
            return_value={"success": True, "result": "Reboot scheduled"}
        )

        result = await delegator.reboot_system()

        assert result["success"] is True
        delegator.system_ops.reboot_system.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_system(self, delegator):
        """Test shutdown_system delegation."""
        delegator.system_ops.shutdown_system = AsyncMock(
            return_value={"success": True, "result": "Shutdown scheduled"}
        )

        result = await delegator.shutdown_system()

        assert result["success"] is True
        delegator.system_ops.shutdown_system.assert_called_once()

    @pytest.mark.asyncio
    async def test_ubuntu_pro_attach(self, delegator):
        """Test ubuntu_pro_attach delegation."""
        delegator.system_ops.ubuntu_pro_attach = AsyncMock(
            return_value={"success": True, "result": "Ubuntu Pro attached"}
        )
        parameters = {"token": "test-token"}

        result = await delegator.ubuntu_pro_attach(parameters)

        assert result["success"] is True
        delegator.system_ops.ubuntu_pro_attach.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_ubuntu_pro_detach(self, delegator):
        """Test ubuntu_pro_detach delegation."""
        delegator.system_ops.ubuntu_pro_detach = AsyncMock(
            return_value={"success": True, "result": "Ubuntu Pro detached"}
        )
        parameters = {}

        result = await delegator.ubuntu_pro_detach(parameters)

        assert result["success"] is True
        delegator.system_ops.ubuntu_pro_detach.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_ubuntu_pro_enable_service(self, delegator):
        """Test ubuntu_pro_enable_service delegation."""
        delegator.system_ops.ubuntu_pro_enable_service = AsyncMock(
            return_value={"success": True, "result": "Service enabled"}
        )
        parameters = {"service": "esm-infra"}

        result = await delegator.ubuntu_pro_enable_service(parameters)

        assert result["success"] is True
        delegator.system_ops.ubuntu_pro_enable_service.assert_called_once_with(
            parameters
        )

    @pytest.mark.asyncio
    async def test_ubuntu_pro_disable_service(self, delegator):
        """Test ubuntu_pro_disable_service delegation."""
        delegator.system_ops.ubuntu_pro_disable_service = AsyncMock(
            return_value={"success": True, "result": "Service disabled"}
        )
        parameters = {"service": "esm-infra"}

        result = await delegator.ubuntu_pro_disable_service(parameters)

        assert result["success"] is True
        delegator.system_ops.ubuntu_pro_disable_service.assert_called_once_with(
            parameters
        )

    @pytest.mark.asyncio
    async def test_deploy_opentelemetry(self, delegator):
        """Test deploy_opentelemetry delegation."""
        delegator.system_ops.deploy_opentelemetry = AsyncMock(
            return_value={"success": True, "result": "OpenTelemetry deployed"}
        )
        parameters = {"endpoint": "http://collector:4317"}

        result = await delegator.deploy_opentelemetry(parameters)

        assert result["success"] is True
        delegator.system_ops.deploy_opentelemetry.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_remove_opentelemetry(self, delegator):
        """Test remove_opentelemetry delegation."""
        delegator.system_ops.remove_opentelemetry = AsyncMock(
            return_value={"success": True, "result": "OpenTelemetry removed"}
        )
        parameters = {}

        result = await delegator.remove_opentelemetry(parameters)

        assert result["success"] is True
        delegator.system_ops.remove_opentelemetry.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_list_third_party_repositories_with_params(self, delegator):
        """Test list_third_party_repositories delegation with parameters."""
        delegator.system_ops.list_third_party_repositories = AsyncMock(
            return_value={"success": True, "repositories": []}
        )
        parameters = {"filter": "enabled"}

        result = await delegator.list_third_party_repositories(parameters)

        assert result["success"] is True
        delegator.system_ops.list_third_party_repositories.assert_called_once_with(
            parameters
        )

    @pytest.mark.asyncio
    async def test_list_third_party_repositories_without_params(self, delegator):
        """Test list_third_party_repositories delegation without parameters."""
        delegator.system_ops.list_third_party_repositories = AsyncMock(
            return_value={"success": True, "repositories": []}
        )

        result = await delegator.list_third_party_repositories()

        assert result["success"] is True
        delegator.system_ops.list_third_party_repositories.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_list_third_party_repositories_none_params(self, delegator):
        """Test list_third_party_repositories delegation with None parameters."""
        delegator.system_ops.list_third_party_repositories = AsyncMock(
            return_value={"success": True, "repositories": []}
        )

        result = await delegator.list_third_party_repositories(None)

        assert result["success"] is True
        delegator.system_ops.list_third_party_repositories.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_add_third_party_repository(self, delegator):
        """Test add_third_party_repository delegation."""
        delegator.system_ops.add_third_party_repository = AsyncMock(
            return_value={"success": True, "result": "Repository added"}
        )
        parameters = {"name": "test-repo", "url": "http://repo.example.com"}

        result = await delegator.add_third_party_repository(parameters)

        assert result["success"] is True
        delegator.system_ops.add_third_party_repository.assert_called_once_with(
            parameters
        )

    @pytest.mark.asyncio
    async def test_delete_third_party_repositories(self, delegator):
        """Test delete_third_party_repositories delegation."""
        delegator.system_ops.delete_third_party_repositories = AsyncMock(
            return_value={"success": True, "result": "Repositories deleted"}
        )
        parameters = {"names": ["repo1", "repo2"]}

        result = await delegator.delete_third_party_repositories(parameters)

        assert result["success"] is True
        delegator.system_ops.delete_third_party_repositories.assert_called_once_with(
            parameters
        )

    @pytest.mark.asyncio
    async def test_enable_third_party_repositories(self, delegator):
        """Test enable_third_party_repositories delegation."""
        delegator.system_ops.enable_third_party_repositories = AsyncMock(
            return_value={"success": True, "result": "Repositories enabled"}
        )
        parameters = {"names": ["repo1"]}

        result = await delegator.enable_third_party_repositories(parameters)

        assert result["success"] is True
        delegator.system_ops.enable_third_party_repositories.assert_called_once_with(
            parameters
        )

    @pytest.mark.asyncio
    async def test_disable_third_party_repositories(self, delegator):
        """Test disable_third_party_repositories delegation."""
        delegator.system_ops.disable_third_party_repositories = AsyncMock(
            return_value={"success": True, "result": "Repositories disabled"}
        )
        parameters = {"names": ["repo1"]}

        result = await delegator.disable_third_party_repositories(parameters)

        assert result["success"] is True
        delegator.system_ops.disable_third_party_repositories.assert_called_once_with(
            parameters
        )

    @pytest.mark.asyncio
    async def test_deploy_antivirus(self, delegator):
        """Test deploy_antivirus delegation."""
        delegator.system_ops.deploy_antivirus = AsyncMock(
            return_value={"success": True, "result": "Antivirus deployed"}
        )
        parameters = {"software": "clamav"}

        result = await delegator.deploy_antivirus(parameters)

        assert result["success"] is True
        delegator.system_ops.deploy_antivirus.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_enable_antivirus(self, delegator):
        """Test enable_antivirus delegation."""
        delegator.system_ops.enable_antivirus = AsyncMock(
            return_value={"success": True, "result": "Antivirus enabled"}
        )
        parameters = {"software": "clamav"}

        result = await delegator.enable_antivirus(parameters)

        assert result["success"] is True
        delegator.system_ops.enable_antivirus.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_disable_antivirus(self, delegator):
        """Test disable_antivirus delegation."""
        delegator.system_ops.disable_antivirus = AsyncMock(
            return_value={"success": True, "result": "Antivirus disabled"}
        )
        parameters = {"software": "clamav"}

        result = await delegator.disable_antivirus(parameters)

        assert result["success"] is True
        delegator.system_ops.disable_antivirus.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_remove_antivirus(self, delegator):
        """Test remove_antivirus delegation."""
        delegator.system_ops.remove_antivirus = AsyncMock(
            return_value={"success": True, "result": "Antivirus removed"}
        )
        parameters = {"software": "clamav"}

        result = await delegator.remove_antivirus(parameters)

        assert result["success"] is True
        delegator.system_ops.remove_antivirus.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_create_host_user(self, delegator):
        """Test create_host_user delegation."""
        delegator.system_ops.create_host_user = AsyncMock(
            return_value={"success": True, "result": "User created"}
        )
        parameters = {"username": "testuser", "groups": ["sudo"]}

        result = await delegator.create_host_user(parameters)

        assert result["success"] is True
        delegator.system_ops.create_host_user.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_create_host_group(self, delegator):
        """Test create_host_group delegation."""
        delegator.system_ops.create_host_group = AsyncMock(
            return_value={"success": True, "result": "Group created"}
        )
        parameters = {"groupname": "testgroup"}

        result = await delegator.create_host_group(parameters)

        assert result["success"] is True
        delegator.system_ops.create_host_group.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_delete_host_user(self, delegator):
        """Test delete_host_user delegation."""
        delegator.system_ops.delete_host_user = AsyncMock(
            return_value={"success": True, "result": "User deleted"}
        )
        parameters = {"username": "testuser"}

        result = await delegator.delete_host_user(parameters)

        assert result["success"] is True
        delegator.system_ops.delete_host_user.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_delete_host_group(self, delegator):
        """Test delete_host_group delegation."""
        delegator.system_ops.delete_host_group = AsyncMock(
            return_value={"success": True, "result": "Group deleted"}
        )
        parameters = {"groupname": "testgroup"}

        result = await delegator.delete_host_group(parameters)

        assert result["success"] is True
        delegator.system_ops.delete_host_group.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_change_hostname(self, delegator):
        """Test change_hostname delegation."""
        delegator.system_ops.change_hostname = AsyncMock(
            return_value={"success": True, "result": "Hostname changed"}
        )
        parameters = {"hostname": "new-hostname"}

        result = await delegator.change_hostname(parameters)

        assert result["success"] is True
        delegator.system_ops.change_hostname.assert_called_once_with(parameters)


class TestDataCollectorDelegator:
    """Test DataCollectorDelegator mixin class."""

    @pytest.fixture
    def delegator(self):
        """Create a mock delegator instance."""
        return MockDelegatorClass()

    @pytest.mark.asyncio
    async def test_send_initial_data_updates(self, delegator):
        """Test send_initial_data_updates delegation."""
        delegator.data_collector.send_initial_data_updates = AsyncMock()

        await delegator.send_initial_data_updates()

        delegator.data_collector.send_initial_data_updates.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_os_version(self, delegator):
        """Test update_os_version delegation."""
        delegator.data_collector.update_os_version = AsyncMock(
            return_value={"success": True}
        )

        result = await delegator.update_os_version()

        assert result["success"] is True
        delegator.data_collector.update_os_version.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_hardware(self, delegator):
        """Test update_hardware delegation."""
        delegator.data_collector.update_hardware = AsyncMock(
            return_value={"success": True}
        )

        result = await delegator.update_hardware()

        assert result["success"] is True
        delegator.data_collector.update_hardware.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_user_access(self, delegator):
        """Test update_user_access delegation."""
        delegator.data_collector.update_user_access = AsyncMock(
            return_value={"success": True}
        )

        result = await delegator.update_user_access()

        assert result["success"] is True
        delegator.data_collector.update_user_access.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_checker(self, delegator):
        """Test update_checker delegation."""
        delegator.data_collector.update_checker = AsyncMock()

        await delegator.update_checker()

        delegator.data_collector.update_checker.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_software_inventory_update(self, delegator):
        """Test _send_software_inventory_update delegation."""
        delegator.data_collector._send_software_inventory_update = AsyncMock()

        await delegator._send_software_inventory_update()

        delegator.data_collector._send_software_inventory_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_user_access_update(self, delegator):
        """Test _send_user_access_update delegation."""
        delegator.data_collector._send_user_access_update = AsyncMock()

        await delegator._send_user_access_update()

        delegator.data_collector._send_user_access_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_hardware_update(self, delegator):
        """Test _send_hardware_update delegation."""
        delegator.data_collector._send_hardware_update = AsyncMock()

        await delegator._send_hardware_update()

        delegator.data_collector._send_hardware_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_certificate_update(self, delegator):
        """Test _send_certificate_update delegation."""
        delegator.data_collector._send_certificate_update = AsyncMock()

        await delegator._send_certificate_update()

        delegator.data_collector._send_certificate_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_role_update(self, delegator):
        """Test _send_role_update delegation."""
        delegator.data_collector._send_role_update = AsyncMock()

        await delegator._send_role_update()

        delegator.data_collector._send_role_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_os_version_update(self, delegator):
        """Test _send_os_version_update delegation."""
        delegator.data_collector._send_os_version_update = AsyncMock()

        await delegator._send_os_version_update()

        delegator.data_collector._send_os_version_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_reboot_status_update(self, delegator):
        """Test _send_reboot_status_update delegation."""
        delegator.data_collector._send_reboot_status_update = AsyncMock()

        await delegator._send_reboot_status_update()

        delegator.data_collector._send_reboot_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_third_party_repository_update(self, delegator):
        """Test _send_third_party_repository_update delegation."""
        delegator.data_collector._send_third_party_repository_update = AsyncMock()

        await delegator._send_third_party_repository_update()

        delegator.data_collector._send_third_party_repository_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update(self, delegator):
        """Test _send_antivirus_status_update delegation."""
        delegator.data_collector._send_antivirus_status_update = AsyncMock()

        await delegator._send_antivirus_status_update()

        delegator.data_collector._send_antivirus_status_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_and_send_periodic_data(self, delegator):
        """Test _collect_and_send_periodic_data delegation."""
        delegator.data_collector._collect_and_send_periodic_data = AsyncMock()

        await delegator._collect_and_send_periodic_data()

        delegator.data_collector._collect_and_send_periodic_data.assert_called_once()

    @pytest.mark.asyncio
    async def test_package_collector(self, delegator):
        """Test package_collector delegation."""
        delegator.data_collector.package_collector = AsyncMock(return_value=None)

        result = await delegator.package_collector()

        assert result is None
        delegator.data_collector.package_collector.assert_called_once()

    @pytest.mark.asyncio
    async def test_child_host_heartbeat(self, delegator):
        """Test child_host_heartbeat delegation."""
        delegator.data_collector.child_host_heartbeat = AsyncMock(return_value=None)

        result = await delegator.child_host_heartbeat()

        assert result is None
        delegator.data_collector.child_host_heartbeat.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_available_packages(self, delegator):
        """Test collect_available_packages delegation."""
        delegator.data_collector.collect_available_packages = AsyncMock(
            return_value={"success": True, "total_packages": 100}
        )

        result = await delegator.collect_available_packages()

        assert result["success"] is True
        assert result["total_packages"] == 100
        delegator.data_collector.collect_available_packages.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_available_packages_paginated(self, delegator):
        """Test _send_available_packages_paginated delegation."""
        delegator.data_collector._send_available_packages_paginated = AsyncMock(
            return_value=True
        )
        package_managers = {"apt": [{"name": "pkg1", "version": "1.0"}]}

        result = await delegator._send_available_packages_paginated(
            package_managers, "Ubuntu", "22.04", 1
        )

        assert result is True
        delegator.data_collector._send_available_packages_paginated.assert_called_once_with(
            package_managers, "Ubuntu", "22.04", 1
        )

    @pytest.mark.asyncio
    async def test_collect_certificates(self, delegator):
        """Test collect_certificates delegation."""
        delegator.data_collector.collect_certificates = AsyncMock(
            return_value={"success": True, "certificate_count": 5}
        )

        result = await delegator.collect_certificates()

        assert result["success"] is True
        assert result["certificate_count"] == 5
        delegator.data_collector.collect_certificates.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_roles(self, delegator):
        """Test collect_roles delegation."""
        delegator.data_collector.collect_roles = AsyncMock(
            return_value={"success": True, "role_count": 3}
        )

        result = await delegator.collect_roles()

        assert result["success"] is True
        assert result["role_count"] == 3
        delegator.data_collector.collect_roles.assert_called_once()


class TestRegistrationDelegator:
    """Test RegistrationDelegator mixin class."""

    @pytest.fixture
    def delegator(self):
        """Create a mock delegator instance."""
        return MockDelegatorClass()

    @pytest.mark.asyncio
    async def test_get_auth_token(self, delegator):
        """Test get_auth_token delegation."""
        delegator.registration_manager.get_auth_token = AsyncMock(
            return_value="test-token-123"
        )

        result = await delegator.get_auth_token()

        assert result == "test-token-123"
        delegator.registration_manager.get_auth_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_fetch_certificates(self, delegator):
        """Test fetch_certificates delegation."""
        delegator.registration_manager.fetch_certificates = AsyncMock(return_value=True)
        host_id = "test-host-id"

        result = await delegator.fetch_certificates(host_id)

        assert result is True
        delegator.registration_manager.fetch_certificates.assert_called_once_with(
            host_id
        )

    @pytest.mark.asyncio
    async def test_ensure_certificates(self, delegator):
        """Test ensure_certificates delegation."""
        delegator.registration_manager.ensure_certificates = AsyncMock(
            return_value=True
        )

        result = await delegator.ensure_certificates()

        assert result is True
        delegator.registration_manager.ensure_certificates.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_host_approval(self, delegator):
        """Test handle_host_approval delegation."""
        delegator.registration_manager.handle_host_approval = AsyncMock()
        message = {"data": {"host_id": "test-id", "approval_status": "approved"}}

        await delegator.handle_host_approval(message)

        delegator.registration_manager.handle_host_approval.assert_called_once_with(
            message
        )

    @pytest.mark.asyncio
    async def test_clear_host_approval(self, delegator):
        """Test clear_host_approval delegation."""
        delegator.registration_manager.clear_host_approval = AsyncMock()

        await delegator.clear_host_approval()

        delegator.registration_manager.clear_host_approval.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_host_approval_without_optional_params(self, delegator):
        """Test store_host_approval delegation without optional parameters."""
        delegator.registration_manager.store_host_approval = AsyncMock()

        await delegator.store_host_approval("host-123", "approved")

        delegator.registration_manager.store_host_approval.assert_called_once_with(
            "host-123", "approved", None, None
        )

    @pytest.mark.asyncio
    async def test_store_host_approval_with_certificate(self, delegator):
        """Test store_host_approval delegation with certificate."""
        delegator.registration_manager.store_host_approval = AsyncMock()

        await delegator.store_host_approval(
            "host-123", "approved", certificate="cert-data"
        )

        delegator.registration_manager.store_host_approval.assert_called_once_with(
            "host-123", "approved", "cert-data", None
        )

    @pytest.mark.asyncio
    async def test_store_host_approval_with_all_params(self, delegator):
        """Test store_host_approval delegation with all parameters."""
        delegator.registration_manager.store_host_approval = AsyncMock()

        await delegator.store_host_approval(
            "host-123", "approved", certificate="cert-data", host_token="token-456"
        )

        delegator.registration_manager.store_host_approval.assert_called_once_with(
            "host-123", "approved", "cert-data", "token-456"
        )

    @pytest.mark.asyncio
    async def test_handle_registration_success(self, delegator):
        """Test handle_registration_success delegation."""
        delegator.registration_manager.handle_registration_success = AsyncMock()
        message = {"host_id": "test-id", "approved": True}

        await delegator.handle_registration_success(message)

        delegator.registration_manager.handle_registration_success.assert_called_once_with(
            message
        )

    @pytest.mark.asyncio
    async def test_get_stored_host_id(self, delegator):
        """Test get_stored_host_id delegation."""
        delegator.registration_manager.get_stored_host_id = AsyncMock(
            return_value="stored-host-id"
        )

        result = await delegator.get_stored_host_id()

        assert result == "stored-host-id"
        delegator.registration_manager.get_stored_host_id.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_stored_host_token(self, delegator):
        """Test get_stored_host_token delegation."""
        delegator.registration_manager.get_stored_host_token = AsyncMock(
            return_value="stored-token"
        )

        result = await delegator.get_stored_host_token()

        assert result == "stored-token"
        delegator.registration_manager.get_stored_host_token.assert_called_once()

    def test_get_stored_host_token_sync(self, delegator):
        """Test get_stored_host_token_sync delegation."""
        delegator.registration_manager.get_stored_host_token_sync = Mock(
            return_value="sync-token"
        )

        result = delegator.get_stored_host_token_sync()

        assert result == "sync-token"
        delegator.registration_manager.get_stored_host_token_sync.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_server_api_post(self, delegator):
        """Test call_server_api delegation with POST method."""
        delegator.registration_manager.call_server_api = AsyncMock(
            return_value={"status": "ok"}
        )

        result = await delegator.call_server_api(
            "test/endpoint", method="POST", data={"key": "value"}
        )

        assert result == {"status": "ok"}
        delegator.registration_manager.call_server_api.assert_called_once_with(
            "test/endpoint", "POST", {"key": "value"}
        )

    @pytest.mark.asyncio
    async def test_call_server_api_get(self, delegator):
        """Test call_server_api delegation with GET method."""
        delegator.registration_manager.call_server_api = AsyncMock(
            return_value={"data": "result"}
        )

        result = await delegator.call_server_api("test/endpoint", method="GET")

        assert result == {"data": "result"}
        delegator.registration_manager.call_server_api.assert_called_once_with(
            "test/endpoint", "GET", None
        )

    @pytest.mark.asyncio
    async def test_call_server_api_default_method(self, delegator):
        """Test call_server_api delegation with default method."""
        delegator.registration_manager.call_server_api = AsyncMock(
            return_value={"success": True}
        )

        result = await delegator.call_server_api("test/endpoint")

        assert result == {"success": True}
        delegator.registration_manager.call_server_api.assert_called_once_with(
            "test/endpoint", "POST", None
        )

    def test_get_host_approval_from_db(self, delegator):
        """Test get_host_approval_from_db delegation."""
        mock_approval = Mock()
        mock_approval.host_id = "test-host-id"
        mock_approval.approval_status = "approved"
        delegator.registration_manager.get_host_approval_from_db = Mock(
            return_value=mock_approval
        )

        result = delegator.get_host_approval_from_db()

        assert result.host_id == "test-host-id"
        assert result.approval_status == "approved"
        delegator.registration_manager.get_host_approval_from_db.assert_called_once()

    def test_get_stored_host_id_sync(self, delegator):
        """Test get_stored_host_id_sync delegation."""
        delegator.registration_manager.get_stored_host_id_sync = Mock(
            return_value="sync-host-id"
        )

        result = delegator.get_stored_host_id_sync()

        assert result == "sync-host-id"
        delegator.registration_manager.get_stored_host_id_sync.assert_called_once()

    def test_cleanup_corrupt_database_entries(self, delegator):
        """Test cleanup_corrupt_database_entries delegation."""
        delegator.registration_manager.cleanup_corrupt_database_entries = Mock()

        delegator.cleanup_corrupt_database_entries()

        delegator.registration_manager.cleanup_corrupt_database_entries.assert_called_once()

    @pytest.mark.asyncio
    async def test_clear_stored_host_id(self, delegator):
        """Test clear_stored_host_id delegation."""
        delegator.registration_manager.clear_stored_host_id = AsyncMock()

        await delegator.clear_stored_host_id()

        delegator.registration_manager.clear_stored_host_id.assert_called_once()


class TestUpdateManagerDelegator:
    """Test UpdateManagerDelegator mixin class."""

    @pytest.fixture
    def delegator(self):
        """Create a mock delegator instance."""
        return MockDelegatorClass()

    @pytest.mark.asyncio
    async def test_check_updates(self, delegator):
        """Test check_updates delegation."""
        delegator.update_manager.check_updates = AsyncMock(
            return_value={"success": True, "total_updates": 10}
        )

        result = await delegator.check_updates()

        assert result["success"] is True
        assert result["total_updates"] == 10
        delegator.update_manager.check_updates.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_updates(self, delegator):
        """Test apply_updates delegation."""
        delegator.update_manager.apply_updates = AsyncMock(
            return_value={"success": True, "updated_packages": 5}
        )
        parameters = {"packages": ["pkg1", "pkg2"]}

        result = await delegator.apply_updates(parameters)

        assert result["success"] is True
        assert result["updated_packages"] == 5
        delegator.update_manager.apply_updates.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_check_reboot_status(self, delegator):
        """Test check_reboot_status delegation."""
        delegator.update_manager.check_reboot_status = AsyncMock(
            return_value={"success": True, "reboot_required": True}
        )

        result = await delegator.check_reboot_status()

        assert result["success"] is True
        assert result["reboot_required"] is True
        delegator.update_manager.check_reboot_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_reboot_status_update(self, delegator):
        """Test send_reboot_status_update delegation."""
        delegator.update_manager.send_reboot_status_update = AsyncMock()

        await delegator.send_reboot_status_update(True)

        delegator.update_manager.send_reboot_status_update.assert_called_once_with(True)

    @pytest.mark.asyncio
    async def test_send_reboot_status_update_false(self, delegator):
        """Test send_reboot_status_update delegation with False."""
        delegator.update_manager.send_reboot_status_update = AsyncMock()

        await delegator.send_reboot_status_update(False)

        delegator.update_manager.send_reboot_status_update.assert_called_once_with(
            False
        )


class TestFirewallDelegator:
    """Test FirewallDelegator mixin class."""

    @pytest.fixture
    def delegator(self):
        """Create a mock delegator instance."""
        return MockDelegatorClass()

    @pytest.mark.asyncio
    async def test_deploy_firewall(self, delegator):
        """Test deploy_firewall delegation."""
        delegator.firewall_ops.deploy_firewall = AsyncMock(
            return_value={"success": True, "result": "Firewall deployed"}
        )
        parameters = {"firewall_type": "ufw"}

        result = await delegator.deploy_firewall(parameters)

        assert result["success"] is True
        delegator.firewall_ops.deploy_firewall.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_enable_firewall(self, delegator):
        """Test enable_firewall delegation."""
        delegator.firewall_ops.enable_firewall = AsyncMock(
            return_value={"success": True, "result": "Firewall enabled"}
        )
        parameters = {}

        result = await delegator.enable_firewall(parameters)

        assert result["success"] is True
        delegator.firewall_ops.enable_firewall.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_disable_firewall(self, delegator):
        """Test disable_firewall delegation."""
        delegator.firewall_ops.disable_firewall = AsyncMock(
            return_value={"success": True, "result": "Firewall disabled"}
        )
        parameters = {}

        result = await delegator.disable_firewall(parameters)

        assert result["success"] is True
        delegator.firewall_ops.disable_firewall.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_restart_firewall(self, delegator):
        """Test restart_firewall delegation."""
        delegator.firewall_ops.restart_firewall = AsyncMock(
            return_value={"success": True, "result": "Firewall restarted"}
        )
        parameters = {}

        result = await delegator.restart_firewall(parameters)

        assert result["success"] is True
        delegator.firewall_ops.restart_firewall.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_apply_firewall_roles(self, delegator):
        """Test apply_firewall_roles delegation."""
        delegator.firewall_ops.apply_firewall_roles = AsyncMock(
            return_value={"success": True, "result": "Roles applied"}
        )
        parameters = {"roles": ["web_server", "ssh"]}

        result = await delegator.apply_firewall_roles(parameters)

        assert result["success"] is True
        delegator.firewall_ops.apply_firewall_roles.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_remove_firewall_ports(self, delegator):
        """Test remove_firewall_ports delegation."""
        delegator.firewall_ops.remove_firewall_ports = AsyncMock(
            return_value={"success": True, "result": "Ports removed"}
        )
        parameters = {"ports": [80, 443]}

        result = await delegator.remove_firewall_ports(parameters)

        assert result["success"] is True
        delegator.firewall_ops.remove_firewall_ports.assert_called_once_with(parameters)


class TestMiscDelegator:
    """Test MiscDelegator mixin class."""

    @pytest.fixture
    def delegator(self):
        """Create a mock delegator instance."""
        return MockDelegatorClass()

    @pytest.mark.asyncio
    async def test_handle_command(self, delegator):
        """Test handle_command delegation."""
        delegator.message_processor.handle_command = AsyncMock()
        message = {"command": "test", "parameters": {}}

        await delegator.handle_command(message)

        delegator.message_processor.handle_command.assert_called_once_with(message)

    @pytest.mark.asyncio
    async def test_execute_script(self, delegator):
        """Test execute_script delegation."""
        delegator.script_ops.execute_script = AsyncMock(
            return_value={"success": True, "result": "Script executed"}
        )
        parameters = {"script": "echo hello", "interpreter": "bash"}

        result = await delegator.execute_script(parameters)

        assert result["success"] is True
        delegator.script_ops.execute_script.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_collect_diagnostics(self, delegator):
        """Test collect_diagnostics delegation."""
        delegator.diagnostic_collector.collect_diagnostics = AsyncMock(
            return_value={"success": True, "diagnostics": {"cpu": "info"}}
        )
        parameters = {"include": ["cpu", "memory"]}

        result = await delegator.collect_diagnostics(parameters)

        assert result["success"] is True
        delegator.diagnostic_collector.collect_diagnostics.assert_called_once_with(
            parameters
        )

    @pytest.mark.asyncio
    async def test_attach_to_graylog(self, delegator):
        """Test attach_to_graylog with dynamic import."""
        mock_graylog_ops = Mock()
        mock_graylog_ops.attach_to_graylog = AsyncMock(
            return_value={"success": True, "result": "Attached to Graylog"}
        )

        with patch(
            "src.sysmanage_agent.operations.graylog_attachment.GraylogAttachmentOperations",
            return_value=mock_graylog_ops,
        ):
            parameters = {"server": "graylog.example.com", "port": 12201}

            result = await delegator.attach_to_graylog(parameters)

            assert result["success"] is True
            mock_graylog_ops.attach_to_graylog.assert_called_once_with(parameters)

    @pytest.mark.asyncio
    async def test_enable_package_manager(self, delegator):
        """Test enable_package_manager with dynamic import."""
        mock_pm_ops = Mock()
        mock_pm_ops.enable_package_manager = AsyncMock(
            return_value={"success": True, "result": "Package manager enabled"}
        )

        with patch(
            "src.sysmanage_agent.operations.package_manager_operations.PackageManagerOperations",
            return_value=mock_pm_ops,
        ):
            parameters = {"package_manager": "flatpak"}

            result = await delegator.enable_package_manager(parameters)

            assert result["success"] is True
            mock_pm_ops.enable_package_manager.assert_called_once_with(parameters)


class TestAgentDelegatorMixin:
    """Test AgentDelegatorMixin combined class."""

    def test_mixin_inheritance(self):
        """Test that AgentDelegatorMixin inherits from all delegator classes."""
        assert issubclass(AgentDelegatorMixin, SystemOperationsDelegator)
        assert issubclass(AgentDelegatorMixin, DataCollectorDelegator)
        assert issubclass(AgentDelegatorMixin, RegistrationDelegator)
        assert issubclass(AgentDelegatorMixin, UpdateManagerDelegator)
        assert issubclass(AgentDelegatorMixin, FirewallDelegator)
        assert issubclass(AgentDelegatorMixin, MiscDelegator)

    def test_mock_delegator_has_all_methods(self):
        """Test that MockDelegatorClass has all expected methods."""
        delegator = MockDelegatorClass()

        # SystemOperationsDelegator methods
        assert hasattr(delegator, "execute_shell_command")
        assert hasattr(delegator, "get_detailed_system_info")
        assert hasattr(delegator, "install_package")
        assert hasattr(delegator, "install_packages")
        assert hasattr(delegator, "uninstall_packages")
        assert hasattr(delegator, "update_system")
        assert hasattr(delegator, "restart_service")
        assert hasattr(delegator, "reboot_system")
        assert hasattr(delegator, "shutdown_system")
        assert hasattr(delegator, "ubuntu_pro_attach")
        assert hasattr(delegator, "ubuntu_pro_detach")
        assert hasattr(delegator, "ubuntu_pro_enable_service")
        assert hasattr(delegator, "ubuntu_pro_disable_service")
        assert hasattr(delegator, "deploy_opentelemetry")
        assert hasattr(delegator, "remove_opentelemetry")
        assert hasattr(delegator, "list_third_party_repositories")
        assert hasattr(delegator, "add_third_party_repository")
        assert hasattr(delegator, "delete_third_party_repositories")
        assert hasattr(delegator, "enable_third_party_repositories")
        assert hasattr(delegator, "disable_third_party_repositories")
        assert hasattr(delegator, "deploy_antivirus")
        assert hasattr(delegator, "enable_antivirus")
        assert hasattr(delegator, "disable_antivirus")
        assert hasattr(delegator, "remove_antivirus")
        assert hasattr(delegator, "create_host_user")
        assert hasattr(delegator, "create_host_group")
        assert hasattr(delegator, "delete_host_user")
        assert hasattr(delegator, "delete_host_group")
        assert hasattr(delegator, "change_hostname")

        # DataCollectorDelegator methods
        assert hasattr(delegator, "send_initial_data_updates")
        assert hasattr(delegator, "update_os_version")
        assert hasattr(delegator, "update_hardware")
        assert hasattr(delegator, "update_user_access")
        assert hasattr(delegator, "update_checker")
        assert hasattr(delegator, "_send_software_inventory_update")
        assert hasattr(delegator, "_send_user_access_update")
        assert hasattr(delegator, "_send_hardware_update")
        assert hasattr(delegator, "_send_certificate_update")
        assert hasattr(delegator, "_send_role_update")
        assert hasattr(delegator, "_send_os_version_update")
        assert hasattr(delegator, "_send_reboot_status_update")
        assert hasattr(delegator, "_send_third_party_repository_update")
        assert hasattr(delegator, "_send_antivirus_status_update")
        assert hasattr(delegator, "_collect_and_send_periodic_data")
        assert hasattr(delegator, "package_collector")
        assert hasattr(delegator, "child_host_heartbeat")
        assert hasattr(delegator, "collect_available_packages")
        assert hasattr(delegator, "_send_available_packages_paginated")
        assert hasattr(delegator, "collect_certificates")
        assert hasattr(delegator, "collect_roles")

        # RegistrationDelegator methods
        assert hasattr(delegator, "get_auth_token")
        assert hasattr(delegator, "fetch_certificates")
        assert hasattr(delegator, "ensure_certificates")
        assert hasattr(delegator, "handle_host_approval")
        assert hasattr(delegator, "clear_host_approval")
        assert hasattr(delegator, "store_host_approval")
        assert hasattr(delegator, "handle_registration_success")
        assert hasattr(delegator, "get_stored_host_id")
        assert hasattr(delegator, "get_stored_host_token")
        assert hasattr(delegator, "get_stored_host_token_sync")
        assert hasattr(delegator, "call_server_api")
        assert hasattr(delegator, "get_host_approval_from_db")
        assert hasattr(delegator, "get_stored_host_id_sync")
        assert hasattr(delegator, "cleanup_corrupt_database_entries")
        assert hasattr(delegator, "clear_stored_host_id")

        # UpdateManagerDelegator methods
        assert hasattr(delegator, "check_updates")
        assert hasattr(delegator, "apply_updates")
        assert hasattr(delegator, "check_reboot_status")
        assert hasattr(delegator, "send_reboot_status_update")

        # FirewallDelegator methods
        assert hasattr(delegator, "deploy_firewall")
        assert hasattr(delegator, "enable_firewall")
        assert hasattr(delegator, "disable_firewall")
        assert hasattr(delegator, "restart_firewall")
        assert hasattr(delegator, "apply_firewall_roles")
        assert hasattr(delegator, "remove_firewall_ports")

        # MiscDelegator methods
        assert hasattr(delegator, "handle_command")
        assert hasattr(delegator, "execute_script")
        assert hasattr(delegator, "collect_diagnostics")
        assert hasattr(delegator, "attach_to_graylog")
        assert hasattr(delegator, "enable_package_manager")


class TestDelegatorErrorHandling:
    """Test error handling in delegator methods."""

    @pytest.fixture
    def delegator(self):
        """Create a mock delegator instance."""
        return MockDelegatorClass()

    @pytest.mark.asyncio
    async def test_system_ops_exception_propagation(self, delegator):
        """Test that exceptions from system_ops propagate correctly."""
        delegator.system_ops.execute_shell_command = AsyncMock(
            side_effect=Exception("Command failed")
        )

        with pytest.raises(Exception, match="Command failed"):
            await delegator.execute_shell_command({"command": "test"})

    @pytest.mark.asyncio
    async def test_data_collector_exception_propagation(self, delegator):
        """Test that exceptions from data_collector propagate correctly."""
        delegator.data_collector.update_os_version = AsyncMock(
            side_effect=Exception("Collection failed")
        )

        with pytest.raises(Exception, match="Collection failed"):
            await delegator.update_os_version()

    @pytest.mark.asyncio
    async def test_registration_manager_exception_propagation(self, delegator):
        """Test that exceptions from registration_manager propagate correctly."""
        delegator.registration_manager.get_auth_token = AsyncMock(
            side_effect=Exception("Auth failed")
        )

        with pytest.raises(Exception, match="Auth failed"):
            await delegator.get_auth_token()

    @pytest.mark.asyncio
    async def test_update_manager_exception_propagation(self, delegator):
        """Test that exceptions from update_manager propagate correctly."""
        delegator.update_manager.check_updates = AsyncMock(
            side_effect=Exception("Update check failed")
        )

        with pytest.raises(Exception, match="Update check failed"):
            await delegator.check_updates()

    @pytest.mark.asyncio
    async def test_firewall_ops_exception_propagation(self, delegator):
        """Test that exceptions from firewall_ops propagate correctly."""
        delegator.firewall_ops.deploy_firewall = AsyncMock(
            side_effect=Exception("Firewall deployment failed")
        )

        with pytest.raises(Exception, match="Firewall deployment failed"):
            await delegator.deploy_firewall({})

    @pytest.mark.asyncio
    async def test_script_ops_exception_propagation(self, delegator):
        """Test that exceptions from script_ops propagate correctly."""
        delegator.script_ops.execute_script = AsyncMock(
            side_effect=Exception("Script execution failed")
        )

        with pytest.raises(Exception, match="Script execution failed"):
            await delegator.execute_script({})

    @pytest.mark.asyncio
    async def test_diagnostic_collector_exception_propagation(self, delegator):
        """Test that exceptions from diagnostic_collector propagate correctly."""
        delegator.diagnostic_collector.collect_diagnostics = AsyncMock(
            side_effect=Exception("Diagnostics collection failed")
        )

        with pytest.raises(Exception, match="Diagnostics collection failed"):
            await delegator.collect_diagnostics({})


class TestDelegatorReturnValues:
    """Test various return value scenarios for delegator methods."""

    @pytest.fixture
    def delegator(self):
        """Create a mock delegator instance."""
        return MockDelegatorClass()

    @pytest.mark.asyncio
    async def test_none_return_value(self, delegator):
        """Test handling of None return values."""
        delegator.registration_manager.call_server_api = AsyncMock(return_value=None)

        result = await delegator.call_server_api("endpoint")

        assert result is None

    @pytest.mark.asyncio
    async def test_empty_dict_return_value(self, delegator):
        """Test handling of empty dict return values."""
        delegator.system_ops.execute_shell_command = AsyncMock(return_value={})

        result = await delegator.execute_shell_command({})

        assert result == {}

    @pytest.mark.asyncio
    async def test_complex_return_value(self, delegator):
        """Test handling of complex return values."""
        complex_result = {
            "success": True,
            "data": {
                "nested": {"value": 123},
                "list": [1, 2, 3],
            },
            "metadata": {
                "timestamp": "2024-01-01T00:00:00Z",
                "version": "1.0.0",
            },
        }
        delegator.data_collector.collect_certificates = AsyncMock(
            return_value=complex_result
        )

        result = await delegator.collect_certificates()

        assert result == complex_result
        assert result["data"]["nested"]["value"] == 123
        assert len(result["data"]["list"]) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
