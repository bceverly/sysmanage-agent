# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive unit tests for agent_delegators.py module.

Tests the delegator mixin classes that forward calls to appropriate handlers:
- SystemOperationsDelegator
- DataCollectorDelegator
- RegistrationDelegator
- UpdateManagerDelegator
- MiscDelegator
- AgentDelegatorMixin

(FirewallDelegator was removed in Phase 3 — see comment in agent_delegators.py.)
"""

# pylint: disable=protected-access,too-many-public-methods

from unittest.mock import AsyncMock, Mock

import pytest

from src.sysmanage_agent.core.agent_delegators import (
    AgentDelegatorMixin,
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

    # Phase 10.2 step 7 close-out (2026-05-14): tests for
    # ``test_deploy_opentelemetry``, ``test_remove_opentelemetry``,
    # and ``test_attach_to_graylog`` are removed.  The delegators
    # they exercised are gone — every observability operation now
    # flows through the Pro+ engine's plan-builders +
    # apply_deployment_plan path.  Engine-path coverage lives in
    # the sysmanage repo at ``tests/services/test_observability_shim.py``
    # and the Pro+ repo's ``module-source/observability_engine/``.

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

    # NOTE: deploy/enable/disable/remove_antivirus delegators were removed
    # in Phase 3; the open-source server now sends apply_deployment_plan
    # messages instead, which are dispatched via the existing generic
    # deployment handler.

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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
