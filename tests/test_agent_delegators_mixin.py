# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive unit tests for agent_delegators.py module (part 2).

Tests the delegator mixin classes that forward calls to appropriate handlers:
- MiscDelegator
- AgentDelegatorMixin

Split from test_agent_delegators.py to keep each file under the 1000-line limit.
"""

# pylint: disable=protected-access,too-many-public-methods

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.core.agent_delegators import (
    AgentDelegatorMixin,
    DataCollectorDelegator,
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


# NOTE: TestFirewallDelegator was removed in Phase 3. The agent no longer
# has a FirewallDelegator mixin — the open-source server now sends
# apply_deployment_plan messages and the agent runs them via the existing
# generic deployment handler (see test_generic_deployment.TestApplyDeploymentPlan).


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

    # ``test_attach_to_graylog`` removed in Phase 10.2 step 7
    # close-out (see comment above the deploy/remove OTEL block).

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
        # ``deploy_opentelemetry`` and ``remove_opentelemetry``
        # delegators removed in the Phase 10.2 step 7 close-out;
        # those operations route server-side through the Pro+
        # observability_engine + apply_deployment_plan now.
        assert hasattr(delegator, "list_third_party_repositories")
        assert hasattr(delegator, "add_third_party_repository")
        assert hasattr(delegator, "delete_third_party_repositories")
        assert hasattr(delegator, "enable_third_party_repositories")
        assert hasattr(delegator, "disable_third_party_repositories")
        # NOTE: deploy/enable/disable/remove_antivirus delegators removed
        # in Phase 3.
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
        assert hasattr(delegator, "get_host_approval_from_db")
        assert hasattr(delegator, "get_stored_host_id_sync")
        assert hasattr(delegator, "cleanup_corrupt_database_entries")
        assert hasattr(delegator, "clear_stored_host_id")

        # UpdateManagerDelegator methods
        assert hasattr(delegator, "check_updates")
        assert hasattr(delegator, "apply_updates")
        assert hasattr(delegator, "check_reboot_status")
        assert hasattr(delegator, "send_reboot_status_update")

        # NOTE: FirewallDelegator removed in Phase 3.

        # MiscDelegator methods
        assert hasattr(delegator, "handle_command")
        assert hasattr(delegator, "execute_script")
        assert hasattr(delegator, "collect_diagnostics")
        # ``attach_to_graylog`` delegator removed in Phase 10.2 step 7
        # close-out (engine path now handles Graylog attaches).
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

    # NOTE: test_firewall_ops_exception_propagation removed in Phase 3 —
    # firewall ops are no longer dispatched through the agent delegator.

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
        """A delegator surface that returns None propagates that None
        through unchanged."""
        delegator.registration_manager.get_stored_host_id = AsyncMock(return_value=None)

        result = await delegator.get_stored_host_id()

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
