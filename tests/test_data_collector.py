"""
Comprehensive test suite for DataCollector class.
Tests data collection, periodic updates, and error handling.
"""

# pylint: disable=protected-access,too-many-lines

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.communication.data_collector import DataCollector


class TestDataCollectorInitialization:
    """Test DataCollector initialization."""

    @pytest.fixture
    def mock_agent(self):
        """Create a mock agent instance."""
        agent = Mock()
        agent.running = True
        agent.connected = True
        agent.registration = Mock()
        agent.registration_manager = Mock()
        agent.create_message = Mock(
            side_effect=lambda msg_type, data: {
                "message_type": msg_type,
                "message_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": data,
            }
        )
        agent.send_message = AsyncMock(return_value=True)
        agent.check_updates = AsyncMock(return_value={"total_updates": 0})
        agent.certificate_collector = Mock()
        agent.role_detector = Mock()
        agent.system_ops = Mock()
        agent.antivirus_collector = Mock()
        agent.update_manager = Mock()
        agent.package_collection_scheduler = Mock()
        agent.update_checker_util = Mock()
        return agent

    def test_data_collector_initialization(self, mock_agent):
        """Test DataCollector initialization with agent instance."""
        collector = DataCollector(mock_agent)

        assert collector.agent == mock_agent
        assert collector.logger is not None


class TestSendInitialDataUpdates:
    """Test send_initial_data_updates method."""

    @pytest.fixture
    def mock_agent(self):
        """Create a comprehensive mock agent for initial data tests."""
        agent = Mock()
        agent.running = True
        agent.connected = True

        # Mock registration methods
        agent.registration = Mock()
        agent.registration.get_os_version_info = Mock(
            return_value={
                "os_type": "Linux",
                "os_version": "5.15.0",
                "distribution": "Ubuntu",
                "distribution_version": "22.04",
            }
        )
        agent.registration.get_system_info = Mock(
            return_value={
                "hostname": "test-host",
                "platform": "Linux",
                "ipv4": "192.168.1.100",
                "ipv6": "2001:db8::1",
            }
        )
        agent.registration.get_hardware_info = Mock(
            return_value={
                "cpu_vendor": "Intel",
                "cpu_model": "Core i7",
                "cpu_cores": 8,
                "memory_total_mb": 16384,
                "storage_devices": [{"name": "sda", "size_gb": 512}],
                "network_interfaces": [{"name": "eth0", "mac": "00:11:22:33:44:55"}],
            }
        )
        agent.registration.get_user_access_info = Mock(
            return_value={
                "total_users": 10,
                "total_groups": 15,
                "regular_users": 5,
                "system_users": 5,
                "regular_groups": 10,
                "system_groups": 5,
            }
        )
        agent.registration.get_software_inventory_info = Mock(
            return_value={
                "total_packages": 100,
                "software_packages": [
                    {"name": "pkg1", "version": "1.0"},
                    {"name": "pkg2", "version": "2.0"},
                    {"name": "pkg3", "version": "3.0"},
                ],
            }
        )

        # Mock other components
        agent.registration_manager = Mock()
        agent.create_message = Mock(
            side_effect=lambda msg_type, data: {
                "message_type": msg_type,
                "message_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": data,
            }
        )
        agent.send_message = AsyncMock(return_value=True)
        agent.check_updates = AsyncMock(return_value={"total_updates": 5})
        agent.certificate_collector = Mock()
        agent.role_detector = Mock()
        agent.system_ops = Mock()

        return agent

    @pytest.mark.asyncio
    async def test_send_initial_data_updates_success(self, mock_agent):
        """Test successful sending of initial data updates."""
        # Mock collect_certificates and collect_roles
        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            return_value={"success": True, "certificate_count": 3}
        )
        collector.collect_roles = AsyncMock(
            return_value={"success": True, "role_count": 2}
        )

        # Mock _send_third_party_repository_update
        collector._send_third_party_repository_update = AsyncMock()

        await collector.send_initial_data_updates()

        # Verify all collection methods were called
        assert mock_agent.registration.get_os_version_info.called
        assert mock_agent.registration.get_hardware_info.called
        assert mock_agent.registration.get_user_access_info.called
        assert mock_agent.registration.get_software_inventory_info.called

        # Verify messages were created and sent
        assert mock_agent.create_message.call_count >= 4
        assert mock_agent.send_message.call_count >= 4

        # Verify update check was performed
        assert mock_agent.check_updates.called

        # Verify certificate and role collection
        assert collector.collect_certificates.called
        assert collector.collect_roles.called
        assert collector._send_third_party_repository_update.called

    @pytest.mark.asyncio
    async def test_send_initial_data_updates_no_updates(self, mock_agent):
        """Test initial data updates when no system updates available."""
        mock_agent.check_updates = AsyncMock(return_value={"total_updates": 0})

        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            return_value={"success": True, "certificate_count": 0}
        )
        collector.collect_roles = AsyncMock(
            return_value={"success": True, "role_count": 0}
        )
        collector._send_third_party_repository_update = AsyncMock()

        await collector.send_initial_data_updates()

        assert mock_agent.check_updates.called

    @pytest.mark.asyncio
    async def test_send_initial_data_updates_update_check_error(self, mock_agent):
        """Test initial data updates with update check error."""
        mock_agent.check_updates = AsyncMock(
            side_effect=Exception("Update check failed")
        )

        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            return_value={"success": True, "certificate_count": 0}
        )
        collector.collect_roles = AsyncMock(
            return_value={"success": True, "role_count": 0}
        )
        collector._send_third_party_repository_update = AsyncMock()

        # Should not raise exception
        await collector.send_initial_data_updates()

    @pytest.mark.asyncio
    async def test_send_initial_data_updates_certificate_error(self, mock_agent):
        """Test initial data updates with certificate collection error."""
        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            side_effect=Exception("Certificate collection failed")
        )
        collector.collect_roles = AsyncMock(
            return_value={"success": True, "role_count": 0}
        )
        collector._send_third_party_repository_update = AsyncMock()

        # Should not raise exception
        await collector.send_initial_data_updates()

    @pytest.mark.asyncio
    async def test_send_initial_data_updates_certificate_failure(self, mock_agent):
        """Test initial data updates with certificate collection returning failure."""
        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            return_value={"success": False, "error": "Permission denied"}
        )
        collector.collect_roles = AsyncMock(
            return_value={"success": True, "role_count": 0}
        )
        collector._send_third_party_repository_update = AsyncMock()

        await collector.send_initial_data_updates()

    @pytest.mark.asyncio
    async def test_send_initial_data_updates_role_error(self, mock_agent):
        """Test initial data updates with role collection error."""
        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            return_value={"success": True, "certificate_count": 0}
        )
        collector.collect_roles = AsyncMock(
            side_effect=Exception("Role detection failed")
        )
        collector._send_third_party_repository_update = AsyncMock()

        # Should not raise exception
        await collector.send_initial_data_updates()

    @pytest.mark.asyncio
    async def test_send_initial_data_updates_role_failure(self, mock_agent):
        """Test initial data updates with role collection returning failure."""
        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            return_value={"success": True, "certificate_count": 0}
        )
        collector.collect_roles = AsyncMock(
            return_value={"success": False, "error": "No roles found"}
        )
        collector._send_third_party_repository_update = AsyncMock()

        await collector.send_initial_data_updates()

    @pytest.mark.asyncio
    async def test_send_initial_data_updates_repo_error(self, mock_agent):
        """Test initial data updates with repository collection error."""
        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            return_value={"success": True, "certificate_count": 0}
        )
        collector.collect_roles = AsyncMock(
            return_value={"success": True, "role_count": 0}
        )
        collector._send_third_party_repository_update = AsyncMock(
            side_effect=Exception("Repository collection failed")
        )

        # Should not raise exception
        await collector.send_initial_data_updates()

    @pytest.mark.asyncio
    async def test_send_initial_data_updates_general_error(self, mock_agent):
        """Test initial data updates with general error."""
        mock_agent.registration.get_os_version_info.side_effect = Exception(
            "Collection failed"
        )

        collector = DataCollector(mock_agent)

        # Should not raise exception
        await collector.send_initial_data_updates()


class TestUpdateMethods:
    """Test individual update methods."""

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent for update tests."""
        agent = Mock()
        agent.registration = Mock()
        agent.registration.get_system_info = Mock(
            return_value={"hostname": "test-host"}
        )
        agent.create_message = Mock(
            side_effect=lambda msg_type, data: {
                "message_type": msg_type,
                "message_id": str(uuid.uuid4()),
                "data": data,
            }
        )
        agent.send_message = AsyncMock(return_value=True)
        return agent

    @pytest.mark.asyncio
    async def test_update_os_version_success(self, mock_agent):
        """Test successful OS version update."""
        mock_agent.registration.get_os_version_info = Mock(
            return_value={"os_type": "Linux", "os_version": "5.15.0"}
        )

        collector = DataCollector(mock_agent)
        result = await collector.update_os_version()

        assert result["success"] is True
        assert "result" in result
        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_os_version_error(self, mock_agent):
        """Test OS version update with error."""
        mock_agent.registration.get_os_version_info.side_effect = Exception(
            "Collection failed"
        )

        collector = DataCollector(mock_agent)
        result = await collector.update_os_version()

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_update_hardware_success(self, mock_agent):
        """Test successful hardware update."""
        mock_agent.registration.get_hardware_info = Mock(
            return_value={
                "cpu_vendor": "Intel",
                "cpu_cores": 8,
                "memory_total_mb": 16384,
            }
        )

        collector = DataCollector(mock_agent)
        result = await collector.update_hardware()

        assert result["success"] is True
        assert "result" in result
        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_hardware_error(self, mock_agent):
        """Test hardware update with error."""
        mock_agent.registration.get_hardware_info.side_effect = Exception(
            "Hardware collection failed"
        )

        collector = DataCollector(mock_agent)
        result = await collector.update_hardware()

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_update_user_access_success(self, mock_agent):
        """Test successful user access update."""
        mock_agent.registration.get_user_access_info = Mock(
            return_value={"total_users": 10, "total_groups": 15}
        )

        collector = DataCollector(mock_agent)
        result = await collector.update_user_access()

        assert result["success"] is True
        assert "result" in result
        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_user_access_error(self, mock_agent):
        """Test user access update with error."""
        mock_agent.registration.get_user_access_info.side_effect = Exception(
            "User collection failed"
        )

        collector = DataCollector(mock_agent)
        result = await collector.update_user_access()

        assert result["success"] is False
        assert "error" in result


class TestPeriodicUpdateMethods:
    """Test periodic update internal methods."""

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent for periodic update tests."""
        agent = Mock()
        agent.registration = Mock()
        agent.registration.get_system_info = Mock(
            return_value={"hostname": "test-host"}
        )
        agent.registration_manager = Mock()
        agent.registration_manager.get_host_approval_from_db = Mock(
            return_value=Mock(host_id="test-host-id")
        )
        agent.create_message = Mock(
            side_effect=lambda msg_type, data: {
                "message_type": msg_type,
                "message_id": str(uuid.uuid4()),
                "data": data,
            }
        )
        agent.send_message = AsyncMock(return_value=True)
        return agent

    @pytest.mark.asyncio
    async def test_send_software_inventory_update(self, mock_agent):
        """Test sending software inventory update."""
        mock_agent.registration.get_software_inventory_info = Mock(
            return_value={"total_packages": 100}
        )

        collector = DataCollector(mock_agent)
        await collector._send_software_inventory_update()

        assert mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_send_software_inventory_update_no_host_approval(self, mock_agent):
        """Test software inventory update without host approval."""
        mock_agent.registration.get_software_inventory_info = Mock(
            return_value={"total_packages": 100}
        )
        mock_agent.registration_manager.get_host_approval_from_db = Mock(
            return_value=None
        )

        collector = DataCollector(mock_agent)
        await collector._send_software_inventory_update()

        assert mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_send_user_access_update(self, mock_agent):
        """Test sending user access update."""
        mock_agent.registration.get_user_access_info = Mock(
            return_value={"total_users": 10}
        )

        collector = DataCollector(mock_agent)
        await collector._send_user_access_update()

        assert mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_send_hardware_update(self, mock_agent):
        """Test sending hardware update."""
        mock_agent.registration.get_hardware_info = Mock(return_value={"cpu_cores": 8})

        collector = DataCollector(mock_agent)
        await collector._send_hardware_update()

        assert mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_send_certificate_update_success(self, mock_agent):
        """Test sending certificate update successfully."""
        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            return_value={"success": True, "certificate_count": 5}
        )

        await collector._send_certificate_update()

        assert collector.collect_certificates.called

    @pytest.mark.asyncio
    async def test_send_certificate_update_no_certificates(self, mock_agent):
        """Test certificate update with no certificates."""
        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            return_value={"success": True, "certificate_count": 0}
        )

        await collector._send_certificate_update()

    @pytest.mark.asyncio
    async def test_send_certificate_update_failure(self, mock_agent):
        """Test certificate update with failure."""
        collector = DataCollector(mock_agent)
        collector.collect_certificates = AsyncMock(
            return_value={"success": False, "error": "Collection failed"}
        )

        await collector._send_certificate_update()

    @pytest.mark.asyncio
    async def test_send_role_update_success(self, mock_agent):
        """Test sending role update successfully."""
        collector = DataCollector(mock_agent)
        collector.collect_roles = AsyncMock(
            return_value={"success": True, "role_count": 3}
        )

        await collector._send_role_update()

        assert collector.collect_roles.called

    @pytest.mark.asyncio
    async def test_send_role_update_no_roles(self, mock_agent):
        """Test role update with no roles."""
        collector = DataCollector(mock_agent)
        collector.collect_roles = AsyncMock(
            return_value={"success": True, "role_count": 0}
        )

        await collector._send_role_update()

    @pytest.mark.asyncio
    async def test_send_role_update_failure(self, mock_agent):
        """Test role update with failure."""
        collector = DataCollector(mock_agent)
        collector.collect_roles = AsyncMock(
            return_value={"success": False, "error": "Detection failed"}
        )

        await collector._send_role_update()

    @pytest.mark.asyncio
    async def test_send_os_version_update(self, mock_agent):
        """Test sending OS version update."""
        mock_agent.registration.get_os_version_info = Mock(
            return_value={"os_type": "Linux"}
        )

        collector = DataCollector(mock_agent)
        await collector._send_os_version_update()

        assert mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_send_os_version_update_send_failure(self, mock_agent):
        """Test OS version update with send failure."""
        mock_agent.registration.get_os_version_info = Mock(
            return_value={"os_type": "Linux"}
        )
        mock_agent.send_message = AsyncMock(return_value=False)

        collector = DataCollector(mock_agent)
        await collector._send_os_version_update()

    @pytest.mark.asyncio
    async def test_send_reboot_status_update(self, mock_agent):
        """Test sending reboot status update."""
        mock_agent.update_manager = Mock()
        mock_agent.update_manager.check_reboot_status = AsyncMock(
            return_value={"reboot_required": True}
        )

        collector = DataCollector(mock_agent)
        await collector._send_reboot_status_update()

        assert mock_agent.update_manager.check_reboot_status.called

    @pytest.mark.asyncio
    async def test_send_third_party_repository_update_success(self, mock_agent):
        """Test sending third-party repository update successfully."""
        mock_agent.system_ops = Mock()
        mock_agent.system_ops.list_third_party_repositories = AsyncMock(
            return_value={
                "success": True,
                "repositories": [
                    {"name": "repo1", "url": "http://repo1.com"},
                    {"name": "repo2", "url": "http://repo2.com"},
                ],
            }
        )

        collector = DataCollector(mock_agent)
        await collector._send_third_party_repository_update()

        assert mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_send_third_party_repository_update_failure(self, mock_agent):
        """Test third-party repository update with failure."""
        mock_agent.system_ops = Mock()
        mock_agent.system_ops.list_third_party_repositories = AsyncMock(
            return_value={"success": False, "error": "Collection failed"}
        )

        collector = DataCollector(mock_agent)
        await collector._send_third_party_repository_update()

        assert not mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_send_third_party_repository_update_send_failure(self, mock_agent):
        """Test repository update with send failure."""
        mock_agent.system_ops = Mock()
        mock_agent.system_ops.list_third_party_repositories = AsyncMock(
            return_value={"success": True, "repositories": []}
        )
        mock_agent.send_message = AsyncMock(return_value=False)

        collector = DataCollector(mock_agent)
        await collector._send_third_party_repository_update()

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update_with_host_approval(self, mock_agent):
        """Test sending antivirus status update with host approval."""
        mock_agent.antivirus_collector = Mock()
        mock_agent.antivirus_collector.collect_antivirus_status = Mock(
            return_value={
                "software_name": "ClamAV",
                "install_path": "/usr/bin/clamav",
                "version": "1.0.0",
                "enabled": True,
            }
        )

        collector = DataCollector(mock_agent)
        await collector._send_antivirus_status_update()

        assert mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update_no_host_approval(self, mock_agent):
        """Test antivirus update without host approval."""
        mock_agent.registration_manager.get_host_approval_from_db = Mock(
            return_value=None
        )
        mock_agent.antivirus_collector = Mock()
        mock_agent.antivirus_collector.collect_antivirus_status = Mock(
            return_value={
                "software_name": "ClamAV",
                "install_path": "/usr/bin/clamav",
                "version": "1.0.0",
                "enabled": True,
            }
        )

        collector = DataCollector(mock_agent)
        await collector._send_antivirus_status_update()

        assert not mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update_send_failure(self, mock_agent):
        """Test antivirus update with send failure."""
        mock_agent.antivirus_collector = Mock()
        mock_agent.antivirus_collector.collect_antivirus_status = Mock(
            return_value={
                "software_name": "ClamAV",
                "install_path": "/usr/bin/clamav",
                "version": "1.0.0",
                "enabled": True,
            }
        )
        mock_agent.send_message = AsyncMock(return_value=False)

        collector = DataCollector(mock_agent)
        await collector._send_antivirus_status_update()


class TestCollectAndSendPeriodicData:
    """Test _collect_and_send_periodic_data method."""

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent for periodic data tests."""
        agent = Mock()
        agent.running = True
        agent.connected = True
        return agent

    @pytest.mark.asyncio
    async def test_collect_and_send_periodic_data_not_running(self, mock_agent):
        """Test periodic data collection when agent not running."""
        mock_agent.running = False

        collector = DataCollector(mock_agent)
        await collector._collect_and_send_periodic_data()

        # Should return early without collecting

    @pytest.mark.asyncio
    async def test_collect_and_send_periodic_data_not_connected(self, mock_agent):
        """Test periodic data collection when agent not connected."""
        mock_agent.connected = False

        collector = DataCollector(mock_agent)
        await collector._collect_and_send_periodic_data()

        # Should return early without collecting

    @pytest.mark.asyncio
    async def test_collect_and_send_periodic_data_success(self, mock_agent):
        """Test successful periodic data collection."""
        collector = DataCollector(mock_agent)

        # Mock all update methods
        collector._send_software_inventory_update = AsyncMock()
        collector._send_user_access_update = AsyncMock()
        collector._send_hardware_update = AsyncMock()
        collector._send_certificate_update = AsyncMock()
        collector._send_role_update = AsyncMock()
        collector._send_os_version_update = AsyncMock()
        collector._send_reboot_status_update = AsyncMock()
        collector._send_third_party_repository_update = AsyncMock()
        collector._send_antivirus_status_update = AsyncMock()

        await collector._collect_and_send_periodic_data()

        # Verify all methods were called
        assert collector._send_software_inventory_update.called
        assert collector._send_user_access_update.called
        assert collector._send_hardware_update.called
        assert collector._send_certificate_update.called
        assert collector._send_role_update.called
        assert collector._send_os_version_update.called
        assert collector._send_reboot_status_update.called
        assert collector._send_third_party_repository_update.called
        assert collector._send_antivirus_status_update.called

    @pytest.mark.asyncio
    async def test_collect_and_send_periodic_data_software_error(self, mock_agent):
        """Test periodic data collection with software inventory error."""
        collector = DataCollector(mock_agent)

        collector._send_software_inventory_update = AsyncMock(
            side_effect=Exception("Software collection failed")
        )
        collector._send_user_access_update = AsyncMock()
        collector._send_hardware_update = AsyncMock()
        collector._send_certificate_update = AsyncMock()
        collector._send_role_update = AsyncMock()
        collector._send_os_version_update = AsyncMock()
        collector._send_reboot_status_update = AsyncMock()
        collector._send_third_party_repository_update = AsyncMock()
        collector._send_antivirus_status_update = AsyncMock()

        await collector._collect_and_send_periodic_data()

        # Should continue with other collections
        assert collector._send_user_access_update.called

    @pytest.mark.asyncio
    async def test_collect_and_send_periodic_data_multiple_errors(self, mock_agent):
        """Test periodic data collection with multiple errors."""
        collector = DataCollector(mock_agent)

        collector._send_software_inventory_update = AsyncMock(
            side_effect=Exception("Error 1")
        )
        collector._send_user_access_update = AsyncMock(side_effect=Exception("Error 2"))
        collector._send_hardware_update = AsyncMock(side_effect=Exception("Error 3"))
        collector._send_certificate_update = AsyncMock()
        collector._send_role_update = AsyncMock()
        collector._send_os_version_update = AsyncMock()
        collector._send_reboot_status_update = AsyncMock()
        collector._send_third_party_repository_update = AsyncMock()
        collector._send_antivirus_status_update = AsyncMock()

        await collector._collect_and_send_periodic_data()

        # Should continue despite errors
        assert collector._send_certificate_update.called


class TestDataCollectorLoop:
    """Test data_collector loop method."""

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent for loop tests."""
        agent = Mock()
        agent.running = True
        agent.connected = True
        return agent

    @pytest.mark.asyncio
    async def test_data_collector_loop_cancelled(self, mock_agent):
        """Test data collector loop cancellation."""
        collector = DataCollector(mock_agent)
        collector._collect_and_send_periodic_data = AsyncMock()

        with patch("asyncio.sleep", side_effect=asyncio.CancelledError()):
            with pytest.raises(asyncio.CancelledError):
                await collector.data_collector()

    @pytest.mark.asyncio
    async def test_data_collector_loop_error(self, mock_agent):
        """Test data collector loop with error."""
        collector = DataCollector(mock_agent)
        collector._collect_and_send_periodic_data = AsyncMock(
            side_effect=Exception("Collection error")
        )

        with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError()]):
            # Should return on error, not raise
            await collector.data_collector()

    @pytest.mark.asyncio
    async def test_data_collector_loop_iteration(self, mock_agent):
        """Test data collector loop iteration."""
        collector = DataCollector(mock_agent)
        collector._collect_and_send_periodic_data = AsyncMock()

        # Mock sleep to run once then cancel
        with patch("asyncio.sleep", side_effect=[None, asyncio.CancelledError()]):
            with pytest.raises(asyncio.CancelledError):
                await collector.data_collector()

        assert collector._collect_and_send_periodic_data.called


class TestPackageAndUpdateCollectors:
    """Test package collector and update checker methods."""

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent with package collection scheduler."""
        agent = Mock()
        agent.package_collection_scheduler = Mock()
        agent.package_collection_scheduler.run_package_collection_loop = AsyncMock()
        agent.update_checker_util = Mock()
        agent.update_checker_util.run_update_checker_loop = AsyncMock()
        return agent

    @pytest.mark.asyncio
    async def test_package_collector(self, mock_agent):
        """Test package collector method."""
        collector = DataCollector(mock_agent)
        await collector.package_collector()

        assert (
            mock_agent.package_collection_scheduler.run_package_collection_loop.called
        )

    @pytest.mark.asyncio
    async def test_update_checker(self, mock_agent):
        """Test update checker method."""
        collector = DataCollector(mock_agent)
        await collector.update_checker()

        assert mock_agent.update_checker_util.run_update_checker_loop.called


class TestCollectAvailablePackages:
    """Test collect_available_packages method."""

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent for package collection tests."""
        agent = Mock()
        agent.package_collection_scheduler = Mock()
        agent.registration = Mock()
        agent.registration.get_system_info = Mock(
            return_value={
                "platform": "Linux",
                "platform_release": "5.15.0",
                "os_info": {
                    "distribution": "Ubuntu",
                    "distribution_version": "22.04",
                },
            }
        )
        return agent

    @pytest.mark.asyncio
    async def test_collect_available_packages_success(self, mock_agent):
        """Test successful package collection."""
        mock_agent.package_collection_scheduler.perform_package_collection = AsyncMock(
            return_value=True
        )
        mock_agent.package_collection_scheduler.package_collector = Mock()
        mock_agent.package_collection_scheduler.package_collector.get_packages_for_transmission = Mock(
            return_value={
                "package_managers": {
                    "apt": [
                        {"name": "pkg1", "version": "1.0"},
                        {"name": "pkg2", "version": "2.0"},
                    ],
                    "pip": [{"name": "pkg3", "version": "3.0"}],
                }
            }
        )

        collector = DataCollector(mock_agent)
        collector._send_available_packages_paginated = AsyncMock(return_value=True)

        result = await collector.collect_available_packages()

        assert result["success"] is True
        assert result["total_packages"] == 3
        assert collector._send_available_packages_paginated.called

    @pytest.mark.asyncio
    async def test_collect_available_packages_collection_failed(self, mock_agent):
        """Test package collection when collection fails."""
        mock_agent.package_collection_scheduler.perform_package_collection = AsyncMock(
            return_value=False
        )

        collector = DataCollector(mock_agent)
        result = await collector.collect_available_packages()

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_collect_available_packages_send_failed(self, mock_agent):
        """Test package collection when sending fails."""
        mock_agent.package_collection_scheduler.perform_package_collection = AsyncMock(
            return_value=True
        )
        mock_agent.package_collection_scheduler.package_collector = Mock()
        mock_agent.package_collection_scheduler.package_collector.get_packages_for_transmission = Mock(
            return_value={"package_managers": {"apt": []}}
        )

        collector = DataCollector(mock_agent)
        collector._send_available_packages_paginated = AsyncMock(return_value=False)

        result = await collector.collect_available_packages()

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_collect_available_packages_error(self, mock_agent):
        """Test package collection with error."""
        mock_agent.package_collection_scheduler.perform_package_collection = AsyncMock(
            side_effect=Exception("Collection error")
        )

        collector = DataCollector(mock_agent)
        result = await collector.collect_available_packages()

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_collect_available_packages_fallback_os_info(self, mock_agent):
        """Test package collection with fallback OS info."""
        mock_agent.registration.get_system_info = Mock(
            return_value={
                "platform": "FreeBSD",
                "platform_release": "13.0",
                "os_info": {},
            }
        )
        mock_agent.package_collection_scheduler.perform_package_collection = AsyncMock(
            return_value=True
        )
        mock_agent.package_collection_scheduler.package_collector = Mock()
        mock_agent.package_collection_scheduler.package_collector.get_packages_for_transmission = Mock(
            return_value={"package_managers": {}}
        )

        collector = DataCollector(mock_agent)
        collector._send_available_packages_paginated = AsyncMock(return_value=True)

        result = await collector.collect_available_packages()

        assert result["success"] is True


class TestSendAvailablePackagesPaginated:
    """Test _send_available_packages_paginated method."""

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent for pagination tests."""
        agent = Mock()
        agent.create_message = Mock(
            side_effect=lambda msg_type, data: {
                "message_type": msg_type,
                "message_id": str(uuid.uuid4()),
                "data": data,
            }
        )
        agent.send_message = AsyncMock(return_value=True)
        return agent

    @pytest.mark.asyncio
    async def test_send_available_packages_paginated_small_batch(self, mock_agent):
        """Test sending small batch of packages."""
        package_managers = {
            "apt": [{"name": f"pkg{i}", "version": "1.0"} for i in range(10)]
        }

        collector = DataCollector(mock_agent)
        result = await collector._send_available_packages_paginated(
            package_managers, "Ubuntu", "22.04", 10
        )

        assert result is True
        # Should send: batch_start + 1 batch + batch_end = 3 messages
        assert mock_agent.send_message.call_count == 3

    @pytest.mark.asyncio
    async def test_send_available_packages_paginated_large_batch(self, mock_agent):
        """Test sending large batch of packages with pagination."""
        package_managers = {
            "apt": [{"name": f"pkg{i}", "version": "1.0"} for i in range(2500)]
        }

        collector = DataCollector(mock_agent)
        result = await collector._send_available_packages_paginated(
            package_managers, "Ubuntu", "22.04", 2500
        )

        assert result is True
        # Should send: batch_start + 3 batches (1000 each) + batch_end = 5 messages
        assert mock_agent.send_message.call_count == 5

    @pytest.mark.asyncio
    async def test_send_available_packages_paginated_multiple_managers(
        self, mock_agent
    ):
        """Test sending packages from multiple package managers."""
        package_managers = {
            "apt": [{"name": f"pkg{i}", "version": "1.0"} for i in range(500)],
            "pip": [{"name": f"pypkg{i}", "version": "2.0"} for i in range(500)],
            "npm": [{"name": f"nmpkg{i}", "version": "3.0"} for i in range(500)],
        }

        collector = DataCollector(mock_agent)
        result = await collector._send_available_packages_paginated(
            package_managers, "Ubuntu", "22.04", 1500
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_send_available_packages_paginated_empty_manager(self, mock_agent):
        """Test sending packages with empty package manager."""
        package_managers = {
            "apt": [{"name": "pkg1", "version": "1.0"}],
            "pip": [],
        }

        collector = DataCollector(mock_agent)
        result = await collector._send_available_packages_paginated(
            package_managers, "Ubuntu", "22.04", 1
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_send_available_packages_paginated_error(self, mock_agent):
        """Test package pagination with error."""
        mock_agent.send_message = AsyncMock(side_effect=Exception("Send error"))

        package_managers = {"apt": [{"name": "pkg1", "version": "1.0"}]}

        collector = DataCollector(mock_agent)
        result = await collector._send_available_packages_paginated(
            package_managers, "Ubuntu", "22.04", 1
        )

        assert result is False


class TestCollectCertificates:
    """Test collect_certificates method."""

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent for certificate tests."""
        agent = Mock()
        agent.certificate_collector = Mock()
        agent.registration = Mock()
        agent.registration.get_system_info = Mock(
            return_value={"fqdn": "test.example.com"}
        )
        agent.create_message = Mock(
            side_effect=lambda msg_type, data: {
                "message_type": msg_type,
                "message_id": str(uuid.uuid4()),
                "data": data,
            }
        )
        agent.send_message = AsyncMock(return_value=True)
        return agent

    @pytest.mark.asyncio
    async def test_collect_certificates_success(self, mock_agent):
        """Test successful certificate collection."""
        mock_agent.certificate_collector.collect_certificates = Mock(
            return_value=[
                {"subject": "cert1.example.com", "issuer": "CA1"},
                {"subject": "cert2.example.com", "issuer": "CA2"},
            ]
        )

        collector = DataCollector(mock_agent)
        result = await collector.collect_certificates()

        assert result["success"] is True
        assert result["certificate_count"] == 2
        assert mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_collect_certificates_no_certificates(self, mock_agent):
        """Test certificate collection with no certificates."""
        mock_agent.certificate_collector.collect_certificates = Mock(return_value=[])

        collector = DataCollector(mock_agent)
        result = await collector.collect_certificates()

        assert result["success"] is True
        assert result["certificate_count"] == 0
        assert not mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_collect_certificates_error(self, mock_agent):
        """Test certificate collection with error."""
        mock_agent.certificate_collector.collect_certificates = Mock(
            side_effect=Exception("Collection failed")
        )

        collector = DataCollector(mock_agent)
        result = await collector.collect_certificates()

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_collect_certificates_fallback_hostname(self, mock_agent):
        """Test certificate collection with fallback hostname."""
        mock_agent.registration.get_system_info = Mock(return_value={})
        mock_agent.certificate_collector.collect_certificates = Mock(
            return_value=[{"subject": "cert1.example.com"}]
        )

        with patch("socket.gethostname", return_value="fallback-host"):
            collector = DataCollector(mock_agent)
            result = await collector.collect_certificates()

        assert result["success"] is True

    @pytest.mark.asyncio
    @patch("src.sysmanage_agent.core.agent_utils.is_running_privileged")
    async def test_collect_certificates_unprivileged(
        self, mock_is_privileged, mock_agent
    ):
        """Test certificate collection in unprivileged mode."""
        mock_is_privileged.return_value = False
        mock_agent.certificate_collector.collect_certificates = Mock(
            return_value=[{"subject": "cert1.example.com"}]
        )

        collector = DataCollector(mock_agent)
        result = await collector.collect_certificates()

        assert result["success"] is True


class TestCollectRoles:
    """Test collect_roles method."""

    @pytest.fixture
    def mock_agent(self):
        """Create mock agent for role tests."""
        agent = Mock()
        agent.role_detector = Mock()
        agent.registration = Mock()
        agent.registration.get_system_info = Mock(
            return_value={"hostname": "test-host"}
        )
        agent.create_message = Mock(
            side_effect=lambda msg_type, data: {
                "message_type": msg_type,
                "message_id": str(uuid.uuid4()),
                "data": data,
            }
        )
        agent.send_message = AsyncMock(return_value=True)
        return agent

    @pytest.mark.asyncio
    async def test_collect_roles_success(self, mock_agent):
        """Test successful role collection."""
        mock_agent.role_detector.detect_roles = Mock(
            return_value=[
                {"role": "web_server", "details": "Apache"},
                {"role": "database", "details": "PostgreSQL"},
            ]
        )

        collector = DataCollector(mock_agent)
        result = await collector.collect_roles()

        assert result["success"] is True
        assert result["role_count"] == 2
        assert mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_collect_roles_no_roles(self, mock_agent):
        """Test role collection with no roles detected."""
        mock_agent.role_detector.detect_roles = Mock(return_value=[])

        collector = DataCollector(mock_agent)
        result = await collector.collect_roles()

        assert result["success"] is True
        assert result["role_count"] == 0
        assert not mock_agent.send_message.called

    @pytest.mark.asyncio
    async def test_collect_roles_error(self, mock_agent):
        """Test role collection with error."""
        mock_agent.role_detector.detect_roles = Mock(
            side_effect=Exception("Detection failed")
        )

        collector = DataCollector(mock_agent)
        result = await collector.collect_roles()

        assert result["success"] is False
        assert "error" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
