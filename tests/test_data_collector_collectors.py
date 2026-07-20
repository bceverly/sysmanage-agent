# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Comprehensive test suite for DataCollector class (package/cert/role collectors).

Split from test_data_collector.py to keep each file under the 1000-line limit.
"""

# pylint: disable=protected-access

import uuid
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.communication.data_collector import DataCollector


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
