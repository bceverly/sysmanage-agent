"""
Tests for antivirus operations deploy_antivirus method.
Tests deployment of antivirus software on various platforms.
"""

# pylint: disable=redefined-outer-name,protected-access

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.antivirus_operations import AntivirusOperations


@pytest.fixture
def mock_agent():
    """Create a mock agent instance for testing."""
    agent = Mock()
    agent.send_message = AsyncMock(return_value=True)
    agent.create_message = Mock(return_value=Mock(to_dict=Mock(return_value={})))
    return agent


@pytest.fixture
def av_ops(mock_agent):
    """Create an AntivirusOperations instance for testing."""
    return AntivirusOperations(mock_agent)


class TestDeployAntivirus:
    """Tests for deploy_antivirus method."""

    @pytest.mark.asyncio
    async def test_deploy_no_package_specified(self, av_ops):
        """Test deployment fails when no package is specified."""
        result = await av_ops.deploy_antivirus({})

        assert result["success"] is False
        assert "No antivirus package specified" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_unsupported_package(self, av_ops):
        """Test deployment fails for unsupported package."""
        result = await av_ops.deploy_antivirus({"antivirus_package": "norton"})

        assert result["success"] is False
        assert "Unsupported antivirus package" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_clamav_debian(self, av_ops):
        """Test ClamAV deployment on Debian/Ubuntu."""
        with patch("os.path.exists", return_value=False):
            with patch("platform.system", return_value="Linux"):
                with patch(
                    "src.sysmanage_agent.operations.antivirus_deployment_helpers.deploy_clamav_debian",
                    new_callable=AsyncMock,
                    return_value=(True, None, "1.0.0", "Installed successfully"),
                ):
                    with patch(
                        "src.sysmanage_agent.collection.antivirus_collection.AntivirusCollector"
                    ) as mock_collector:
                        mock_collector.return_value.collect_antivirus_status.return_value = {
                            "software_name": "clamav"
                        }
                        with patch.object(
                            av_ops,
                            "_send_antivirus_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await av_ops.deploy_antivirus(
                                {"antivirus_package": "clamav"}
                            )

        assert result["success"] is True
        assert result["installed_version"] == "1.0.0"

    @pytest.mark.asyncio
    async def test_deploy_clamav_macos(self, av_ops):
        """Test ClamAV deployment on macOS."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/opt/homebrew/bin/brew"
            with patch(
                "src.sysmanage_agent.operations.antivirus_deployment_helpers.deploy_clamav_macos",
                new_callable=AsyncMock,
                return_value=(True, None, "1.0.0", "Installed successfully"),
            ):
                with patch(
                    "src.sysmanage_agent.collection.antivirus_collection.AntivirusCollector"
                ) as mock_collector:
                    mock_collector.return_value.collect_antivirus_status.return_value = {
                        "software_name": "clamav"
                    }
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.deploy_antivirus(
                            {"antivirus_package": "clamav"}
                        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_clamav_freebsd(self, av_ops):
        """Test ClamAV deployment on FreeBSD."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = (
                lambda p: p == "/usr/sbin/pkg" and p != "/usr/sbin/pkg_add"
            )
            with patch(
                "src.sysmanage_agent.operations.antivirus_deployment_helpers.deploy_clamav_freebsd",
                new_callable=AsyncMock,
                return_value=(True, None, "1.0.0", "Installed successfully"),
            ):
                with patch(
                    "src.sysmanage_agent.collection.antivirus_collection.AntivirusCollector"
                ) as mock_collector:
                    mock_collector.return_value.collect_antivirus_status.return_value = {
                        "software_name": "clamav"
                    }
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.deploy_antivirus(
                            {"antivirus_package": "clamav"}
                        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_clamav_openbsd(self, av_ops):
        """Test ClamAV deployment on OpenBSD."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/usr/sbin/pkg_add"
            with patch(
                "src.sysmanage_agent.operations.antivirus_deployment_helpers.deploy_clamav_openbsd",
                new_callable=AsyncMock,
                return_value=(True, None, "1.0.0", "Installed successfully"),
            ):
                with patch(
                    "src.sysmanage_agent.collection.antivirus_collection.AntivirusCollector"
                ) as mock_collector:
                    mock_collector.return_value.collect_antivirus_status.return_value = {
                        "software_name": "clamav"
                    }
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.deploy_antivirus(
                            {"antivirus_package": "clamav"}
                        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_clamav_netbsd(self, av_ops):
        """Test ClamAV deployment on NetBSD."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/usr/pkg/bin/pkgin"
            with patch(
                "src.sysmanage_agent.operations.antivirus_deployment_helpers.deploy_clamav_netbsd",
                new_callable=AsyncMock,
                return_value=(True, None, "1.0.0", "Installed successfully"),
            ):
                with patch(
                    "src.sysmanage_agent.collection.antivirus_collection.AntivirusCollector"
                ) as mock_collector:
                    mock_collector.return_value.collect_antivirus_status.return_value = {
                        "software_name": "clamav"
                    }
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.deploy_antivirus(
                            {"antivirus_package": "clamav"}
                        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_clamav_opensuse(self, av_ops):
        """Test ClamAV deployment on openSUSE."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/usr/bin/zypper"
            with patch(
                "src.sysmanage_agent.operations.antivirus_deployment_helpers.deploy_clamav_opensuse",
                new_callable=AsyncMock,
                return_value=(True, None, "1.0.0", "Installed successfully"),
            ):
                with patch(
                    "src.sysmanage_agent.collection.antivirus_collection.AntivirusCollector"
                ) as mock_collector:
                    mock_collector.return_value.collect_antivirus_status.return_value = {
                        "software_name": "clamav"
                    }
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.deploy_antivirus(
                            {"antivirus_package": "clamav"}
                        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_clamav_rhel(self, av_ops):
        """Test ClamAV deployment on RHEL/CentOS."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/usr/bin/dnf"
            with patch(
                "src.sysmanage_agent.operations.antivirus_deployment_helpers.deploy_clamav_rhel",
                new_callable=AsyncMock,
                return_value=(True, None, "1.0.0", "Installed successfully"),
            ):
                with patch(
                    "src.sysmanage_agent.collection.antivirus_collection.AntivirusCollector"
                ) as mock_collector:
                    mock_collector.return_value.collect_antivirus_status.return_value = {
                        "software_name": "clamav"
                    }
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.deploy_antivirus(
                            {"antivirus_package": "clamav"}
                        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_clamav_windows(self, av_ops):
        """Test ClamAV deployment on Windows."""
        with patch("os.path.exists", return_value=False):
            with patch("platform.system", return_value="Windows"):
                with patch(
                    "src.sysmanage_agent.operations.antivirus_deployment_helpers.deploy_clamav_windows",
                    new_callable=AsyncMock,
                    return_value=(True, None, "1.0.0", "Installed successfully"),
                ):
                    with patch(
                        "src.sysmanage_agent.collection.antivirus_collection.AntivirusCollector"
                    ) as mock_collector:
                        mock_collector.return_value.collect_antivirus_status.return_value = {
                            "software_name": "clamav"
                        }
                        with patch.object(
                            av_ops,
                            "_send_antivirus_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await av_ops.deploy_antivirus(
                                {"antivirus_package": "clamav"}
                            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_exception(self, av_ops):
        """Test deployment handles exceptions."""
        with patch("os.path.exists", return_value=False):
            with patch("platform.system", return_value="Linux"):
                with patch(
                    "src.sysmanage_agent.operations.antivirus_deployment_helpers.deploy_clamav_debian",
                    new_callable=AsyncMock,
                    side_effect=Exception("Deployment failed"),
                ):
                    result = await av_ops.deploy_antivirus(
                        {"antivirus_package": "clamav"}
                    )

        assert result["success"] is False
        assert "Deployment failed" in result["error"]
