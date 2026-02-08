"""
Tests for antivirus operations module.
Tests deployment, enabling, disabling, and removal of antivirus software.
"""

# pylint: disable=redefined-outer-name,protected-access

import asyncio
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


class TestAntivirusOperationsInit:
    """Tests for AntivirusOperations initialization."""

    def test_init_with_agent(self, mock_agent):
        """Test initialization with agent instance."""
        ops = AntivirusOperations(mock_agent)
        assert ops.agent_instance == mock_agent
        assert ops.logger is not None


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


class TestEnableAntivirus:
    """Tests for enable_antivirus method."""

    @pytest.mark.asyncio
    async def test_enable_no_antivirus_detected(self, av_ops):
        """Test enable fails when no antivirus is detected."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {}

            result = await av_ops.enable_antivirus({})

        assert result["success"] is False
        assert "No antivirus software detected" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_unknown_software(self, av_ops):
        """Test enable fails for unknown software."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "unknown"
            }

            result = await av_ops.enable_antivirus({})

        assert result["success"] is False
        assert "Unknown antivirus software" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_clamav_linux_systemctl(self, av_ops):
        """Test enable ClamAV on Linux with systemctl."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists", return_value=False):
                with patch("platform.system", return_value="Linux"):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        return_value=mock_process,
                    ):
                        with patch.object(
                            av_ops,
                            "_send_antivirus_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await av_ops.enable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_clamav_openbsd_rcctl(self, av_ops):
        """Test enable ClamAV on OpenBSD with rcctl."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/usr/sbin/rcctl"

                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.enable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_clamav_macos_brew(self, av_ops):
        """Test enable ClamAV on macOS with brew services."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/opt/homebrew/bin/brew"

                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.enable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_clamav_windows(self, av_ops):
        """Test enable ClamAV on Windows."""
        mock_query_process = AsyncMock()
        mock_query_process.returncode = 0
        mock_query_process.communicate = AsyncMock(return_value=(b"", b""))

        mock_start_process = AsyncMock()
        mock_start_process.returncode = 0
        mock_start_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("platform.system", return_value="Windows"):
                with patch("os.path.exists", return_value=False):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        side_effect=[mock_query_process, mock_start_process],
                    ):
                        with patch.object(
                            av_ops,
                            "_send_antivirus_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await av_ops.enable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_clamav_windows_service_not_configured(self, av_ops):
        """Test enable ClamAV on Windows when service is not configured."""
        mock_query_process = AsyncMock()
        mock_query_process.returncode = 1
        mock_query_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("platform.system", return_value="Windows"):
                with patch("os.path.exists", return_value=False):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        return_value=mock_query_process,
                    ):
                        result = await av_ops.enable_antivirus({})

        assert result["success"] is False
        assert "manual service setup" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_exception(self, av_ops):
        """Test enable handles exceptions."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector",
            side_effect=Exception("Collection failed"),
        ):
            result = await av_ops.enable_antivirus({})

        assert result["success"] is False


class TestDisableAntivirus:
    """Tests for disable_antivirus method."""

    @pytest.mark.asyncio
    async def test_disable_no_antivirus_detected(self, av_ops):
        """Test disable fails when no antivirus is detected."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {}

            result = await av_ops.disable_antivirus({})

        assert result["success"] is False
        assert "No antivirus software detected" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_clamav_linux_systemctl(self, av_ops):
        """Test disable ClamAV on Linux with systemctl."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists", return_value=False):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.disable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_clamav_openbsd_rcctl(self, av_ops):
        """Test disable ClamAV on OpenBSD with rcctl."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/usr/sbin/rcctl"

                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.disable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_clamav_macos_brew(self, av_ops):
        """Test disable ClamAV on macOS with brew services."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/opt/homebrew/bin/brew"

                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.disable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_clamav_windows(self, av_ops):
        """Test disable ClamAV on Windows."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("platform.system", return_value="Windows"):
                with patch("os.path.exists", return_value=False):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        return_value=mock_process,
                    ):
                        with patch.object(
                            av_ops,
                            "_send_antivirus_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await av_ops.disable_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_failure(self, av_ops):
        """Test disable handles service failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Service failed"))

        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists", return_value=False):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    result = await av_ops.disable_antivirus({})

        assert result["success"] is False
        assert "Service failed" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_exception(self, av_ops):
        """Test disable handles exceptions."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector",
            side_effect=Exception("Collection failed"),
        ):
            result = await av_ops.disable_antivirus({})

        assert result["success"] is False


class TestRemoveAntivirus:
    """Tests for remove_antivirus method."""

    @pytest.mark.asyncio
    async def test_remove_no_antivirus_detected(self, av_ops):
        """Test remove fails when no antivirus is detected."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {}

            result = await av_ops.remove_antivirus({})

        assert result["success"] is False
        assert "No antivirus software detected" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_unknown_software(self, av_ops):
        """Test remove fails for unknown software."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "unknown"
            }

            result = await av_ops.remove_antivirus({})

        assert result["success"] is False
        assert "Unknown antivirus software" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_clamav_macos(self, av_ops):
        """Test remove ClamAV on macOS."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/opt/homebrew/bin/brew"

                with patch(
                    "src.sysmanage_agent.operations.antivirus_removal_helpers.remove_clamav_macos",
                    new_callable=AsyncMock,
                    return_value=None,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.remove_antivirus({})

        assert result["success"] is True
        assert result["software_name"] == "clamav"

    @pytest.mark.asyncio
    async def test_remove_clamav_debian(self, av_ops):
        """Test remove ClamAV on Debian/Ubuntu."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/usr/bin/apt"

                with patch(
                    "src.sysmanage_agent.operations.antivirus_removal_helpers.remove_clamav_debian",
                    new_callable=AsyncMock,
                    return_value=None,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.remove_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_clamav_rhel(self, av_ops):
        """Test remove ClamAV on RHEL/CentOS."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p in ["/usr/bin/dnf"]

                with patch(
                    "src.sysmanage_agent.operations.antivirus_removal_helpers.remove_clamav_rhel",
                    new_callable=AsyncMock,
                    return_value=None,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.remove_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_clamav_opensuse(self, av_ops):
        """Test remove ClamAV on openSUSE."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/usr/bin/zypper"

                with patch(
                    "src.sysmanage_agent.operations.antivirus_removal_helpers.remove_clamav_opensuse",
                    new_callable=AsyncMock,
                    return_value=None,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.remove_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_clamav_freebsd(self, av_ops):
        """Test remove ClamAV on FreeBSD."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = (
                    lambda p: p == "/usr/sbin/pkg" and p != "/usr/sbin/pkg_add"
                )

                with patch(
                    "src.sysmanage_agent.operations.antivirus_removal_helpers.remove_clamav_freebsd",
                    new_callable=AsyncMock,
                    return_value=None,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.remove_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_clamav_openbsd(self, av_ops):
        """Test remove ClamAV on OpenBSD."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/usr/sbin/pkg_delete"

                with patch(
                    "src.sysmanage_agent.operations.antivirus_removal_helpers.remove_clamav_openbsd",
                    new_callable=AsyncMock,
                    return_value=None,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.remove_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_clamav_netbsd(self, av_ops):
        """Test remove ClamAV on NetBSD."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/usr/pkg/bin/pkgin"

                with patch(
                    "src.sysmanage_agent.operations.antivirus_removal_helpers.remove_clamav_netbsd",
                    new_callable=AsyncMock,
                    return_value=None,
                ):
                    with patch.object(
                        av_ops,
                        "_send_antivirus_status_update",
                        new_callable=AsyncMock,
                    ):
                        result = await av_ops.remove_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_clamav_windows(self, av_ops):
        """Test remove ClamAV on Windows."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists", return_value=False):
                with patch("platform.system", return_value="Windows"):
                    with patch(
                        "src.sysmanage_agent.operations.antivirus_removal_helpers.remove_clamav_windows",
                        new_callable=AsyncMock,
                        return_value=None,
                    ):
                        with patch.object(
                            av_ops,
                            "_send_antivirus_status_update",
                            new_callable=AsyncMock,
                        ):
                            result = await av_ops.remove_antivirus({})

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_unsupported_platform(self, av_ops):
        """Test remove fails on unsupported platform."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists", return_value=False):
                with patch("platform.system", return_value="Linux"):
                    result = await av_ops.remove_antivirus({})

        assert result["success"] is False
        assert "Unsupported package manager" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_failure(self, av_ops):
        """Test remove handles removal failure."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector"
        ) as mock_collector:
            mock_collector.return_value.collect_antivirus_status.return_value = {
                "software_name": "clamav"
            }

            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda p: p == "/usr/bin/apt"

                with patch(
                    "src.sysmanage_agent.operations.antivirus_removal_helpers.remove_clamav_debian",
                    new_callable=AsyncMock,
                    return_value="Removal failed",
                ):
                    result = await av_ops.remove_antivirus({})

        assert result["success"] is False
        assert "Removal failed" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_exception(self, av_ops):
        """Test remove handles exceptions."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_operations.AntivirusCollector",
            side_effect=Exception("Collection failed"),
        ):
            result = await av_ops.remove_antivirus({})

        assert result["success"] is False


class TestDetectServiceContext:
    """Tests for _detect_service_context method."""

    def test_detect_context_unknown_software(self, av_ops):
        """Test detection returns None for unknown software."""
        result = av_ops._detect_service_context("unknown")
        assert result is None

    def test_detect_context_non_clamav(self, av_ops):
        """Test detection returns None for non-ClamAV software."""
        result = av_ops._detect_service_context("norton")
        assert result is None

    def test_detect_context_windows(self, av_ops):
        """Test detection on Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch("os.path.exists", return_value=False):
                result = av_ops._detect_service_context("clamav")

        assert result == ("ClamAV", "windows")

    def test_detect_context_macos_brew(self, av_ops):
        """Test detection on macOS with brew."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/opt/homebrew/bin/brew"

            result = av_ops._detect_service_context("clamav")

        assert result == ("clamav", "brew")

    def test_detect_context_openbsd_rcctl(self, av_ops):
        """Test detection on OpenBSD with rcctl."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/usr/sbin/rcctl"

            result = av_ops._detect_service_context("clamav")

        assert result == ("clamd", "rcctl")

    def test_detect_context_netbsd(self, av_ops):
        """Test detection on NetBSD."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/usr/pkg/bin/pkgin"

            result = av_ops._detect_service_context("clamav")

        assert result == ("clamd", "bsd")

    def test_detect_context_freebsd(self, av_ops):
        """Test detection on FreeBSD."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = (
                lambda p: p == "/usr/sbin/pkg" and p != "/usr/sbin/pkg_add"
            )

            result = av_ops._detect_service_context("clamav")

        assert result == ("clamav_clamd", "bsd")

    def test_detect_context_opensuse(self, av_ops):
        """Test detection on openSUSE."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/usr/bin/zypper"

            result = av_ops._detect_service_context("clamav")

        assert result == ("clamd.service", "systemctl")

    def test_detect_context_rhel(self, av_ops):
        """Test detection on RHEL/CentOS."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/usr/bin/dnf"

            result = av_ops._detect_service_context("clamav")

        assert result == ("clamd@scan", "systemctl")

    def test_detect_context_debian_default(self, av_ops):
        """Test detection falls back to Debian default."""
        with patch("os.path.exists", return_value=False):
            with patch("platform.system", return_value="Linux"):
                result = av_ops._detect_service_context("clamav")

        assert result == ("clamav_freshclam", "systemctl")


class TestSendAntivirusStatusUpdate:
    """Tests for _send_antivirus_status_update method."""

    @pytest.mark.asyncio
    async def test_send_status_update_success(self, av_ops, mock_agent):
        """Test successful status update."""
        status = {"software_name": "clamav", "version": "1.0.0"}

        await av_ops._send_antivirus_status_update(status)

        mock_agent.create_message.assert_called_once()
        mock_agent.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_status_update_send_failure(self, av_ops, mock_agent):
        """Test status update when send fails."""
        mock_agent.send_message.return_value = False

        status = {"software_name": "clamav"}

        # Should not raise exception
        await av_ops._send_antivirus_status_update(status)

    @pytest.mark.asyncio
    async def test_send_status_update_exception(self, av_ops, mock_agent):
        """Test status update handles exceptions."""
        mock_agent.send_message.side_effect = Exception("Send failed")

        status = {"software_name": "clamav"}

        # Should not raise exception
        await av_ops._send_antivirus_status_update(status)


class TestEnableBsdService:
    """Tests for _enable_bsd_service method."""

    @pytest.mark.asyncio
    async def test_enable_bsd_service_freebsd(self, av_ops):
        """Test enable BSD service on FreeBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=False):
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_process,
            ):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await av_ops._enable_bsd_service("clamav_clamd")

        assert result[0].returncode == 0

    @pytest.mark.asyncio
    async def test_enable_bsd_service_netbsd(self, av_ops):
        """Test enable BSD service on NetBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/usr/pkg/bin/pkgin"

            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_process,
            ):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await av_ops._enable_bsd_service("clamd")

        assert result[0].returncode == 0

    @pytest.mark.asyncio
    async def test_enable_bsd_service_failure(self, av_ops):
        """Test enable BSD service failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Failed to start"))

        with patch("os.path.exists", return_value=False):
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_process,
            ):
                result = await av_ops._enable_bsd_service("clamav_clamd")

        assert result["success"] is False


class TestDisableBsdService:
    """Tests for _disable_bsd_service method."""

    @pytest.mark.asyncio
    async def test_disable_bsd_service_freebsd(self, av_ops):
        """Test disable BSD service on FreeBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=False):
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_process,
            ):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await av_ops._disable_bsd_service("clamav_clamd")

        assert result[0].returncode == 0

    @pytest.mark.asyncio
    async def test_disable_bsd_service_netbsd(self, av_ops):
        """Test disable BSD service on NetBSD."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists") as mock_exists:
            mock_exists.side_effect = lambda p: p == "/usr/pkg/bin/pkgin"

            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_process,
            ):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    result = await av_ops._disable_bsd_service("clamd")

        assert result[0].returncode == 0
