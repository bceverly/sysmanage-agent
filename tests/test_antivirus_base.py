"""
Unit tests for src.sysmanage_agent.operations.antivirus_base module.
Tests base class for antivirus operations.
"""

# pylint: disable=protected-access,too-many-public-methods,attribute-defined-outside-init

import sys
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.antivirus_base import (
    AntivirusOperationsBase,
    _get_brew_user,
)


class TestGetBrewUserFunction:
    """Test cases for _get_brew_user function."""

    def test_get_brew_user_opt_homebrew(self):
        """Test _get_brew_user with /opt/homebrew."""
        mock_stat = Mock()
        mock_stat.st_uid = 501
        mock_pwd_entry = Mock()
        mock_pwd_entry.pw_name = "testuser"

        mock_pwd = Mock()
        mock_pwd.getpwuid = Mock(return_value=mock_pwd_entry)

        with patch.dict(sys.modules, {"pwd": mock_pwd}):
            with patch("os.path.exists", return_value=True):
                with patch("os.stat", return_value=mock_stat):
                    result = _get_brew_user()
                    assert result == "testuser"


class TestAntivirusOperationsBase:
    """Test cases for AntivirusOperationsBase class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_agent = Mock()
        self.mock_agent.websocket_client = Mock()
        self.mock_agent.websocket_client.send_message = AsyncMock()
        self.base_ops = AntivirusOperationsBase(self.mock_agent)

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update_success(self):
        """Test successful antivirus status update."""
        status = {"software_name": "ClamAV", "version": "1.0.0"}

        # Mock the dynamic import of websocket.messages
        mock_module = Mock()
        mock_message_class = Mock()
        mock_message_instance = Mock()
        mock_message_instance.to_dict.return_value = {
            "data": {"antivirus_status": status}
        }
        mock_message_class.return_value = mock_message_instance
        mock_module.Message = mock_message_class
        mock_module.MessageType = Mock()

        with patch.dict("sys.modules", {"websocket.messages": mock_module}):
            await self.base_ops.send_antivirus_status_update(status)

            self.mock_agent.websocket_client.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_antivirus_status_update_failure(self):
        """Test antivirus status update with exception."""
        self.mock_agent.websocket_client.send_message.side_effect = Exception(
            "Connection error"
        )
        status = {"software_name": "ClamAV"}

        # Should not raise exception
        await self.base_ops.send_antivirus_status_update(status)

    @pytest.mark.asyncio
    async def test_enable_antivirus_no_software_detected(self):
        """Test enable_antivirus when no antivirus is detected."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {}

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            result = await self.base_ops.enable_antivirus({})

            assert result["success"] is False
            assert "No antivirus software detected" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_antivirus_unknown_software(self):
        """Test enable_antivirus with unknown antivirus software."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "UnknownAV"
        }

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            result = await self.base_ops.enable_antivirus({})

            assert result["success"] is False
            assert "Unknown antivirus software" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_antivirus_linux_systemctl_success(self):
        """Test enable_antivirus on Linux with systemctl."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists", return_value=False):
                with patch("platform.system", return_value="Linux"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        result = await self.base_ops.enable_antivirus({})

                        assert result["success"] is True
                        assert result["service_name"] == "clamav_freshclam"

    @pytest.mark.asyncio
    async def test_enable_antivirus_linux_systemctl_failure(self):
        """Test enable_antivirus on Linux with systemctl failure."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Service failed"))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists", return_value=False):
                with patch("platform.system", return_value="Linux"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        result = await self.base_ops.enable_antivirus({})

                        assert result["success"] is False
                        assert "Service failed" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_antivirus_openbsd_rcctl(self):
        """Test enable_antivirus on OpenBSD with rcctl."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/sbin/rcctl"
                with patch("platform.system", return_value="OpenBSD"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        result = await self.base_ops.enable_antivirus({})

                        assert result["success"] is True
                        assert result["service_name"] == "clamd"

    @pytest.mark.asyncio
    async def test_enable_antivirus_macos_brew_services(self):
        """Test enable_antivirus on macOS with brew services."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/opt/homebrew/bin/brew"
                with patch("platform.system", return_value="Darwin"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        result = await self.base_ops.enable_antivirus({})

                        assert result["success"] is True
                        assert result["service_name"] == "clamav"

    @pytest.mark.asyncio
    async def test_enable_antivirus_windows_service_not_configured(self):
        """Test enable_antivirus on Windows when service is not configured."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 1  # Service doesn't exist
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("platform.system", return_value="Windows"):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    result = await self.base_ops.enable_antivirus({})

                    assert result["success"] is False
                    assert "manual service setup" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_antivirus_windows_service_exists(self):
        """Test enable_antivirus on Windows when service exists."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        # First process for query (success), second for start (success)
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 0
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_start = AsyncMock()
        mock_process_start.returncode = 0
        mock_process_start.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("platform.system", return_value="Windows"):
                with patch(
                    "asyncio.create_subprocess_exec",
                    side_effect=[mock_process_query, mock_process_start],
                ):
                    result = await self.base_ops.enable_antivirus({})

                    assert result["success"] is True
                    assert result["service_name"] == "ClamAV"

    @pytest.mark.asyncio
    async def test_enable_antivirus_netbsd_service(self):
        """Test enable_antivirus on NetBSD with service command."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/pkg/bin/pkgin"
                with patch("platform.system", return_value="NetBSD"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        with patch("asyncio.sleep", return_value=None):
                            result = await self.base_ops.enable_antivirus({})

                            assert result["success"] is True
                            assert result["service_name"] == "clamd"

    @pytest.mark.asyncio
    async def test_enable_antivirus_netbsd_service_failure(self):
        """Test enable_antivirus on NetBSD with service failure."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Failed to start"))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/pkg/bin/pkgin"
                with patch("platform.system", return_value="NetBSD"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        result = await self.base_ops.enable_antivirus({})

                        assert result["success"] is False
                        assert "Failed to start" in result["error"]

    @pytest.mark.asyncio
    async def test_enable_antivirus_freebsd_service(self):
        """Test enable_antivirus on FreeBSD."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = (
                    lambda path: path == "/usr/sbin/pkg"
                    and not path == "/usr/sbin/pkg_add"
                )
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("asyncio.sleep", return_value=None):
                        result = await self.base_ops.enable_antivirus({})

                        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_enable_antivirus_opensuse(self):
        """Test enable_antivirus on openSUSE."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/bin/zypper"
                with patch("platform.system", return_value="Linux"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        result = await self.base_ops.enable_antivirus({})

                        assert result["success"] is True
                        assert result["service_name"] == "clamd.service"

    @pytest.mark.asyncio
    async def test_enable_antivirus_rhel(self):
        """Test enable_antivirus on RHEL/CentOS."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/bin/dnf"
                with patch("platform.system", return_value="Linux"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        result = await self.base_ops.enable_antivirus({})

                        assert result["success"] is True
                        assert result["service_name"] == "clamd@scan"

    @pytest.mark.asyncio
    async def test_enable_antivirus_exception(self):
        """Test enable_antivirus with unexpected exception."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.base_ops.enable_antivirus({})

            assert result["success"] is False
            assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_antivirus_no_software_detected(self):
        """Test disable_antivirus when no antivirus is detected."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {}

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            result = await self.base_ops.disable_antivirus({})

            assert result["success"] is False
            assert "No antivirus software detected" in result["error"]

    @pytest.mark.asyncio
    async def test_disable_antivirus_linux_success(self):
        """Test disable_antivirus on Linux with systemctl."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists", return_value=False):
                with patch("platform.system", return_value="Linux"):
                    with patch(
                        "asyncio.create_subprocess_exec", return_value=mock_process
                    ):
                        result = await self.base_ops.disable_antivirus({})

                        assert result["success"] is True
                        assert result["service_name"] == "clamav_freshclam"

    @pytest.mark.asyncio
    async def test_disable_antivirus_openbsd(self):
        """Test disable_antivirus on OpenBSD."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/sbin/rcctl"
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    result = await self.base_ops.disable_antivirus({})

                    assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_antivirus_netbsd_warning(self):
        """Test disable_antivirus on NetBSD with service warning."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        # First service fails, second succeeds
        mock_process_fail = AsyncMock()
        mock_process_fail.returncode = 1
        mock_process_fail.communicate = AsyncMock(return_value=(b"", b"Warning"))

        mock_process_success = AsyncMock()
        mock_process_success.returncode = 0
        mock_process_success.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/pkg/bin/pkgin"
                with patch("platform.system", return_value="NetBSD"):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        side_effect=[mock_process_fail, mock_process_success],
                    ):
                        with patch("asyncio.sleep", return_value=None):
                            result = await self.base_ops.disable_antivirus({})

                            # Last process determines success
                            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_disable_antivirus_exception(self):
        """Test disable_antivirus with unexpected exception."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.base_ops.disable_antivirus({})

            assert result["success"] is False
            assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_antivirus_no_software_detected(self):
        """Test remove_antivirus when no antivirus is detected."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {}

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            result = await self.base_ops.remove_antivirus({})

            assert result["success"] is False
            assert "No antivirus software detected" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_antivirus_unknown_software(self):
        """Test remove_antivirus with unknown antivirus software."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "UnknownAV"
        }

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            result = await self.base_ops.remove_antivirus({})

            assert result["success"] is False
            assert "Unknown antivirus software" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_antivirus_macos_success(self):
        """Test remove_antivirus on macOS."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/opt/homebrew/bin/brew"
                with patch("platform.system", return_value="Darwin"):
                    with patch(
                        "src.sysmanage_agent.operations.antivirus_base.os.geteuid",
                        return_value=1000,
                        create=True,
                    ):
                        with patch(
                            "asyncio.create_subprocess_exec", return_value=mock_process
                        ):
                            with patch("asyncio.sleep", return_value=None):
                                result = await self.base_ops.remove_antivirus({})

                                assert result["success"] is True
                                assert result["software_name"] == "ClamAV"

    @pytest.mark.asyncio
    async def test_remove_antivirus_macos_as_root(self):
        """Test remove_antivirus on macOS as root."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/opt/homebrew/bin/brew"
                with patch("platform.system", return_value="Darwin"):
                    with patch(
                        "src.sysmanage_agent.operations.antivirus_base.os.geteuid",
                        return_value=0,
                        create=True,
                    ):
                        with patch(
                            "src.sysmanage_agent.operations.antivirus_base._get_brew_user",
                            return_value="brewuser",
                        ):
                            with patch(
                                "asyncio.create_subprocess_exec",
                                return_value=mock_process,
                            ):
                                with patch("asyncio.sleep", return_value=None):
                                    result = await self.base_ops.remove_antivirus({})

                                    assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_antivirus_macos_brew_fails_cleanup_succeeds(self):
        """Test remove_antivirus on macOS when brew fails but cleanup succeeds."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        # Stop process succeeds, uninstall fails
        mock_process_stop = AsyncMock()
        mock_process_stop.returncode = 0
        mock_process_stop.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall = AsyncMock()
        mock_process_uninstall.returncode = 1
        mock_process_uninstall.communicate = AsyncMock(
            return_value=(b"", b"Uninstall failed")
        )

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists", return_value=True):
                with patch("platform.system", return_value="Darwin"):
                    with patch(
                        "src.sysmanage_agent.operations.antivirus_base.os.geteuid",
                        return_value=1000,
                        create=True,
                    ):
                        with patch(
                            "asyncio.create_subprocess_exec",
                            side_effect=[mock_process_stop, mock_process_uninstall],
                        ):
                            with patch("asyncio.sleep", return_value=None):
                                with patch.object(
                                    self.base_ops,
                                    "_cleanup_clamav_cellar_macos",
                                    return_value=None,
                                ):
                                    result = await self.base_ops.remove_antivirus({})

                                    assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_antivirus_debian(self):
        """Test remove_antivirus on Debian/Ubuntu."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/bin/apt"
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    result = await self.base_ops.remove_antivirus({})

                    assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_antivirus_debian_failure(self):
        """Test remove_antivirus on Debian with failure."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Remove failed"))

        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            return_value=mock_collector,
        ):
            with patch("os.path.exists") as mock_exists:
                mock_exists.side_effect = lambda path: path == "/usr/bin/apt"
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    result = await self.base_ops.remove_antivirus({})

                    assert result["success"] is False
                    assert "Remove failed" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_antivirus_windows(self):
        """Test remove_antivirus on Windows."""
        mock_collector = Mock()
        mock_collector.collect_antivirus_status.return_value = {
            "software_name": "ClamAV"
        }

        # Query returns 0 (service exists), stop succeeds, first uninstall succeeds
        mock_process_query = AsyncMock()
        mock_process_query.returncode = 0
        mock_process_query.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_stop = AsyncMock()
        mock_process_stop.returncode = 0
        mock_process_stop.communicate = AsyncMock(return_value=(b"", b""))

        mock_process_uninstall1 = AsyncMock()
        mock_process_uninstall1.returncode = 0
        mock_process_uninstall1.communicate = AsyncMock(return_value=(b"", b""))

        # Mock the websocket.messages module for status update
        mock_module = Mock()
        mock_message_class = Mock()
        mock_message_instance = Mock()
        mock_message_instance.to_dict.return_value = {"data": {}}
        mock_message_class.return_value = mock_message_instance
        mock_module.Message = mock_message_class
        mock_module.MessageType = Mock()

        with patch.dict("sys.modules", {"websocket.messages": mock_module}):
            with patch(
                "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
                return_value=mock_collector,
            ):
                with patch("platform.system", return_value="Windows"):
                    with patch(
                        "os.path.exists", return_value=False
                    ):  # No other package managers
                        with patch(
                            "asyncio.create_subprocess_exec",
                            side_effect=[
                                mock_process_query,
                                mock_process_stop,
                                mock_process_uninstall1,  # First uninstall attempt succeeds
                            ],
                        ):
                            with patch("asyncio.sleep", return_value=None):
                                result = await self.base_ops.remove_antivirus({})

                                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_antivirus_exception(self):
        """Test remove_antivirus with unexpected exception."""
        with patch(
            "src.sysmanage_agent.operations.antivirus_base.AntivirusCollector",
            side_effect=Exception("Unexpected error"),
        ):
            result = await self.base_ops.remove_antivirus({})

            assert result["success"] is False
            assert "Unexpected error" in result["error"]

    @pytest.mark.asyncio
    async def test_cleanup_clamav_cellar_macos_no_directory(self):
        """Test _cleanup_clamav_cellar_macos when directory doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = await self.base_ops._cleanup_clamav_cellar_macos()

            assert result is None

    @pytest.mark.asyncio
    async def test_cleanup_clamav_cellar_macos_no_versions(self):
        """Test _cleanup_clamav_cellar_macos when no version directories."""
        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=[]):
                result = await self.base_ops._cleanup_clamav_cellar_macos()

                assert result is None

    @pytest.mark.asyncio
    async def test_cleanup_clamav_cellar_macos_success(self):
        """Test _cleanup_clamav_cellar_macos successful cleanup."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=["/opt/homebrew/Cellar/clamav/1.0.0"]):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("os.rmdir") as mock_rmdir:
                        result = await self.base_ops._cleanup_clamav_cellar_macos()

                        assert result is None
                        mock_rmdir.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_clamav_cellar_macos_rm_failure(self):
        """Test _cleanup_clamav_cellar_macos with rm failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Permission denied"))

        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=["/opt/homebrew/Cellar/clamav/1.0.0"]):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    result = await self.base_ops._cleanup_clamav_cellar_macos()

                    assert result == "Permission denied"

    @pytest.mark.asyncio
    async def test_cleanup_clamav_cellar_macos_rmdir_fails(self):
        """Test _cleanup_clamav_cellar_macos when final rmdir fails."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch("glob.glob", return_value=["/opt/homebrew/Cellar/clamav/1.0.0"]):
                with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                    with patch("os.rmdir", side_effect=OSError("Not empty")):
                        result = await self.base_ops._cleanup_clamav_cellar_macos()

                        # Should not raise, just log and continue
                        assert result is None
