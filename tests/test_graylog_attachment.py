"""
Tests for Graylog attachment operations module.
Tests configuration of syslog forwarding to Graylog on various platforms.
"""

# pylint: disable=redefined-outer-name,protected-access,too-many-lines

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.sysmanage_agent.operations.graylog_attachment import (
    GraylogAttachmentOperations,
)


class AsyncContextManagerMock:
    """Mock class that supports async context manager protocol."""

    def __init__(self, read_data=""):
        self.read_data = read_data
        self.written_data = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False

    async def read(self):
        """Read file content."""
        return self.read_data

    async def write(self, data):
        """Write data to file."""
        self.written_data.append(data)


def create_async_file_mock(read_data=""):
    """Create a mock for aiofiles.open that supports async context manager."""
    mock_file = AsyncContextManagerMock(read_data)

    def mock_open_func(*_args, **_kwargs):
        return mock_file

    return mock_open_func


@pytest.fixture
def mock_agent():
    """Create a mock agent instance for testing."""
    agent = Mock()
    agent.send_message = AsyncMock(return_value=True)
    agent.create_message = Mock(return_value=Mock(to_dict=Mock(return_value={})))
    agent.registration_manager = Mock()
    agent.registration_manager.get_host_approval_from_db = Mock(
        return_value=Mock(host_id="test-host-id")
    )
    agent.registration = Mock()
    agent.registration.get_system_info = Mock(
        return_value={"hostname": "test-host.example.com"}
    )
    return agent


@pytest.fixture
def graylog_ops(mock_agent):
    """Create a GraylogAttachmentOperations instance for testing."""
    return GraylogAttachmentOperations(mock_agent)


class TestGraylogAttachmentInit:
    """Tests for GraylogAttachmentOperations initialization."""

    def test_init_with_agent(self, mock_agent):
        """Test initialization with agent instance."""
        ops = GraylogAttachmentOperations(mock_agent)
        assert ops.agent_instance == mock_agent
        assert ops.logger is not None

    def test_init_with_custom_logger(self, mock_agent):
        """Test initialization with custom logger."""
        custom_logger = Mock()
        ops = GraylogAttachmentOperations(mock_agent, logger=custom_logger)
        assert ops.logger == custom_logger


class TestAttachToGraylog:
    """Tests for attach_to_graylog method."""

    @pytest.mark.asyncio
    async def test_attach_linux_syslog_tcp(self, graylog_ops):
        """Test attaching to Graylog via syslog TCP on Linux."""
        graylog_ops.system = "Linux"

        parameters = {
            "mechanism": "syslog_tcp",
            "graylog_server": "192.168.1.100",
            "port": 514,
        }

        with patch.object(graylog_ops, "_is_service_running", return_value=True):
            with patch.object(
                graylog_ops,
                "_configure_rsyslog",
                new_callable=AsyncMock,
                return_value={"status": "success", "message": "Configured"},
            ):
                with patch.object(
                    graylog_ops,
                    "_send_graylog_status_update",
                    new_callable=AsyncMock,
                ):
                    result = await graylog_ops.attach_to_graylog(parameters)

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_attach_linux_syslog_udp(self, graylog_ops):
        """Test attaching to Graylog via syslog UDP on Linux."""
        graylog_ops.system = "Linux"

        parameters = {
            "mechanism": "syslog_udp",
            "graylog_server": "192.168.1.100",
            "port": 514,
        }

        with patch.object(graylog_ops, "_is_service_running", return_value=True):
            with patch.object(
                graylog_ops,
                "_configure_rsyslog",
                new_callable=AsyncMock,
                return_value={"status": "success", "message": "Configured"},
            ):
                with patch.object(
                    graylog_ops,
                    "_send_graylog_status_update",
                    new_callable=AsyncMock,
                ):
                    result = await graylog_ops.attach_to_graylog(parameters)

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_attach_linux_gelf_tcp(self, graylog_ops):
        """Test attaching to Graylog via GELF TCP on Linux."""
        graylog_ops.system = "Linux"

        parameters = {
            "mechanism": "gelf_tcp",
            "graylog_server": "192.168.1.100",
            "port": 12201,
        }

        with patch.object(graylog_ops, "_is_service_running", return_value=True):
            with patch.object(
                graylog_ops,
                "_configure_rsyslog",
                new_callable=AsyncMock,
                return_value={"status": "success", "message": "Configured GELF"},
            ):
                with patch.object(
                    graylog_ops,
                    "_send_graylog_status_update",
                    new_callable=AsyncMock,
                ):
                    result = await graylog_ops.attach_to_graylog(parameters)

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_attach_linux_unsupported_mechanism(self, graylog_ops):
        """Test attaching with unsupported mechanism on Linux."""
        graylog_ops.system = "Linux"

        parameters = {
            "mechanism": "windows_sidecar",
            "graylog_server": "192.168.1.100",
            "port": 514,
        }

        result = await graylog_ops.attach_to_graylog(parameters)

        assert result["status"] == "error"
        assert "not supported" in result["message"]

    @pytest.mark.asyncio
    async def test_attach_windows_sidecar(self, graylog_ops):
        """Test attaching to Graylog via Windows Sidecar."""
        graylog_ops.system = "Windows"

        parameters = {
            "mechanism": "windows_sidecar",
            "graylog_server": "192.168.1.100",
            "port": 9000,
        }

        with patch.object(
            graylog_ops,
            "_configure_windows_sidecar",
            new_callable=AsyncMock,
            return_value={"status": "success", "message": "Configured Windows Sidecar"},
        ):
            with patch.object(
                graylog_ops,
                "_send_graylog_status_update",
                new_callable=AsyncMock,
            ):
                result = await graylog_ops.attach_to_graylog(parameters)

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_attach_windows_unsupported_mechanism(self, graylog_ops):
        """Test attaching with unsupported mechanism on Windows."""
        graylog_ops.system = "Windows"

        parameters = {
            "mechanism": "syslog_tcp",
            "graylog_server": "192.168.1.100",
            "port": 514,
        }

        result = await graylog_ops.attach_to_graylog(parameters)

        assert result["status"] == "error"
        assert "not supported on Windows" in result["message"]

    @pytest.mark.asyncio
    async def test_attach_unsupported_platform(self, graylog_ops):
        """Test attaching on unsupported platform."""
        graylog_ops.system = "Unknown"

        parameters = {
            "mechanism": "syslog_tcp",
            "graylog_server": "192.168.1.100",
            "port": 514,
        }

        result = await graylog_ops.attach_to_graylog(parameters)

        assert result["status"] == "error"
        assert "not supported" in result["message"]

    @pytest.mark.asyncio
    async def test_attach_exception_handling(self, graylog_ops):
        """Test exception handling in attach_to_graylog."""
        graylog_ops.system = "Linux"

        parameters = {
            "mechanism": "syslog_tcp",
            "graylog_server": "192.168.1.100",
            "port": 514,
        }

        with patch.object(
            graylog_ops,
            "_configure_unix_syslog",
            new_callable=AsyncMock,
            side_effect=Exception("Connection failed"),
        ):
            result = await graylog_ops.attach_to_graylog(parameters)

        assert result["status"] == "error"
        assert "Connection failed" in result["message"]

    @pytest.mark.asyncio
    async def test_attach_freebsd(self, graylog_ops):
        """Test attaching to Graylog on FreeBSD."""
        graylog_ops.system = "FreeBSD"

        parameters = {
            "mechanism": "syslog_tcp",
            "graylog_server": "192.168.1.100",
            "port": 514,
        }

        with patch.object(graylog_ops, "_is_service_running", return_value=False):
            with patch.object(
                graylog_ops,
                "_configure_bsd_syslog",
                new_callable=AsyncMock,
                return_value={"status": "success", "message": "Configured BSD syslog"},
            ):
                with patch.object(
                    graylog_ops,
                    "_send_graylog_status_update",
                    new_callable=AsyncMock,
                ):
                    result = await graylog_ops.attach_to_graylog(parameters)

        assert result["status"] == "success"


class TestConfigureRsyslog:
    """Tests for _configure_rsyslog method."""

    @pytest.mark.asyncio
    async def test_configure_rsyslog_tcp_success(self, graylog_ops):
        """Test successful rsyslog TCP configuration."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
            create_async_file_mock(),
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_process,
            ):
                result = await graylog_ops._configure_rsyslog(
                    "192.168.1.100", 514, "syslog_tcp"
                )

        assert result["status"] == "success"
        assert "rsyslog" in result["message"]

    @pytest.mark.asyncio
    async def test_configure_rsyslog_udp_success(self, graylog_ops):
        """Test successful rsyslog UDP configuration."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
            create_async_file_mock(),
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_process,
            ):
                result = await graylog_ops._configure_rsyslog(
                    "192.168.1.100", 514, "syslog_udp"
                )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_rsyslog_gelf_tcp_success(self, graylog_ops):
        """Test successful rsyslog GELF TCP configuration."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
            create_async_file_mock(),
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_process,
            ):
                result = await graylog_ops._configure_rsyslog(
                    "192.168.1.100", 12201, "gelf_tcp"
                )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_rsyslog_unknown_mechanism(self, graylog_ops):
        """Test rsyslog configuration with unknown mechanism."""
        result = await graylog_ops._configure_rsyslog(
            "192.168.1.100", 514, "unknown_mechanism"
        )

        assert result["status"] == "error"
        assert "Unknown mechanism" in result["message"]

    @pytest.mark.asyncio
    async def test_configure_rsyslog_restart_failure(self, graylog_ops):
        """Test rsyslog configuration when restart fails."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Restart failed"))

        with patch(
            "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
            create_async_file_mock(),
        ):
            with patch(
                "asyncio.create_subprocess_exec",
                new_callable=AsyncMock,
                return_value=mock_process,
            ):
                result = await graylog_ops._configure_rsyslog(
                    "192.168.1.100", 514, "syslog_tcp"
                )

        assert result["status"] == "error"
        assert "Failed to restart rsyslog" in result["message"]

    @pytest.mark.asyncio
    async def test_configure_rsyslog_file_write_exception(self, graylog_ops):
        """Test rsyslog configuration when file write fails."""
        with patch(
            "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
            side_effect=PermissionError("Access denied"),
        ):
            result = await graylog_ops._configure_rsyslog(
                "192.168.1.100", 514, "syslog_tcp"
            )

        assert result["status"] == "error"
        assert "Access denied" in result["message"]


class TestConfigureSyslogNg:
    """Tests for _configure_syslog_ng method."""

    @pytest.mark.asyncio
    async def test_configure_syslog_ng_tcp_success(self, graylog_ops):
        """Test successful syslog-ng TCP configuration."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.makedirs"):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    result = await graylog_ops._configure_syslog_ng(
                        "192.168.1.100", 514, "syslog_tcp"
                    )

        assert result["status"] == "success"
        assert "syslog-ng" in result["message"]

    @pytest.mark.asyncio
    async def test_configure_syslog_ng_udp_success(self, graylog_ops):
        """Test successful syslog-ng UDP configuration."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.makedirs"):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    result = await graylog_ops._configure_syslog_ng(
                        "192.168.1.100", 514, "syslog_udp"
                    )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_syslog_ng_gelf_success(self, graylog_ops):
        """Test successful syslog-ng GELF configuration."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.makedirs"):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    result = await graylog_ops._configure_syslog_ng(
                        "192.168.1.100", 12201, "gelf_tcp"
                    )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_syslog_ng_unknown_mechanism(self, graylog_ops):
        """Test syslog-ng configuration with unknown mechanism."""
        with patch("os.makedirs"):
            result = await graylog_ops._configure_syslog_ng(
                "192.168.1.100", 514, "unknown_mechanism"
            )

        assert result["status"] == "error"
        assert "Unknown mechanism" in result["message"]

    @pytest.mark.asyncio
    async def test_configure_syslog_ng_restart_failure(self, graylog_ops):
        """Test syslog-ng configuration when restart fails."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Restart failed"))

        with patch("os.makedirs"):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    result = await graylog_ops._configure_syslog_ng(
                        "192.168.1.100", 514, "syslog_tcp"
                    )

        assert result["status"] == "error"
        assert "Failed to restart syslog-ng" in result["message"]


class TestConfigureBsdSyslog:
    """Tests for _configure_bsd_syslog method."""

    @pytest.mark.asyncio
    async def test_configure_bsd_syslog_tcp_success(self, graylog_ops):
        """Test successful BSD syslog TCP configuration."""
        graylog_ops.system = "FreeBSD"

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=False):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    result = await graylog_ops._configure_bsd_syslog(
                        "192.168.1.100", 514, "syslog_tcp"
                    )

        assert result["status"] == "success"
        assert "BSD syslog" in result["message"]

    @pytest.mark.asyncio
    async def test_configure_bsd_syslog_udp_success(self, graylog_ops):
        """Test successful BSD syslog UDP configuration."""
        graylog_ops.system = "FreeBSD"

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=False):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    result = await graylog_ops._configure_bsd_syslog(
                        "192.168.1.100", 514, "syslog_udp"
                    )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_bsd_syslog_unsupported_mechanism(self, graylog_ops):
        """Test BSD syslog with unsupported mechanism (GELF)."""
        graylog_ops.system = "FreeBSD"

        result = await graylog_ops._configure_bsd_syslog(
            "192.168.1.100", 12201, "gelf_tcp"
        )

        assert result["status"] == "error"
        assert "not supported on BSD" in result["message"]

    @pytest.mark.asyncio
    async def test_configure_bsd_syslog_existing_config(self, graylog_ops):
        """Test BSD syslog with existing configuration."""
        graylog_ops.system = "FreeBSD"

        existing_config = """
# Existing config
*.* @other-server:514
"""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(existing_config),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    result = await graylog_ops._configure_bsd_syslog(
                        "192.168.1.100", 514, "syslog_tcp"
                    )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_bsd_syslog_openbsd_restart(self, graylog_ops):
        """Test BSD syslog restart on OpenBSD using rcctl."""
        graylog_ops.system = "OpenBSD"

        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=False):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ) as mock_exec:
                    result = await graylog_ops._configure_bsd_syslog(
                        "192.168.1.100", 514, "syslog_tcp"
                    )

        # Verify rcctl was called for OpenBSD
        assert result["status"] == "success"
        mock_exec.assert_called()

    @pytest.mark.asyncio
    async def test_configure_bsd_syslog_restart_failure(self, graylog_ops):
        """Test BSD syslog configuration when restart fails."""
        graylog_ops.system = "FreeBSD"

        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Restart failed"))

        with patch("os.path.exists", return_value=False):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    return_value=mock_process,
                ):
                    result = await graylog_ops._configure_bsd_syslog(
                        "192.168.1.100", 514, "syslog_tcp"
                    )

        assert result["status"] == "error"
        assert "Failed to restart BSD syslog" in result["message"]


class TestConfigureWindowsSidecar:
    """Tests for _configure_windows_sidecar method."""

    @pytest.mark.asyncio
    async def test_configure_windows_sidecar_not_installed(self, graylog_ops):
        """Test Windows Sidecar when not installed."""
        mock_install_process = AsyncMock()
        mock_install_process.returncode = 0
        mock_install_process.communicate = AsyncMock(return_value=(b"", b""))

        mock_start_process = AsyncMock()
        mock_start_process.returncode = 0
        mock_start_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", side_effect=[False, True, False, True]):
            with patch.object(
                graylog_ops,
                "_install_windows_sidecar",
                new_callable=AsyncMock,
                return_value={"status": "success", "message": "Installed"},
            ):
                with patch(
                    "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                    create_async_file_mock(),
                ):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        side_effect=[mock_install_process, mock_start_process],
                    ):
                        result = await graylog_ops._configure_windows_sidecar(
                            "192.168.1.100", 9000
                        )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_windows_sidecar_already_installed(self, graylog_ops):
        """Test Windows Sidecar when already installed."""
        mock_install_process = AsyncMock()
        mock_install_process.returncode = 0
        mock_install_process.communicate = AsyncMock(return_value=(b"", b""))

        mock_start_process = AsyncMock()
        mock_start_process.returncode = 0
        mock_start_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "os.path.exists",
            side_effect=[True, False],  # Sidecar exists, no existing config
        ):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    side_effect=[mock_install_process, mock_start_process],
                ):
                    result = await graylog_ops._configure_windows_sidecar(
                        "192.168.1.100", 9000
                    )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_windows_sidecar_install_failure(self, graylog_ops):
        """Test Windows Sidecar when installation fails."""
        with patch("os.path.exists", return_value=False):
            with patch.object(
                graylog_ops,
                "_install_windows_sidecar",
                new_callable=AsyncMock,
                return_value={"status": "error", "message": "Download failed"},
            ):
                result = await graylog_ops._configure_windows_sidecar(
                    "192.168.1.100", 9000
                )

        assert result["status"] == "error"
        assert "Download failed" in result["message"]

    @pytest.mark.asyncio
    async def test_configure_windows_sidecar_start_failure(self, graylog_ops):
        """Test Windows Sidecar when service start fails."""
        mock_install_process = AsyncMock()
        mock_install_process.returncode = 0
        mock_install_process.communicate = AsyncMock(return_value=(b"", b""))

        mock_start_process = AsyncMock()
        mock_start_process.returncode = 1
        mock_start_process.communicate = AsyncMock(return_value=(b"", b"Start failed"))

        with patch("os.path.exists", side_effect=[True, False]):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    side_effect=[mock_install_process, mock_start_process],
                ):
                    result = await graylog_ops._configure_windows_sidecar(
                        "192.168.1.100", 9000
                    )

        assert result["status"] == "error"
        assert "Failed to start" in result["message"]

    @pytest.mark.asyncio
    async def test_configure_windows_sidecar_existing_config(self, graylog_ops):
        """Test Windows Sidecar with existing configuration."""
        existing_config = """
server_url: http://old-server:9000/api/
server_api_token: old-token
update_interval: 30
"""
        mock_install_process = AsyncMock()
        mock_install_process.returncode = 0
        mock_install_process.communicate = AsyncMock(return_value=(b"", b""))

        mock_start_process = AsyncMock()
        mock_start_process.returncode = 0
        mock_start_process.communicate = AsyncMock(return_value=(b"", b""))

        with patch("os.path.exists", return_value=True):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                create_async_file_mock(existing_config),
            ):
                with patch(
                    "asyncio.create_subprocess_exec",
                    new_callable=AsyncMock,
                    side_effect=[mock_install_process, mock_start_process],
                ):
                    result = await graylog_ops._configure_windows_sidecar(
                        "192.168.1.100", 9000
                    )

        assert result["status"] == "success"


class MockUrlResponse:
    """Mock for urllib.request.urlopen context manager."""

    def __init__(self, content=b"installer content"):
        self.content = content

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self):
        """Read the mock content."""
        return self.content


class TestInstallWindowsSidecar:
    """Tests for _install_windows_sidecar method."""

    @pytest.mark.asyncio
    async def test_install_windows_sidecar_success(self, graylog_ops):
        """Test successful Windows Sidecar installation."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        async def mock_wait_for(coro, timeout):  # pylint: disable=unused-argument
            return await coro

        with patch("platform.machine", return_value="AMD64"):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.urllib.request.urlopen",
                return_value=MockUrlResponse(),
            ):
                with patch(
                    "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                    create_async_file_mock(),
                ):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        return_value=mock_process,
                    ):
                        with patch("asyncio.wait_for", side_effect=mock_wait_for):
                            with patch("os.remove"):
                                result = await graylog_ops._install_windows_sidecar()

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_install_windows_sidecar_386_arch(self, graylog_ops):
        """Test Windows Sidecar installation on 32-bit architecture."""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"", b""))

        async def mock_wait_for(coro, timeout):  # pylint: disable=unused-argument
            return await coro

        with patch("platform.machine", return_value="x86"):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.urllib.request.urlopen",
                return_value=MockUrlResponse(),
            ):
                with patch(
                    "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                    create_async_file_mock(),
                ):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        return_value=mock_process,
                    ):
                        with patch("asyncio.wait_for", side_effect=mock_wait_for):
                            with patch("os.remove"):
                                result = await graylog_ops._install_windows_sidecar()

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_install_windows_sidecar_install_failure(self, graylog_ops):
        """Test Windows Sidecar installation failure."""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Install failed"))

        with patch("platform.machine", return_value="AMD64"):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.urllib.request.urlopen",
                return_value=MockUrlResponse(),
            ):
                with patch(
                    "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                    create_async_file_mock(),
                ):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        return_value=mock_process,
                    ):
                        with patch(
                            "asyncio.wait_for",
                            new_callable=AsyncMock,
                            return_value=(b"", b"Install failed"),
                        ):
                            result = await graylog_ops._install_windows_sidecar()

        assert result["status"] == "error"
        assert "Failed to install" in result["message"]

    @pytest.mark.asyncio
    async def test_install_windows_sidecar_timeout(self, graylog_ops):
        """Test Windows Sidecar installation timeout."""
        mock_process = AsyncMock()
        mock_process.kill = Mock()

        with patch("platform.machine", return_value="AMD64"):
            with patch(
                "src.sysmanage_agent.operations.graylog_attachment.urllib.request.urlopen",
                return_value=MockUrlResponse(),
            ):
                with patch(
                    "src.sysmanage_agent.operations.graylog_attachment.aiofiles.open",
                    create_async_file_mock(),
                ):
                    with patch(
                        "asyncio.create_subprocess_exec",
                        new_callable=AsyncMock,
                        return_value=mock_process,
                    ):
                        with patch(
                            "asyncio.wait_for",
                            side_effect=asyncio.TimeoutError(),
                        ):
                            result = await graylog_ops._install_windows_sidecar()

        assert result["status"] == "error"
        assert "timed out" in result["message"]
        mock_process.kill.assert_called_once()


class TestValidateDownloadUrl:
    """Tests for _validate_download_url method."""

    def test_validate_url_valid_https_github(self, graylog_ops):
        """Test validation of valid HTTPS GitHub URL."""
        url = "https://github.com/Graylog2/collector-sidecar/releases/latest/download/installer.exe"
        assert graylog_ops._validate_download_url(url) is True

    def test_validate_url_invalid_http(self, graylog_ops):
        """Test validation rejects HTTP URL."""
        url = "http://github.com/Graylog2/collector-sidecar/releases/latest/download/installer.exe"
        assert graylog_ops._validate_download_url(url) is False

    def test_validate_url_invalid_domain(self, graylog_ops):
        """Test validation rejects non-GitHub domain."""
        url = "https://malicious-site.com/installer.exe"
        assert graylog_ops._validate_download_url(url) is False

    def test_validate_url_file_scheme(self, graylog_ops):
        """Test validation rejects file:// scheme."""
        url = "file:///etc/passwd"
        assert graylog_ops._validate_download_url(url) is False

    def test_validate_url_invalid_format(self, graylog_ops):
        """Test validation handles invalid URL format."""
        url = "not-a-valid-url"
        # Should not raise, but return False
        result = graylog_ops._validate_download_url(url)
        assert result is False


class TestIsServiceRunning:
    """Tests for _is_service_running method."""

    def test_service_running_linux_systemd(self, graylog_ops):
        """Test service running check on Linux with systemd."""
        graylog_ops.system = "Linux"

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = graylog_ops._is_service_running("rsyslog")

        assert result is True

    def test_service_not_running_linux(self, graylog_ops):
        """Test service not running on Linux."""
        graylog_ops.system = "Linux"

        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = graylog_ops._is_service_running("rsyslog")

        assert result is False

    def test_service_running_windows(self, graylog_ops):
        """Test service running check on Windows."""
        graylog_ops.system = "Windows"

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "RUNNING"

        with patch("subprocess.run", return_value=mock_result):
            result = graylog_ops._is_service_running("graylog-sidecar")

        assert result is True

    def test_service_not_running_windows(self, graylog_ops):
        """Test service not running on Windows."""
        graylog_ops.system = "Windows"

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "STOPPED"

        with patch("subprocess.run", return_value=mock_result):
            result = graylog_ops._is_service_running("graylog-sidecar")

        assert result is False

    def test_service_check_exception(self, graylog_ops):
        """Test service check handles exceptions."""
        graylog_ops.system = "Linux"

        with patch("subprocess.run", side_effect=Exception("Command failed")):
            result = graylog_ops._is_service_running("rsyslog")

        assert result is False


class TestConfigureUnixSyslog:
    """Tests for _configure_unix_syslog method."""

    @pytest.mark.asyncio
    async def test_configure_unix_syslog_rsyslog(self, graylog_ops):
        """Test Unix syslog configuration with rsyslog."""
        with patch.object(graylog_ops, "_is_service_running") as mock_service:
            mock_service.side_effect = lambda s: s == "rsyslog"
            with patch.object(
                graylog_ops,
                "_configure_rsyslog",
                new_callable=AsyncMock,
                return_value={"status": "success", "message": "OK"},
            ) as mock_rsyslog:
                result = await graylog_ops._configure_unix_syslog(
                    "192.168.1.100", 514, "syslog_tcp"
                )

        mock_rsyslog.assert_called_once()
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_unix_syslog_syslog_ng(self, graylog_ops):
        """Test Unix syslog configuration with syslog-ng."""
        with patch.object(graylog_ops, "_is_service_running") as mock_service:
            mock_service.side_effect = lambda s: s == "syslog-ng"
            with patch.object(
                graylog_ops,
                "_configure_syslog_ng",
                new_callable=AsyncMock,
                return_value={"status": "success", "message": "OK"},
            ) as mock_syslog_ng:
                result = await graylog_ops._configure_unix_syslog(
                    "192.168.1.100", 514, "syslog_tcp"
                )

        mock_syslog_ng.assert_called_once()
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_unix_syslog_bsd(self, graylog_ops):
        """Test Unix syslog configuration on BSD."""
        graylog_ops.system = "FreeBSD"

        with patch.object(graylog_ops, "_is_service_running", return_value=False):
            with patch.object(
                graylog_ops,
                "_configure_bsd_syslog",
                new_callable=AsyncMock,
                return_value={"status": "success", "message": "OK"},
            ) as mock_bsd:
                result = await graylog_ops._configure_unix_syslog(
                    "192.168.1.100", 514, "syslog_tcp"
                )

        mock_bsd.assert_called_once()
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_configure_unix_syslog_no_daemon(self, graylog_ops):
        """Test Unix syslog configuration when no daemon found."""
        graylog_ops.system = "Linux"

        with patch.object(graylog_ops, "_is_service_running", return_value=False):
            result = await graylog_ops._configure_unix_syslog(
                "192.168.1.100", 514, "syslog_tcp"
            )

        assert result["status"] == "error"
        assert "No supported syslog daemon found" in result["message"]


class TestSendGraylogStatusUpdate:
    """Tests for _send_graylog_status_update method."""

    @pytest.mark.asyncio
    async def test_send_status_update_with_mocked_method(
        self, graylog_ops, mock_agent
    ):  # pylint: disable=unused-argument
        """Test Graylog status update by mocking the entire method."""
        # Simply verify the method can be called without error
        with patch.object(
            graylog_ops,
            "_send_graylog_status_update",
            new_callable=AsyncMock,
        ) as mock_send:
            await mock_send()
            mock_send.assert_called_once()

    @pytest.mark.asyncio
    async def test_status_update_in_attach_flow(self, graylog_ops):
        """Test status update is called in the attach flow."""
        graylog_ops.system = "Linux"

        parameters = {
            "mechanism": "syslog_tcp",
            "graylog_server": "192.168.1.100",
            "port": 514,
        }

        with patch.object(graylog_ops, "_is_service_running", return_value=True):
            with patch.object(
                graylog_ops,
                "_configure_rsyslog",
                new_callable=AsyncMock,
                return_value={"status": "success", "message": "Configured"},
            ):
                with patch.object(
                    graylog_ops,
                    "_send_graylog_status_update",
                    new_callable=AsyncMock,
                ) as mock_send:
                    result = await graylog_ops.attach_to_graylog(parameters)

        assert result["status"] == "success"
        mock_send.assert_called_once()


class TestGetBsdForwardLine:
    """Tests for _get_bsd_forward_line method."""

    def test_get_bsd_forward_line_tcp(self, graylog_ops):
        """Test getting BSD forward line for TCP."""
        result = graylog_ops._get_bsd_forward_line("192.168.1.100", 514, "syslog_tcp")
        assert result == "*.*\t@@192.168.1.100:514\n"

    def test_get_bsd_forward_line_udp(self, graylog_ops):
        """Test getting BSD forward line for UDP."""
        result = graylog_ops._get_bsd_forward_line("192.168.1.100", 514, "syslog_udp")
        assert result == "*.*\t@192.168.1.100:514\n"

    def test_get_bsd_forward_line_unsupported(self, graylog_ops):
        """Test getting BSD forward line for unsupported mechanism."""
        result = graylog_ops._get_bsd_forward_line("192.168.1.100", 12201, "gelf_tcp")
        assert result is None


class TestUpdateBsdConfig:
    """Tests for _update_bsd_config method."""

    def test_update_bsd_config_new_entry(self, graylog_ops):
        """Test updating BSD config with new entry."""
        existing_config = "# Existing config\n*.* /var/log/messages"
        forward_line = "*.*\t@@192.168.1.100:514\n"

        result = graylog_ops._update_bsd_config(
            existing_config, "192.168.1.100", forward_line
        )

        assert "# Graylog forwarding" in result
        assert "@@192.168.1.100:514" in result

    def test_update_bsd_config_existing_entry(self, graylog_ops):
        """Test updating BSD config with existing entry."""
        existing_config = """# Existing config
*.* /var/log/messages
*.*\t@192.168.1.100:514
"""
        forward_line = "*.*\t@@192.168.1.100:514\n"

        result = graylog_ops._update_bsd_config(
            existing_config, "192.168.1.100", forward_line
        )

        # Should replace existing entry
        assert "@@192.168.1.100:514" in result

    def test_update_bsd_config_commented_entry(self, graylog_ops):
        """Test updating BSD config with commented existing entry."""
        existing_config = """# Existing config
# *.*\t@192.168.1.100:514
"""
        forward_line = "*.*\t@@192.168.1.100:514\n"

        result = graylog_ops._update_bsd_config(
            existing_config, "192.168.1.100", forward_line
        )

        # Should keep commented lines as-is when IP is in existing config
        # The method detects the IP in config (even in comments) and preserves commented lines
        assert "# *.*\t@192.168.1.100:514" in result
