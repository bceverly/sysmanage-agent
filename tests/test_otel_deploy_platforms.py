"""
Unit tests for platform-specific OpenTelemetry deployers.
Tests otel_deploy_bsd.py, otel_deploy_linux.py, otel_deploy_macos.py, otel_deploy_windows.py
"""

# pylint: disable=unused-variable,unused-argument

from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from src.sysmanage_agent.operations.otel_deploy_bsd import (
    BSDOtelDeployer,
    FreeBSDOtelDeployer,
    NetBSDOtelDeployer,
    OpenBSDOtelDeployer,
)
from src.sysmanage_agent.operations.otel_deploy_linux import LinuxOtelDeployer
from src.sysmanage_agent.operations.otel_deploy_macos import MacOSOtelDeployer
from src.sysmanage_agent.operations.otel_deploy_windows import WindowsOtelDeployer


class TestFreeBSDOtelDeployer:
    """Test suite for FreeBSD OpenTelemetry deployer."""

    @pytest.mark.asyncio
    async def test_deploy_success(self):
        """Test successful FreeBSD deployment."""
        agent_instance = MagicMock()
        deployer = FreeBSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess, patch(
            "os.makedirs"
        ) as mock_makedirs, patch("builtins.open", mock_open()) as mock_file:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is True
            assert "successfully" in result["message"]
            assert result["config_file"] == "/usr/local/etc/alloy/config.alloy"

    @pytest.mark.asyncio
    async def test_deploy_install_failure(self):
        """Test FreeBSD deployment with installation failure."""
        agent_instance = MagicMock()
        deployer = FreeBSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"Installation failed")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "Failed to install" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_config_creation(self):
        """Test that config file is created with proper content."""
        agent_instance = MagicMock()
        deployer = FreeBSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess, patch(
            "os.makedirs"
        ) as mock_makedirs, patch("builtins.open", mock_open()) as mock_file:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com:8080")

            mock_file.assert_called_with(
                "/usr/local/etc/alloy/config.alloy", "w", encoding="utf-8"
            )

    @pytest.mark.asyncio
    async def test_deploy_exception(self):
        """Test FreeBSD deployment with exception."""
        agent_instance = MagicMock()
        deployer = FreeBSDOtelDeployer(agent_instance)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_success(self):
        """Test successful FreeBSD removal."""
        agent_instance = MagicMock()
        deployer = FreeBSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.remove()

            assert result["success"] is True
            assert "successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_remove_exception(self):
        """Test FreeBSD removal with exception."""
        agent_instance = MagicMock()
        deployer = FreeBSDOtelDeployer(agent_instance)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Remove error")
        ):
            result = await deployer.remove()

            assert result["success"] is False
            assert "Remove error" in result["error"]


class TestOpenBSDOtelDeployer:
    """Test suite for OpenBSD OpenTelemetry deployer."""

    @pytest.mark.asyncio
    async def test_deploy_success(self):
        """Test successful OpenBSD deployment."""
        agent_instance = MagicMock()
        deployer = OpenBSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess, patch(
            "os.makedirs"
        ), patch("builtins.open", mock_open()):
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is True
            assert result["config_file"] == "/etc/otelcol/config.yaml"

    @pytest.mark.asyncio
    async def test_deploy_install_failure(self):
        """Test OpenBSD deployment with installation failure."""
        agent_instance = MagicMock()
        deployer = OpenBSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"pkg_add failed")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "Failed to install" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_success(self):
        """Test successful OpenBSD removal."""
        agent_instance = MagicMock()
        deployer = OpenBSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.remove()

            assert result["success"] is True


class TestNetBSDOtelDeployer:
    """Test suite for NetBSD OpenTelemetry deployer."""

    @pytest.mark.asyncio
    async def test_deploy_success(self):
        """Test successful NetBSD deployment."""
        agent_instance = MagicMock()
        deployer = NetBSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess, patch(
            "os.makedirs"
        ), patch("builtins.open", mock_open()):
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is True
            assert result["config_file"] == "/usr/pkg/etc/otelcol/config.yaml"

    @pytest.mark.asyncio
    async def test_deploy_install_failure(self):
        """Test NetBSD deployment with installation failure."""
        agent_instance = MagicMock()
        deployer = NetBSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"pkgin failed")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_remove_success(self):
        """Test successful NetBSD removal."""
        agent_instance = MagicMock()
        deployer = NetBSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_subprocess.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.remove()

            assert result["success"] is True


class TestBSDOtelDeployer:
    """Test suite for generic BSD OpenTelemetry deployer."""

    @pytest.mark.asyncio
    async def test_deploy_returns_error(self):
        """Test that generic BSD deploy returns error."""
        agent_instance = MagicMock()
        deployer = BSDOtelDeployer(agent_instance)

        result = await deployer.deploy("http://grafana.example.com")

        assert result["success"] is False
        assert "should not be called directly" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_success(self):
        """Test generic BSD removal."""
        agent_instance = MagicMock()
        deployer = BSDOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.remove()

            assert result["success"] is True


class TestLinuxOtelDeployer:
    """Test suite for Linux OpenTelemetry deployer."""

    @pytest.mark.asyncio
    async def test_deploy_with_apt(self):
        """Test Linux deployment with apt package manager."""
        agent_instance = MagicMock()
        deployer = LinuxOtelDeployer(agent_instance)

        with patch("os.path.exists") as mock_exists, patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch("os.makedirs"), patch(
            "builtins.open", mock_open()
        ), patch(
            "tempfile.NamedTemporaryFile"
        ) as mock_tempfile, patch(
            "os.unlink"
        ), patch(
            "os.chmod"
        ):
            # Configure mocks
            mock_exists.side_effect = lambda path: path == "/usr/bin/apt"

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"fake deb content", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            # Mock temp file
            mock_temp = MagicMock()
            mock_temp.name = "/tmp/test.deb"
            mock_temp.__enter__ = MagicMock(return_value=mock_temp)
            mock_temp.__exit__ = MagicMock(return_value=False)
            mock_tempfile.return_value = mock_temp

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is True
            assert "config_file" in result

    @pytest.mark.asyncio
    async def test_deploy_with_yum(self):
        """Test Linux deployment with yum package manager."""
        agent_instance = MagicMock()
        deployer = LinuxOtelDeployer(agent_instance)

        with patch("os.path.exists") as mock_exists, patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch("os.makedirs"), patch(
            "builtins.open", mock_open()
        ), patch(
            "os.chmod"
        ):
            mock_exists.side_effect = lambda path: path == "/usr/bin/yum"

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_with_dnf(self):
        """Test Linux deployment with dnf package manager."""
        agent_instance = MagicMock()
        deployer = LinuxOtelDeployer(agent_instance)

        with patch("os.path.exists") as mock_exists, patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch("os.makedirs"), patch(
            "builtins.open", mock_open()
        ), patch(
            "os.chmod"
        ):
            mock_exists.side_effect = lambda path: path == "/usr/bin/dnf"

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_deploy_no_package_manager(self):
        """Test Linux deployment with no supported package manager."""
        agent_instance = MagicMock()
        deployer = LinuxOtelDeployer(agent_instance)

        with patch("os.path.exists", return_value=False):
            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "No supported package manager" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_apt_download_failure(self):
        """Test Linux deployment with download failure."""
        agent_instance = MagicMock()
        deployer = LinuxOtelDeployer(agent_instance)

        with patch("os.path.exists") as mock_exists, patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess:
            mock_exists.side_effect = lambda path: path == "/usr/bin/apt"

            # First call succeeds (prerequisites), second fails (download)
            call_count = [0]

            async def side_effect(*args, **kwargs):
                mock_process = AsyncMock()
                if call_count[0] == 0:
                    mock_process.communicate.return_value = (b"", b"")
                    mock_process.returncode = 0
                else:
                    mock_process.communicate.return_value = (b"", b"Download failed")
                    mock_process.returncode = 1
                call_count[0] += 1
                return mock_process

            mock_subprocess.side_effect = side_effect

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_remove_with_apt(self):
        """Test Linux removal with apt."""
        agent_instance = MagicMock()
        deployer = LinuxOtelDeployer(agent_instance)

        with patch("os.path.exists") as mock_exists, patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch("shutil.rmtree"):
            mock_exists.side_effect = lambda path: path in [
                "/usr/bin/apt",
                "/etc/otelcol-contrib",
            ]

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.remove()

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_with_yum(self):
        """Test Linux removal with yum."""
        agent_instance = MagicMock()
        deployer = LinuxOtelDeployer(agent_instance)

        with patch("os.path.exists") as mock_exists, patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch("shutil.rmtree"):
            mock_exists.side_effect = lambda path: path in [
                "/usr/bin/yum",
                "/etc/otelcol-contrib",
            ]

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.remove()

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_with_dnf(self):
        """Test Linux removal with dnf."""
        agent_instance = MagicMock()
        deployer = LinuxOtelDeployer(agent_instance)

        with patch("os.path.exists") as mock_exists, patch(
            "asyncio.create_subprocess_exec"
        ) as mock_subprocess, patch("shutil.rmtree"):
            mock_exists.side_effect = lambda path: path in [
                "/usr/bin/dnf",
                "/etc/otelcol-contrib",
            ]

            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.remove()

            assert result["success"] is True


class TestMacOSOtelDeployer:
    """Test suite for macOS OpenTelemetry deployer."""

    @pytest.mark.asyncio
    async def test_deploy_success(self):
        """Test successful macOS deployment."""
        agent_instance = MagicMock()
        deployer = MacOSOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess, patch(
            "os.makedirs"
        ), patch("builtins.open", mock_open()):
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is True
            assert result["config_file"] == "/usr/local/etc/otelcol-contrib/config.yaml"

    @pytest.mark.asyncio
    async def test_deploy_install_failure(self):
        """Test macOS deployment with installation failure."""
        agent_instance = MagicMock()
        deployer = MacOSOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"brew install failed")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "Failed to install" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_exception(self):
        """Test macOS deployment with exception."""
        agent_instance = MagicMock()
        deployer = MacOSOtelDeployer(agent_instance)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "Test error" in result["error"]

    @pytest.mark.asyncio
    async def test_remove_success(self):
        """Test successful macOS removal."""
        agent_instance = MagicMock()
        deployer = MacOSOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.remove()

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_exception(self):
        """Test macOS removal with exception."""
        agent_instance = MagicMock()
        deployer = MacOSOtelDeployer(agent_instance)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Remove error")
        ):
            result = await deployer.remove()

            assert result["success"] is False


class TestWindowsOtelDeployer:
    """Test suite for Windows OpenTelemetry deployer."""

    @pytest.mark.asyncio
    async def test_deploy_success(self):
        """Test successful Windows deployment."""
        agent_instance = MagicMock()
        deployer = WindowsOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess, patch(
            "os.makedirs"
        ), patch("builtins.open", mock_open()):
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is True
            assert (
                result["config_file"]
                == "C:\\Program Files\\OpenTelemetry Collector\\config.yaml"
            )

    @pytest.mark.asyncio
    async def test_deploy_install_failure(self):
        """Test Windows deployment with installation failure."""
        agent_instance = MagicMock()
        deployer = WindowsOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"choco install failed")
            mock_process.returncode = 1
            mock_subprocess.return_value = mock_process

            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False
            assert "Failed to install" in result["error"]

    @pytest.mark.asyncio
    async def test_deploy_exception(self):
        """Test Windows deployment with exception."""
        agent_instance = MagicMock()
        deployer = WindowsOtelDeployer(agent_instance)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Test error")
        ):
            result = await deployer.deploy("http://grafana.example.com")

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_remove_success(self):
        """Test successful Windows removal."""
        agent_instance = MagicMock()
        deployer = WindowsOtelDeployer(agent_instance)

        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process

            result = await deployer.remove()

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_remove_exception(self):
        """Test Windows removal with exception."""
        agent_instance = MagicMock()
        deployer = WindowsOtelDeployer(agent_instance)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=Exception("Remove error")
        ):
            result = await deployer.remove()

            assert result["success"] is False
