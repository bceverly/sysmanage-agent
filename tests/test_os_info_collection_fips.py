"""
Tests for FIPS compliance-mode detection in the OS information collector
(Phase 14.4).
"""

import subprocess
from unittest.mock import MagicMock, mock_open, patch

import pytest

from src.sysmanage_agent.collection.os_info_collection import OSInfoCollector


class TestGetFipsModeInfo:
    """Tests for OSInfoCollector.get_fips_mode_info across platforms."""

    @pytest.fixture
    def collector(self):
        """Create an OS info collector instance for testing."""
        return OSInfoCollector()

    @patch("platform.system", return_value="Darwin")
    def test_macos_is_not_applicable(self, _sys, collector):
        """macOS has no OS-level FIPS mode."""
        info = collector.get_fips_mode_info()
        assert info["status"] == "not_applicable"
        assert info["enabled"] is False
        assert info["available"] is False

    @patch("platform.system", return_value="FreeBSD")
    def test_bsd_is_not_applicable(self, _sys, collector):
        """The BSDs have no OS-level FIPS mode."""
        assert collector.get_fips_mode_info()["status"] == "not_applicable"

    @patch("platform.system", return_value="Linux")
    def test_kernel_flag_enables(self, _sys, collector):
        """A set /proc fips flag marks FIPS enabled + kernel enforced."""
        with patch("builtins.open", mock_open(read_data="1\n")), patch(
            "subprocess.run", side_effect=FileNotFoundError()
        ):
            info = collector.get_fips_mode_info()
        assert info["enabled"] is True
        assert info["kernel_enforced"] is True
        assert info["status"] == "enabled"

    @patch("platform.system", return_value="Linux")
    def test_linux_disabled_default(self, _sys, collector):
        """Linux with nothing reporting FIPS resolves to disabled."""
        with patch("builtins.open", side_effect=OSError()), patch(
            "subprocess.run", side_effect=FileNotFoundError()
        ):
            info = collector.get_fips_mode_info()
        assert info["status"] == "disabled"
        assert info["enabled"] is False

    @patch("platform.system", return_value="Linux")
    def test_rhel_fips_enabled(self, _sys, collector):
        """fips-mode-setup reporting 'enabled' is detected on RHEL."""

        def _run(cmd, **_kw):
            result = MagicMock()
            if cmd[0] == "fips-mode-setup":
                result.stdout = "FIPS mode is enabled.\n"
                result.returncode = 0
            else:  # pro
                raise FileNotFoundError()
            return result

        with patch("builtins.open", side_effect=OSError()), patch(
            "subprocess.run", side_effect=_run
        ):
            info = collector.get_fips_mode_info()
        assert info["available"] is True
        assert info["enabled"] is True
        assert info["vendor"] == "rhel"
        assert info["status"] == "enabled"

    @patch("platform.system", return_value="Linux")
    def test_ubuntu_pro_available(self, _sys, collector):
        """Ubuntu Pro exposing a disabled fips service => available, off."""
        pro_json = (
            '{"services": [{"name": "fips", "status": "disabled"},'
            ' {"name": "esm-infra", "status": "enabled"}]}'
        )

        def _run(cmd, **_kw):
            result = MagicMock()
            if cmd[0] == "fips-mode-setup":
                raise FileNotFoundError()
            result.returncode = 0
            result.stdout = pro_json
            return result

        with patch("builtins.open", side_effect=OSError()), patch(
            "subprocess.run", side_effect=_run
        ):
            info = collector.get_fips_mode_info()
        assert info["available"] is True
        assert info["vendor"] == "ubuntu-pro"
        assert info["enabled"] is False
        assert info["status"] == "available"

    @patch("platform.system", return_value="Windows")
    def test_windows_fips_enabled(self, _sys, collector):
        """Windows FipsAlgorithmPolicy=0x1 is detected as enabled."""
        result = MagicMock()
        result.stdout = "    Enabled    REG_DWORD    0x1\n"
        with patch("subprocess.run", return_value=result):
            info = collector.get_fips_mode_info()
        assert info["vendor"] == "windows"
        assert info["enabled"] is True
        assert info["status"] == "enabled"

    @patch("platform.system", return_value="Windows")
    def test_windows_fips_disabled(self, _sys, collector):
        """Windows FipsAlgorithmPolicy=0x0 is detected as disabled."""
        result = MagicMock()
        result.stdout = "    Enabled    REG_DWORD    0x0\n"
        with patch("subprocess.run", return_value=result):
            info = collector.get_fips_mode_info()
        assert info["enabled"] is False
        assert info["status"] == "disabled"

    @patch("platform.system", return_value="Linux")
    def test_tool_timeout_swallowed(self, _sys, collector):
        """A detection-tool timeout does not raise; status stays disabled."""
        with patch("builtins.open", side_effect=OSError()), patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired("x", 10)
        ):
            info = collector.get_fips_mode_info()
        assert info["status"] == "disabled"
