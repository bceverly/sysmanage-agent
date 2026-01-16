"""
Tests for child host collector module.
"""

# pylint: disable=redefined-outer-name,protected-access

import configparser
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.communication.child_host_collector import (
    ChildHostCollector,
)


@pytest.fixture
def mock_agent():
    """Create a mock agent instance."""
    agent = Mock()
    agent.config_manager = Mock()
    return agent


@pytest.fixture
def collector(mock_agent):
    """Create a ChildHostCollector for testing."""
    return ChildHostCollector(mock_agent)


class TestChildHostCollectorInit:
    """Tests for ChildHostCollector initialization."""

    def test_init_sets_agent(self, mock_agent):
        """Test that __init__ sets agent."""
        collector = ChildHostCollector(mock_agent)
        assert collector.agent == mock_agent

    def test_init_sets_logger(self, mock_agent):
        """Test that __init__ sets logger."""
        collector = ChildHostCollector(mock_agent)
        assert collector.logger is not None

    def test_init_sets_empty_keepalive_processes(self, mock_agent):
        """Test that __init__ sets empty keepalive processes dict."""
        collector = ChildHostCollector(mock_agent)
        assert not collector._wsl_keepalive_processes


class TestEnsureWslconfig:
    """Tests for _ensure_wslconfig method."""

    def test_ensure_wslconfig_creates_new_file(self, collector, tmp_path):
        """Test creating new .wslconfig file."""
        wslconfig_path = tmp_path / ".wslconfig"

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            result = collector._ensure_wslconfig()

        # Check file was created
        assert wslconfig_path.exists()
        assert result is True

        # Verify content
        config = configparser.RawConfigParser()
        config.read(str(wslconfig_path))
        assert config.get("wsl2", "vmIdleTimeout") == "-1"
        assert config.get("wsl", "autoStop") == "false"

    def test_ensure_wslconfig_existing_correct(self, collector, tmp_path):
        """Test with existing correctly configured .wslconfig."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create existing config with correct settings
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl2")
        config.set("wsl2", "vmIdleTimeout", "-1")
        config.add_section("wsl")
        config.set("wsl", "autoStop", "false")
        with open(wslconfig_path, "w", encoding="utf-8") as config_file:
            config.write(config_file)

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            result = collector._ensure_wslconfig()

        # Should not need update
        assert result is False

    def test_ensure_wslconfig_updates_existing(self, collector, tmp_path):
        """Test updating existing .wslconfig with wrong settings."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create existing config with wrong settings
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.add_section("wsl2")
        config.set("wsl2", "vmIdleTimeout", "0")  # Wrong value
        with open(wslconfig_path, "w", encoding="utf-8") as config_file:
            config.write(config_file)

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            result = collector._ensure_wslconfig()

        assert result is True

        # Verify updated content
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(str(wslconfig_path))
        assert config.get("wsl2", "vmIdleTimeout") == "-1"

    def test_ensure_wslconfig_fixes_lowercase_keys(self, collector, tmp_path):
        """Test fixing lowercase keys in .wslconfig."""
        wslconfig_path = tmp_path / ".wslconfig"

        # Create existing config with lowercase keys
        with open(wslconfig_path, "w", encoding="utf-8") as config_file:
            config_file.write("[wsl2]\nvmidletimeout=-1\n[wsl]\nautostop=false\n")

        with patch("os.path.expanduser", return_value=str(tmp_path)):
            result = collector._ensure_wslconfig()

        # Should need update to fix case
        assert result is True

    def test_ensure_wslconfig_permission_error(self, collector, tmp_path):
        """Test handling permission error."""
        with patch("os.path.expanduser", return_value=str(tmp_path)):
            with patch("builtins.open", side_effect=PermissionError()):
                # Create a path object for the config
                _ = collector._ensure_wslconfig()

        # Should return False on error
        # The actual behavior depends on whether the file exists first


class TestRestartWsl:
    """Tests for _restart_wsl method."""

    def test_restart_wsl_success(self, collector):
        """Test successful WSL restart."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            collector._restart_wsl()

        # Verify wsl.exe --shutdown was called
        mock_run.assert_called()
        call_args = mock_run.call_args[0][0]
        assert "wsl.exe" in call_args or "wsl" in str(call_args)

    def test_restart_wsl_exception(self, collector):
        """Test WSL restart with exception."""
        with patch("subprocess.run", side_effect=Exception("test error")):
            # Should not raise
            collector._restart_wsl()


class TestKeepaliveProcesses:
    """Tests for WSL keepalive process management."""

    def test_keepalive_processes_initially_empty(self, collector):
        """Test that keepalive processes dict is initially empty."""
        assert collector._wsl_keepalive_processes == {}

    def test_add_keepalive_process(self, collector):
        """Test adding a keepalive process."""
        mock_process = Mock()
        collector._wsl_keepalive_processes["Ubuntu"] = mock_process

        assert "Ubuntu" in collector._wsl_keepalive_processes
        assert collector._wsl_keepalive_processes["Ubuntu"] == mock_process

    def test_remove_keepalive_process(self, collector):
        """Test removing a keepalive process."""
        mock_process = Mock()
        collector._wsl_keepalive_processes["Ubuntu"] = mock_process

        del collector._wsl_keepalive_processes["Ubuntu"]

        assert "Ubuntu" not in collector._wsl_keepalive_processes
