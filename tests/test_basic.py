"""
Basic tests for SysManage Agent components.
"""

import os
import tempfile as temp_module
import unittest.mock
import yaml as yaml_module

import main
import registration
from config import ConfigManager
from main import SysManageAgent


def test_config_manager_basic():
    """Test basic ConfigManager functionality."""
    config_data = {"server": {"hostname": "test.example.com", "port": 8443}}

    with temp_module.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml_module.dump(config_data, f)
        f.flush()

        config = ConfigManager(f.name)
        assert config.get("server.hostname") == "test.example.com"
        assert config.get("server.port") == 8443

        os.unlink(f.name)


def test_config_manager_defaults():
    """Test ConfigManager default values."""
    config_data = {}

    with temp_module.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml_module.dump(config_data, f)
        f.flush()

        config = ConfigManager(f.name)
        assert config.get_log_level() == "INFO"
        assert config.get_registration_retry_interval() == 30

        os.unlink(f.name)


def test_config_manager_url_building():
    """Test URL building functionality."""
    config_data = {
        "server": {
            "hostname": "secure.example.com",
            "port": 8443,
            "use_https": True,
            "api_path": "/api",
        }
    }

    with temp_module.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml_module.dump(config_data, f)
        f.flush()

        config = ConfigManager(f.name)
        url = config.get_server_url()
        assert url == "wss://secure.example.com:8443/api/agent/connect"

        rest_url = config.get_server_rest_url()
        assert rest_url == "https://secure.example.com:8443/api"

        os.unlink(f.name)


def test_import_main_module():
    """Test that main module can be imported."""
    assert hasattr(main, "SysManageAgent")


def test_import_registration_module():
    """Test that registration module can be imported."""
    assert hasattr(registration, "ClientRegistration")


def test_agent_basic_creation():
    """Test basic agent creation."""
    config_data = {"server": {"hostname": "test.com"}, "logging": {"level": "INFO"}}

    with temp_module.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml_module.dump(config_data, f)
        f.flush()

        try:
            # Mock logging to avoid setup issues
            with unittest.mock.patch("main.logging"):
                agent = SysManageAgent(f.name)
                assert agent.config is not None
                assert agent.agent_id is not None
                assert len(agent.agent_id) == 36  # UUID4 length
        finally:
            os.unlink(f.name)
