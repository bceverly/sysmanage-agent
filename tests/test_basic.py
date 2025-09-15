"""
Basic tests for SysManage Agent components.
"""

import os
import tempfile as temp_module
import unittest.mock
import yaml as yaml_module

import main
from src.sysmanage_agent.registration import registration
from src.sysmanage_agent.core.config import ConfigManager
from main import SysManageAgent


def test_config_manager_basic():
    """Test basic ConfigManager functionality."""
    config_data = {"server": {"hostname": "test.example.com", "port": 8443}}

    with temp_module.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml_module.dump(config_data, f)
        f.flush()
        temp_file_name = f.name

    try:
        config = ConfigManager(temp_file_name)
        assert config.get("server.hostname") == "test.example.com"  # nosec B101
        assert config.get("server.port") == 8443  # nosec B101
    finally:
        if os.path.exists(temp_file_name):
            os.unlink(temp_file_name)


def test_config_manager_defaults():
    """Test ConfigManager default values."""
    config_data = {}

    with temp_module.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml_module.dump(config_data, f)
        f.flush()
        temp_file_name = f.name

    try:
        config = ConfigManager(temp_file_name)
        assert config.get_log_level() == "INFO"  # nosec B101
        assert config.get_registration_retry_interval() == 30  # nosec B101
    finally:
        if os.path.exists(temp_file_name):
            os.unlink(temp_file_name)


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
        temp_file_name = f.name

    try:
        config = ConfigManager(temp_file_name)
        url = config.get_server_url()
        assert url == "wss://secure.example.com:8443/api/agent/connect"  # nosec B101

        rest_url = config.get_server_rest_url()
        assert rest_url == "https://secure.example.com:8443/api"  # nosec B101
    finally:
        if os.path.exists(temp_file_name):
            os.unlink(temp_file_name)


def test_import_main_module():
    """Test that main module can be imported."""
    assert hasattr(main, "SysManageAgent")  # nosec B101


def test_import_registration_module():
    """Test that registration module can be imported."""
    assert hasattr(registration, "ClientRegistration")  # nosec B101


def test_agent_basic_creation():
    """Test basic agent creation."""
    config_data = {"server": {"hostname": "test.com"}, "logging": {"level": "INFO"}}

    with temp_module.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml_module.dump(config_data, f)
        f.flush()
        temp_file_name = f.name

    try:
        # Mock logging and database initialization to avoid setup issues
        with unittest.mock.patch("main.logging"), unittest.mock.patch(
            "main.initialize_database", return_value=True
        ):
            agent = SysManageAgent(temp_file_name)
            assert agent.config is not None  # nosec B101
            assert agent.agent_id is not None  # nosec B101
            assert len(agent.agent_id) == 36  # UUID4 length  # nosec B101
    finally:
        if os.path.exists(temp_file_name):
            os.unlink(temp_file_name)
