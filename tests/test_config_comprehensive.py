"""
Comprehensive unit tests for src.sysmanage_agent.core.config module.
Tests configuration management with YAML files and security priority.
"""

# pylint: disable=attribute-defined-outside-init

from unittest.mock import patch, mock_open

import pytest
import yaml

from src.sysmanage_agent.core.config import ConfigManager


class TestConfigManager:  # pylint: disable=too-many-public-methods
    """Test cases for ConfigManager class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.test_config_data = {
            "server": {
                "hostname": "test.example.com",
                "port": 9000,
                "use_https": True,
                "verify_ssl": False,
                "api_path": "/custom-api",
            },
            "client": {
                "hostname_override": "custom-hostname",
                "registration_retry_interval": 60,
                "max_registration_retries": 5,
                "update_check_interval": 7200,
            },
            "logging": {
                "level": "DEBUG|INFO|ERROR",
                "format": "%(asctime)s - %(levelname)s - %(message)s",
                "file": "/var/log/test.log",
            },
            "websocket": {
                "auto_reconnect": False,
                "reconnect_interval": 10,
                "ping_interval": 60,
            },
            "i18n": {"language": "fr"},
            "script_execution": {
                "enabled": True,
                "timeout": 600,
                "max_concurrent": 5,
                "allowed_shells": ["bash", "sh", "zsh"],
                "max_timeout": 7200,
                "user_restrictions": {
                    "allow_user_switching": True,
                    "allowed_users": ["root", "admin"],
                },
                "security": {
                    "restricted_paths": ["/etc", "/var"],
                    "audit_logging": False,
                    "require_approval": True,
                },
            },
        }

    @patch("os.path.exists", return_value=True)
    def test_determine_config_path_absolute_path(self, mock_exists):
        """Test config path determination with absolute path."""
        with patch("builtins.open", mock_open(read_data="{}")):
            config = ConfigManager("/absolute/path/config.yaml")
            assert config.config_file == "/absolute/path/config.yaml"

    @patch("os.name", "nt")
    @patch("os.path.exists")
    def test_determine_config_path_windows_system(self, mock_exists):
        """Test config path determination on Windows with system config."""
        mock_exists.side_effect = (
            lambda path: path == r"C:\ProgramData\SysManage\sysmanage-agent.yaml"
        )

        with patch("builtins.open", mock_open(read_data="{}")):
            config = ConfigManager("test-config.yaml")
            assert (
                config.config_file == r"C:\ProgramData\SysManage\sysmanage-agent.yaml"
            )

    @patch("os.name", "posix")
    @patch("os.path.exists")
    def test_determine_config_path_unix_system(self, mock_exists):
        """Test config path determination on Unix with system config."""
        mock_exists.side_effect = lambda path: path == "/etc/sysmanage-agent.yaml"

        with patch("builtins.open", mock_open(read_data="{}")):
            config = ConfigManager("test-config.yaml")
            assert config.config_file == "/etc/sysmanage-agent.yaml"

    @patch("os.path.exists")
    def test_determine_config_path_local_config(self, mock_exists):
        """Test config path determination with local config."""
        mock_exists.side_effect = lambda path: path == "./sysmanage-agent.yaml"

        with patch("builtins.open", mock_open(read_data="{}")):
            config = ConfigManager("test-config.yaml")
            assert config.config_file == "./sysmanage-agent.yaml"

    @patch("os.path.exists")
    def test_determine_config_path_backward_compatibility(self, mock_exists):
        """Test config path determination with backward compatibility."""
        mock_exists.side_effect = lambda path: path == "test-config.yaml"

        with patch("builtins.open", mock_open(read_data="{}")):
            config = ConfigManager("test-config.yaml")
            assert config.config_file == "test-config.yaml"

    @patch("os.name", "nt")
    @patch("os.path.exists", return_value=False)
    def test_determine_config_path_default_windows(self, mock_exists):
        """Test config path determination default on Windows."""
        with pytest.raises(FileNotFoundError):
            ConfigManager("test-config.yaml")

    @patch("os.name", "posix")
    @patch("os.path.exists", return_value=False)
    def test_determine_config_path_default_unix(self, mock_exists):
        """Test config path determination default on Unix."""
        with pytest.raises(FileNotFoundError):
            ConfigManager("test-config.yaml")

    @patch("os.name", "nt")
    @patch("os.path.exists", return_value=False)
    def test_load_config_file_not_found_windows(self, mock_exists):
        """Test loading config when file not found on Windows."""
        with pytest.raises(FileNotFoundError) as exc_info:
            ConfigManager("nonexistent.yaml")

        assert (
            "C:\\ProgramData\\SysManage\\sysmanage-agent.yaml or ./sysmanage-agent.yaml"
            in str(exc_info.value)
        )

    @patch("os.name", "posix")
    @patch("os.path.exists", return_value=False)
    def test_load_config_file_not_found_unix(self, mock_exists):
        """Test loading config when file not found on Unix."""
        with pytest.raises(FileNotFoundError) as exc_info:
            ConfigManager("nonexistent.yaml")

        assert "/etc/sysmanage-agent.yaml or ./sysmanage-agent.yaml" in str(
            exc_info.value
        )

    @patch("os.path.exists", return_value=True)
    def test_load_config_yaml_error(self, mock_exists):
        """Test loading config with YAML error."""
        invalid_yaml = "invalid: yaml: content: ["

        with patch("builtins.open", mock_open(read_data=invalid_yaml)):
            with pytest.raises(ValueError) as exc_info:
                ConfigManager("test-config.yaml")

            assert "Invalid YAML in configuration file" in str(exc_info.value)

    @patch("os.path.exists", return_value=True)
    def test_load_config_file_error(self, mock_exists):
        """Test loading config with file read error."""
        with patch("builtins.open", side_effect=OSError("Permission denied")):
            with pytest.raises(RuntimeError) as exc_info:
                ConfigManager("test-config.yaml")

            assert "Failed to load configuration file" in str(exc_info.value)

    @patch("os.path.exists", return_value=True)
    def test_load_config_empty_file(self, mock_exists):
        """Test loading config with empty YAML file."""
        with patch("builtins.open", mock_open(read_data="")):
            config = ConfigManager("test-config.yaml")
            assert config.config_data == {}

    @patch("os.path.exists", return_value=True)
    def test_load_config_success(self, mock_exists):
        """Test successful config loading."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            assert config.config_data == self.test_config_data

    @patch("os.path.exists", return_value=True)
    def test_get_simple_key(self, mock_exists):
        """Test getting simple configuration key."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            assert config.get("server") == self.test_config_data["server"]

    @patch("os.path.exists", return_value=True)
    def test_get_nested_key(self, mock_exists):
        """Test getting nested configuration key."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            assert config.get("server.hostname") == "test.example.com"
            assert config.get("server.port") == 9000

    def test_get_nonexistent_key_with_default(self):
        """Test getting non-existent key with default value."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        assert config.get("nonexistent.key", "default_value") == "default_value"

    def test_get_key_type_error(self):
        """Test getting key when config data is not a dict."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = "not_a_dict"

        assert config.get("any.key", "default") == "default"

    @patch("os.path.exists", return_value=True)
    def test_get_server_config(self, mock_exists):
        """Test getting server configuration section."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            server_config = config.get_server_config()
            assert server_config == self.test_config_data["server"]

    @patch("os.path.exists", return_value=True)
    def test_get_client_config(self, mock_exists):
        """Test getting client configuration section."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            client_config = config.get_client_config()
            assert client_config == self.test_config_data["client"]

    @patch("os.path.exists", return_value=True)
    def test_get_logging_config(self, mock_exists):
        """Test getting logging configuration section."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            logging_config = config.get_logging_config()
            assert logging_config == self.test_config_data["logging"]

    @patch("os.path.exists", return_value=True)
    def test_get_websocket_config(self, mock_exists):
        """Test getting WebSocket configuration section."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            websocket_config = config.get_websocket_config()
            assert websocket_config == self.test_config_data["websocket"]

    @patch("os.path.exists", return_value=True)
    def test_get_i18n_config(self, mock_exists):
        """Test getting i18n configuration section."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            i18n_config = config.get_i18n_config()
            assert i18n_config == self.test_config_data["i18n"]

    @patch("os.path.exists", return_value=True)
    def test_get_server_url_https(self, mock_exists):
        """Test building server WebSocket URL with HTTPS."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            url = config.get_server_url()
            assert url == "wss://test.example.com:9000/api/agent/connect"

    @patch("os.path.exists", return_value=True)
    def test_get_server_url_http(self, mock_exists):
        """Test building server WebSocket URL with HTTP."""
        config_data = self.test_config_data.copy()
        config_data["server"]["use_https"] = False
        yaml_content = yaml.dump(config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            url = config.get_server_url()
            assert url == "ws://test.example.com:9000/api/agent/connect"

    def test_get_server_url_defaults(self):
        """Test building server WebSocket URL with defaults."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        url = config.get_server_url()
        assert url == "ws://localhost:8000/api/agent/connect"

    @patch("os.path.exists", return_value=True)
    def test_get_server_rest_url_https(self, mock_exists):
        """Test building server REST URL with HTTPS."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            url = config.get_server_rest_url()
            assert url == "https://test.example.com:9000/custom-api"

    @patch("os.path.exists", return_value=True)
    def test_get_server_rest_url_http(self, mock_exists):
        """Test building server REST URL with HTTP."""
        config_data = self.test_config_data.copy()
        config_data["server"]["use_https"] = False
        yaml_content = yaml.dump(config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            url = config.get_server_rest_url()
            assert url == "http://test.example.com:9000/custom-api"

    def test_get_server_rest_url_defaults(self):
        """Test building server REST URL with defaults."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        url = config.get_server_rest_url()
        assert url == "http://localhost:8000/api"

    @patch("os.path.exists", return_value=True)
    def test_get_hostname_override(self, mock_exists):
        """Test getting hostname override."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            override = config.get_hostname_override()
            assert override == "custom-hostname"

    def test_get_hostname_override_none(self):
        """Test getting hostname override when none set."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        override = config.get_hostname_override()
        assert override is None

    @patch("os.path.exists", return_value=True)
    def test_get_registration_retry_interval(self, mock_exists):
        """Test getting registration retry interval."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            interval = config.get_registration_retry_interval()
            assert interval == 60

    def test_get_registration_retry_interval_default(self):
        """Test getting registration retry interval default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        interval = config.get_registration_retry_interval()
        assert interval == 30

    @patch("os.path.exists", return_value=True)
    def test_get_max_registration_retries(self, mock_exists):
        """Test getting max registration retries."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            retries = config.get_max_registration_retries()
            assert retries == 5

    def test_get_max_registration_retries_default(self):
        """Test getting max registration retries default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        retries = config.get_max_registration_retries()
        assert retries == 10

    @patch("os.path.exists", return_value=True)
    def test_get_log_level(self, mock_exists):
        """Test getting log level."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            level = config.get_log_level()
            assert level == "DEBUG|INFO|ERROR"

    def test_get_log_level_default(self):
        """Test getting log level default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        level = config.get_log_level()
        assert level == "INFO"

    @patch("os.path.exists", return_value=True)
    def test_get_log_file(self, mock_exists):
        """Test getting log file path."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            log_file = config.get_log_file()
            assert log_file == "/var/log/test.log"

    def test_get_log_file_none(self):
        """Test getting log file when none set."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        log_file = config.get_log_file()
        assert log_file is None

    @patch("os.path.exists", return_value=True)
    def test_get_log_format(self, mock_exists):
        """Test getting log format."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            log_format = config.get_log_format()
            assert log_format == "%(asctime)s - %(levelname)s - %(message)s"

    def test_get_log_format_default(self):
        """Test getting log format default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        log_format = config.get_log_format()
        assert log_format == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    @patch("os.path.exists", return_value=True)
    def test_get_log_levels(self, mock_exists):
        """Test getting log levels configuration."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            levels = config.get_log_levels()
            assert levels == "DEBUG|INFO|ERROR"

    def test_get_log_levels_default(self):
        """Test getting log levels default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        levels = config.get_log_levels()
        assert levels == "INFO|WARNING|ERROR|CRITICAL"

    @patch("os.path.exists", return_value=True)
    def test_should_auto_reconnect(self, mock_exists):
        """Test getting auto reconnect setting."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            auto_reconnect = config.should_auto_reconnect()
            assert auto_reconnect is False

    def test_should_auto_reconnect_default(self):
        """Test getting auto reconnect default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        auto_reconnect = config.should_auto_reconnect()
        assert auto_reconnect is True

    @patch("os.path.exists", return_value=True)
    def test_get_reconnect_interval(self, mock_exists):
        """Test getting reconnect interval."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            interval = config.get_reconnect_interval()
            assert interval == 10

    def test_get_reconnect_interval_default(self):
        """Test getting reconnect interval default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        interval = config.get_reconnect_interval()
        assert interval == 5

    @patch("os.path.exists", return_value=True)
    def test_get_ping_interval(self, mock_exists):
        """Test getting ping interval."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            interval = config.get_ping_interval()
            assert interval == 60

    def test_get_ping_interval_default(self):
        """Test getting ping interval default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        interval = config.get_ping_interval()
        assert interval == 30

    @patch("os.path.exists", return_value=True)
    def test_get_language(self, mock_exists):
        """Test getting language setting."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            language = config.get_language()
            assert language == "fr"

    def test_get_language_default(self):
        """Test getting language default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        language = config.get_language()
        assert language == "en"

    @patch("os.path.exists", return_value=True)
    def test_should_verify_ssl(self, mock_exists):
        """Test getting SSL verification setting."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            verify_ssl = config.should_verify_ssl()
            assert verify_ssl is False

    def test_should_verify_ssl_default(self):
        """Test getting SSL verification default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        verify_ssl = config.should_verify_ssl()
        assert verify_ssl is True

    @patch("os.path.exists", return_value=True)
    def test_get_update_check_interval(self, mock_exists):
        """Test getting update check interval."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            interval = config.get_update_check_interval()
            assert interval == 7200

    def test_get_update_check_interval_default(self):
        """Test getting update check interval default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        interval = config.get_update_check_interval()
        assert interval == 3600

    @patch("os.path.exists", return_value=True)
    def test_get_script_execution_config(self, mock_exists):
        """Test getting script execution configuration."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            script_config = config.get_script_execution_config()
            assert script_config == self.test_config_data["script_execution"]

    def test_get_script_execution_config_default(self):
        """Test getting script execution configuration default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        script_config = config.get_script_execution_config()
        assert script_config == {}

    @patch("os.path.exists", return_value=True)
    def test_is_script_execution_enabled(self, mock_exists):
        """Test checking if script execution is enabled."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            enabled = config.is_script_execution_enabled()
            assert enabled is True

    def test_is_script_execution_enabled_default(self):
        """Test checking if script execution is enabled default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        enabled = config.is_script_execution_enabled()
        assert enabled is False

    @patch("os.path.exists", return_value=True)
    def test_get_script_execution_timeout(self, mock_exists):
        """Test getting script execution timeout."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            timeout = config.get_script_execution_timeout()
            assert timeout == 600

    def test_get_script_execution_timeout_default(self):
        """Test getting script execution timeout default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        timeout = config.get_script_execution_timeout()
        assert timeout == 300

    @patch("os.path.exists", return_value=True)
    def test_get_max_concurrent_scripts(self, mock_exists):
        """Test getting max concurrent scripts."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            max_concurrent = config.get_max_concurrent_scripts()
            assert max_concurrent == 5

    def test_get_max_concurrent_scripts_default(self):
        """Test getting max concurrent scripts default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        max_concurrent = config.get_max_concurrent_scripts()
        assert max_concurrent == 3

    @patch("os.path.exists", return_value=True)
    def test_get_allowed_shells(self, mock_exists):
        """Test getting allowed shells."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            shells = config.get_allowed_shells()
            assert shells == ["bash", "sh", "zsh"]

    def test_get_allowed_shells_default(self):
        """Test getting allowed shells default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        shells = config.get_allowed_shells()
        assert shells == ["bash", "sh"]

    @patch("os.path.exists", return_value=True)
    def test_get_max_script_timeout(self, mock_exists):
        """Test getting max script timeout."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            max_timeout = config.get_max_script_timeout()
            assert max_timeout == 7200

    def test_get_max_script_timeout_default(self):
        """Test getting max script timeout default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        max_timeout = config.get_max_script_timeout()
        assert max_timeout == 3600

    @patch("os.path.exists", return_value=True)
    def test_is_user_switching_allowed(self, mock_exists):
        """Test checking if user switching is allowed."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            allowed = config.is_user_switching_allowed()
            assert allowed is True

    def test_is_user_switching_allowed_default(self):
        """Test checking if user switching is allowed default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        allowed = config.is_user_switching_allowed()
        assert allowed is False

    @patch("os.path.exists", return_value=True)
    def test_get_allowed_users(self, mock_exists):
        """Test getting allowed users."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            users = config.get_allowed_users()
            assert users == ["root", "admin"]

    def test_get_allowed_users_default(self):
        """Test getting allowed users default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        users = config.get_allowed_users()
        assert users == []

    @patch("os.path.exists", return_value=True)
    def test_get_restricted_paths(self, mock_exists):
        """Test getting restricted paths."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            paths = config.get_restricted_paths()
            assert paths == ["/etc", "/var"]

    def test_get_restricted_paths_default(self):
        """Test getting restricted paths default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        paths = config.get_restricted_paths()
        assert paths == []

    @patch("os.path.exists", return_value=True)
    def test_is_audit_logging_enabled(self, mock_exists):
        """Test checking if audit logging is enabled."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            enabled = config.is_audit_logging_enabled()
            assert enabled is False

    def test_is_audit_logging_enabled_default(self):
        """Test checking if audit logging is enabled default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        enabled = config.is_audit_logging_enabled()
        assert enabled is True

    @patch("os.path.exists", return_value=True)
    def test_is_script_approval_required(self, mock_exists):
        """Test checking if script approval is required."""
        yaml_content = yaml.dump(self.test_config_data)

        with patch("builtins.open", mock_open(read_data=yaml_content)):
            config = ConfigManager("test-config.yaml")
            required = config.is_script_approval_required()
            assert required is True

    def test_is_script_approval_required_default(self):
        """Test checking if script approval is required default."""
        config = ConfigManager.__new__(ConfigManager)
        config.config_data = {}

        required = config.is_script_approval_required()
        assert required is False
