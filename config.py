"""
Configuration management for SysManage Agent.
Reads YAML configuration files and provides configuration data.
"""

import os
from typing import Any, Dict, Optional

import yaml


class ConfigManager:
    """Manages configuration for the SysManage Agent."""

    def __init__(self, config_file: str = "sysmanage-agent.yaml"):
        # Determine config file path with security priority
        self.config_file = self._determine_config_path(config_file)
        self.config_data: Dict[str, Any] = {}
        self.load_config()

    def _determine_config_path(self, default_filename: str) -> str:
        """
        Determine configuration file path with security priority.

        Priority order (security-first):
        1. If absolute path provided (e.g., for tests), use it directly
        2. /etc/sysmanage-agent.yaml (system config)
        3. ./sysmanage-agent.yaml (local config)
        4. Fallback to provided filename for backward compatibility
        """
        # If absolute path provided (tests, explicit config), use it directly
        if os.path.isabs(default_filename):
            return default_filename

        system_config = "/etc/sysmanage-agent.yaml"
        local_config = "./sysmanage-agent.yaml"

        if os.path.exists(system_config):
            return system_config
        if os.path.exists(local_config):
            return local_config
        if os.path.exists(default_filename):
            # Backward compatibility - warn but allow
            return default_filename
        # Default to system location for error message clarity
        return system_config

    def load_config(self) -> None:
        """Load configuration from YAML file."""
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(
                f"Configuration file '{self.config_file}' not found. "
                f"Expected locations: /etc/sysmanage-agent.yaml or ./sysmanage-agent.yaml"
            )

        try:
            with open(self.config_file, "r", encoding="utf-8") as file:
                self.config_data = yaml.safe_load(file) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in configuration file: {e}") from e
        except Exception as e:
            raise RuntimeError(f"Failed to load configuration file: {e}") from e

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            key_path: Dot-separated path to the configuration key (e.g., 'server.hostname')
            default: Default value if key is not found

        Returns:
            Configuration value or default
        """
        keys = key_path.split(".")
        value = self.config_data

        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default

    def get_server_config(self) -> Dict[str, Any]:
        """Get server configuration section."""
        return self.get("server", {})

    def get_client_config(self) -> Dict[str, Any]:
        """Get client configuration section."""
        return self.get("client", {})

    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration section."""
        return self.get("logging", {})

    def get_websocket_config(self) -> Dict[str, Any]:
        """Get WebSocket configuration section."""
        return self.get("websocket", {})

    def get_i18n_config(self) -> Dict[str, Any]:
        """Get internationalization configuration section."""
        return self.get("i18n", {})

    def get_server_url(self) -> str:
        """Build the complete server WebSocket URL."""
        server_config = self.get_server_config()

        hostname = server_config.get("hostname", "localhost")
        port = server_config.get("port", 8000)
        use_https = server_config.get("use_https", False)
        api_path = server_config.get("api_path", "/api")

        # Build WebSocket URL
        protocol = "wss" if use_https else "ws"
        return f"{protocol}://{hostname}:{port}{api_path}/agent/connect"

    def get_server_rest_url(self) -> str:
        """Build the complete server REST API URL."""
        server_config = self.get_server_config()

        hostname = server_config.get("hostname", "localhost")
        port = server_config.get("port", 8000)
        use_https = server_config.get("use_https", False)
        api_path = server_config.get("api_path", "/api")

        # Build REST URL
        protocol = "https" if use_https else "http"
        return f"{protocol}://{hostname}:{port}{api_path}"

    def get_hostname_override(self) -> Optional[str]:
        """Get hostname override if specified."""
        return self.get("client.hostname_override")

    def get_registration_retry_interval(self) -> int:
        """Get registration retry interval in seconds."""
        return self.get("client.registration_retry_interval", 30)

    def get_max_registration_retries(self) -> int:
        """Get maximum registration retry attempts."""
        return self.get("client.max_registration_retries", 10)

    def get_log_level(self) -> str:
        """Get logging level."""
        return self.get("logging.level", "INFO")

    def get_log_file(self) -> Optional[str]:
        """Get log file path if specified."""
        return self.get("logging.file")

    def get_log_format(self) -> str:
        """Get log format string."""
        return self.get(
            "logging.format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    def should_auto_reconnect(self) -> bool:
        """Check if WebSocket should auto-reconnect."""
        return self.get("websocket.auto_reconnect", True)

    def get_reconnect_interval(self) -> int:
        """Get WebSocket reconnection interval in seconds."""
        return self.get("websocket.reconnect_interval", 5)

    def get_ping_interval(self) -> int:
        """Get WebSocket ping interval in seconds."""
        return self.get("websocket.ping_interval", 30)

    def get_language(self) -> str:
        """Get configured language/locale."""
        return self.get("i18n.language", "en")

    def should_verify_ssl(self) -> bool:
        """Check if SSL certificates should be verified."""
        return self.get("server.verify_ssl", True)
