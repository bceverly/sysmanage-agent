"""
Configuration management for SysManage Agent.
Reads YAML configuration files and provides configuration data.
"""

import os
import yaml
from typing import Dict, Any, Optional


class ConfigManager:
    """Manages configuration for the SysManage Agent."""

    def __init__(self, config_file: str = "client.yaml"):
        self.config_file = config_file
        self.config_data: Dict[str, Any] = {}
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from YAML file."""
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(
                f"Configuration file '{self.config_file}' not found"
            )

        try:
            with open(self.config_file, "r", encoding="utf-8") as file:
                self.config_data = yaml.safe_load(file) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in configuration file: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to load configuration file: {e}")

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
