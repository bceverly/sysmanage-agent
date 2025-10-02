"""
Flexible logging utility for SysManage Agent.

Provides granular logging control with pipe-separated level configuration.
Supports custom formats and selective level filtering.
"""

import logging
from typing import Set


class FlexibleLogger:
    """
    Logger that supports granular level filtering with pipe-separated configuration.

    Examples:
    - "DEBUG" - Only debug messages
    - "INFO|ERROR" - Only info and error messages
    - "WARNING|ERROR|CRITICAL" - Only warnings, errors, and critical messages
    - "INFO|WARNING|ERROR|CRITICAL" - Standard operational logging
    """

    def __init__(self, name: str, config_manager=None):
        """Initialize flexible logger."""
        self.logger = logging.getLogger(name)
        self.name = name
        self.config_manager = config_manager

        # Parse enabled levels from config
        self.enabled_levels = self._parse_enabled_levels()

        # Don't add handlers here - main.py sets up the file handler
        # We only control the logger level, not the handler destination
        self.logger.setLevel(logging.DEBUG)  # Let our filtering logic control output

    def _parse_enabled_levels(self) -> Set[int]:
        """Parse pipe-separated levels from config into a set of logging constants."""
        try:
            level_config = (
                self.config_manager.get("logging.level", "INFO|WARNING|ERROR|CRITICAL")
                if self.config_manager
                else "INFO|WARNING|ERROR|CRITICAL"
            )
            enabled_levels = set()

            # Split by pipe and parse each level
            for level_name in level_config.split("|"):
                level_name = level_name.strip().upper()
                if hasattr(logging, level_name):
                    enabled_levels.add(getattr(logging, level_name))

            return enabled_levels
        except Exception:  # pylint: disable=broad-exception-caught
            # Default fallback to standard operational logging
            return {logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL}

    def _get_log_format(self) -> str:
        """Get log format from config."""
        try:
            return (
                self.config_manager.get("logging.format", "%(levelname)s: %(message)s")
                if self.config_manager
                else "%(levelname)s: %(message)s"
            )
        except Exception:  # pylint: disable=broad-exception-caught
            return "%(levelname)s: %(message)s"

    def _should_log(self, level: int) -> bool:
        """Check if message should be logged based on configured levels."""
        return level in self.enabled_levels

    def debug(self, msg: str, *args, **kwargs):
        """Log debug message if verbosity allows."""
        if self._should_log(logging.DEBUG):
            self.logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        """Log info message if verbosity allows."""
        if self._should_log(logging.INFO):
            self.logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        """Log warning message if verbosity allows."""
        if self._should_log(logging.WARNING):
            self.logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs):
        """Log error message if verbosity allows."""
        if self._should_log(logging.ERROR):
            self.logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs):
        """Log critical message if verbosity allows."""
        if self._should_log(logging.CRITICAL):
            self.logger.critical(msg, *args, **kwargs)


def get_logger(name: str, config_manager=None) -> FlexibleLogger:
    """Get a flexible logger instance with granular level control."""
    return FlexibleLogger(name, config_manager)
