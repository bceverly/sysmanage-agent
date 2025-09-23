"""
Comprehensive unit tests for src.sysmanage_agent.utils.verbosity_logger module.
Tests flexible logging with granular level control.
"""

# pylint: disable=protected-access,attribute-defined-outside-init

import logging
from unittest.mock import Mock, patch

from src.sysmanage_agent.utils.verbosity_logger import FlexibleLogger, get_logger


class TestFlexibleLogger:  # pylint: disable=too-many-public-methods
    """Test cases for FlexibleLogger class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_config = Mock()

        # Set up different return values for different config keys
        def mock_get(key, default):
            if key == "logging.level":
                return "INFO|WARNING|ERROR|CRITICAL"
            if key == "logging.format":
                return "%(levelname)s: %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

    def test_init_with_config(self):
        """Test FlexibleLogger initialization with config manager."""
        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)

            assert logger.name == "test.logger"
            assert logger.config_manager == self.mock_config
            assert logger.logger == mock_logger
            assert logging.INFO in logger.enabled_levels
            assert logging.WARNING in logger.enabled_levels
            assert logging.ERROR in logger.enabled_levels
            assert logging.CRITICAL in logger.enabled_levels

    def test_init_without_config(self):
        """Test FlexibleLogger initialization without config manager."""
        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger")

            assert logger.config_manager is None
            # Should use default levels
            assert logging.INFO in logger.enabled_levels
            assert logging.WARNING in logger.enabled_levels
            assert logging.ERROR in logger.enabled_levels
            assert logging.CRITICAL in logger.enabled_levels

    def test_init_existing_handlers(self):
        """Test FlexibleLogger initialization when logger already has handlers."""
        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = [Mock()]  # Already has handlers
            mock_get_logger.return_value = mock_logger

            FlexibleLogger("test.logger", self.mock_config)

            # Should not add new handlers
            assert len(mock_logger.handlers) == 1

    def test_parse_enabled_levels_debug_only(self):
        """Test parsing DEBUG only level configuration."""

        def mock_get(key, default):
            if key == "logging.level":
                return "DEBUG"
            if key == "logging.format":
                return "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        logger = FlexibleLogger("test.logger", self.mock_config)

        assert logger.enabled_levels == {logging.DEBUG}

    def test_parse_enabled_levels_multiple(self):
        """Test parsing multiple level configuration."""

        def mock_get(key, default):
            if key == "logging.level":
                return "WARNING|ERROR|CRITICAL"
            if key == "logging.format":
                return "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        logger = FlexibleLogger("test.logger", self.mock_config)

        expected = {logging.WARNING, logging.ERROR, logging.CRITICAL}
        assert logger.enabled_levels == expected

    def test_parse_enabled_levels_mixed_case(self):
        """Test parsing level configuration with mixed case."""

        def mock_get(key, default):
            if key == "logging.level":
                return "info|Warning|ERROR"
            if key == "logging.format":
                return "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        logger = FlexibleLogger("test.logger", self.mock_config)

        expected = {logging.INFO, logging.WARNING, logging.ERROR}
        assert logger.enabled_levels == expected

    def test_parse_enabled_levels_with_spaces(self):
        """Test parsing level configuration with spaces."""

        def mock_get(key, default):
            if key == "logging.level":
                return " INFO | WARNING | ERROR "
            if key == "logging.format":
                return "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        logger = FlexibleLogger("test.logger", self.mock_config)

        expected = {logging.INFO, logging.WARNING, logging.ERROR}
        assert logger.enabled_levels == expected

    def test_parse_enabled_levels_invalid_level(self):
        """Test parsing configuration with invalid level names."""

        def mock_get(key, default):
            if key == "logging.level":
                return "INFO|INVALID_LEVEL|ERROR"
            if key == "logging.format":
                return "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        logger = FlexibleLogger("test.logger", self.mock_config)

        # Should ignore invalid levels
        expected = {logging.INFO, logging.ERROR}
        assert logger.enabled_levels == expected

    def test_parse_enabled_levels_config_exception(self):
        """Test parsing levels when config access raises exception."""
        self.mock_config.get.side_effect = Exception("Config error")

        logger = FlexibleLogger("test.logger", self.mock_config)

        # Should fall back to default levels
        expected = {logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL}
        assert logger.enabled_levels == expected

    def test_get_log_format_from_config(self):
        """Test getting log format from config."""

        def mock_get(key, default):
            if key == "logging.level":
                return "INFO|WARNING|ERROR|CRITICAL"
            if key == "logging.format":
                return "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            format_result = (
                logger._get_log_format()
            )  # pylint: disable=protected-access,attribute-defined-outside-init

            assert (
                format_result == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )

    def test_get_log_format_no_config(self):
        """Test getting log format without config manager."""
        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger")
            format_result = (
                logger._get_log_format()
            )  # pylint: disable=protected-access,attribute-defined-outside-init

            assert format_result == "%(levelname)s: %(message)s"

    def test_get_log_format_config_exception(self):
        """Test getting log format when config access raises exception."""
        self.mock_config.get.side_effect = Exception("Config error")

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            format_result = (
                logger._get_log_format()
            )  # pylint: disable=protected-access,attribute-defined-outside-init

            assert format_result == "%(levelname)s: %(message)s"

    def test_should_log_enabled_level(self):
        """Test _should_log for enabled level."""
        self.mock_config.get.return_value = "INFO|ERROR"

        logger = FlexibleLogger("test.logger", self.mock_config)

        assert (
            logger._should_log(logging.INFO) is True
        )  # pylint: disable=protected-access,attribute-defined-outside-init
        assert (
            logger._should_log(logging.ERROR) is True
        )  # pylint: disable=protected-access,attribute-defined-outside-init

    def test_should_log_disabled_level(self):
        """Test _should_log for disabled level."""

        def mock_get(key, default):
            if key == "logging.level":
                return "INFO|ERROR"
            if key == "logging.format":
                return "%(levelname)s: %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        logger = FlexibleLogger("test.logger", self.mock_config)

        assert (
            logger._should_log(logging.DEBUG) is False
        )  # pylint: disable=protected-access,attribute-defined-outside-init
        assert (
            logger._should_log(logging.WARNING) is False
        )  # pylint: disable=protected-access,attribute-defined-outside-init
        assert (
            logger._should_log(logging.CRITICAL) is False
        )  # pylint: disable=protected-access,attribute-defined-outside-init

    def test_debug_logging_enabled(self):
        """Test debug logging when DEBUG level is enabled."""

        def mock_get(key, default):
            if key == "logging.level":
                return "DEBUG"
            if key == "logging.format":
                return "%(levelname)s: %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            logger.debug("Test debug message", "arg1", extra="kwarg1")

            mock_logger.debug.assert_called_once_with(
                "Test debug message", "arg1", extra="kwarg1"
            )

    def test_debug_logging_disabled(self):
        """Test debug logging when DEBUG level is disabled."""
        self.mock_config.get.return_value = "INFO|ERROR"

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            logger.debug("Test debug message")

            mock_logger.debug.assert_not_called()

    def test_info_logging_enabled(self):
        """Test info logging when INFO level is enabled."""
        self.mock_config.get.return_value = "INFO"

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            logger.info("Test info message", "arg1", extra="kwarg1")

            mock_logger.info.assert_called_once_with(
                "Test info message", "arg1", extra="kwarg1"
            )

    def test_info_logging_disabled(self):
        """Test info logging when INFO level is disabled."""

        def mock_get(key, default):
            if key == "logging.level":
                return "ERROR"
            if key == "logging.format":
                return "%(levelname)s: %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            logger.info("Test info message")

            mock_logger.info.assert_not_called()

    def test_warning_logging_enabled(self):
        """Test warning logging when WARNING level is enabled."""
        self.mock_config.get.return_value = "WARNING"

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            logger.warning("Test warning message", "arg1", extra="kwarg1")

            mock_logger.warning.assert_called_once_with(
                "Test warning message", "arg1", extra="kwarg1"
            )

    def test_warning_logging_disabled(self):
        """Test warning logging when WARNING level is disabled."""

        def mock_get(key, default):
            if key == "logging.level":
                return "ERROR"
            if key == "logging.format":
                return "%(levelname)s: %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            logger.warning("Test warning message")

            mock_logger.warning.assert_not_called()

    def test_error_logging_enabled(self):
        """Test error logging when ERROR level is enabled."""
        self.mock_config.get.return_value = "ERROR"

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            logger.error("Test error message", "arg1", extra="kwarg1")

            mock_logger.error.assert_called_once_with(
                "Test error message", "arg1", extra="kwarg1"
            )

    def test_error_logging_disabled(self):
        """Test error logging when ERROR level is disabled."""

        def mock_get(key, default):
            if key == "logging.level":
                return "INFO"
            if key == "logging.format":
                return "%(levelname)s: %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            logger.error("Test error message")

            mock_logger.error.assert_not_called()

    def test_critical_logging_enabled(self):
        """Test critical logging when CRITICAL level is enabled."""
        self.mock_config.get.return_value = "CRITICAL"

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            logger.critical("Test critical message", "arg1", extra="kwarg1")

            mock_logger.critical.assert_called_once_with(
                "Test critical message", "arg1", extra="kwarg1"
            )

    def test_critical_logging_disabled(self):
        """Test critical logging when CRITICAL level is disabled."""

        def mock_get(key, default):
            if key == "logging.level":
                return "INFO"
            if key == "logging.format":
                return "%(levelname)s: %(message)s"
            return default

        self.mock_config.get.side_effect = mock_get

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []
            mock_get_logger.return_value = mock_logger

            logger = FlexibleLogger("test.logger", self.mock_config)
            logger.critical("Test critical message")

            mock_logger.critical.assert_not_called()


def test_get_logger_function():
    """Test get_logger convenience function."""
    mock_config = Mock()

    with patch(
        "src.sysmanage_agent.utils.verbosity_logger.FlexibleLogger"
    ) as mock_logger_class:
        result = get_logger("test.logger", mock_config)

        mock_logger_class.assert_called_once_with("test.logger", mock_config)
        assert result == mock_logger_class.return_value


def test_get_logger_function_no_config():
    """Test get_logger convenience function without config."""
    with patch(
        "src.sysmanage_agent.utils.verbosity_logger.FlexibleLogger"
    ) as mock_logger_class:
        result = get_logger("test.logger")

        mock_logger_class.assert_called_once_with("test.logger", None)
        assert result == mock_logger_class.return_value
