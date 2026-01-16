"""
Tests for flexible verbosity logger module.
"""

# pylint: disable=redefined-outer-name,protected-access

import logging
from unittest.mock import Mock, patch

import pytest

from src.sysmanage_agent.utils.verbosity_logger import FlexibleLogger, get_logger


@pytest.fixture
def mock_config():
    """Create a mock config manager."""
    config = Mock()
    config.get = Mock(return_value="INFO|WARNING|ERROR|CRITICAL")
    return config


@pytest.fixture
def logger(mock_config):
    """Create a FlexibleLogger for testing."""
    return FlexibleLogger("test_logger", mock_config)


class TestFlexibleLoggerInit:
    """Tests for FlexibleLogger initialization."""

    def test_init_sets_name(self, mock_config):
        """Test that __init__ sets name."""
        logger = FlexibleLogger("my_logger", mock_config)
        assert logger.name == "my_logger"

    def test_init_sets_config_manager(self, mock_config):
        """Test that __init__ sets config_manager."""
        logger = FlexibleLogger("test", mock_config)
        assert logger.config_manager == mock_config

    def test_init_parses_enabled_levels(self, mock_config):
        """Test that __init__ parses enabled levels."""
        logger = FlexibleLogger("test", mock_config)
        assert len(logger.enabled_levels) > 0

    def test_init_without_config_manager(self):
        """Test initialization without config manager uses defaults."""
        logger = FlexibleLogger("test", None)
        # Should default to INFO, WARNING, ERROR, CRITICAL
        assert logging.INFO in logger.enabled_levels
        assert logging.WARNING in logger.enabled_levels
        assert logging.ERROR in logger.enabled_levels
        assert logging.CRITICAL in logger.enabled_levels

    def test_init_sets_logger_level_to_debug(self, mock_config):
        """Test that logger level is set to DEBUG for flexible filtering."""
        logger = FlexibleLogger("test", mock_config)
        assert logger.logger.level == logging.DEBUG


class TestParseEnabledLevels:
    """Tests for _parse_enabled_levels method."""

    def test_parse_single_level(self):
        """Test parsing single level."""
        config = Mock()
        config.get = Mock(return_value="DEBUG")
        logger = FlexibleLogger("test", config)

        assert logger.enabled_levels == {logging.DEBUG}

    def test_parse_multiple_levels(self):
        """Test parsing multiple levels."""
        config = Mock()
        config.get = Mock(return_value="DEBUG|INFO|ERROR")
        logger = FlexibleLogger("test", config)

        assert logger.enabled_levels == {logging.DEBUG, logging.INFO, logging.ERROR}

    def test_parse_all_levels(self):
        """Test parsing all levels."""
        config = Mock()
        config.get = Mock(return_value="DEBUG|INFO|WARNING|ERROR|CRITICAL")
        logger = FlexibleLogger("test", config)

        assert logger.enabled_levels == {
            logging.DEBUG,
            logging.INFO,
            logging.WARNING,
            logging.ERROR,
            logging.CRITICAL,
        }

    def test_parse_with_whitespace(self):
        """Test parsing with whitespace around levels."""
        config = Mock()
        config.get = Mock(return_value="  DEBUG | INFO  |  ERROR  ")
        logger = FlexibleLogger("test", config)

        assert logger.enabled_levels == {logging.DEBUG, logging.INFO, logging.ERROR}

    def test_parse_case_insensitive(self):
        """Test parsing is case insensitive."""
        config = Mock()
        config.get = Mock(return_value="debug|Info|WARNING")
        logger = FlexibleLogger("test", config)

        assert logging.DEBUG in logger.enabled_levels
        assert logging.INFO in logger.enabled_levels
        assert logging.WARNING in logger.enabled_levels

    def test_parse_invalid_level_ignored(self):
        """Test that invalid level names are ignored."""
        config = Mock()
        config.get = Mock(return_value="INFO|INVALID|ERROR")
        logger = FlexibleLogger("test", config)

        assert logging.INFO in logger.enabled_levels
        assert logging.ERROR in logger.enabled_levels
        assert len(logger.enabled_levels) == 2

    def test_parse_exception_uses_default(self):
        """Test that exception during parsing uses default levels."""
        config = Mock()
        config.get = Mock(side_effect=Exception("config error"))
        logger = FlexibleLogger("test", config)

        # Should use default: INFO, WARNING, ERROR, CRITICAL
        assert logging.INFO in logger.enabled_levels
        assert logging.WARNING in logger.enabled_levels
        assert logging.ERROR in logger.enabled_levels
        assert logging.CRITICAL in logger.enabled_levels


class TestGetLogFormat:
    """Tests for _get_log_format method."""

    def test_get_format_from_config(self, mock_config):
        """Test getting format from config."""
        mock_config.get = Mock(return_value="%(name)s - %(message)s")
        logger = FlexibleLogger("test", mock_config)

        result = logger._get_log_format()
        assert result == "%(name)s - %(message)s"

    def test_get_format_default(self):
        """Test default format without config."""
        logger = FlexibleLogger("test", None)

        result = logger._get_log_format()
        assert result == "%(levelname)s: %(message)s"

    def test_get_format_exception_uses_default(self):
        """Test exception during format retrieval uses default."""
        config = Mock()
        config.get = Mock(side_effect=Exception("config error"))
        logger = FlexibleLogger("test", config)

        result = logger._get_log_format()
        assert result == "%(levelname)s: %(message)s"


class TestShouldLog:
    """Tests for _should_log method."""

    def test_should_log_enabled_level(self, logger):
        """Test should_log returns True for enabled level."""
        assert logger._should_log(logging.INFO) is True

    def test_should_not_log_disabled_level(self):
        """Test should_log returns False for disabled level."""
        config = Mock()
        config.get = Mock(return_value="ERROR|CRITICAL")
        logger = FlexibleLogger("test", config)

        assert logger._should_log(logging.DEBUG) is False
        assert logger._should_log(logging.INFO) is False
        assert logger._should_log(logging.WARNING) is False


class TestLoggingMethods:
    """Tests for logging methods (debug, info, warning, error, critical)."""

    def test_debug_when_enabled(self):
        """Test debug logging when enabled."""
        config = Mock()
        config.get = Mock(return_value="DEBUG")
        logger = FlexibleLogger("test", config)

        with patch.object(logger.logger, "debug") as mock_debug:
            logger.debug("Debug message")
            mock_debug.assert_called_once_with("Debug message")

    def test_debug_when_disabled(self):
        """Test debug logging when disabled."""
        config = Mock()
        config.get = Mock(return_value="INFO")
        logger = FlexibleLogger("test", config)

        with patch.object(logger.logger, "debug") as mock_debug:
            logger.debug("Debug message")
            mock_debug.assert_not_called()

    def test_info_when_enabled(self, logger):
        """Test info logging when enabled."""
        with patch.object(logger.logger, "info") as mock_info:
            logger.info("Info message")
            mock_info.assert_called_once_with("Info message")

    def test_info_when_disabled(self):
        """Test info logging when disabled."""
        config = Mock()
        config.get = Mock(return_value="DEBUG")
        logger = FlexibleLogger("test", config)

        with patch.object(logger.logger, "info") as mock_info:
            logger.info("Info message")
            mock_info.assert_not_called()

    def test_warning_when_enabled(self, logger):
        """Test warning logging when enabled."""
        with patch.object(logger.logger, "warning") as mock_warning:
            logger.warning("Warning message")
            mock_warning.assert_called_once_with("Warning message")

    def test_error_when_enabled(self, logger):
        """Test error logging when enabled."""
        with patch.object(logger.logger, "error") as mock_error:
            logger.error("Error message")
            mock_error.assert_called_once_with("Error message")

    def test_critical_when_enabled(self, logger):
        """Test critical logging when enabled."""
        with patch.object(logger.logger, "critical") as mock_critical:
            logger.critical("Critical message")
            mock_critical.assert_called_once_with("Critical message")

    def test_logging_with_args(self, logger):
        """Test logging with format arguments."""
        with patch.object(logger.logger, "info") as mock_info:
            logger.info("Value: %d", 42)
            mock_info.assert_called_once_with("Value: %d", 42)

    def test_logging_with_kwargs(self, logger):
        """Test logging with keyword arguments."""
        with patch.object(logger.logger, "error") as mock_error:
            logger.error("Error occurred", exc_info=True)
            mock_error.assert_called_once_with("Error occurred", exc_info=True)


class TestGetLogger:
    """Tests for get_logger function."""

    def test_get_logger_returns_flexible_logger(self):
        """Test that get_logger returns FlexibleLogger instance."""
        result = get_logger("test_logger")

        assert isinstance(result, FlexibleLogger)

    def test_get_logger_with_config_manager(self, mock_config):
        """Test get_logger with config manager."""
        result = get_logger("test_logger", mock_config)

        assert result.config_manager == mock_config

    def test_get_logger_without_config_manager(self):
        """Test get_logger without config manager."""
        result = get_logger("test_logger", None)

        assert result.config_manager is None

    def test_get_logger_sets_correct_name(self):
        """Test that get_logger sets the correct logger name."""
        result = get_logger("my_custom_logger")

        assert result.name == "my_custom_logger"
