"""
Test agent configuration internationalization functionality.
This tests the i18n configuration that was added for the agent.
"""

import os
import tempfile
from unittest.mock import patch

import pytest

from main import SysManageAgent
from src.i18n import TRANSLATIONS, _, get_language, get_translation, set_language
from src.sysmanage_agent.core.config import ConfigManager


class TestAgentI18nConfiguration:
    """Test agent internationalization configuration."""

    @pytest.fixture
    def config_with_i18n(self, tmp_path):
        """Create a config file with i18n settings."""
        config_file = tmp_path / "test_i18n_config.yaml"
        log_file = tmp_path / "test.log"
        # Convert to forward slashes for YAML compatibility on Windows
        log_file_str = str(log_file).replace("\\", "/")
        config_content = f"""
server:
  hostname: "test-server.example.com"
  port: 8000

i18n:
  language: "es"

logging:
  level: "INFO"
  file: "{log_file_str}"
"""
        config_file.write_text(config_content)
        return str(config_file)

    @pytest.fixture
    def config_without_i18n(self, tmp_path):
        """Create a config file without i18n settings."""
        config_file = tmp_path / "test_no_i18n_config.yaml"
        log_file = tmp_path / "test.log"
        # Convert to forward slashes for YAML compatibility on Windows
        log_file_str = str(log_file).replace("\\", "/")
        config_content = f"""
server:
  hostname: "test-server.example.com"
  port: 8000

logging:
  level: "INFO"
  file: "{log_file_str}"
"""
        config_file.write_text(config_content)
        return str(config_file)

    def test_config_manager_language_configured(self, config_with_i18n):
        """Test that config manager returns configured language."""
        config = ConfigManager(config_with_i18n)
        assert config.get_language() == "es"

    def test_config_manager_language_default(self, config_without_i18n):
        """Test that config manager returns default language when not configured."""
        config = ConfigManager(config_without_i18n)
        assert config.get_language() == "en"

    def test_config_manager_i18n_section(self, config_with_i18n):
        """Test that config manager can retrieve i18n section."""
        config = ConfigManager(config_with_i18n)
        i18n_config = config.get_i18n_config()

        assert isinstance(i18n_config, dict)
        assert i18n_config["language"] == "es"

    def test_config_manager_i18n_section_empty(self, config_without_i18n):
        """Test that config manager returns empty dict when i18n section missing."""
        config = ConfigManager(config_without_i18n)
        i18n_config = config.get_i18n_config()

        assert isinstance(i18n_config, dict)
        assert len(i18n_config) == 0

    def test_all_supported_languages(self):
        """Test all supported languages can be configured."""
        supported_languages = [
            "en",
            "es",
            "fr",
            "de",
            "it",
            "pt",
            "nl",
            "ja",
            "zh_CN",
            "ko",
            "ru",
        ]

        for lang in supported_languages:
            config_content = f"""
server:
  hostname: "test-server.example.com"
  port: 8000

i18n:
  language: "{lang}"
"""
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            ) as config_file:
                config_file.write(config_content)
                temp_config = config_file.name

            try:
                config = ConfigManager(temp_config)
                assert config.get_language() == lang
            finally:
                os.unlink(temp_config)

    def test_config_dot_notation_i18n(self, config_with_i18n):
        """Test accessing i18n config with dot notation."""
        config = ConfigManager(config_with_i18n)

        # Test dot notation access
        language = config.get("i18n.language")
        assert language == "es"

        # Test with default
        fallback = config.get("i18n.nonexistent", "default_value")
        assert fallback == "default_value"

    def test_config_integration_with_main_agent(self, config_with_i18n):
        """Test config integration with main agent initialization."""
        with patch("main.ClientRegistration"), patch(
            "main.set_language"
        ) as mock_set_language, patch("main.initialize_database", return_value=True):
            SysManageAgent(config_with_i18n)

            # Verify that set_language was called with the configured language
            mock_set_language.assert_called_once_with("es")


class TestI18nFunctionality:
    """Test internationalization functionality."""

    def test_set_and_get_language(self):
        """Test setting and getting language."""
        original_language = get_language()

        try:
            set_language("fr")
            assert get_language() == "fr"

            set_language("de")
            assert get_language() == "de"

        finally:
            # Restore original language
            set_language(original_language)

    def test_translation_function_fallback(self):
        """Test translation function with fallback."""
        # Set to a language that likely doesn't have translation files
        original_language = get_language()

        try:
            set_language("xx")  # Non-existent language

            # Should fallback to original text
            result = _("Starting SysManage Agent")
            assert isinstance(result, str)

        finally:
            set_language(original_language)

    def test_translation_with_existing_language(self):
        """Test translation with a language that should exist."""
        original_language = get_language()

        try:
            set_language("en")  # English should always exist

            # Should return some translation (even if it's the same as input)
            result = _("Starting SysManage Agent")
            assert isinstance(result, str)
            assert len(result) > 0

        finally:
            set_language(original_language)

    def test_translation_caching(self):
        """Test that translations are cached properly."""

        original_language = get_language()

        try:
            # Clear cache
            TRANSLATIONS.clear()

            set_language("en")
            translation1 = get_translation("en")

            # Second call should use cached version
            translation2 = get_translation("en")

            assert translation1 is translation2
            assert "en" in TRANSLATIONS

        finally:
            set_language(original_language)


class TestConfigValidation:
    """Test configuration validation."""

    def test_invalid_yaml_handling(self, tmp_path):
        """Test handling of invalid YAML configuration."""
        config_file = tmp_path / "invalid.yaml"
        config_file.write_text("invalid: yaml: content: [")

        with pytest.raises(ValueError, match="Invalid YAML"):
            ConfigManager(str(config_file))

    def test_missing_config_file(self, tmp_path):
        """Test handling of missing configuration file."""
        # Use absolute path to avoid falling back to local config
        nonexistent_file = tmp_path / "nonexistent_file.yaml"
        with pytest.raises(FileNotFoundError):
            ConfigManager(str(nonexistent_file))

    def test_empty_config_file(self, tmp_path):
        """Test handling of empty configuration file."""
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")

        config = ConfigManager(str(config_file))
        # Should use defaults
        assert config.get_language() == "en"

    def test_config_with_only_i18n(self, tmp_path):
        """Test configuration with only i18n section."""
        config_file = tmp_path / "i18n_only.yaml"
        config_content = """
i18n:
  language: "ja"
"""
        config_file.write_text(config_content)

        config = ConfigManager(str(config_file))
        assert config.get_language() == "ja"

    def test_config_type_safety(self, tmp_path):
        """Test configuration type safety."""
        config_file = tmp_path / "type_test.yaml"
        config_content = """
i18n:
  language: ja  # Without quotes - should still work
"""
        config_file.write_text(config_content)

        config = ConfigManager(str(config_file))
        language = config.get_language()
        assert isinstance(language, str)
        assert language == "ja"
