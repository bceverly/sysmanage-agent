"""
Test internationalization configuration functionality.
"""

import tempfile
import os
from config import ConfigManager
from i18n import set_language, get_language


def test_config_manager_language_default():
    """Test that config manager returns default language."""
    # Create a temporary config file without i18n section
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(
            """
server:
  hostname: "localhost"
  port: 8000
logging:
  level: "INFO"
"""
        )
        temp_config = f.name

    try:
        config = ConfigManager(temp_config)
        assert config.get_language() == "en"  # Should default to English
    finally:
        os.unlink(temp_config)


def test_config_manager_language_configured():
    """Test that config manager returns configured language."""
    # Create a temporary config file with i18n section
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(
            """
server:
  hostname: "localhost"
  port: 8000
i18n:
  language: "es"
logging:
  level: "INFO"
"""
        )
        temp_config = f.name

    try:
        config = ConfigManager(temp_config)
        assert config.get_language() == "es"  # Should return Spanish
    finally:
        os.unlink(temp_config)


def test_language_setting_integration():
    """Test that language setting works with i18n system."""
    # Test setting different languages
    original_language = get_language()

    try:
        # Test setting Spanish
        set_language("es")
        assert get_language() == "es"

        # Test setting German
        set_language("de")
        assert get_language() == "de"

        # Test setting back to English
        set_language("en")
        assert get_language() == "en"
    finally:
        # Restore original language
        set_language(original_language)
