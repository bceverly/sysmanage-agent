"""
Test internationalization configuration functionality.
"""

import os
import tempfile

from src.i18n import get_language, set_language
from src.sysmanage_agent.core.config import ConfigManager


def test_config_lang_default():
    """Test that config manager returns default language."""
    # Create a temporary config file without i18n section
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as config_file:
        config_file.write("""
server:
  hostname: "localhost"
  port: 8000
logging:
  level: "INFO"
""")
        temp_config = config_file.name

    try:
        config = ConfigManager(temp_config)
        assert config.get_language() == "en"  # Should default to English
    finally:
        os.unlink(temp_config)


def test_config_lang_configured():
    """Test that config manager returns configured language."""
    # Create a temporary config file with i18n section
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as config_file:
        config_file.write("""
server:
  hostname: "localhost"
  port: 8000
i18n:
  language: "es"
logging:
  level: "INFO"
""")
        temp_config = config_file.name

    try:
        config = ConfigManager(temp_config)
        assert config.get_language() == "es"  # Should return Spanish
    finally:
        os.unlink(temp_config)


def test_lang_integration():
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
