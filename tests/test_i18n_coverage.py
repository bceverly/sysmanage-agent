"""
Additional tests for i18n module to achieve full coverage.
Tests the missing coverage areas.
"""

from unittest.mock import patch

from src.i18n import (
    set_language,
    get_translation,
    ngettext,
    DEFAULT_LANGUAGE,
    TRANSLATIONS,
)


class TestI18nCoverage:
    """Test cases for i18n module coverage."""

    def setup_method(self):
        """Set up test environment."""
        # Clear translations cache before each test
        TRANSLATIONS.clear()
        set_language(DEFAULT_LANGUAGE)

    def test_get_translation_with_valid_translation_file(self):
        """Test get_translation when translation file exists (line 36)."""
        # Mock gettext.translation to return a valid translation object
        with patch("src.i18n.gettext.translation") as mock_translation:
            mock_trans_obj = mock_translation.return_value

            # Test that translation is cached
            result = get_translation("es")

            assert result == mock_trans_obj
            assert "es" in TRANSLATIONS
            assert TRANSLATIONS["es"] == mock_trans_obj

            # Verify gettext.translation was called correctly
            mock_translation.assert_called_once()

    def test_ngettext_function(self):
        """Test ngettext function for plural translations (lines 54-55)."""
        # Mock get_translation to return a mock translation object
        with patch("src.i18n.get_translation") as mock_get_trans:
            mock_trans_obj = mock_get_trans.return_value
            mock_trans_obj.ngettext.return_value = "2 files"

            result = ngettext("file", "files", 2, "en")

            assert result == "2 files"
            mock_get_trans.assert_called_once_with("en")
            mock_trans_obj.ngettext.assert_called_once_with("file", "files", 2)

    def test_ngettext_with_default_language(self):
        """Test ngettext function with default language parameter."""
        with patch("src.i18n.get_translation") as mock_get_trans:
            mock_trans_obj = mock_get_trans.return_value
            mock_trans_obj.ngettext.return_value = "1 file"

            result = ngettext("file", "files", 1)

            assert result == "1 file"
            mock_get_trans.assert_called_once_with(None)
            mock_trans_obj.ngettext.assert_called_once_with("file", "files", 1)

    def test_translation_caching_behavior(self):
        """Test that translations are properly cached."""
        with patch("src.i18n.gettext.translation") as mock_translation:
            mock_trans_obj = mock_translation.return_value

            # First call should create translation
            result1 = get_translation("fr")
            assert result1 == mock_trans_obj
            assert mock_translation.call_count == 1

            # Second call should use cached translation
            result2 = get_translation("fr")
            assert result2 == mock_trans_obj
            assert result1 is result2
            assert mock_translation.call_count == 1  # Still only called once
