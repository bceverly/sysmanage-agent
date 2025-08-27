import gettext
import os
from typing import Optional

# Default language
DEFAULT_LANGUAGE = "en"

# Current language (can be changed at runtime)
CURRENT_LANGUAGE = DEFAULT_LANGUAGE

# Cache for loaded translation objects
TRANSLATIONS = {}


def set_language(language: str) -> None:
    """Set the current language for translations."""
    global CURRENT_LANGUAGE  # pylint: disable=global-statement
    CURRENT_LANGUAGE = language


def get_language() -> str:
    """Get the current language."""
    return CURRENT_LANGUAGE


def get_translation(language: Optional[str] = None) -> gettext.GNUTranslations:
    """Get translation object for the specified language."""
    if language is None:
        language = CURRENT_LANGUAGE

    if language not in TRANSLATIONS:
        try:
            # Get the directory containing this file
            localedir = os.path.join(os.path.dirname(__file__), "locales")
            translation = gettext.translation("messages", localedir, [language])
            TRANSLATIONS[language] = translation
        except FileNotFoundError:
            # Fall back to no translation (English)
            TRANSLATIONS[language] = gettext.NullTranslations()

    return TRANSLATIONS[language]


def _(message: str, language: Optional[str] = None) -> str:
    """Translate a message."""
    translation = get_translation(language)
    return translation.gettext(message)


def ngettext(
    singular: str, plural: str, count: int, language: Optional[str] = None
) -> str:
    """Translate a message with plural forms."""
    translation = get_translation(language)
    return translation.ngettext(singular, plural, count)
