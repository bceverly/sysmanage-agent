# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""
Internationalization (i18n) module for SysManage Agent.
Provides translation support for multiple languages.
"""

import gettext
import os
from typing import Optional

# Default language
DEFAULT_LANGUAGE = "en"

# Current language (can be changed at runtime)
CURRENT_LANGUAGE = DEFAULT_LANGUAGE  # pylint: disable=invalid-name

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
    """Translate a message.

    NOTE: ``language`` is the SECOND positional argument — this is NOT the
    i18next ``t(key, englishDefault)`` signature.  Passing English there asks
    gettext for a locale by that name, falls back to ``NullTranslations`` and
    returns the msgid verbatim.  ``make lint`` gates against it
    (``scripts/i18n_check_msgid_style.py``).
    """
    translation = get_translation(language)
    return translation.gettext(message)


def N_(message: str) -> str:  # pylint: disable=invalid-name
    """Mark a string for extraction WITHOUT translating it yet.

    The standard gettext idiom for deferred translation.  pybabel/xgettext
    only ever see string *literals*, so a message held in a module constant
    (``_MSG_HOSTNAME_CHANGED = "..."`` then ``_(_MSG_HOSTNAME_CHANGED)``) is
    never extracted, never reaches a catalog, and renders English in all 13
    locales forever — silently, since no gate can miss a msgid that was never
    extracted.  Wrapping the DEFINITION in ``N_`` puts the text in the .pot
    (pybabel is passed ``-k N_``) while leaving the value an ordinary string;
    the ``_()`` at the call site resolves it against the current locale.
    """
    return message


def ngettext(
    singular: str, plural: str, count: int, language: Optional[str] = None
) -> str:
    """Translate a message with plural forms."""
    translation = get_translation(language)
    return translation.ngettext(singular, plural, count)
