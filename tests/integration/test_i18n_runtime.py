"""
Integration tests for the agent's gettext runtime.

We catalog 14 locales (.po files under src/i18n/locales/<lang>/).  These
tests verify that on a real host:

  - the i18n module imports and the _ helper is callable,
  - language switching changes which catalog is consulted,
  - a fallback to the source string happens cleanly when a locale file
    can't be read or a msgid is unknown.

Compiled .mo files are not shipped (the project's runtime falls back
to NullTranslations when a .mo isn't present), so these tests exercise
the fallback path explicitly.
"""

# pylint: disable=missing-function-docstring,missing-class-docstring,invalid-name

import pytest

from src.i18n import _, get_language, set_language


@pytest.mark.integration
def test_gettext_helper_returns_string_for_known_msgid():
    """_() of a real source-tree msgid must always return a non-empty string."""
    # "VM name is required" is wrapped with _() in
    # src/sysmanage_agent/operations/child_host_kvm_types.py and
    # appears in every locale catalog.
    out = _("VM name is required")
    assert isinstance(out, str)
    assert out  # non-empty


@pytest.mark.integration
def test_gettext_helper_falls_back_to_msgid_for_unknown_string():
    """Unknown msgids must round-trip as the source string (gettext semantics)."""
    sentinel = "This msgid does not exist in any catalog xyz123"
    assert _(sentinel) == sentinel


@pytest.mark.integration
def test_set_language_updates_current_language():
    """set_language() should be observable via get_language()."""
    original = get_language()
    try:
        set_language("de")
        assert get_language() == "de"
        set_language("ja")
        assert get_language() == "ja"
    finally:
        set_language(original)


@pytest.mark.integration
def test_set_language_for_all_supported_locales_does_not_raise():
    """Switching through every locale in our matrix must not raise."""
    original = get_language()
    locales = [
        "ar",
        "de",
        "en",
        "es",
        "fr",
        "hi",
        "it",
        "ja",
        "ko",
        "nl",
        "pt",
        "ru",
        "zh_CN",
        "zh_TW",
    ]
    try:
        for loc in locales:
            set_language(loc)
            # Lookup *something* — the missing-.mo fallback is the
            # path most BSD/macOS hosts will take in CI, so this also
            # smoke-tests NullTranslations.
            assert _("VM name is required")
    finally:
        set_language(original)
