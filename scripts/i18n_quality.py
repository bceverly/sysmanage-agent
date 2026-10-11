#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
"""
Deterministic translation-quality checks, shared by the verifier and the
translation service.

Every other i18n gate in these repos was written after one particular failure
was found, and only recognizes that failure.  These checks are the part of
``i18n_verify.py`` that needs no model: they run on EVERY translated value on
every ``make lint``, and the translation service runs the same ones on its own
output so it stops producing these defects instead of handing them to a gate.

Each check was calibrated on 2026-10-08 against 780 randomly sampled real
translations and the defects a scan found in sysmanage-docs that day:

  ENGLISH   ordinary English left in a translation, whole or word by word:
            "Cliquer "Ajouter Dépôt" to appliquer to tous compatible hôtes",
            "The 규정 준수 엔진 is accessible 을(를) 통해 the REST API:".
            Detected by English FUNCTION words (the, to, is, with...) outside
            code, quotes and placeholders.  Kept IT terms ("Rate Limiting",
            "Backup") never contain them, which is why this beats both a
            language-ID library (flagged 23 of the 780 good values) and asking
            the model (it passed whole English paragraphs).  2+ hits flagged
            4 of the 780 -- every one genuinely broken -- and 112 of 126
            known half-English values; the other 14 were correct.

  SHAPE     a value that is not a translation at all: a Python list literal
            ("['Main Config File', 'Arquivo de Configuração Principal']"), a
            non-string JSON leaf, or a "[MISSING: ...]" / "[... MANQUANT: ...]"
            marker a pipeline wrote and a later run translated.

  PLACEHOLDERS  an interpolation token added, dropped or altered.

Shared verbatim by sysmanage, sysmanage-agent, sysmanage-professional-plus and
sysmanage-docs (scripts/sync_i18n_tooling.py); only the license header differs.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import List, Optional

# English function words: never a product name, never an IT term kept in
# English, always present in English prose.  Two or more outside code, quotes
# and placeholders means English was left in the translation.
FUNCTION_WORDS = frozenset(
    "the to is are of and with for from that which this these those be by on "
    "as it its an or not when will can your you into than been has have was "
    "were should must only each does do if then there their they so but at "
    "such also any all more most other our we may how what who why where "
    "while".split()
)

# Words that are ALSO ordinary words in a target language.  Dutch "is", "of"
# (or), "was"; German "in", "will" (wants), "was" (what); and so on.  Without
# these exclusions correct Dutch and German fail.
SHARED_WORDS = {
    "nl": {"is", "in", "of", "an", "was", "on", "been", "has", "have", "what", "we"},
    "de": {"in", "an", "will", "was", "also", "so"},
    "it": {"in", "come", "as", "do", "all"},
    "es": {"as", "do", "has"},
    "pt": {"as", "do", "on", "so"},
    "fr": {"on", "as", "an", "or", "but"},
}

ENGLISH_HIT_LIMIT = 2

# Stripped before counting: code, markup, placeholders, URLs, quoted text (a
# quoted log line or UI label is SUPPOSED to stay English) and path-, flag- or
# identifier-shaped tokens.
#
# Linear by construction, not by careful regex (CodeQL py/polynomial-redos,
# 2026-10-11): <code>/<pre> spans are removed with str.find, every regex
# alternative below is delimited by a class that excludes its own opening
# character, and path-shaped tokens are dropped by splitting on whitespace.
_SPANS = (("<code>", "</code>"), ("<pre>", "</pre>"))
_NOT_PROSE = re.compile(
    r"<[^<>]+>"
    r"|\{\{[^{}]+\}\}|\{[A-Za-z_]\w*\}|%\(\w+\)[sd]|%[sd]|\$\{\w+\}|&\w+;"
    r"|https?://\S+|`[^`]*`"
    r"|\"[^\"]*\"|“[^“”]*”|„[^„“”]*[“”]|«[^«»]*»|「[^「」]*」|『[^『』]*』"
)
_PATHLIKE = frozenset("/_.=")


def _strip_spans(text: str) -> str:
    """Remove every <code>...</code> and <pre>...</pre> span, in one pass each."""
    for opening, closing in _SPANS:
        out, pos = [], 0
        while True:
            start = text.find(opening, pos)
            if start < 0:
                break
            end = text.find(closing, start + len(opening))
            if end < 0:
                break  # unclosed: leave the rest as prose, as the regex did
            out.append(text[pos:start])
            out.append(" ")
            pos = end + len(closing)
        out.append(text[pos:])
        text = "".join(out)
    return text


def _prose(value: str) -> str:
    """``value`` with everything that is allowed to stay English removed."""
    text = _NOT_PROSE.sub(" ", _strip_spans(value))
    return " ".join(t for t in text.split() if not _PATHLIKE.intersection(t))


# A WORD is a run of letters in any script, so accented words stay whole:
# with [A-Za-z]+ Spanish "Análisis" split into "An" + "lisis" and Portuguese
# "até" became "at", and correct translations were refused (2026-10-09).
# Hyphen-joined runs ("Man-in-the-Middle", "Trust-on-First-Use") are one
# word -- an English term kept whole, not prose left untranslated.
_WORD = re.compile(r"[^\W\d_]+(?:-[^\W\d_]+)*")

PLACEHOLDER = re.compile(
    r"\{\{\s*[\w.]+\s*\}\}|\{[A-Za-z_]\w*\}|%\(\w+\)[sd]|%[sd]|\$\{\w+\}"
)

# A pipeline marker that reached a locale file: "[MISSING: key]" and its
# translated forms ("[RAPPORT ... MANQUANT:pro_plus...]").
_MARKER = re.compile(r"^\s*\[[^\]]*(?:MISSING|MANQUANT|FEHLT|FALTA|MANCANTE)\b[^\]]*:")
_LIST_LITERAL = re.compile(r"^\s*\[\s*['\"]")


def english_words(lang: str, value: str) -> List[str]:
    """English function words found in ``value`` outside code and quotes."""
    if lang == "en":
        return []
    allowed = SHARED_WORDS.get(lang.split("_")[0], set())
    text = _prose(value)
    return [
        w
        for w in _WORD.findall(text)
        if w.lower() in FUNCTION_WORDS and w.lower() not in allowed
    ]


def placeholders(text: str) -> Counter:
    return Counter(m.group(0).replace(" ", "") for m in PLACEHOLDER.finditer(text))


def problem(lang: str, source: str, value) -> Optional[str]:
    """Why ``value`` cannot be a correct ``lang`` translation, or None.

    Order matters only for the message: the first failure is reported.
    """
    if not isinstance(value, str):
        return f"not a string ({type(value).__name__})"
    if _LIST_LITERAL.match(value) and not _LIST_LITERAL.match(source):
        return "a list literal, not a translation"
    if _MARKER.match(value) and not _MARKER.match(source):
        return "a pipeline marker, not a translation"
    if placeholders(value) != placeholders(source):
        want = sorted(placeholders(source).elements())
        have = sorted(placeholders(value).elements())
        return f"placeholders {have} do not match the source's {want}"
    if ("\u2013" in value or "\u2014" in value) and not (
        "\u2013" in source or "\u2014" in source
    ):
        # ASCII hyphens only, in every repository and every locale.
        return "an en or em dash (use ASCII: ' -- ' where the English has it)"
    hits = english_words(lang, value)
    if len(hits) >= ENGLISH_HIT_LIMIT:
        return "untranslated English: " + " ".join(hits[:6])
    return None
