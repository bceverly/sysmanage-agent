#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Gate: backend gettext ``_()`` must take ENGLISH PROSE, never a lookup key.

WHAT THIS CATCHES (and why it exists)
-------------------------------------
``backend/i18n/__init__.py`` declares::

    def _(message: str, language: Optional[str] = None) -> str

The second positional argument is the **language**.  It is not an i18next-style
English default.  On 2026-08-05 an audit found 40 call sites written as::

    _("openbao.sealed", "OpenBAO sealed successfully")     # WRONG

which asks gettext for a locale literally named "OpenBAO sealed successfully".
That raises ``FileNotFoundError`` inside ``get_translation``, falls back to
``NullTranslations``, and returns the msgid verbatim — so **every one of those
endpoints returned ``"message": "openbao.sealed"`` to every client in every
language, including English**, and the .po translations could never be reached.

Nothing caught it.  ``xgettext --keyword=_`` extracts argument 1, so the
catalogs filled up with dotted keys as msgids, the translation service
cheerfully "translated" those keys (German got ``openbao.bereits_laufen``), and
``i18n-validate`` / ``i18n-strict`` / ``i18n-complete`` were all green because
each key was present, non-``[TODO]`` and not English-identical.

The pattern is easy to reintroduce because the FRONTEND's
``t('openbao.startError', 'Failed to start OpenBAO')`` two-arg form is genuinely
correct i18next.  Switching between the two layers is all it takes.

THE TWO CHECKS
--------------
1. **Source (AST).**  Every ``_()`` / ``ngettext()`` call is inspected:
   * a msgid argument that looks like a dotted identifier (``openbao.sealed``)
     is an error — gettext msgids are English prose;
   * a second positional argument to ``_()`` that is a string literal and is not
     a locale code (``de``, ``zh_CN``) is an error — that slot is the language.
   AST, not regex: the original grep missed 8 of the 40 sites purely because
   black had wrapped them across lines.

2. **Catalogs.**  Any ``msgid`` in the compiled-from .po files that is a dotted
   identifier.  Defence in depth for hand-edited catalogs and for keys that
   entered before this gate existed.

Usage::

    python3 scripts/i18n_check_msgid_style.py \
        --source-root backend --locales backend/i18n/locales
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

# A gettext msgid should be English prose.  This is the shape of a lookup key:
# all-lowercase dotted segments, no spaces.  Deliberately strict — it must not
# fire on real prose that happens to contain a period ("Done. Restarting.")
# because that has a space, nor on a sentence ending in a period.
KEY_SHAPED = re.compile(r"^[a-z0-9_]+(?:\.[a-z0-9_]+)+$")

# What a genuine `language=` argument looks like: "de", "pt", "zh_CN".
LOCALE_CODE = re.compile(r"^[a-z]{2}(?:_[A-Z]{2})?$")

TRANSLATOR_NAMES = {"_", "gettext", "ngettext"}


def _msgid_args(node: ast.Call) -> list[int]:
    """Indices of positional args that are msgids for this call."""
    name = _callee(node)
    if name == "ngettext":
        return [0, 1]  # singular, plural
    return [0]


def _lang_arg_index(node: ast.Call) -> int | None:
    """Index of the positional `language` argument, if this callee has one."""
    name = _callee(node)
    if name == "ngettext":
        return 3  # (singular, plural, count, language)
    if name in ("_", "gettext"):
        return 1
    return None


def _callee(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


# The escape hatch, for a msgid that is genuinely dynamic at the call site.
# It must still be marked with N_ wherever the text is DEFINED, or it will not
# be in the catalog — this only silences the call site.  Requiring a reason
# keeps it from becoming a reflex.
SUPPRESS = re.compile(r"#\s*i18n:\s*dynamic\b\s*(?:[-—]\s*\S+)")


def _suppressed(lines: list[str], lineno: int) -> bool:
    """True if the call carries ``# i18n: dynamic — <reason>`` on or above it."""
    for idx in (lineno - 1, lineno - 2):
        if 0 <= idx < len(lines) and SUPPRESS.search(lines[idx]):
            return True
    return False


def _is_gettext_internal(node: ast.Call) -> bool:
    """``translation.gettext(message)`` inside the i18n package itself.

    Those ARE the gettext API being called with a variable, by definition —
    flagging them would mean the module that implements ``_()`` can never
    satisfy the gate that guards ``_()``.
    """
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id in {"translation", "gettext"}
    )


def _const_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def collect_marked(root: Path) -> set[str]:
    """Names assigned from ``N_("...")`` — legitimately deferred msgids.

    ``_(SOME_CONST)`` is only safe when the constant's text was marked with
    ``N_`` at its definition, because that is what puts it in the .pot.  These
    are collected across the whole source root (not per file) since the
    constants live in shared modules like ``backend/api/error_constants.py``.
    """
    marked: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            value = node.value
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Call)
                and _callee(value) == "N_"
            ):
                marked.add(target.id)
    return marked


def check_sources(root: Path) -> list[str]:
    problems: list[str] = []
    marked = collect_marked(root)
    for path in sorted(root.rglob("*.py")):
        parts = path.parts
        if "__pycache__" in parts or any(p.startswith("test") for p in parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            problems.append(f"{path}: could not parse ({exc})")
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _callee(node) not in TRANSLATOR_NAMES:
                continue
            if _is_gettext_internal(node):
                continue
            if _suppressed(lines, node.lineno):
                continue
            for idx in _msgid_args(node):
                if idx >= len(node.args):
                    continue
                arg = node.args[idx]
                value = _const_str(arg)
                if value is None and isinstance(arg, ast.Name) and arg.id in marked:
                    continue  # deferred msgid, marked with N_ at its definition
                if value is None:
                    # xgettext only extracts STRING LITERALS.  `_(SOME_CONST)`
                    # puts nothing in the .pot, so the msgid never reaches a
                    # catalog and gettext returns the constant's value verbatim
                    # — in every language, English included.  This is how
                    # `_(OPENBAO_NOT_RUNNING_KEY)` shipped the literal
                    # "openbao.not_running" to users from 4 call sites, with
                    # every gate green: msgcmp cannot miss a msgid that was
                    # never extracted in the first place.
                    problems.append(
                        f"{path}:{node.lineno}: msgid of {_callee(node)}() is not "
                        f"a string literal ({ast.dump(arg)[:60]}…) — xgettext "
                        "cannot extract it, so it can never be translated"
                    )
                elif KEY_SHAPED.match(value):
                    problems.append(
                        f"{path}:{node.lineno}: msgid is a lookup key, not English "
                        f"prose: {value!r}"
                    )
            lang_idx = _lang_arg_index(node)
            if lang_idx is not None and lang_idx < len(node.args):
                value = _const_str(node.args[lang_idx])
                if value is not None and not LOCALE_CODE.match(value):
                    problems.append(
                        f"{path}:{node.lineno}: positional arg {lang_idx} of "
                        f"{_callee(node)}() is the LANGUAGE, but got {value!r} — "
                        "this is not an i18next-style English default"
                    )
    return problems


def check_catalogs(locales: Path) -> list[str]:
    """Flag key-shaped msgids in the .po files (no polib dependency)."""
    problems: list[str] = []
    msgid_line = re.compile(r'^msgid\s+"(.*)"\s*$')
    for po in sorted(locales.rglob("*.po")):
        for lineno, raw in enumerate(po.read_text(encoding="utf-8").splitlines(), 1):
            match = msgid_line.match(raw.strip())
            if match and KEY_SHAPED.match(match.group(1)):
                problems.append(
                    f"{po}:{lineno}: catalog msgid is a lookup key: "
                    f"{match.group(1)!r}"
                )
    return problems


REMEDY = """
How to fix
----------
gettext msgids are the English text itself.  The catalog keys on that text, so
there is no separate key to invent:

    -    _("openbao.sealed", "OpenBAO sealed successfully")
    +    _("OpenBAO sealed successfully")

Then re-sync and re-fill the catalogs:

    make i18n-extract-backend
    make translate SERVICE=http://<gpu-box>:8765
    make i18n-compile-backend

If a catalog already holds translations keyed on the OLD dotted msgid, discard
them — they are translations OF THE KEY (German literally had
"openbao.bereits_laufen"), not of the English.

NOTE: the frontend's t('some.key', 'English default') IS correct i18next and is
not affected by this gate.  Only backend gettext is.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--locales", required=True, type=Path)
    args = parser.parse_args()

    problems: list[str] = []
    if args.source_root.is_dir():
        problems += check_sources(args.source_root)
    if args.locales.is_dir():
        problems += check_catalogs(args.locales)

    if problems:
        print(
            f"FAIL: {len(problems)} gettext msgid-style problem(s) — a lookup key "
            "is being used where English prose belongs.",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(REMEDY, file=sys.stderr)
        return 1
    print("[OK] backend gettext msgids are English prose (no lookup keys).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
