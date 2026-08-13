#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""The English catalogue must translate English to itself.

WHY THIS EXISTS
---------------
On 2026-08-13 the agent logged::

    ERROR: Error detecting partitions: Textual SQL expression ...

There is no partition code in that path.  The real message was "Error detecting
antivirus", and ``en.po`` had it translated to "Error detecting partitions" --
one of **347** entries whose msgstr belonged to a different msgid entirely.
Whatever produced the file paired msgstrs to msgids positionally rather than by
key.

The damage was not confined to English.  ``make translate`` translates the
English msgstr, so all thirteen locales faithfully rendered the WRONG English:
French, German, Spanish and Japanese all said "partitions" for the antivirus
message.  Every log line from an affected message named the wrong subsystem, in
every language, for weeks -- which is a debugging tax paid at exactly the moment
somebody is trying to work out what broke.

WHY IT WENT UNNOTICED
---------------------
Every existing i18n gate asks "is anything missing or untranslated?"  The file
was 100% complete.  Completeness was never the problem; correctness was, and
nothing checked it.

For English -- and only English -- correctness is trivially checkable:
``msgstr`` must equal ``msgid``.  That single assertion would have caught this
on the day it was introduced.

    python3 scripts/i18n_check_english_identity.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Only real source catalogues.  Build trees under installer/dist/ contain copies
# staged for packaging; they are outputs, not something anyone edits.
EXCLUDED_PARTS = ("installer/dist/", ".venv/", "node_modules/", "build/")


def english_catalogues(root: Path) -> list[Path]:
    return sorted(
        p
        for p in root.glob("**/en/LC_MESSAGES/messages.po")
        if not any(part in str(p) for part in EXCLUDED_PARTS)
    )


def mismatches(path: Path) -> list[tuple[str, str]]:
    """Entries whose English "translation" is not the English source.

    Uses polib when available -- it understands multi-line strings, plurals and
    obsolete entries -- and falls back to a regex so the gate still runs on a
    machine without it rather than silently passing.
    """
    try:
        import polib  # noqa: PLC0415
    except ImportError:
        import re  # noqa: PLC0415

        text = path.read_text(encoding="utf-8")
        pairs = re.findall(
            r'msgid "((?:[^"\\]|\\.)*)"\nmsgstr "((?:[^"\\]|\\.)*)"', text
        )
        return [(a, b) for a, b in pairs if a and b and a != b]

    catalogue = polib.pofile(str(path))
    bad = []
    for entry in catalogue:
        if entry.obsolete or not entry.msgid:
            continue
        # An empty msgstr is a GAP, not a scramble: gettext falls back to the
        # msgid, so the text is still correct English.  Other gates cover
        # completeness; this one is only about the message being WRONG.
        if entry.msgstr and entry.msgstr != entry.msgid:
            bad.append((entry.msgid, entry.msgstr))
    return bad


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fix",
        action="store_true",
        help="rewrite each offending msgstr to equal its msgid",
    )
    args = parser.parse_args()

    catalogues = english_catalogues(REPO)
    if not catalogues:
        print("[OK] no English catalogues found")
        return 0

    total_bad = 0
    for path in catalogues:
        bad = mismatches(path)
        rel = path.relative_to(REPO)
        if not bad:
            print(f"[OK] {rel}: English is identity")
            continue

        total_bad += len(bad)
        if args.fix:
            import polib  # noqa: PLC0415

            catalogue = polib.pofile(str(path))
            for entry in catalogue:
                if entry.msgid and entry.msgstr and entry.msgstr != entry.msgid:
                    entry.msgstr = entry.msgid
            catalogue.save(str(path))
            print(f"[FIXED] {rel}: {len(bad)} entries reset to identity")
            continue

        print(f"\nFAIL {rel}: {len(bad)} entrie(s) where the English msgstr is")
        print("     NOT the English msgid -- these messages say the wrong thing,")
        print("     and every other locale was translated from them:\n")
        for msgid, msgstr in bad[:10]:
            print(f"       msgid  {msgid[:66]}")
            print(f"       msgstr {msgstr[:66]}\n")
        if len(bad) > 10:
            print(f"       ... and {len(bad) - 10} more\n")

    if total_bad and not args.fix:
        print("Fix with: python3 scripts/i18n_check_english_identity.py --fix")
        print("Then clear the affected msgids in the other locales and re-run")
        print("`make translate` -- they were translated from the wrong English.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
