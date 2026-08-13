#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Gate: the string extractor must SEE every file that has translatable text.

WHY THIS EXISTS
---------------
Every i18n completeness gate in these repos compares the catalog against what
the extractor produced.  That is a closed loop: when the extractor's file list
is wrong, the ``.pot`` and the ``.po`` agree perfectly about a catalog that is
missing whole files, and every gate stays green.

That is not hypothetical.  The Pro+ engines were originally single ``.pyx``
files.  The 1000-line-per-file cap later split them into ``.pxi`` includes —
and ``.pxi`` was never added to the extractor's glob.  Cython resolves
``include`` at COMPILE time, so xgettext reading the ``.pyx`` sees none of it.
650 strings across 16 engines dropped out of the extractor's view on the day of
the split.  Nothing failed: the existing translations sat in the catalogs, so
runtime was fine, and ``--check`` compared a ``.pxi``-blind pot to a
``.pxi``-blind po and pronounced them in sync.  The damage was latent — any NEW
string in a ``.pxi`` could never be translated, and the next ``--extract``
would have marked all 650 obsolete and dropped them from the ``.mo``.

HOW IT CHECKS
-------------
It does NOT re-derive the extractor's file list — comparing the extractor to a
second copy of its own configuration would reproduce the same blind spot.
Instead it runs ``xgettext`` over EVERY plausible source file and compares the
msgids that come back against the catalog.  Anything xgettext can find in the
tree but the catalog does not have is, by definition, a string the real
extractor never saw.

Using xgettext for the broad scan matters: it is the same lexer the real
extractor uses, so this cannot disagree with it about what counts as a
translatable call, and hand-rolled parsing cannot produce false positives.
"""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# One entry per gettext surface in this repo.  ``globs`` is deliberately WIDER
# than the real extractor's: that gap is exactly what this gate measures.
SURFACES = [
    {
        "name": "agent",
        "roots": ["src"],
        "globs": ["*.py"],
        "catalog": "src/i18n/locales/en/LC_MESSAGES/messages.po",
        "keywords": ["_", "N_", "ngettext:1,2"],
    },
]

# Files that legitimately hold no shipped strings.  Kept tight on purpose: a
# broad skip here silently re-opens the hole this gate exists to close.
SKIP_PARTS = ("__pycache__", ".git", "node_modules", ".venv", "build", "dist")
SKIP_NAME_RE = re.compile(r"^(test_|conftest\.py$)")

# A .po entry may be a single line, or gettext's standard wrapped form for long
# strings:
#
#     msgid ""
#     "a string too long for one line"
#
# Both are valid, and msgmerge/msgfmt/polib all emit the wrapped form above ~78
# columns.  The old pattern matched only the single-line case, so a legitimately
# wrapped entry looked ABSENT and this gate reported a string as "never reached a
# catalog" when it was sitting right there.  That is a false alarm on the one
# check whose whole job is telling you a string is missing.
MSGID_RE = re.compile(r'^msgid "(.*)"$', re.M)
CONTINUATION_RE = re.compile(r'^"(.*)"$')


def _source_files(surface) -> list[Path]:
    out: list[Path] = []
    for root in surface["roots"]:
        base = REPO / root
        if not base.is_dir():
            continue
        for pattern in surface["globs"]:
            for path in sorted(base.rglob(pattern)):
                if any(part in SKIP_PARTS for part in path.parts):
                    continue
                if SKIP_NAME_RE.match(path.name):
                    continue
                if any(part.startswith("test") for part in path.parts):
                    continue
                out.append(path)
    return out


def _msgids_from(paths: list[Path], keywords: list[str]) -> dict[str, str]:
    """``{msgid: "file:line"}`` for everything xgettext can find in ``paths``."""
    if not paths:
        return {}
    with tempfile.TemporaryDirectory() as tmp:
        pot = Path(tmp) / "broad.pot"
        cmd = ["xgettext", "--language=Python", "--from-code=UTF-8"]
        for keyword in keywords:
            cmd.append(f"--keyword={keyword}")
        cmd += ["-o", str(pot)] + [str(p) for p in paths]
        try:
            subprocess.run(cmd, check=True, capture_output=True)  # nosec B603 B607
        except subprocess.CalledProcessError as exc:
            print(
                f"FAIL: xgettext failed during the coverage scan:\n"
                f"{exc.stderr.decode('utf-8', 'replace')}",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        if not pot.exists():
            return {}
        text = pot.read_text(encoding="utf-8")
    found: dict[str, str] = {}
    location = ""
    for line in text.splitlines():
        if line.startswith("#: "):
            location = line[3:].strip().split()[0]
        elif line.startswith('msgid "'):
            msgid = line[7:-1]
            if msgid:
                found.setdefault(msgid, location)
    return found


def _catalog_msgids(path: Path) -> set[str]:
    """Every msgid in a .po/.pot, including gettext's wrapped multi-line form."""
    if not path.exists():
        return set()

    found: set[str] = set()
    pending: list[str] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("msgid "):
            match = MSGID_RE.match(line)
            pending = [match.group(1)] if match else None
            continue
        if pending is not None:
            continuation = CONTINUATION_RE.match(line)
            if continuation:
                pending.append(continuation.group(1))
                continue
            joined = "".join(pending)
            if joined:
                found.add(joined)
            pending = None
    if pending:
        joined = "".join(pending)
        if joined:
            found.add(joined)
    return found


def check() -> int:
    problems: list[str] = []
    for surface in SURFACES:
        paths = _source_files(surface)
        found = _msgids_from(paths, surface["keywords"])
        catalog = _catalog_msgids(REPO / surface["catalog"])
        if not catalog:
            if not found:
                # No catalog AND nothing to extract: this surface simply has no
                # translatable text.  Let xgettext be the judge of that rather
                # than a substring guess — every engine defines a `def _(s)`
                # translator shim, so "contains _(" is not evidence of a string.
                continue
            problems.append(
                f"{surface['name']}: {len(found)} translatable string(s) in the "
                f"source but catalog {surface['catalog']} does not exist"
            )
            continue
        missing = {k: v for k, v in found.items() if k not in catalog}
        for msgid, location in sorted(missing.items(), key=lambda kv: kv[1]):
            problems.append(
                f"{surface['name']}: {location}: not in the catalog: {msgid[:70]!r}"
            )
    if problems:
        print(
            f"FAIL: {len(problems)} translatable string(s) exist in the source but "
            "never reached a catalog.\n"
            "The extractor is not reading every file that has translatable text.",
            file=sys.stderr,
        )
        for problem in problems[:40]:
            print(f"  {problem}", file=sys.stderr)
        if len(problems) > 40:
            print(f"  ... and {len(problems) - 40} more", file=sys.stderr)
        print(
            "\nHow to fix\n"
            "----------\n"
            "Usually the extractor's file glob has drifted from reality — a new\n"
            "file extension, a new directory, or code moved into an include that\n"
            "the extractor does not read.  Widen the extractor's source list, then\n"
            "re-extract and translate:\n"
            "\n"
            "  make i18n-extract-backend\n"
            "  make translate SERVICE=http://<gpu-box>:8765\n"
            "  make i18n-compile-backend\n"
            "\n"
            "If a string genuinely should not ship, do not silence it here — stop\n"
            "wrapping it in _().\n",
            file=sys.stderr,
        )
        return 1
    print("[OK] every translatable string in the source reached a catalog.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if subprocess.run(  # nosec B603 B607
        ["sh", "-c", "command -v xgettext"], capture_output=True, check=False
    ).returncode:
        print("[skip] i18n-check-coverage: GNU gettext not installed — skipped")
        return 0
    return check()


if __name__ == "__main__":
    sys.exit(main())
