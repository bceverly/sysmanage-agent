#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""i18n extraction + validation pipeline for sysmanage-agent.

Modes (one required):
  --extract  Run pybabel-extract over ``src/`` and write the master .pot
             template to ``src/i18n/locales/messages.pot``.
  --merge    Merge the .pot template's new strings into every locale's
             messages.po (using ``msgmerge``).  Run after --extract.
  --compile  Compile every locale's messages.po → messages.mo.
  --validate Verify every ``_(...)`` msgid in the source tree is present
             (and not fuzzy) in every locale's messages.po.  Exit 1 on
             missing or excessive fuzzy entries.
  --strip-fuzzy  Remove the ``fuzzy`` flag from entries where the msgstr
                 looks complete (non-empty + not equal to msgid).  Use as
                 a one-time hygiene pass before re-translating; never run
                 in CI.

The 14 supported locales are auto-discovered from
``src/i18n/locales/<lang>/LC_MESSAGES/messages.po``.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess  # nosec B404 - calls pinned gettext binaries
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
LOCALES_DIR = REPO_ROOT / "src" / "i18n" / "locales"
POT_PATH = LOCALES_DIR / "messages.pot"
BABEL_CFG = REPO_ROOT / "babel.cfg"

# Hard limits, locked at zero (Phase 10 close-out, May 2026): every
# code-extracted msgid must be translated in every locale, and no
# fuzzy entries are tolerated.  CI fails on any drift.  If you need
# to bypass temporarily, fix the strings instead — the auto-translate
# tooling in ``scripts/`` can fill new keys across all 14 locales.
FUZZY_BUDGET = 0
MISSING_BUDGET = 0


def list_locales() -> list[str]:
    return sorted(
        p.name
        for p in LOCALES_DIR.iterdir()
        if p.is_dir() and (p / "LC_MESSAGES" / "messages.po").exists()
    )


def parse_po_msgids(po_path: Path) -> tuple[set[str], int]:
    """Return (set of translated msgids, fuzzy count) for one .po file.

    A msgid counts as "translated" when the corresponding msgstr is
    non-empty AND the entry is not flagged ``fuzzy``.  We don't shell out
    to msggrep — pure-Python parser works for our PO files (no plurals,
    no contexts in current usage).
    """
    text = po_path.read_text(encoding="utf-8")
    translated: set[str] = set()
    fuzzy_count = 0
    block: list[str] = []
    is_fuzzy = False

    def flush():
        nonlocal block, is_fuzzy, fuzzy_count
        if not block:
            block = []
            is_fuzzy = False
            return
        msgid = _extract_quoted(block, "msgid")
        msgstr = _extract_quoted(block, "msgstr")
        if msgid is not None and msgstr:
            if is_fuzzy:
                fuzzy_count += 1
            else:
                translated.add(msgid)
        block = []
        is_fuzzy = False

    for line in text.splitlines():
        if not line.strip() and block:
            flush()
            continue
        if line.startswith("#, ") and "fuzzy" in line:
            is_fuzzy = True
        block.append(line)
    flush()
    translated.discard("")  # PO header has empty msgid
    return translated, fuzzy_count


_QUOTED = re.compile(r'^(?P<key>msgid|msgstr)\s+"(?P<val>.*)"\s*$')
_CONT = re.compile(r'^"(?P<val>.*)"\s*$')


def _extract_quoted(block: list[str], key: str) -> str | None:
    """Extract the (possibly multi-line) value for ``key`` from a PO entry block."""
    out: list[str] = []
    found = False
    for line in block:
        if found:
            cont = _CONT.match(line)
            if cont:
                out.append(_unescape(cont.group("val")))
                continue
            break
        match = _QUOTED.match(line)
        if match and match.group("key") == key:
            out.append(_unescape(match.group("val")))
            found = True
    return "".join(out) if found else None


def _unescape(value: str) -> str:
    return value.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")


def extract_msgids() -> set[str]:
    """Run pybabel-extract over the source tree and return the set of msgids.

    Templates have empty msgstr by design, so we can't reuse
    parse_po_msgids (which keys off non-empty msgstr).  Just walk every
    msgid block in the .pot.
    """
    import tempfile

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".pot", delete=False, dir=str(REPO_ROOT)
    ) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _run_pybabel_extract(tmp_path)
        return _collect_pot_msgids(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _collect_pot_msgids(path: Path) -> set[str]:
    """Collect every non-empty msgid from a .pot or .po file."""
    msgids: set[str] = set()
    text = path.read_text(encoding="utf-8")
    block: list[str] = []

    def flush():
        if block:
            msgid = _extract_quoted(block, "msgid")
            if msgid:  # skip the empty-msgid PO header
                msgids.add(msgid)

    for line in text.splitlines():
        if not line.strip():
            flush()
            block.clear()
        else:
            block.append(line)
    flush()
    return msgids


def _run_pybabel_extract(out_path: Path) -> None:
    cmd = [
        "pybabel",
        "extract",
        "-F",
        str(BABEL_CFG),
        "-k",
        "_",
        "-k",
        "gettext",
        "-k",
        "ngettext:1,2",
        "-o",
        str(out_path),
        "--no-location",
        "--omit-header",
        "--no-wrap",
        "src",
    ]
    subprocess.run(  # nosec B603 - pinned argv
        cmd,
        check=True,
        cwd=str(REPO_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def cmd_extract() -> int:
    cmd = [
        "pybabel",
        "extract",
        "-F",
        str(BABEL_CFG),
        "-k",
        "_",
        "-k",
        "gettext",
        "-k",
        "ngettext:1,2",
        "-o",
        str(POT_PATH),
        "--copyright-holder=SysManage",
        "--project=sysmanage-agent",
        "src",
    ]
    subprocess.run(cmd, check=True, cwd=str(REPO_ROOT))  # nosec B603
    print(f"OK: wrote {POT_PATH}")
    return 0


def _clear_fuzzy(po_path: Path) -> None:
    """Drop the ``fuzzy`` flag AND empty the msgstr on every fuzzy entry, so a
    msgmerge GUESS becomes an honest empty gap that ``make translate`` refills
    accurately (a non-empty fuzzy hides the gap from the completeness check)."""
    if shutil.which("msgattrib"):
        subprocess.run(  # nosec B603 B607
            ["msgattrib", "--clear-fuzzy", "--empty", str(po_path), "-o", str(po_path)],
            check=True,
        )
    else:
        import polib  # noqa: PLC0415

        pofile = polib.pofile(str(po_path))
        for entry in pofile:
            if "fuzzy" in entry.flags:
                entry.flags.remove("fuzzy")
                entry.msgstr = ""
        pofile.save(str(po_path))


def _seed_english(po_path: Path) -> None:
    """English is the SOURCE, never a translation target (``make translate``
    deliberately skips it), so seed ``msgstr = msgid`` for every empty entry —
    otherwise the ``en`` locale fails the completeness check on new strings."""
    if shutil.which("msgen"):
        subprocess.run(  # nosec B603 B607
            ["msgen", "--output-file", str(po_path), str(po_path)], check=True
        )
    else:
        import polib  # noqa: PLC0415

        pofile = polib.pofile(str(po_path))
        changed = False
        for entry in pofile:
            if entry.msgid and not entry.obsolete and not entry.msgstr:
                entry.msgstr = entry.msgid
                changed = True
        if changed:
            pofile.save(str(po_path))


def cmd_merge() -> int:
    if not POT_PATH.exists():
        print("FAIL: run --extract first to generate messages.pot", file=sys.stderr)
        return 1
    for lang in list_locales():
        po_path = LOCALES_DIR / lang / "LC_MESSAGES" / "messages.po"
        # --no-fuzzy-matching: never let msgmerge GUESS a translation from a
        # similar string (guesses land `fuzzy`, which `make translate` skips and
        # validate rejects) — new strings become honest empty gaps instead.
        cmd = [
            "msgmerge",
            "--update",
            "--backup=none",
            "--no-fuzzy-matching",
            str(po_path),
            str(POT_PATH),
        ]
        subprocess.run(cmd, check=True)  # nosec B603
        # Also clear any PRE-EXISTING fuzzy guesses to honest gaps, and seed
        # English (source == translation) so `en` never fails on new strings.
        _clear_fuzzy(po_path)
        if lang == "en":
            _seed_english(po_path)
        print(f"OK: merged {lang}")
    return 0


def cmd_compile() -> int:
    for lang in list_locales():
        po_path = LOCALES_DIR / lang / "LC_MESSAGES" / "messages.po"
        mo_path = LOCALES_DIR / lang / "LC_MESSAGES" / "messages.mo"
        try:
            cmd = ["msgfmt", "-o", str(mo_path), str(po_path)]
            subprocess.run(cmd, check=True)  # nosec B603
        except (FileNotFoundError, OSError):
            # msgfmt (GNU gettext) not installed — fall back to pure-Python polib
            # so packaging works on platforms without gettext (e.g. Windows MSI).
            import polib  # noqa: PLC0415

            polib.pofile(str(po_path)).save_as_mofile(str(mo_path))
        print(f"OK: compiled {lang}")
    return 0


def cmd_validate() -> int:
    code_msgids = extract_msgids()
    print(f"INFO: extracted {len(code_msgids)} msgid(s) from source", file=sys.stderr)
    locales = list_locales()
    failures = 0
    for lang in locales:
        po_path = LOCALES_DIR / lang / "LC_MESSAGES" / "messages.po"
        translated, fuzzy = parse_po_msgids(po_path)
        missing = sorted(code_msgids - translated)
        if missing:
            print(
                f"{lang} [FAIL]: {len(missing)} msgid(s) untranslated "
                f"in messages.po",
                file=sys.stderr,
            )
            for msgid in missing[:5]:
                print(f"  - {msgid!r}", file=sys.stderr)
            if len(missing) > 5:
                print(f"  ... and {len(missing) - 5} more", file=sys.stderr)
            failures += 1
        if fuzzy > FUZZY_BUDGET:
            print(
                f"{lang} [FAIL]: {fuzzy} fuzzy entries",
                file=sys.stderr,
            )
            failures += 1
    if failures:
        print(f"\nFAIL: {failures} issue(s)", file=sys.stderr)
        print(
            "\nTo fix, run these in order ('make translate' only fills EMPTY msgstr,\n"
            "so new strings must first be merged in — i18n-merge also clears fuzzy\n"
            "guesses and seeds English, which translate does not touch):\n"
            "  make i18n-extract                              # source -> messages.pot\n"
            "  make i18n-merge                                # .pot -> locale .po (add msgids, clear fuzzy, seed en)\n"
            "  make translate SERVICE=http://<host>:8765      # fill foreign-language gaps via the GPU service\n"
            "  make i18n-compile                              # .po -> .mo\n"
            "  make i18n-validate                             # re-check (should pass)\n"
            "(SERVICE also reads $TRANSLATION_SERVICE_URL; defaults to http://localhost:8765.)",
            file=sys.stderr,
        )
        return 1
    print(
        "\nOK: every code msgid is translated and fuzzy budget respected",
        file=sys.stderr,
    )
    return 0


def cmd_strip_fuzzy() -> int:
    """Turn every fuzzy entry into a clean untranslated gap: drop the ``fuzzy``
    flag AND empty its msgstr.

    A fuzzy msgstr is msgmerge's GUESS carried over from a different (similar)
    string — NOT a real translation.  ``msgfmt`` already drops fuzzy entries from
    the compiled ``.mo`` (so they render English at runtime), but a NON-EMPTY
    fuzzy msgstr hides the gap from the completeness check, so a wrong/absent
    translation ships silently.  Emptying makes the gap honest: ``make translate``
    (or a human) then fills it accurately.  Uses gettext's ``msgattrib`` when
    present, else a pure-Python ``polib`` fallback (matches ``cmd_compile``)."""
    for lang in list_locales():
        po_path = LOCALES_DIR / lang / "LC_MESSAGES" / "messages.po"
        if shutil.which("msgattrib"):
            subprocess.run(  # nosec B603 B607
                [
                    "msgattrib",
                    "--clear-fuzzy",
                    "--empty",
                    str(po_path),
                    "-o",
                    str(po_path),
                ],
                check=True,
            )
        else:
            import polib  # noqa: PLC0415

            pofile = polib.pofile(str(po_path))
            for entry in pofile:
                if "fuzzy" in entry.flags:
                    entry.flags.remove("fuzzy")
                    entry.msgstr = ""
            pofile.save(str(po_path))
        print(f"OK: cleared fuzzy -> gaps in {lang}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--extract", action="store_true")
    mode.add_argument("--merge", action="store_true")
    mode.add_argument("--compile", action="store_true")
    mode.add_argument("--validate", action="store_true")
    mode.add_argument("--strip-fuzzy", action="store_true")
    args = parser.parse_args()
    if args.extract:
        return cmd_extract()
    if args.merge:
        return cmd_merge()
    if args.compile:
        return cmd_compile()
    if args.strip_fuzzy:
        return cmd_strip_fuzzy()
    return cmd_validate()


if __name__ == "__main__":
    sys.exit(main())
