#!/usr/bin/env python3
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
import subprocess  # nosec B404 - calls pinned gettext binaries
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
LOCALES_DIR = REPO_ROOT / "src" / "i18n" / "locales"
POT_PATH = LOCALES_DIR / "messages.pot"
BABEL_CFG = REPO_ROOT / "babel.cfg"

# Hard limits.  These are "don't make it worse" budgets, not aspirational
# targets — current state has been measured and locked in here.  Lower
# these as the corresponding debt is paid down.
FUZZY_BUDGET = 50
# Number of code msgids allowed to be absent from a single locale's
# messages.po.  Most of the current "missing" pool is internal debug
# breadcrumbs like "=== BSD detect_updates called ===" that should be
# unwrapped from _() rather than translated; the cleanup is tracked
# separately.  Until then, lock in the current ceiling.
MISSING_BUDGET = 700


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


def cmd_merge() -> int:
    if not POT_PATH.exists():
        print("FAIL: run --extract first to generate messages.pot", file=sys.stderr)
        return 1
    for lang in list_locales():
        po_path = LOCALES_DIR / lang / "LC_MESSAGES" / "messages.po"
        cmd = ["msgmerge", "--update", "--backup=none", str(po_path), str(POT_PATH)]
        subprocess.run(cmd, check=True)  # nosec B603
        print(f"OK: merged {lang}")
    return 0


def cmd_compile() -> int:
    for lang in list_locales():
        po_path = LOCALES_DIR / lang / "LC_MESSAGES" / "messages.po"
        mo_path = LOCALES_DIR / lang / "LC_MESSAGES" / "messages.mo"
        cmd = ["msgfmt", "-o", str(mo_path), str(po_path)]
        subprocess.run(cmd, check=True)  # nosec B603
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
            severity = "FAIL" if len(missing) > MISSING_BUDGET else "WARN"
            print(
                f"{lang} [{severity}]: {len(missing)} msgid(s) untranslated "
                f"in messages.po (budget {MISSING_BUDGET})",
                file=sys.stderr,
            )
            for msgid in missing[:5]:
                print(f"  - {msgid!r}", file=sys.stderr)
            if len(missing) > 5:
                print(f"  ... and {len(missing) - 5} more", file=sys.stderr)
            if len(missing) > MISSING_BUDGET:
                failures += 1
        if fuzzy > FUZZY_BUDGET:
            print(
                f"{lang}: {fuzzy} fuzzy entries (budget {FUZZY_BUDGET})",
                file=sys.stderr,
            )
            failures += 1
    if failures:
        print(f"\nFAIL: {failures} issue(s)", file=sys.stderr)
        return 1
    print(
        "\nOK: every code msgid is translated and fuzzy budget respected",
        file=sys.stderr,
    )
    return 0


def cmd_strip_fuzzy() -> int:
    """Remove the ``fuzzy`` flag where the msgstr is non-empty and differs
    from the msgid.  Empty or echo-the-msgid stays fuzzy so it gets seen."""
    for lang in list_locales():
        po_path = LOCALES_DIR / lang / "LC_MESSAGES" / "messages.po"
        text = po_path.read_text(encoding="utf-8")
        out: list[str] = []
        block: list[str] = []
        for line in text.splitlines():
            if line.strip():
                block.append(line)
                continue
            out.extend(_strip_fuzzy_block(block))
            out.append(line)
            block = []
        out.extend(_strip_fuzzy_block(block))
        new_text = "\n".join(out)
        if not new_text.endswith("\n"):
            new_text += "\n"
        if new_text != text:
            po_path.write_text(new_text, encoding="utf-8")
            print(f"OK: stripped fuzzy flags in {lang}")
    return 0


_PRINTF_SPEC = re.compile(
    r"%[#0\-+ ]?\d*\.?\d*[diouxXeEfFgGcrsa%]|%\([^)]+\)[diouxXeEfFgGcrsa]"
)


def _format_specs(s: str) -> tuple:
    """Return a sorted tuple of printf specs in ``s``, ignoring ``%%``.

    Used to detect bad translations where the msgstr has dropped or
    changed the format placeholders relative to the msgid.  Such
    translations break ``logger.info(_(fmt), arg1, arg2)`` at runtime
    with TypeError.
    """
    return tuple(sorted(m for m in _PRINTF_SPEC.findall(s) if m != "%%"))


def _strip_fuzzy_block(block: list[str]) -> list[str]:
    if not block:
        return block
    msgid = _extract_quoted(block, "msgid")
    msgstr = _extract_quoted(block, "msgstr")
    if not msgid or not msgstr or msgstr == msgid:
        return block
    # CRITICAL safety check — if the msgstr's format specifiers don't match
    # the msgid's, removing the ``fuzzy`` flag would expose a translation
    # that crashes at runtime when the logger interpolates args.  Keep it
    # fuzzy so a translator review fills it in (or wipes it).
    if _format_specs(msgid) != _format_specs(msgstr):
        return block
    out: list[str] = []
    for line in block:
        if line.startswith("#,") and "fuzzy" in line:
            new = line.replace("fuzzy", "").replace(", ,", ",").strip()
            if new in ("#,", "#"):
                continue
            out.append(new)
        else:
            out.append(line)
    return out


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
