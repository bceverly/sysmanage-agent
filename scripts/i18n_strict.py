#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
"""
Strict i18n gate: fail on translations that are English, or gone stale.

The existing completeness checks ask one question — "is the value present and
not ``[TODO]``?" — so two whole classes of broken translation sail past them:

  ENGLISH   The value is byte-identical to its English source with no marker.
            Renders English in every locale, forever, and every gate is green.
            A cross-repo audit on 2026-08-04 found 2,733 of these.

  STALE     The English was edited *after* the translation was made, so the
            locale still carries text describing the old behaviour.  Found in
            the docs, e.g. a German string still saying "Add one key to
            /etc/sysmanage.yaml" long after the English became "Set the role
            from the web UI".

Detection differs by format, and the difference is structural rather than a
matter of effort:

  * **gettext (.po)** keys each entry by the msgid, which *is* the English.
    Change the English and you get a NEW entry with an empty msgstr, which the
    completeness gate already fails on.  Staleness is therefore impossible by
    construction here and this tool only looks for ENGLISH.

  * **JSON / TS bundles** key on a stable dotted path with the English as a
    *value*.  Editing that value leaves every translation untouched and
    silently wrong — nothing about the file records that they no longer
    correspond.  So this tool keeps a sidecar of
    ``sha256(english)`` per key and calls a translation stale when the
    recorded hash no longer matches.

ESCAPE HATCH: ``i18n-allow.txt`` (same syntax as the docs repo's
``no-translate.txt``) lists keys that are *intentionally* identical to English
— product names, CLI snippets, protocol tokens.  Prefer a tight rule over a
broad glob; a rule that suppresses real prose is how this rots again.

Usage:
  python3 scripts/i18n_strict.py                # check; exit 1 on violations
  python3 scripts/i18n_strict.py --baseline     # accept current English as the
                                                # reference for staleness
  python3 scripts/i18n_strict.py --requeue      # re-mark violations '[TODO] …'
                                                # so `make translate` fills them
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
import unicodedata
from collections import OrderedDict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ALLOW_FILE = REPO / "i18n-allow.txt"

# Wrong-language RATCHET.  Widening wrong_script() to catch mixed-script values
# surfaced 1,146 pre-existing ones in sysmanage-docs -- corruption the model has
# been emitting for months (Chinese inside Arabic, Cyrillic inside Hindi).  They
# cannot be fixed by re-running the service: measured 2026-08-14, 6 of 8 came
# back contaminated again, because the fault is the 14b model bleeding its
# dominant language, not the prompt.
#
# So they are recorded here and the gate fails only on NEW ones.  A ratchet, not
# an amnesty: an entry that is now clean FAILS until pruned, so the list can
# only shrink.  Same contract as .i18n-markup-baseline.json.
LANG_BASELINE = REPO / ".i18n-language-baseline.json"


def _lang_identity(row):
    surface, lang, _path, key, _src = row
    return (surface, lang, key)


def load_lang_baseline() -> set:
    if not LANG_BASELINE.exists():
        return set()
    data = json.loads(LANG_BASELINE.read_text(encoding="utf-8"))
    return {(e["surface"], e["locale"], e["key"]) for e in data.get("known", [])}


def save_lang_baseline(entries: set) -> None:
    payload = {
        "_comment": (
            "Pre-existing wrong-language values, recorded so the gate fails on NEW "
            "ones. A ratchet, not an amnesty: this list may only shrink. See "
            "wrong_script() for why re-translating does not clear them."
        ),
        "known": [
            {"surface": s, "locale": lang, "key": key}
            for s, lang, key in sorted(entries)
        ],
    }
    LANG_BASELINE.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


TODO = "[TODO] "

# Surfaces this repo owns.  ``kind`` picks the reader; ``hashes`` is the
# staleness sidecar and is omitted for .po (see the module docstring).
# ===== per-repo surfaces: the ONLY part of this file that differs =====
SURFACES = [
    {
        "name": "agent",
        "kind": "po",
        "root": REPO / "src" / "i18n" / "locales",
    },
]
# ===== end per-repo surfaces ==========================================

EN = "en"

# Anything containing a letter is translatable until an allow-list rule says
# otherwise.  There is deliberately NO length threshold: "Login" is as much a
# user-facing string as a paragraph, and a threshold is an invisible exemption
# that nobody ever reviews — which is how 2,733 English values accumulated
# behind green gates in the first place.  Only genuine non-prose is excluded
# here (pure punctuation or digits, a bare URL); everything else that should
# stay English is a deliberate, visible entry in the allow-list.
_NOT_PROSE = re.compile(r"^[\W\d_]*$|^https?://\S*$")


def is_prose(text: str) -> bool:
    text = (text or "").strip()
    if not text or _NOT_PROSE.match(text):
        return False
    return bool(re.search(r"[A-Za-z]", text))


# Locales whose translations must be written in a specific script.  A value in
# some OTHER script is not a translation at all — it is the service having
# answered in the wrong language, and BOTH other checks pass it because it
# differs from English and carries no [TODO].  Found 2026-08-05: the Arabic
# locale held Chinese text in 52 places and Hindi held Korean/Japanese in 6.
_EXPECTED_SCRIPT = {
    "ar": ("ARABIC",),
    "hi": ("DEVANAGARI",),
    "ru": ("CYRILLIC",),
    "ja": ("CJK", "HIRAGANA", "KATAKANA"),
    "ko": ("HANGUL", "CJK"),
    "zh_CN": ("CJK",),
    "zh_TW": ("CJK",),
}
_SCRIPT_TAGS = (
    "ARABIC",
    "DEVANAGARI",
    "CYRILLIC",
    "HANGUL",
    "HIRAGANA",
    "KATAKANA",
    "CJK",
    "LATIN",
)


def scripts_used(text: str) -> set:
    """Unicode scripts present in ``text``, ignoring Latin.

    Latin is excluded because every locale legitimately carries product names,
    CLI snippets and acronyms in Latin script.
    """
    found = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        for tag in _SCRIPT_TAGS:
            if name.startswith(tag) or tag in name.split()[0:2]:
                found.add(tag)
                break
    return found - {"LATIN"}


def wrong_script(lang: str, text: str, source: str = None) -> bool:
    """True if ``text`` CONTAINS a script this locale never uses.

    Widened 2026-08-14.  It used to fire only when no expected script was
    present at all::

        return bool(used) and not used & set(expected)

    so a wholly-Chinese Arabic value was caught (52 of those, 2026-08-05) but a
    MIXED one was not: mostly-correct Arabic with Chinese spliced into the
    middle intersects {ARABIC} and passed.  410 such values were live in
    sysmanage-docs when this was found — ar 275, hi 50, de 40, ru 16, es 13,
    fr 9, pt 4, nl 2, it 1 — and `make i18n-strict` was green throughout.

    Latin is already excluded by scripts_used, so product names, paths and CLI
    snippets still pass.  A locale with no expectation (the Latin-script
    targets) now means exactly that: no non-Latin script.  Those were skipped
    entirely before, which is how German acquired 40 Chinese values.
    """
    expected = set(_EXPECTED_SCRIPT.get(lang) or ())
    # A script the ENGLISH already contains is legitimate in every locale: a
    # language picker renders "ko - 한국어" natively everywhere, and that is the
    # case the allow-list was being used to protect.  Deriving it from the
    # source instead is exact, and it closes the hole that protection opened --
    # an allow-listed value was exempt from this check ENTIRELY, so the model
    # rendering "fr - French" as "fr - 法语" in Arabic, or "401 Unauthorized" as
    # "401未经授权", passed silently.  45 such values on 2026-08-14.
    if source:
        expected |= scripts_used(source)
    used = scripts_used(text)
    return bool(used - expected)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------
# allow-list
# --------------------------------------------------------------------------


class Allow:
    """Key globs + value regexes that may legitimately stay English.

    Rules may be scoped to specific locales with a ``<langs>:`` prefix::

        de,nl: re:Status

    which matters more than it looks: "Status" and "Version" ARE the German
    word, so demanding a different string there is wrong — but Spanish should
    say "Estado", and an unscoped rule would silently bless the English in
    every locale.  Cognates are the main reason this scoping exists.
    """

    _SCOPE = re.compile(
        r"^([a-z]{2}(?:_[A-Z]{2})?(?:\s*,\s*[a-z]{2}(?:_[A-Z]{2})?)*)\s*:\s*(.+)$"
    )

    def __init__(self, path: Path):
        # None = applies to every locale; otherwise a set of locale names.
        self.keys: list[tuple[object, str]] = []
        self.values: list[tuple[object, re.Pattern]] = []
        if not path.exists():
            return
        bad = []
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Strip a trailing inline comment.  The convention in these files is
            # two-or-more spaces before the '#', which keeps a '#' that is part
            # of a pattern intact.  Not doing this makes the comment text part
            # of the regex, so the rule matches nothing — the docs repo had 23
            # rules silently dead that way.
            line = re.sub(r"\s{2,}#.*$", "", line).strip()
            scope = None
            scoped = self._SCOPE.match(line)
            if scoped and not line.startswith("re:"):
                scope = {p.strip() for p in scoped.group(1).split(",")}
                line = scoped.group(2).strip()
            if line.startswith("re:"):
                try:
                    self.values.append((scope, re.compile(line[3:])))
                except re.error as exc:
                    bad.append(f"{path.name}:{lineno}: {exc}")
            else:
                self.keys.append((scope, line))
        if bad:
            # Loudly.  Silently dropping a malformed rule means an entry the
            # author meant to exempt starts failing the build for no visible
            # reason, or worse, keeps passing when they meant to exempt it.
            raise SystemExit(
                f"i18n allow-list has {len(bad)} unusable rule(s):\n" + "\n  ".join(bad)
            )

    def allows(self, key: str, value: str, lang: str = None) -> bool:
        def live(scope):
            return scope is None or lang is None or lang in scope

        if any(live(s) and fnmatch.fnmatch(key, k) for s, k in self.keys):
            return True
        # fullmatch, NOT search.  "This value is untranslatable" means the WHOLE
        # value is a path/URL/identifier — not that a sentence happens to
        # mention one.  With search, `re://` exempted "Enterprise buyers buy
        # teams. Here's ours." because some sibling rule matched a substring,
        # which is precisely the "broad rule swallows the prose next to it"
        # failure this file's own header warns about.  A rule that really wants
        # substring semantics can say so with an explicit `.*`.
        return any(live(s) and p.fullmatch(value.strip()) for s, p in self.values)


# --------------------------------------------------------------------------
# readers
# --------------------------------------------------------------------------


def flatten(node, prefix=""):
    out = {}
    if isinstance(node, dict):
        for key, val in node.items():
            out.update(flatten(val, f"{prefix}{key}." if prefix else f"{key}."))
    elif isinstance(node, str):
        out[prefix.rstrip(".")] = node
    return out


def json_locales(surface):
    """{lang: (path, {key: value})} for a locales directory."""
    root, fname = surface["root"], surface.get("file")
    out = {}
    if not root.is_dir():
        return out
    for entry in sorted(root.iterdir()):
        # Two shapes in the wild: <lang>/translation.json (apps) and
        # <lang>.json (docs).  A leading dot is ours (the hash sidecar).
        if entry.is_dir() and fname:
            path = entry / fname
            if path.exists():
                out[entry.name] = (
                    path,
                    flatten(json.loads(path.read_text(encoding="utf-8"))),
                )
        elif (
            entry.is_file()
            and entry.suffix == ".json"
            and not entry.name.startswith(".")
        ):
            out[entry.stem] = (
                path := entry,
                flatten(json.loads(path.read_text(encoding="utf-8"))),
            )
    return out


_PO_DIRECTIVE = re.compile(r'^(msgid|msgstr)\s+"(.*)"\s*$')
_PO_CONTINUATION = re.compile(r'^"(.*)"\s*$')


def po_unescape(text: str) -> str:
    return text.replace(r"\"", '"').replace(r"\n", "\n").replace(r"\\", "\\")


def read_po(path: Path):
    """{msgid: msgstr} for entries with a non-empty translation."""
    entries, key, buf, field = {}, None, [], None

    def flush():
        if field == "msgstr" and key:
            value = po_unescape("".join(buf))
            if value:
                entries[key] = value

    for raw in path.read_text(encoding="utf-8").split("\n"):
        line = raw.strip()
        directive = _PO_DIRECTIVE.match(line)
        if directive:
            name, first = directive.groups()
            if name == "msgid":
                flush()
                field, buf = "msgid", [first]
            else:
                key = po_unescape("".join(buf))
                field, buf = "msgstr", [first]
            continue
        continuation = _PO_CONTINUATION.match(line)
        if continuation and field:
            buf.append(continuation.group(1))
            continue
        flush()
        field, buf = None, []
    flush()
    entries.pop("", None)
    return entries


def po_files(surface):
    root = surface["root"]
    if not root.is_dir():
        return []
    out = []
    for lang_dir in sorted(root.iterdir()):
        if not lang_dir.is_dir() or lang_dir.name == EN:
            continue
        for po in sorted((lang_dir / "LC_MESSAGES").glob("*.po")):
            out.append((lang_dir.name, po))
    return out


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------


def check_json(surface, allow, hashes):
    """(english, stale, wrong) violation lists for one JSON surface.

    All three returns are 3-tuples.  This one used to return a 2-tuple, which
    was not a style nit: ``gather`` unpacks three, so any JSON surface without
    an ``en`` locale crashed the whole gate with a ValueError instead of being
    skipped.  (``check_po`` returns TWO by design — a .po msgid IS the English,
    so a .po translation cannot go stale.)
    """
    locales = json_locales(surface)
    if EN not in locales:
        return [], [], []
    _, en = locales[EN]
    english, stale, wrong = [], [], []
    for lang, (path, loc) in sorted(locales.items()):
        if lang == EN:
            continue
        for key, value in loc.items():
            src = en.get(key)
            if src is None or value.startswith(TODO) or not value.strip():
                continue  # absent / already queued — the completeness gate owns these
            # The allow-list is consulted FIRST, including for wrong-script.
            # It has to be: a language picker legitimately renders native
            # names ("ko - 한국어") in every locale, and with the script check
            # ahead of it there would be no way to say so.  The safety comes
            # from the rules being whole-value (fullmatch) and tight, not from
            # denying the escape hatch.
            # Script check FIRST and source-aware: "may stay English" must not
            # mean "may be in any language at all".
            if wrong_script(lang, value, src):
                wrong.append((surface["name"], lang, path, key, src))
                continue
            if allow.allows(key, src, lang):
                continue
            if wrong_script(lang, value, src):
                wrong.append((surface["name"], lang, path, key, src))
                continue
            if value == src and is_prose(src):
                english.append((surface["name"], lang, path, key, src))
            elif key in hashes and hashes[key] != digest(src):
                stale.append((surface["name"], lang, path, key, src))
    return english, stale, wrong


def check_po(surface, allow):
    english, wrong = [], []
    for lang, path in po_files(surface):
        for msgid, msgstr in read_po(path).items():
            if msgstr.startswith(TODO) or allow.allows(msgid, msgid, lang):
                continue
            if wrong_script(lang, msgstr, msgid):
                wrong.append((surface["name"], lang, path, msgid, msgid))
                continue
            if msgstr == msgid and is_prose(msgid):
                english.append((surface["name"], lang, path, msgid, msgid))
    return english, wrong


def gather(allow):
    english, stale, wrong = [], [], []
    for surface in SURFACES:
        if surface["kind"] == "po":
            e, w = check_po(surface, allow)
            english += e
            wrong += w
        else:
            hashes = {}
            hp = surface.get("hashes")
            if hp and hp.exists():
                hashes = json.loads(hp.read_text(encoding="utf-8"))
            e, s, w = check_json(surface, allow, hashes)
            english += e
            stale += s
            wrong += w
    return english, stale, wrong


# --------------------------------------------------------------------------
# actions
# --------------------------------------------------------------------------


def do_baseline():
    """Record today's English as the staleness reference."""
    for surface in SURFACES:
        hp = surface.get("hashes")
        if not hp:
            continue
        locales = json_locales(surface)
        if EN not in locales:
            continue
        _, en = locales[EN]
        hp.write_text(
            json.dumps({k: digest(v) for k, v in sorted(en.items())}, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"  baselined {surface['name']:<10} {len(en)} key(s) -> {hp.name}")
    return 0


def _set_nested(tree, dotted, value):
    parts = dotted.split(".")
    for part in parts[:-1]:
        tree = tree[part]
    tree[parts[-1]] = value


def do_requeue(english, stale):
    """Re-mark every violation ``[TODO] <english>``.

    That prefix is the only state ``make translate`` acts on, so this is what
    converts "silently wrong" into "queued for the next translation run".
    """
    by_path = {}
    for _s, _lang, path, key, src in english + stale:
        by_path.setdefault(path, []).append((key, src))

    total = 0
    for path, items in sorted(by_path.items()):
        if path.suffix == ".po":
            # Key on the MSGID, not the msgstr.  Matching the msgstr only
            # works when it happens to equal the msgid (the English-identical
            # case) and silently does nothing for a wrong-language entry,
            # whose msgstr is the very text being replaced — that bug left 21
            # Arabic entries holding Chinese while reporting "converged".
            # Line-wise because gettext wraps long entries across
            # continuation lines.
            targets = {key for key, _src in items}
            lines = path.read_text(encoding="utf-8").split("\n")
            out, i, seen = [], 0, set()
            while i < len(lines):
                directive = _PO_DIRECTIVE.match(lines[i].strip())
                if directive and directive.group(1) == "msgid":
                    buf, j = [directive.group(2)], i + 1
                    while j < len(lines) and _PO_CONTINUATION.match(lines[j].strip()):
                        buf.append(_PO_CONTINUATION.match(lines[j].strip()).group(1))
                        j += 1
                    msgid = po_unescape("".join(buf))
                    out.extend(lines[i:j])
                    i = j
                    if msgid in targets and i < len(lines):
                        # Replace this entry's whole msgstr block with an empty
                        # one so the completeness gate sees a gap to refill.
                        d2 = _PO_DIRECTIVE.match(lines[i].strip())
                        if d2 and d2.group(1) == "msgstr":
                            k = i + 1
                            while k < len(lines) and _PO_CONTINUATION.match(
                                lines[k].strip()
                            ):
                                k += 1
                            out.append('msgstr ""')
                            seen.add(msgid)
                            i = k
                    continue
                out.append(lines[i])
                i += 1
            path.write_text("\n".join(out), encoding="utf-8")
            total += len(seen)
        else:
            doc = json.loads(
                path.read_text(encoding="utf-8"), object_pairs_hook=OrderedDict
            )
            for key, src in items:
                _set_nested(doc, key, TODO + src)
                total += 1
            path.write_text(
                json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--requeue", action="store_true")
    parser.add_argument("--language-baseline", action="store_true")
    parser.add_argument("--prune-language", action="store_true")
    parser.add_argument("--limit", type=int, default=8)
    args = parser.parse_args()

    if args.baseline:
        return do_baseline()

    allow = Allow(ALLOW_FILE)
    english, stale, wrong = gather(allow)

    known_wrong = load_lang_baseline()
    current_wrong = {_lang_identity(r) for r in wrong}
    if args.language_baseline:
        save_lang_baseline(current_wrong)
        print(f"[OK] recorded {len(current_wrong)} known wrong-language value(s)")
        return 0
    fixed_wrong = known_wrong - current_wrong
    if args.prune_language:
        save_lang_baseline(known_wrong - fixed_wrong)
        n = len(fixed_wrong)
        print(f"[OK] pruned {n} {'entry' if n == 1 else 'entries'} that are now clean")
        return 0
    # --requeue deliberately works on the FULL list, baseline included: an
    # explicit requeue is someone choosing to re-attempt them.
    if not args.requeue:
        wrong = [r for r in wrong if _lang_identity(r) not in known_wrong]
        if fixed_wrong and not (english or stale or wrong):
            print(
                f"\nFAIL: {len(fixed_wrong)} wrong-language baseline "
                f"{'entry' if len(fixed_wrong) == 1 else 'entries'} are "
                "now clean — the ratchet must tighten.\n"
                "  Drop them:  python3 scripts/i18n_strict.py --prune-language\n",
                file=sys.stderr,
            )
            return 1

    # Wrong-language content is requeued too: it is not a translation at all,
    # so the only fix is to ask the service again.
    if args.requeue:
        # Loop until the gate is clean.  A single pass is NOT guaranteed to
        # converge: re-reading a rewritten file can surface values the first
        # gather did not report, and a requeue that silently leaves violations
        # behind is worse than useless — it reports success and the overnight
        # translation run then misses them.
        total = 0
        for _round in range(6):
            # ``wrong`` MUST be in both the loop condition and the call.  It was
            # omitted from each at first, so the loop exited immediately and
            # reported "converged; 0 queued" while 21 wrong-language entries
            # sat untouched — a requeue that silently does nothing is exactly
            # the failure this loop exists to prevent.
            if not (english or stale or wrong):
                break
            total += do_requeue(english + wrong, stale)
            english, stale, wrong = gather(allow)
        else:
            print(
                f"FAIL: still {len(english)} English / {len(stale)} stale / "
                f"{len(wrong)} wrong-script after 6 requeue rounds",
                file=sys.stderr,
            )
            return 1
        print(f"  requeue converged; {total} value(s) queued for `make translate`")
        return 0

    for label, rows in (
        ("WRONG LANGUAGE", wrong),
        ("ENGLISH", english),
        ("STALE", stale),
    ):
        if not rows:
            continue
        print(f"\n{label} — {len(rows)} value(s):", file=sys.stderr)
        for surface, lang, _p, key, src in rows[: args.limit]:
            print(f"  {surface:<10} {lang:<6} {key}", file=sys.stderr)
            print("      " + src[:88].replace("\n", " "), file=sys.stderr)
        if len(rows) > args.limit:
            print(f"  ... and {len(rows) - args.limit} more", file=sys.stderr)

    if english or stale or wrong:
        print(
            f"\nFAIL: {len(english)} English-identical, {len(stale)} stale, "
            f"{len(wrong)} wrong-language.\n"
            "  Queue them for translation:  python3 scripts/i18n_strict.py --requeue\n"
            "  Then:                        make translate SERVICE=http://<gpu-box>:8765\n"
            + (
                # Neither --requeue nor `make translate` touches the hash
                # sidecar, so a STALE key raised by a deliberate English edit
                # survives both and reports stale forever.  Omitting this step
                # from the hint cost a full requeue/translate/still-stale loop
                # on docs roadmap.edition.community (2026-08-12).  Only shown
                # when something is actually stale: after an English-identical
                # or wrong-language failure, baselining is the WRONG move --
                # it would record the untranslated value as the reference.
                "  English edit now retranslated?  "
                "python3 scripts/i18n_strict.py --baseline\n"
                "      (records today's English as the staleness reference; run it\n"
                "       ONLY once the translations above are genuinely current)\n"
                if stale
                else ""
            )
            + "  Intentionally-English value? Add a tight rule to i18n-allow.txt.",
            file=sys.stderr,
        )
        return 1

    print("OK: no English-identical, stale or wrong-language translations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
