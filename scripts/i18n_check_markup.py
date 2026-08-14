#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
"""
Markup gate: a translation must carry the same inline tags as its English.

WHY THIS EXISTS
---------------
Every other i18n gate asks about PRESENCE or LANGUAGE:

  i18n-validate    is the key there?
  translate-check  is the value non-``[TODO]`` / non-empty?
  i18n-strict      is it English, stale, or in the wrong script?

None of them looks at STRUCTURE, so a translation can satisfy all of them and
still render wrongly, because the markup its English source carries did not
survive translation.  Found 2026-08-14 in sysmanage-docs, after a routine
``make translate``:

  * ``docs.admin.airgap.collection_cycle.step_request`` carries 20 tags in
    English (10 ``<code>`` pairs) and NONE in Arabic — every command in that
    step renders as ordinary prose for Arabic readers.
  * 660 such values across 13 locales, accumulated over years of runs.

The failure is silent in the worst way: the page still renders, so nobody
notices until a reader of that language complains, and the English-speaking
maintainer never sees it at all.

WHAT IT CHECKS
--------------
For every entry whose English contains markup, the multiset of tags in the
translation must equal the multiset in English — same tag names, same number of
opening and closing tags of each.  Order is deliberately NOT compared: word
order legitimately differs between languages, so a translator moving
``<code>foo</code>`` to the other end of a sentence is correct, while dropping
it is not.

It cannot catch a tag whose SCOPE moved — the Hindi
``server_quickstart.before.ports`` kept both ``<strong>`` tags but wrapped the
whole sentence instead of the port number, so the entire bullet rendered bold.
Counts matched, and nothing in the string says what the emphasis was meant to
cover.  A dropped tag is checkable; a misplaced one is not.

SURFACES come from ``i18n_strict.py`` rather than being redeclared here, so
there is one per-repo table and this file is byte-identical in all four repos
(see ``sync_i18n_tooling.py``).  Both JSON bundles and gettext ``.po`` are
covered: for ``.po`` the msgid IS the English, so it is compared to its msgstr.

THE BASELINE
------------
Pre-existing violations are recorded in ``.i18n-markup-baseline.json`` at the
repo root, so the gate fails only on NEW ones.  It is a RATCHET, not an
amnesty: if a baseline entry is now clean the gate FAILS and asks you to prune
it, so the list can only ever shrink.

Burn it down with ``--requeue`` (re-marks the offenders so the translation run
picks them up) followed by ``make translate``, then ``--prune``.

Usage:
  python3 scripts/i18n_check_markup.py            # check; exit 1 on new violations
  python3 scripts/i18n_check_markup.py --baseline # record current state (first run)
  python3 scripts/i18n_check_markup.py --prune    # drop entries that are now clean
  python3 scripts/i18n_check_markup.py --requeue  # re-mark violations for translation
  python3 scripts/i18n_check_markup.py --limit 40 # how many to print
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The per-repo SURFACES table and the loaders live in i18n_strict, which is
# itself kept in sync across the four repos.  Importing it rather than copying
# the table is what keeps this file identical everywhere -- and means a new
# surface is declared in exactly one place.
import i18n_strict as strict  # noqa: E402  (path set up above)

REPO = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO / ".i18n-markup-baseline.json"

# An HTML tag. Deliberately not a parser: these values are fragments, often
# with unbalanced markup by design, and a parser would reject them outright.
_TAG = re.compile(r"</?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>")


def signature(value: str) -> Counter:
    """Tags by name AND direction.

    ``<code>`` and ``</code>`` are counted separately on purpose: a translation
    that keeps two tags but turns a matched pair into two opening tags is
    broken, and a bare total would call it identical.
    """
    sig: Counter = Counter()
    for match in _TAG.finditer(value):
        name = match.group(1).lower()
        closing = match.group(0).startswith("</")
        sig[f"{'/' if closing else ''}{name}"] += 1
    return sig


def gather():
    """(surface, lang, path, key, english, en_sig, loc_sig) per mismatch."""
    found = []
    for surface in strict.SURFACES:
        if surface["kind"] == "po":
            for lang, path in strict.po_files(surface):
                for msgid, msgstr in strict.read_po(path).items():
                    if not _TAG.search(msgid):
                        continue
                    en_sig, loc_sig = signature(msgid), signature(msgstr)
                    if en_sig != loc_sig:
                        found.append(
                            (surface["name"], lang, path, msgid, msgid, en_sig, loc_sig)
                        )
            continue

        locales = strict.json_locales(surface)
        if strict.EN not in locales:
            continue
        _, english = locales[strict.EN]
        for lang, (path, values) in sorted(locales.items()):
            if lang == strict.EN:
                continue
            for key, en_value in english.items():
                if not _TAG.search(en_value):
                    continue
                value = values.get(key)
                # A gap is translate-check's problem, not ours; reporting it
                # here would name the same string under two different faults.
                if not isinstance(value, str) or value.startswith(strict.TODO.strip()):
                    continue
                en_sig, loc_sig = signature(en_value), signature(value)
                if en_sig != loc_sig:
                    found.append(
                        (surface["name"], lang, path, key, en_value, en_sig, loc_sig)
                    )
    return found


def identity(violation):
    surface, lang, _path, key = violation[0], violation[1], violation[2], violation[3]
    return (surface, lang, key)


def load_baseline() -> set:
    if not BASELINE_PATH.exists():
        return set()
    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    return {(e["surface"], e["locale"], e["key"]) for e in data.get("known", [])}


def save_baseline(entries: set) -> None:
    payload = {
        "_comment": (
            "Pre-existing markup mismatches, recorded so the gate fails on NEW ones. "
            "A ratchet, not an amnesty: this list may only shrink. Fix with "
            "`python3 scripts/i18n_check_markup.py --requeue`, then `make translate`, "
            "then `--prune`."
        ),
        "known": [
            {"surface": s, "locale": lang, "key": key}
            for s, lang, key in sorted(entries)
        ],
    }
    BASELINE_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def describe(en_sig: Counter, loc_sig: Counter) -> str:
    lost, gained = en_sig - loc_sig, loc_sig - en_sig
    bits = []
    if lost:
        bits.append("lost " + ", ".join(f"{n}x <{t}>" for t, n in sorted(lost.items())))
    if gained:
        bits.append(
            "added " + ", ".join(f"{n}x <{t}>" for t, n in sorted(gained.items()))
        )
    return "; ".join(bits) or "differs"


def show(violations, limit):
    for surface, lang, _path, key, _en, en_sig, loc_sig in violations[:limit]:
        label = key if len(key) <= 70 else key[:67] + "..."
        print(f"  [{surface}] {lang}  {label}")
        print(f"      {describe(en_sig, loc_sig)}")
    if len(violations) > limit:
        print(f"  ... and {len(violations) - limit} more")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--prune", action="store_true")
    parser.add_argument("--requeue", action="store_true")
    parser.add_argument("--limit", type=int, default=12)
    args = parser.parse_args()

    violations = gather()
    current = {identity(v) for v in violations}

    if args.baseline:
        save_baseline(current)
        print(f"[OK] recorded {len(current)} known markup mismatch(es)")
        return 0

    if args.requeue:
        if not violations:
            print("[OK] nothing to requeue")
            return 0
        # Same requeue used by i18n_strict, so .po and JSON are handled
        # identically here and there -- one implementation, one behaviour.
        items = [
            (s, lang, path, key, en) for s, lang, path, key, en, _, _ in violations
        ]
        total = strict.do_requeue(items, [])
        print(f"requeued {total} value(s); run `make translate` to refill them,")
        print("then `python3 scripts/i18n_check_markup.py --prune`.")
        return 0

    known = load_baseline()
    fixed = known - current

    if args.prune:
        save_baseline(known - fixed)
        print(f"[OK] pruned {len(fixed)} entrie(s) that are now clean")
        return 0

    new = [v for v in violations if identity(v) not in known]
    if new:
        print(
            f"\nFAIL: {len(new)} translation(s) do not carry the markup of "
            "their English source.\n"
        )
        show(new, args.limit)
        print(
            "\nThe page still renders, which is what makes this class of bug survive:\n"
            "a dropped <code> turns a command into prose, a dropped <strong> loses the\n"
            "emphasis, and no other gate looks at structure.\n"
            "\nWHAT TO DO:\n"
            "  * If YOU just wrote the translation, put the missing tag back.\n"
            "  * If a translation run produced it, re-translate the offenders:\n"
            "        make i18n-markup-fix SERVICE=http://<gpu-box>:8765\n"
            "    (requeue -> translate -> prune -> verify. Needs the GPU service,\n"
            "     which is why it is NOT part of make lint.)\n"
            "  * If the English changed and the tag is genuinely gone, the\n"
            "    translations are stale: `make i18n-fix` re-translates those.\n"
        )
        return 1

    if fixed:
        print(
            f"\nFAIL: {len(fixed)} baseline entrie(s) are now clean — "
            "the ratchet must tighten.\n"
        )
        for surface, lang, key in sorted(fixed)[: args.limit]:
            label = key if len(key) <= 70 else key[:67] + "..."
            print(f"  [{surface}] {lang}  {label}")
        if len(fixed) > args.limit:
            print(f"  ... and {len(fixed) - args.limit} more")
        print(
            "\nWHAT TO DO: they were fixed, so retire them from the baseline:\n"
            "  python3 scripts/i18n_check_markup.py --prune\n"
            "(or `make i18n-markup-fix`, which prunes as its third step)\n"
        )
        return 1

    if known:
        print(
            f"OK: no new markup mismatches ({len(known)} pre-existing, see "
            f"{BASELINE_PATH.name})"
        )
    else:
        print("OK: every translation carries the markup of its English source")
    return 0


if __name__ == "__main__":
    sys.exit(main())
