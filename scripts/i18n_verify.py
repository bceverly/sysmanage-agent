#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
"""
Translation verifier: every translated value must be PROVEN good, not merely
free of the defects someone already found.

The older gates (completeness, English-identical, stale, wrong script, wrong
sense, markup, code) each recognize one failure found in the past.  A
translation that is wrong in a new way passes all of them -- which is how a
French file came to hold English text filed under unrelated keys, Portuguese
values became Python list literals, and Korean became "The 규정 준수 엔진 is
accessible 을(를) 통해 the REST API:" without a single gate noticing.

So this inverts the question.  A value is accepted only when it is in the
LEDGER (``.i18n-verified`` at the repository root): one line per
``(locale, English source, translation)`` that passed verification.  Editing
either the English or the translation changes the digest, so the value must be
verified again.  Nothing else writes the ledger.

Verification has two layers:

  1. Deterministic (``i18n_quality.py``; runs everywhere, CI included): no list
     literals or non-string values, no pipeline markers, placeholders intact,
     no English function words outside code and quotes.

  2. Model-backed (the translation service on the GPU box, ``POST
     /verify/batch``): a multilingual embedding must place the translation
     next to its source (bge-m3 cosine >= 0.75 passes, < 0.40 fails), and
     anything between goes to a single-item judge asked one question -- does
     this say what the source says?  Calibrated 2026-10-08: the embedding
     separates a translation from another key's text (swapped pairs never
     exceeded 0.62), and the judge rejected 24 of 25 wrong-key values and
     every one of 25 good ones it was shown.

Usage:
  python3 scripts/i18n_verify.py                   # CI gate: deterministic +
                                                   # every value in the ledger
  python3 scripts/i18n_verify.py --deterministic-only
  python3 scripts/i18n_verify.py --service http://beast:8765
                                                   # verify what is missing;
                                                   # passes go in the ledger
  python3 scripts/i18n_verify.py --requeue         # mark the last run's
                                                   # failures [TODO] so
                                                   # `make translate` redoes them
  python3 scripts/i18n_verify.py --accept fr some.key --reason "..."
                                                   # a human vouches for one
                                                   # value the checks reject

Shared verbatim by sysmanage, sysmanage-agent, sysmanage-professional-plus and
sysmanage-docs (scripts/sync_i18n_tooling.py); only the license header differs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import i18n_quality  # noqa: E402
import i18n_strict as strict  # noqa: E402

try:  # Pro+ only: the plugin bundles are a surface i18n_strict does not read.
    import plugin_i18n_lib as plugins
except ImportError:
    plugins = None

REPO = strict.REPO
LEDGER = REPO / ".i18n-verified"
FAILURES = REPO / ".i18n-verify-failures.json"
BATCH = 64
SAVE_EVERY = 60.0  # seconds between ledger saves, so an interrupted run resumes
# A locale directory can hold other JSON (sysmanage-docs kept an analysis dump
# beside its locale files); only names shaped like a locale are translations.
_LOCALE = re.compile(r"^[a-z]{2}(?:_[A-Z]{2})?$")


class Value(NamedTuple):
    surface: str
    lang: str
    path: Path
    key: str
    source: str
    value: object  # usually str; anything else is itself a failure


def digest(lang: str, source: str, value: str) -> str:
    raw = f"{lang}\0{source}\0{value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


# --------------------------------------------------------------------------
# reading every translated value
# --------------------------------------------------------------------------


def _json_leaves(node, prefix=""):
    """Every leaf, strings or not -- ``strict.flatten`` drops non-strings,
    which is exactly the shape of value this verifier must see."""
    if isinstance(node, dict):
        for key, val in node.items():
            yield from _json_leaves(val, f"{prefix}{key}." if prefix else f"{key}.")
    else:
        yield prefix.rstrip("."), node


def _json_values(surface) -> Iterator[Value]:
    locales = strict.json_locales(surface)
    if strict.EN not in locales:
        return
    _, en = locales[strict.EN]
    for lang, (path, _flat) in sorted(locales.items()):
        if lang == strict.EN or not _LOCALE.match(lang):
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        for key, val in _json_leaves(doc):
            src = en.get(key)
            if src is not None:
                yield Value(surface["name"], lang, path, key, src, val)


def _po_values(surface) -> Iterator[Value]:
    for lang, path in strict.po_files(surface):
        for msgid, msgstr in strict.read_po(path).items():
            yield Value(surface["name"], lang, path, msgid, msgid, msgstr)


def _plugin_values() -> Iterator[Value]:
    if plugins is None:
        return
    for name, entry, bundle in plugins.plugins():
        english = plugins.leaves(plugins.entry_english(entry))
        for lang, tree in sorted(plugins.bundle_languages(bundle).items()):
            if lang == strict.EN:
                continue
            for key, val in plugins.leaves(tree).items():
                src = english.get(key)
                if isinstance(src, str):
                    yield Value(f"plugin:{name}", lang, bundle, key, src, val)


def _kept_english(item: Value, allow) -> bool:
    """Whether a value identical to its English was deliberately left so.

    The JSON and .po surfaces answer through i18n-allow.txt; the Pro+ plugin
    bundles keep their own list (plugin_i18n_keep_english.json) and rule, and
    the verifier must honor whichever one the surface's own gate uses.
    """
    if item.surface.startswith("plugin:") and plugins is not None:
        return not plugins.looks_untranslated(item.source, item.source, item.lang)
    return allow.allows(item.key, item.source, item.lang)


def translated_values(allow) -> Iterator[Value]:
    """Every value that claims to be a translation and so must be verified."""
    sources = []
    for surface in strict.SURFACES:
        sources.append(
            _po_values(surface) if surface["kind"] == "po" else _json_values(surface)
        )
    sources.append(_plugin_values())
    for stream in sources:
        for item in stream:
            val = item.value
            if isinstance(val, str):
                if not val.strip() or val.startswith(strict.TODO):
                    continue  # absent / queued: the completeness gate owns it
                if not strict.is_prose(item.source):
                    continue  # nothing translatable in the source
                if val.strip() == item.source.strip() and _kept_english(item, allow):
                    continue  # a reviewed decision to keep the English
            yield item


# --------------------------------------------------------------------------
# the ledger
# --------------------------------------------------------------------------


def load_ledger() -> Dict[str, str]:
    """{``lang:digest``: ``model`` | ``human <reason>``}."""
    out = {}
    if LEDGER.exists():
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            parts = line.split("\t", 2)
            if len(parts) >= 3:
                out[f"{parts[0]}:{parts[1]}"] = parts[2]
    return out


def save_ledger(entries: Dict[str, str]) -> None:
    lines = []
    for entry, how in sorted(entries.items()):
        lang, dig = entry.split(":", 1)
        lines.append(f"{lang}\t{dig}\t{how}")
    LEDGER.write_text(
        "# Verified translations: <locale> <digest of locale+English+translation>"
        " <model|human reason>.\n# Written ONLY by scripts/i18n_verify.py; see its"
        " docstring.\n" + "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def ident(item: Value) -> str:
    return f"{item.lang}:{digest(item.lang, item.source, str(item.value))}"


# --------------------------------------------------------------------------
# modes
# --------------------------------------------------------------------------


def classify(allow, ledger) -> Tuple[List[Tuple[Value, str]], List[Value]]:
    """(deterministic failures, values still awaiting model verification)."""
    failed, pending = [], []
    for item in translated_values(allow):
        how = ledger.get(ident(item), "")
        if how.startswith("human"):
            continue  # a person vouched for exactly this text
        why = i18n_quality.problem(item.lang, item.source, item.value)
        if not why and str(item.value).strip() == item.source.strip():
            # The embedding would score this a perfect match.  Kept-English
            # values are exempted earlier, through the allow-list, or not at all.
            why = "identical to the English source"
        if why:
            failed.append((item, why))
        elif not how:
            pending.append(item)
    return failed, pending


def _report(failed, pending, deterministic_only, limit) -> int:
    if failed:
        print(
            f"\nFAILED deterministic checks -- {len(failed)} value(s):", file=sys.stderr
        )
        by_kind = Counter(why.split(":")[0].split(" [")[0] for _i, why in failed)
        for kind, n in by_kind.most_common():
            print(f"  {n:6}  {kind}", file=sys.stderr)
        for item, why in failed[:limit]:
            print(f"  {item.surface} {item.lang} {item.key}: {why}", file=sys.stderr)
    if pending and not deterministic_only:
        print(
            f"\nNOT VERIFIED -- {len(pending)} value(s) have no ledger entry:",
            file=sys.stderr,
        )
        per = Counter((i.surface, i.lang) for i in pending)
        for (surface, lang), n in sorted(per.items())[:limit]:
            print(f"  {n:6}  {surface} {lang}", file=sys.stderr)
    if failed or (pending and not deterministic_only):
        print(
            "\n  Verify (GPU box):  make i18n-verify-run SERVICE=http://<gpu-box>:8765\n"
            "  Redo failures:     python3 scripts/i18n_verify.py --requeue, then make translate\n"
            "  A false alarm:     python3 scripts/i18n_verify.py --accept <locale> <key>"
            ' --reason "..."',
            file=sys.stderr,
        )
        return 1
    if deterministic_only:
        print(
            "[OK] every translated value passes the deterministic checks"
            " (ledger not consulted)"
        )
    else:
        print("[OK] every translated value is verified")
    return 0


def _post(service: str, lang: str, batch: List[Value]) -> List[dict]:
    body = json.dumps(
        {"lang": lang, "items": [{"source": i.source, "value": i.value} for i in batch]}
    ).encode("utf-8")
    req = urllib.request.Request(
        service.rstrip("/") + "/verify/batch",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    # The URL is the operator's own --service argument, and only http(s) is
    # accepted (checked in main), so urllib's file:// handling is unreachable.
    with urllib.request.urlopen(  # nosec B310 # nosemgrep: dynamic-urllib-use-detected
        req, timeout=1800
    ) as resp:
        results = json.loads(resp.read())["results"]
    if len(results) != len(batch):
        raise RuntimeError(f"service returned {len(results)} results for {len(batch)}")
    return results


RETRIES = 3


def _post_with_retries(service: str, lang: str, batch: List[Value]):
    """The service's verdicts, or None after RETRIES failures in a row.

    A run over the docs takes hours; one dropped connection (Ollama restarted,
    a model reloaded) must not end it.
    """
    for attempt in range(1, RETRIES + 1):
        try:
            return _post(service, lang, batch)
        except (urllib.error.URLError, OSError, RuntimeError, ValueError) as exc:
            print(
                f"\n  service error ({exc}); attempt {attempt} of {RETRIES}",
                file=sys.stderr,
            )
            time.sleep(10 * attempt)
    return None


def _run_batches(service, by_lang, total, ledger, model_failed) -> Optional[int]:
    """Send every pending value; the number sent, or None when the service failed."""
    done, started = 0, time.time()
    saved = started
    for lang in sorted(by_lang):
        items = by_lang[lang]
        for start in range(0, len(items), BATCH):
            chunk = items[start : start + BATCH]
            results = _post_with_retries(service, lang, chunk)
            if results is None:
                save_ledger(ledger)
                print(
                    "\nERROR: the service kept failing; progress saved -- "
                    "re-run to resume.",
                    file=sys.stderr,
                )
                return None
            for item, res in zip(chunk, results):
                if res.get("ok"):
                    ledger[ident(item)] = "model"
                else:
                    model_failed[ident(item)] = res.get("reason") or "rejected"
            done += len(chunk)
            if time.time() - saved >= SAVE_EVERY:
                save_ledger(ledger)
                saved = time.time()
            rate = done / max(time.time() - started, 1e-6)
            left = (total - done) / rate if rate else 0
            print(
                f"\r  {done}/{total}  {lang:<6} {len(model_failed)} rejected"
                f"  ~{left / 60:.0f} min left   ",
                end="",
                flush=True,
            )
    print()
    return done


def do_verify(service: str, allow, limit: int) -> int:
    ledger = load_ledger()
    failed, pending = classify(allow, ledger)
    # Identical (locale, source, translation) triples are verified once: the
    # docs repeat many strings across pages.
    unique: "OrderedDict[str, Value]" = OrderedDict()
    for item in pending:
        unique.setdefault(ident(item), item)
    by_lang: Dict[str, List[Value]] = defaultdict(list)
    for item in unique.values():
        by_lang[item.lang].append(item)
    total = len(unique)
    print(
        f"{len(failed)} deterministic failure(s); verifying {total} value(s) "
        f"({len(pending)} before de-duplication) against {service}"
    )

    model_failed: Dict[str, str] = {}
    try:
        done = _run_batches(service, by_lang, total, ledger, model_failed)
    except KeyboardInterrupt:
        save_ledger(ledger)
        print("\ninterrupted; progress saved -- re-run to resume.", file=sys.stderr)
        return 130
    if done is None:
        return 1

    # Drop ledger lines for text that no longer exists, so the file tracks the
    # repository instead of growing forever.
    live = {ident(i) for i in translated_values(allow)}
    ledger = {k: v for k, v in ledger.items() if k in live}
    save_ledger(ledger)

    rows = [
        {
            "surface": i.surface,
            "lang": i.lang,
            "path": str(i.path),
            "key": i.key,
            "source": i.source,
            "value": i.value,
            "reason": why,
        }
        for i, why in failed
    ]
    for item in pending:
        reason = model_failed.get(ident(item))
        if reason:
            rows.append(
                {
                    "surface": item.surface,
                    "lang": item.lang,
                    "path": str(item.path),
                    "key": item.key,
                    "source": item.source,
                    "value": item.value,
                    "reason": reason,
                }
            )
    FAILURES.write_text(
        json.dumps(rows, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    print(
        f"verified {done - len(model_failed)}, rejected {len(model_failed)} "
        f"by the model, {len(failed)} by the deterministic checks"
    )
    if rows:
        print(f"Failures listed in {FAILURES.name}; queue them with --requeue.")
        for row in rows[:limit]:
            print(f"  {row['surface']} {row['lang']} {row['key']}: {row['reason']}")
    return 1 if rows else 0


def _requeue_plugin(rows) -> int:
    by_bundle = defaultdict(list)
    for row in rows:
        by_bundle[row["path"]].append(row)
    total = 0
    for path_str, items in by_bundle.items():
        path = Path(path_str)
        name = path.name[: -len("-i18n.ts")]
        langs = plugins.bundle_languages(path)
        for row in items:
            plugins.set_path(
                langs.setdefault(row["lang"], {}),
                row["key"],
                strict.TODO + row["source"],
            )
            total += 1
        plugins.write_bundle(name, path, langs)
    return total


def do_requeue() -> int:
    if not FAILURES.exists():
        print(
            f"Nothing to requeue: run a verification first ({FAILURES.name} is absent)."
        )
        return 1
    rows = json.loads(FAILURES.read_text(encoding="utf-8"))
    plugin_rows = [r for r in rows if r["surface"].startswith("plugin:")]
    other = [
        (r["surface"], r["lang"], Path(r["path"]), r["key"], r["source"])
        for r in rows
        if not r["surface"].startswith("plugin:")
    ]
    total = strict.do_requeue(other, [])
    if plugin_rows:
        total += _requeue_plugin(plugin_rows)
    FAILURES.unlink()
    print(
        f"queued {total} value(s) as [TODO]; now run `make translate`, "
        "which verifies what it writes"
    )
    return 0


def do_accept(lang: str, key: str, reason: str, allow) -> int:
    if not reason.strip():
        print(
            "--accept needs --reason: an override is a reviewed decision.",
            file=sys.stderr,
        )
        return 1
    ledger = load_ledger()
    hits = [i for i in translated_values(allow) if i.lang == lang and i.key == key]
    if not hits:
        print(f"No translated value for {lang} {key}.", file=sys.stderr)
        return 1
    for item in hits:
        ledger[ident(item)] = "human " + " ".join(reason.split())
        print(f"accepted {item.surface} {lang} {key}: {str(item.value)[:80]!r}")
    save_ledger(ledger)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 2)[1])
    parser.add_argument(
        "--service", help="translation service URL; verify what is missing"
    )
    parser.add_argument(
        "--deterministic-only",
        action="store_true",
        help="skip the ledger requirement (no model available)",
    )
    parser.add_argument("--requeue", action="store_true")
    parser.add_argument("--accept", nargs=2, metavar=("LOCALE", "KEY"))
    parser.add_argument("--reason", default="")
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args(argv)

    allow = strict.Allow(strict.ALLOW_FILE)
    if args.requeue:
        return do_requeue()
    if args.accept:
        return do_accept(args.accept[0], args.accept[1], args.reason, allow)
    if args.service:
        if not args.service.lower().startswith(("http://", "https://")):
            print("--service must be an http:// or https:// URL", file=sys.stderr)
            return 2
        return do_verify(args.service, allow, args.limit)
    failed, pending = classify(allow, load_ledger())
    return _report(failed, pending, args.deterministic_only, args.limit)


if __name__ == "__main__":
    sys.exit(main())
