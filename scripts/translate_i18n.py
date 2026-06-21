#!/usr/bin/env python3
"""
translate_i18n.py — idempotent i18n translation backfill for THIS project,
via the SysManage GPU translation service.

Finds the untranslated strings in this repo's locale store, batch-translates the
gaps through the service, and writes them back — only ever sending strings that
are NOT yet translated, so re-running is cheap and resumable.  The service lives
in the sysmanage repo at ``scripts/translation-service/`` (run it on the GPU box).

Usage:
  export TRANSLATION_SERVICE_URL=http://beast:8765   # your GPU box
  python3 scripts/translate_i18n.py            # or:  make translate
  python3 scripts/translate_i18n.py --dry-run  # report gap counts, no writes

Flags: --service URL, --langs de,ja, --limit N, --client-batch N, --dry-run.
The .po driver needs polib (pip install polib); JSON needs only the stdlib.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ===== per-project configuration (the ONLY part that differs per repo) =====
PROJECT = "sysmanage-agent"
FORMAT = "po"  # "json" | "po"
LOCALES_REL = "src/i18n/locales"  # relative to the repo root (parent of scripts/)
FILE_TEMPLATE = "{lang}/LC_MESSAGES/messages.po"  # per-language file under LOCALES_REL
# ===========================================================================

# The 13 translation targets (English is the source, never a target).
TARGET_LANGS = [
    "ar",
    "de",
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

# A string with no letters (pure placeholder/code) is correct to leave
# unchanged; used to tell "legitimately identical" from "service fell back to
# English because it couldn't translate safely".
_HAS_LETTER = re.compile(r"[^\W\d_]", re.UNICODE)

# Placeholder/markup tokens — used to distinguish a placeholder-fallback
# (identical output because the service couldn't translate a {{…}}/%s/<tag>
# safely) from a legitimately-identical term (acronyms like URL/IPv4 or words
# the model keeps as-is, e.g. "Details"). Only the former is held back to retry.
_PLACEHOLDER_RE = re.compile(
    r"\{\{.*?\}\}|\$\{[^}]+\}|\{[^{}]*\}|%\d+\$[sdfgex]|%\(\w+\)[sdfgexr]"
    r"|%[sdfgexr%]|\$[A-Za-z_]\w*|</?[A-Za-z][^>]*>|&[a-zA-Z]+;|&#\d+;"
)


# ---------------------------------------------------------------------------
# Service client
# ---------------------------------------------------------------------------


def _post(url: str, payload: dict, timeout: float = 1800.0) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    # nosemgrep: dynamic-urllib-use-detected -- service URL is operator config (trusted LAN), not request input
    with urllib.request.urlopen(
        req, timeout=timeout
    ) as resp:  # noqa: S310 (trusted LAN)
        return json.loads(resp.read().decode("utf-8"))


def _service_ok(service: str) -> bool:
    try:
        # nosemgrep: dynamic-urllib-use-detected -- service URL is operator config (trusted LAN), not request input
        with urllib.request.urlopen(  # noqa: S310
            f"{service.rstrip('/')}/health", timeout=10
        ) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


def translate_to(
    service: str, texts: List[str], lang: str, client_batch: int
) -> List[str]:
    out: List[str] = []
    for i in range(0, len(texts), client_batch):
        chunk = texts[i : i + client_batch]
        try:
            resp = _post(
                f"{service.rstrip('/')}/translate/batch",
                {"texts": chunk, "targets": [lang]},
            )
        except (urllib.error.URLError, OSError) as exc:
            sys.exit(
                f"\nERROR: lost connection to the translation service at {service}: {exc}\n"
                "  Already-finished languages are saved; re-run to resume."
            )
        for item in resp["results"]:
            out.append(item["translations"][lang])
        print(f"      …{min(i + client_batch, len(texts))}/{len(texts)}", flush=True)
    return out


def _accept(source: str, translated: str) -> bool:
    """Decide whether to write a translation back.

    Write it when it actually changed.  When it comes back identical, only hold
    it back (leave a [TODO] gap to retry) if the source is a letter-bearing
    string that ALSO contains a placeholder/markup token — that combination is
    the service's English fallback for a {{…}}/%s/<tag> it couldn't translate
    safely.  An identical result with no placeholder is a term the model
    legitimately keeps as-is (acronyms like URL/IPv4, or words such as
    "Details") and IS written, so it doesn't linger as a gap forever."""
    if translated != source:
        return True
    return not (_HAS_LETTER.search(source) and _PLACEHOLDER_RE.search(source))


# ---------------------------------------------------------------------------
# JSON driver  (nested dict, dotted keys, [TODO] placeholders)
# ---------------------------------------------------------------------------


def _flatten(obj: dict, prefix: str = "") -> Dict[str, str]:
    flat: Dict[str, str] = {}
    for key, val in obj.items():
        dotted = f"{prefix}.{key}" if prefix else key
        if isinstance(val, dict):
            flat.update(_flatten(val, dotted))
        elif isinstance(val, str):
            flat[dotted] = val
    return flat


def _set_dotted(obj: dict, dotted: str, value: str) -> None:
    cur = obj
    parts = dotted.split(".")
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def _is_json_gap(value: Optional[str]) -> bool:
    return value is None or (isinstance(value, str) and value.startswith("[TODO]"))


def run_json(
    base: Path,
    template: str,
    langs: List[str],
    service: Optional[str],
    client_batch: int,
    limit: Optional[int],
) -> None:
    en_path = base / template.format(lang="en")
    if not en_path.exists():
        sys.exit(f"ERROR: source file not found: {en_path}")
    en_flat = _flatten(json.loads(en_path.read_text(encoding="utf-8")))

    for lang in langs:
        path = base / template.format(lang=lang)
        if not path.exists():
            print(f"  {lang}: file missing ({path}) — skipped", flush=True)
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        lang_flat = _flatten(doc)
        gaps: List[Tuple[str, str]] = [
            (key, en_src)
            for key, en_src in en_flat.items()
            if _is_json_gap(lang_flat.get(key))
        ]
        if limit:
            gaps = gaps[:limit]
        print(f"  {lang}: {len(gaps)} gap(s)", flush=True)
        if not gaps or service is None:
            continue
        uniq = sorted({src for _, src in gaps})
        translations = dict(zip(uniq, translate_to(service, uniq, lang, client_batch)))
        wrote = skipped = 0
        for key, en_src in gaps:
            cand = translations.get(en_src, en_src)
            if _accept(en_src, cand):
                _set_dotted(doc, key, cand)
                wrote += 1
            else:
                skipped += 1
        path.write_text(
            json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"  {lang}: wrote {wrote}, left {skipped} gap(s) for retry", flush=True)


# ---------------------------------------------------------------------------
# gettext .po driver  (empty msgstr = gap)
# ---------------------------------------------------------------------------


def run_po(
    base: Path,
    template: str,
    langs: List[str],
    service: Optional[str],
    client_batch: int,
    limit: Optional[int],
) -> None:
    try:
        import polib  # noqa: PLC0415
    except ImportError:
        sys.exit("ERROR: the .po driver needs polib — run: pip install polib")
    for lang in langs:
        path = base / template.format(lang=lang)
        if not path.exists():
            print(f"  {lang}: file missing ({path}) — skipped", flush=True)
            continue
        po = polib.pofile(str(path))
        gap_entries = [e for e in po if e.msgid and not e.obsolete and not e.msgstr]
        if limit:
            gap_entries = gap_entries[:limit]
        print(f"  {lang}: {len(gap_entries)} gap(s)", flush=True)
        if not gap_entries or service is None:
            continue
        uniq = sorted({e.msgid for e in gap_entries})
        translations = dict(zip(uniq, translate_to(service, uniq, lang, client_batch)))
        wrote = skipped = 0
        for e in gap_entries:
            cand = translations.get(e.msgid, e.msgid)
            if _accept(e.msgid, cand):
                e.msgstr = cand
                wrote += 1
            else:
                skipped += 1
        po.save(str(path))
        print(f"  {lang}: wrote {wrote}, left {skipped} gap(s) for retry", flush=True)


# ---------------------------------------------------------------------------
# Completeness gate  (fail loudly if any locale is still untranslated)
# ---------------------------------------------------------------------------


def scan_gaps(
    base: Path, template: str, langs: List[str], fmt: str
) -> Dict[str, List[str]]:
    """Re-read the locale files on disk and return {lang: [untranslated keys]}.

    Authoritative — reads what was actually written, so it reflects strings the
    service held back (placeholder fallbacks) as well as any never filled."""
    result: Dict[str, List[str]] = {}
    if fmt == "json":
        en_flat = _flatten(
            json.loads((base / template.format(lang="en")).read_text(encoding="utf-8"))
        )
        for lang in langs:
            path = base / template.format(lang=lang)
            if not path.exists():
                result[lang] = ["<file missing>"]
                continue
            lf = _flatten(json.loads(path.read_text(encoding="utf-8")))
            result[lang] = [k for k in en_flat if _is_json_gap(lf.get(k))]
    else:
        import polib  # noqa: PLC0415

        for lang in langs:
            path = base / template.format(lang=lang)
            if not path.exists():
                result[lang] = ["<file missing>"]
                continue
            po = polib.pofile(str(path))
            result[lang] = [
                e.msgid for e in po if e.msgid and not e.obsolete and not e.msgstr
            ]
    return result


def enforce_no_gaps(base: Path, template: str, langs: List[str], fmt: str) -> None:
    """Exit NON-ZERO, loudly, if any locale still has untranslated strings.

    Wired into ``make translate`` so an incomplete locale set fails the build
    instead of quietly sliding through — translations must be 100%."""
    offenders = {l: ks for l, ks in scan_gaps(base, template, langs, fmt).items() if ks}
    if not offenders:
        print(
            f"[OK] {PROJECT}: all {len(langs)} locale(s) fully translated — 0 gaps.",
            flush=True,
        )
        return
    total = sum(len(ks) for ks in offenders.values())
    bar = "=" * 72
    lines = [
        "",
        bar,
        f"  ✗✗✗  TRANSLATION INCOMPLETE — {PROJECT}: {total} untranslated string(s) "
        f"in {len(offenders)} locale(s)  ✗✗✗",
        bar,
    ]
    for lang in sorted(offenders):
        ks = offenders[lang]
        sample = ", ".join(ks[:4]) + (" …" if len(ks) > 4 else "")
        lines.append(f"    {lang}: {len(ks):>5} gap(s)   {sample}")
    lines += [
        bar,
        "  These locales are NOT fully translated.  Fill them with:",
        "      make translate SERVICE=http://<gpu-box>:8765",
        "  or translate the remaining keys by hand.  Locales must be 100%.",
        bar,
        "",
    ]
    print("\n".join(lines), file=sys.stderr, flush=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--service",
        default=os.getenv("TRANSLATION_SERVICE_URL", "http://localhost:8765"),
    )
    ap.add_argument("--langs", default=None, help="comma-separated locale subset")
    ap.add_argument("--client-batch", type=int, default=100)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--fail-on-gaps",
        action="store_true",
        help="after the run, exit non-zero (loudly) if any locale still has gaps",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="offline completeness gate: scan locales and exit non-zero if any gap "
        "remains. NO service calls, NO writes — safe for CI / release hooks.",
    )
    args = ap.parse_args()

    base = Path(__file__).resolve().parents[1] / LOCALES_REL
    if not base.exists():
        sys.exit(f"ERROR: locale dir not found: {base}")

    langs = (
        [x.strip() for x in args.langs.split(",") if x.strip()]
        if args.langs
        else TARGET_LANGS
    )
    service = None if args.dry_run else args.service

    print(f"project={PROJECT} format={FORMAT} base={base}", flush=True)

    # Offline completeness gate — no service, no writes.  Scans the files on
    # disk and exits non-zero (loudly) if anything is still untranslated.
    if args.check:
        print("mode=check (offline — no service calls, no writes)", flush=True)
        enforce_no_gaps(base, FILE_TEMPLATE, langs, FORMAT)
        return

    print(f"service={service or '(dry-run)'} langs={langs}", flush=True)

    if service and not _service_ok(service):
        sys.exit(
            f"\nERROR: translation service not reachable at {service}\n"
            "  Is it running on the GPU box?  Point at it with one of:\n"
            "    make translate SERVICE=http://<beast>:8765\n"
            "    export TRANSLATION_SERVICE_URL=http://<beast>:8765\n"
            "  (the default is http://localhost:8765)."
        )

    if FORMAT == "json":
        run_json(base, FILE_TEMPLATE, langs, service, args.client_batch, args.limit)
    else:
        run_po(base, FILE_TEMPLATE, langs, service, args.client_batch, args.limit)

    print("done.", flush=True)

    # Final gate: make an incomplete locale set a hard, loud failure.
    if args.fail_on_gaps:
        enforce_no_gaps(base, FILE_TEMPLATE, langs, FORMAT)


if __name__ == "__main__":
    main()
