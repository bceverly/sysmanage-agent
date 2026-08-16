#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
"""
Propagate the shared package-repository tooling to the sibling repos.

WHY
---
``build-apt-repo.sh`` regenerates the apt metadata under ``repo/*/deb``, and
THREE separate publishers run it:

  * this repo's release workflow          -> repo/agent/deb
  * sysmanage's release workflow          -> repo/server/deb
  * sysmanage-docs' prune job             -> BOTH, and it runs LAST (fired by
    repository_dispatch straight after a release, plus a weekly cron) and
    mirrors back to R2 with ``--delete``.

They live in separate git repos, so there is no import and nothing notices when
they diverge.  They diverged.  Measured 2026-08-16: the sysmanage-docs copy was
69 lines behind, and sysmanage had a THIRD implementation inline in its release
workflow.  The copy that mattered was the prune job's, because it runs last --
so a correct release-time ``Release`` was overwritten within minutes, every
release.  The file's own header had said "kept byte-identical -- if you change
one, change both", which is precisely the convention that failed.

The stakes went up with signing.  The prune copy has no signing support and
begins by removing ``Release Release.gpg InRelease``.  Left alone it would have
stripped the signatures a release had just written, un-signing the repository
minutes after publication -- and again every Monday on the cron, in weeks when
nothing shipped at all.  Every consumer would then need verification disabled,
which is the exact hole this work set out to close.

WHAT IS ALLOWED TO DIFFER
-------------------------
Nothing but the licence header, preserved verbatim from the target so a repo
with different licensing keeps its own.  The body is copied whole.

Usage:
  python3 scripts/sync_repo_tooling.py            # rewrite the copies
  python3 scripts/sync_repo_tooling.py --check    # exit 1 if any has drifted
  python3 scripts/sync_repo_tooling.py --diff     # show what would change
"""

import argparse
import difflib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIBLINGS = ROOT.parent

# (canonical path relative to this repo, path relative to each sibling repo)
SHARED = [
    ("scripts/build-apt-repo.sh", "scripts/build-apt-repo.sh"),
]

TARGETS = ["sysmanage-docs", "sysmanage"]


def split_header(text):
    """(licence header, everything from the first non-comment line onward).

    The header is the shebang plus the contiguous comment block that carries the
    copyright/licence -- the part that must NOT be copied between repos with
    different licensing.  The canonical file's own explanatory comments live
    below it and DO travel, because they are the documentation.
    """
    lines = text.splitlines(keepends=True)
    if not lines:
        raise SystemExit("empty file")
    end = 1 if lines[0].startswith("#!") else 0
    while end < len(lines) and lines[end].startswith("#"):
        end += 1
        # Stop at the blank line that ends the licence block.
        if end < len(lines) and not lines[end].startswith("#"):
            break
    return "".join(lines[:end]), "".join(lines[end:])


def render(canonical_text, target_text):
    """Canonical body wearing the target's licence header."""
    _, canon_body = split_header(canonical_text)
    target_header, _ = split_header(target_text)
    return target_header + canon_body


def pairs():
    out = []
    for canon_rel, target_rel in SHARED:
        for repo in TARGETS:
            out.append((repo, ROOT / canon_rel, SIBLINGS / repo / target_rel))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit 1 on drift")
    parser.add_argument("--diff", action="store_true", help="show the drift")
    args = parser.parse_args()

    drifted, missing, wrote, skipped = [], [], [], set()
    for repo, canon, target in pairs():
        if not canon.exists():
            missing.append(f"{canon} (canonical)")
            continue
        # A sibling that is not checked out is not drift.  CI clones ONE repo,
        # so failing here would break every pipeline; this is only meaningful on
        # a machine holding all three.
        if not (SIBLINGS / repo).is_dir():
            skipped.add(repo)
            continue
        if not target.exists():
            missing.append(str(target))
            continue
        want = render(
            canon.read_text(encoding="utf-8"), target.read_text(encoding="utf-8")
        )
        have = target.read_text(encoding="utf-8")
        if want == have:
            continue
        drifted.append(f"{repo}/{target.name}")
        if args.diff:
            sys.stdout.writelines(
                difflib.unified_diff(
                    have.splitlines(keepends=True),
                    want.splitlines(keepends=True),
                    fromfile=f"{target} (current)",
                    tofile=f"{target} (synced)",
                )
            )
        if not (args.check or args.diff):
            target.write_text(want, encoding="utf-8")
            wrote.append(f"{repo}/{target.name}")

    for path in missing:
        print(f"MISSING: {path}", file=sys.stderr)
    if skipped:
        print(f"skipped (not checked out): {', '.join(sorted(skipped))}")
    for name in wrote:
        print(f"  synced   {name}")

    if missing:
        return 1
    if drifted and (args.check or args.diff):
        print(
            f"\nDRIFT: {len(drifted)} copy/copies differ from canonical",
            file=sys.stderr,
        )
        for name in drifted:
            print(f"  {name}", file=sys.stderr)
        print("\nFix:  python3 scripts/sync_repo_tooling.py", file=sys.stderr)
        return 1
    if not drifted and not wrote:
        print("OK: shared package-repo tooling is in sync across all repos")
    return 0


if __name__ == "__main__":
    sys.exit(main())
