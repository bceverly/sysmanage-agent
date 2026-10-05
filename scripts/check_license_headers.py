#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""License-header gate: every source file opens with our copyright notice and
the RIGHT license for this repository.

The four repositories carry two licenses, and crossing them is a real
licensing problem, not a style nit:

  * sysmanage, sysmanage-agent, sysmanage-docs -- AGPL-3.0
  * sysmanage-professional-plus -- proprietary; never AGPL, never "open source"

This script is identical in all four repositories except for ``LICENSE_KIND``
below.  For each source file it checks, within the first lines (after a
shebang, coding cookie or lint pragma):

  1. ``Copyright (c) 2024-<year> Bryan Everly`` with ``<year>`` the current
     year or later;
  2. this repository's license text is there;
  3. the OTHER license's text is not.

``--fix`` adds the standard header to files that have none (after any shebang
or coding cookie) and moves a stale end year to the current one.  A header
naming the wrong license is reported, never rewritten: that needs a person.

Files come from ``git ls-files``; ``--walk`` scans the directory tree instead
(build output, virtualenvs and caches skipped); explicit paths check just those.
"""

import argparse
import datetime
import os
import re
import subprocess  # nosec B404 - fixed argv (git ls-files), no shell
import sys
from pathlib import Path

LICENSE_KIND = "agpl"  # "agpl" or "proprietary" -- the one per-repo line

OWNER = "Bryan Everly"
FIRST_YEAR = 2024

LICENSE_TEXT = {
    "agpl": [
        "Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).",
        "See the LICENSE file in the project root for the full terms.",
    ],
    "proprietary": [
        "PROPRIETARY AND CONFIDENTIAL commercial software - NOT open source, NOT",
        "licensed under the AGPL. Unauthorized copying, distribution, or use is",
        "prohibited. See the LICENSE file in the project root for the full terms.",
    ],
}
# What must appear in a header of each kind, and what must never.
REQUIRED = {"agpl": "GNU Affero General Public License", "proprietary": "PROPRIETARY"}
FORBIDDEN = {"agpl": "PROPRIETARY", "proprietary": "GNU Affero"}
RIGHTS = {"agpl": "", "proprietary": ". All rights reserved."}

HASH_COMMENT = {".py", ".pyx", ".pxi", ".pxd", ".sh", ".ps1", ".psm1", ".rb", ".pl"}
SLASH_COMMENT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go"}
SUFFIXES = HASH_COMMENT | SLASH_COMMENT

# The header must start within this many lines (room for a shebang, a coding
# cookie and lint pragmas such as "/* eslint-disable */").
HEAD_LINES = 15

# Not ours to label: third-party or generated files kept in the tree.
EXEMPT = re.compile(
    r"(^|/)("
    r"node_modules|\.venv[^/]*|venv|dist|build|coverage|htmlcov|__pycache__"
    r"|playwright-report|test-results|\.vagrant|plugin-dist|\.runtime-logs"
    r")/"
    r"|\.min\.js$|(^|/)mockServiceWorker\.js$"
)
WALK_SKIP_DIRS = {".git", ".mypy_cache", ".pytest_cache", "site-packages", "storage"}

COPYRIGHT_RE = re.compile(
    r"Copyright \(c\) (?P<first>\d{4})(?:-(?P<last>\d{4}))? " + re.escape(OWNER)
)


def current_year() -> int:
    return datetime.date.today().year


def header_lines(kind: str, comment: str, year: int) -> list:
    first = f"Copyright (c) {FIRST_YEAR}-{year} {OWNER}{RIGHTS[kind]}"
    return [f"{comment} {line}" for line in [first, *LICENSE_TEXT[kind]]]


def comment_for(path: str) -> str:
    return "#" if Path(path).suffix in HASH_COMMENT else "//"


def problems(text: str, kind: str, year: int) -> list:
    """What is wrong with this file's header ([] when nothing)."""
    head = "\n".join(text.splitlines()[:HEAD_LINES])
    match = COPYRIGHT_RE.search(head)
    if match is None:
        return ["no copyright header"]
    found = []
    last = int(match.group("last") or match.group("first"))
    if last < year:
        found.append(f"copyright year ends {last}, not {year}")
    if REQUIRED[kind] not in head:
        found.append(f"license text missing ({REQUIRED[kind]!r})")
    if FORBIDDEN[kind] in head:
        found.append(f"WRONG license: {FORBIDDEN[kind]!r} in this {kind} repository")
    return found


def _insert_at(lines: list) -> int:
    """Where a new header goes: after a shebang and a PEP 263 coding cookie."""
    at = 0
    if lines and lines[0].startswith("#!"):
        at = 1
    if len(lines) > at and re.match(r"#.*coding[:=]", lines[at]):
        at += 1
    return at


def fixed(text: str, path: str, kind: str, year: int) -> str:
    """``text`` with a missing header added or a stale year moved forward."""
    head = "\n".join(text.splitlines()[:HEAD_LINES])
    match = COPYRIGHT_RE.search(head)
    if match is None:
        lines = text.splitlines(keepends=True)
        at = _insert_at(lines)
        newline = "\r\n" if "\r\n" in text else "\n"  # keep the file's own
        block = [line + newline for line in header_lines(kind, comment_for(path), year)]
        if at < len(lines) and lines[at].strip():
            block.append(newline)
        return "".join(lines[:at] + block + lines[at:])
    last = int(match.group("last") or match.group("first"))
    if last < year:
        old = match.group(0)
        new = f"Copyright (c) {match.group('first')}-{year} {OWNER}"
        return text.replace(old, new, 1)
    return text


def _git_files() -> list:
    result = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", "ls-files"], capture_output=True, text=True, check=True
    )
    return result.stdout.splitlines()


def _walked_files() -> list:
    found = []
    for root, dirs, files in os.walk("."):
        dirs[:] = [
            d
            for d in dirs
            if d not in WALK_SKIP_DIRS
            and not d.endswith(".egg-info")
            and not EXEMPT.search(f"{d}/")
        ]
        found.extend(os.path.relpath(os.path.join(root, f)) for f in files)
    return found


def source_files(paths, walk: bool) -> list:
    if paths:
        candidates = paths
    elif walk:
        candidates = _walked_files()
    else:
        candidates = _git_files()
    return sorted(
        path.replace(os.sep, "/")
        for path in candidates
        if Path(path).suffix in SUFFIXES
        and not EXEMPT.search(path.replace(os.sep, "/"))
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="*", help="check just these files")
    parser.add_argument("--fix", action="store_true", help="add/refresh headers")
    parser.add_argument("--walk", action="store_true", help="scan the tree, not git")
    args = parser.parse_args(argv)
    year = current_year()
    bad = []
    for path in source_files(args.paths, args.walk):
        try:
            # Bytes, not text mode: text mode would rewrite line endings.
            text = Path(path).read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # deleted since listing, or not text
        if args.fix:
            new = fixed(text, path, LICENSE_KIND, year)
            if new != text:
                Path(path).write_bytes(new.encode("utf-8"))
                print(f"  fixed {path}")
                text = new
        for problem in problems(text, LICENSE_KIND, year):
            bad.append(f"  {path}: {problem}")
    if bad:
        print(f"[ERROR] {len(bad)} license-header problem(s) ({LICENSE_KIND}):")
        print("\n".join(bad))
        print(
            "Run: make lint-license-headers-fix  (wrong-license headers need a person)"
        )
        return 1
    print(f"[OK] License headers ({LICENSE_KIND}) present and current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
