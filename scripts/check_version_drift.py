#!/usr/bin/env python3
"""Version-drift check (and surgical fix) for sysmanage-agent.

Queries the GitHub tags API via curl (no git invocation) and compares
the highest numeric tag against every on-disk version marker that
ships with the running app or with package metadata that isn't
already auto-bumped by the release workflow.

Run as ``make lint-version`` (read-only check) or
``make lint-version-fix`` (rewrites drifted files in-place).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

GITHUB_REPO = "bceverly/sysmanage-agent"
REPO_ROOT = Path(__file__).resolve().parent.parent

# (path relative to repo root, handler kind)
#
# Files in packaging/* are intentional stubs at 0.0.0 — CI bumps them
# from the git tag at release time and never commits the bumped form
# back.  They're excluded here on purpose.
#
# Files in installer/* that ALSO get sed-bumped by build-and-release.yml
# (.spec, APKBUILD) are included here anyway: the staleness is cosmetic
# for the release artifacts themselves but misleads any developer who
# reads the file at HEAD.
TRACKED_FILES = [
    ("installer/centos/sysmanage-agent.spec", "rpmspec"),
    ("installer/opensuse/sysmanage-agent.spec", "rpmspec"),
    ("installer/alpine/APKBUILD", "apkbuild"),
]


def fetch_highest_tag() -> str | None:
    """Return the highest semver-like tag (without leading ``v``).

    Pulls the top 100 tags from the GitHub tags API and picks the
    semver-maximum.  Returns None on any curl/network/parse failure —
    callers treat None as a soft-skip so offline ``make lint`` runs
    don't block development.
    """
    if not shutil.which("curl"):
        print("WARNING: curl not found, skipping version-drift check", file=sys.stderr)
        return None
    url = f"https://api.github.com/repos/{GITHUB_REPO}/tags?per_page=100"
    cmd = ["curl", "-fsSL", "-H", "Accept: application/vnd.github+json", url]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, check=True
        )
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip() or f"curl exit {e.returncode}"
        print(f"WARNING: could not reach GitHub: {msg}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("WARNING: GitHub API timed out", file=sys.stderr)
        return None
    try:
        tags = [t["name"] for t in json.loads(result.stdout)]
    except (json.JSONDecodeError, KeyError, TypeError):
        print("WARNING: malformed response from GitHub tags API", file=sys.stderr)
        return None

    def parse(t: str):
        bare = t.lstrip("v")
        try:
            return tuple(int(p) for p in bare.split("."))
        except ValueError:
            return None

    candidates = [(t, parse(t)) for t in tags]
    candidates = [(t, k) for t, k in candidates if k is not None]
    if not candidates:
        return None
    candidates.sort(key=lambda pair: pair[1], reverse=True)
    return candidates[0][0].lstrip("v")


# --- per-format readers/writers ---

_SPEC_VERSION_RE = re.compile(r"^(Version:\s+)(\S+)\s*$", re.MULTILINE)
_APK_VERSION_RE = re.compile(r"^(pkgver=)(\S+)\s*$", re.MULTILINE)


def _read_regex(path: Path, regex: re.Pattern) -> str | None:
    m = regex.search(path.read_text())
    return m.group(2) if m else None


def _write_regex(path: Path, regex: re.Pattern, value: str) -> None:
    text = path.read_text()
    new_text, n = regex.subn(lambda m: f"{m.group(1)}{value}", text, count=1)
    if n != 1:
        raise RuntimeError(f"{path}: could not locate version line")
    path.write_text(new_text)


def _read_rpmspec(p):
    return _read_regex(p, _SPEC_VERSION_RE)


def _write_rpmspec(p, v):
    _write_regex(p, _SPEC_VERSION_RE, v)


def _read_apkbuild(p):
    return _read_regex(p, _APK_VERSION_RE)


def _write_apkbuild(p, v):
    _write_regex(p, _APK_VERSION_RE, v)


HANDLERS = {
    "rpmspec": (_read_rpmspec, _write_rpmspec),
    "apkbuild": (_read_apkbuild, _write_apkbuild),
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare on-disk version markers to the highest " "GitHub tag."
    )
    parser.add_argument(
        "--fix", action="store_true", help="Rewrite drifted files in-place."
    )
    args = parser.parse_args()

    expected = fetch_highest_tag()
    if expected is None:
        # Soft-skip: offline / rate-limited / repo has no tags yet.
        return 0

    print(f"Highest GitHub tag ({GITHUB_REPO}): v{expected}")
    drift = []
    for rel, kind in TRACKED_FILES:
        path = REPO_ROOT / rel
        if not path.exists():
            print(f"  ?  {rel}  (missing — skipping)")
            continue
        reader, writer = HANDLERS[kind]
        actual = reader(path)
        if actual is None:
            print(f"  ?  {rel}  (could not parse current version)")
            continue
        if actual != expected:
            print(f"  X  {rel}: {actual}  (expected {expected})")
            drift.append((path, rel, actual, writer))
        else:
            print(f"  OK {rel}: {actual}")

    if not drift:
        print("All version markers in sync.")
        return 0

    if args.fix:
        print()
        for path, rel, actual, writer in drift:
            writer(path, expected)
            print(f"  fixed: {rel}  {actual} -> {expected}")
        return 0

    print()
    print(
        f"{len(drift)} file(s) out of sync. "
        f"Run `make lint-version-fix` to apply surgical updates."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
