#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Version-drift check (and surgical fix) for sysmanage-agent.

Queries the GitHub tags API (via curl) AND local git tags, comparing the
highest numeric tag across both against every on-disk version marker that
ships with the running app or with package metadata that isn't
already auto-bumped by the release workflow.  Local git tags are included
because a tag just created with ``git tag`` shows there immediately, before
it has propagated to (and un-cached from) the GitHub tags API — so running
``make lint-version-fix`` right after tagging still sees the new version.

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


def _api_tags() -> list[str]:
    """Tag names from the GitHub tags API (page 1, up to 100).

    Returns an empty list on any curl/network/parse failure — the caller falls
    back to local git tags, and soft-skips only when both sources are empty.
    """
    if not shutil.which("curl"):
        return []
    url = f"https://api.github.com/repos/{GITHUB_REPO}/tags?per_page=100"
    cmd = ["curl", "-fsSL", "-H", "Accept: application/vnd.github+json", url]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15, check=True
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []
    try:
        return [t["name"] for t in json.loads(result.stdout)]
    except (json.JSONDecodeError, KeyError, TypeError):
        return []


def _local_git_tags() -> list[str]:
    """Local git tags.  A tag just created with ``git tag`` appears here
    immediately — before it has propagated to (and un-cached from) the GitHub
    API — so ``make lint-version-fix`` right after tagging sees the new version.
    Empty on any failure (e.g. a CI shallow checkout without tags), leaving the
    API as the source of truth there.
    """
    if not shutil.which("git"):
        return []
    try:
        result = subprocess.run(
            ["git", "tag", "--list"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
            cwd=REPO_ROOT,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return []
    return [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]


def fetch_highest_tag() -> str | None:
    """Return the highest semver-like tag (without leading ``v``).

    Considers the union of the GitHub tags API and local git tags so a
    just-created local tag isn't missed while the API is still stale/cached.
    Returns None when neither source yields a parseable tag (e.g. offline CI
    with a shallow checkout) — callers treat None as a soft-skip so
    ``make lint`` doesn't block development.
    """

    def parse(t: str):
        bare = t.lstrip("v")
        try:
            return tuple(int(p) for p in bare.split("."))
        except ValueError:
            return None

    tags = set(_api_tags()) | set(_local_git_tags())
    candidates = [(t, parse(t)) for t in tags]
    candidates = [(t, k) for t, k in candidates if k is not None]
    if not candidates:
        print(
            "WARNING: no tags from the GitHub API or local git; "
            "skipping version-drift check",
            file=sys.stderr,
        )
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


def _parse_version(text: str):
    """``"v3.5.1.26"`` -> ``(3, 5, 1, 26)``; None when not numeric-dotted."""
    try:
        return tuple(int(p) for p in text.lstrip("v").split("."))
    except ValueError:
        return None


def _assert_newer(candidate: str) -> int:
    """Exit non-zero unless ``candidate`` beats every tag we know about.

    Releases only ever move forward.  Re-cutting a version -- or typing an
    older one -- would rewrite the on-disk version markers to a value CI has
    already built, or will never build.  Soft-skips when no tag is resolvable
    (offline with a shallow checkout), matching the drift check.
    """
    want = _parse_version(candidate)
    if want is None:
        print(f"ERROR: {candidate!r} is not a numeric dotted version", file=sys.stderr)
        return 1
    highest = fetch_highest_tag()
    if highest is None:
        print("WARNING: no tags resolvable; skipping newer-than check", file=sys.stderr)
        return 0
    have = _parse_version(highest)
    if have is not None and want <= have:
        rel = "the same as" if want == have else "older than"
        print(
            f"ERROR: v{candidate.lstrip('v')} is {rel} the highest existing tag "
            f"v{highest}.  Releases only move forward -- pick a higher version.",
            file=sys.stderr,
        )
        return 1
    print(f"Version check: v{candidate.lstrip('v')} > highest existing tag v{highest}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare on-disk version markers to the highest " "GitHub tag."
    )
    parser.add_argument(
        "--fix", action="store_true", help="Rewrite drifted files in-place."
    )
    parser.add_argument(
        "--assert-newer",
        metavar="X.Y.Z",
        help=(
            "Exit non-zero unless X.Y.Z is strictly greater than the highest "
            "tag known locally or on GitHub.  Guards `make release` against "
            "re-cutting a released version or going backwards."
        ),
    )
    parser.add_argument(
        "--version",
        metavar="X.Y.Z",
        help=(
            "Treat this as the release version instead of resolving the "
            "highest tag.  Without it this script needs the tag to ALREADY "
            "exist, which forces `git tag` to run before the version-bump "
            "commit -- and a tag cut before a commit can never contain it. "
            "Pass --version and the tag can be cut last, on the commit that "
            "actually carries the bump.  See `make release`."
        ),
    )
    args = parser.parse_args()

    if args.assert_newer:
        return _assert_newer(args.assert_newer)

    if args.version:
        expected = args.version.lstrip("v")
        print(f"Target version (explicit): v{expected}")
    else:
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
