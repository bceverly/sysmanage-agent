#!/usr/bin/env python3
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

"""Cut a release: bump version markers, COMMIT, then TAG, then push.

The ordering is the entire point.  The old ritual was `git tag` first (because
``check_version_drift.py`` resolved the version from an already-existing tag),
then bump, then commit -- which leaves the tag pointing at the commit BEFORE the
one carrying the work.  CI checks out the tag and faithfully rebuilds the old
tree.  That is how v3.5.1.24 shipped with broken OpenBSD and Flatpak jobs whose
fixes were already on main, and v3.5.1.25 the same way for the Windows ARM64
MSI.  Tagging last makes that impossible.

This is Python rather than Makefile shell on purpose: these repos are built on
Windows too, where make drives cmd.exe and ``test`` / ``grep`` / ``sed`` do not
exist.  Every git call here goes through subprocess with an argument LIST and no
shell, so quoting behaves the same on Windows, Linux, macOS and the BSDs.

Identical file in all four repos.  Everything repo-specific is discovered:
version markers are bumped only when ``scripts/check_version_drift.py`` exists,
so a docs-only repo just gets a tag.

    python scripts/release.py --version 3.5.1.26 --message "..."
    python scripts/release.py --version 3.5.1.26 --dry-run
"""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404 - git plumbing, argument lists only, never shell
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directories whose contents ship.  An untracked file in one of these would be
# absent from the release commit -- `git commit -a` stages modified TRACKED
# files and silently skips untracked ones -- while code importing it ships.
# Only those that exist in this repo are checked.
CANDIDATE_SRC_DIRS = (
    "src",
    "backend",
    "frontend/src",
    "alembic",
    "scripts",
    "installer",
    "packaging",
    ".githooks",
)

VERSION_RE = re.compile(r"^\d+(\.\d+){3}$")
TAG_RE = re.compile(r"^refs/tags/v?(\d+(?:\.\d+){3})(?:\^\{\})?$")


def git(
    *args: str, check: bool = True, timeout: int = 120
) -> subprocess.CompletedProcess:
    """Run a git command in the repo root.  Never uses a shell."""
    return (
        subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no user interpolation
            ["git", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )
    )


def fail(*lines: str) -> int:
    """Print an error block and return the failing exit code."""
    print("ERROR: " + lines[0], file=sys.stderr)
    for line in lines[1:]:
        print("       " + line, file=sys.stderr)
    return 1


def parse_version(text: str):
    """``"v3.5.1.26"`` -> ``(3, 5, 1, 26)``; None when not four numeric parts."""
    bare = text.lstrip("v")
    if not VERSION_RE.match(bare):
        return None
    return tuple(int(p) for p in bare.split("."))


def known_tags() -> set:
    """Four-part version tags known locally AND on origin.

    Origin matters: a version can be released while its local tag has been
    deleted, and re-cutting it would collide only at push time -- after the
    commit and tag already exist locally.
    """
    tags = set()
    local = git("tag", "--list", check=False)
    if local.returncode == 0:
        for line in local.stdout.splitlines():
            parsed = parse_version(line.strip())
            if parsed:
                tags.add(parsed)
    try:
        remote = git("ls-remote", "--tags", "origin", check=False, timeout=60)
    except subprocess.TimeoutExpired:
        print(
            "WARNING: `git ls-remote` timed out; checked local tags only",
            file=sys.stderr,
        )
        return tags
    if remote.returncode != 0:
        print(
            "WARNING: could not reach origin; checked local tags only", file=sys.stderr
        )
        return tags
    for line in remote.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        match = TAG_RE.match(parts[1].strip())
        if match:
            parsed = parse_version(match.group(1))
            if parsed:
                tags.add(parsed)
    return tags


def untracked_source_files() -> list:
    """Non-ignored untracked files under the directories that ship."""
    dirs = [d for d in CANDIDATE_SRC_DIRS if (REPO_ROOT / d).exists()]
    if not dirs:
        return []
    result = git("ls-files", "--others", "--exclude-standard", "--", *dirs, check=False)
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def check_guards(version: str, want, allow_untracked: bool):
    """Every refusal happens here, BEFORE anything is modified."""
    tags = known_tags()
    if tags:
        highest = max(tags)
        if want <= highest:
            highest_str = ".".join(str(p) for p in highest)
            relation = "the same as" if want == highest else "older than"
            return fail(
                f"v{version} is {relation} the highest existing tag v{highest_str}.",
                "Releases only move forward -- pick a higher version.",
            )
        if want in tags:
            return fail(f"tag v{version} already exists.", "Pick a higher version.")
        print(
            f"Version check: v{version} > highest existing tag "
            f"v{'.'.join(str(p) for p in highest)}"
        )
    else:
        print(
            "WARNING: no version tags resolvable; skipping newer-than check",
            file=sys.stderr,
        )

    if not allow_untracked:
        stray = untracked_source_files()
        if stray:
            return fail(
                "untracked file(s) under the shipping source tree:",
                *[f"  {s}" for s in stray],
                "'git commit -a' skips untracked files, so these would be MISSING",
                "from the release while code that imports them ships.",
                "Run: git add <file>   (or .gitignore them), then re-run.",
                "Deliberate?  make release ALLOW_UNTRACKED=1 ...",
            )
    return 0


def bump_markers(version: str, dry_run: bool) -> int:
    """Bump on-disk version markers when this repo tracks any."""
    drift = REPO_ROOT / "scripts" / "check_version_drift.py"
    if not drift.exists():
        print("No check_version_drift.py in this repo - nothing to bump, tag only.")
        return 0
    args = [sys.executable, str(drift), "--version", version]
    if not dry_run:
        args.append("--fix")
    # The child writes straight to the inherited stdout; flush ours first or
    # our buffered prints surface AFTER its output and the log reads backwards.
    sys.stdout.flush()
    result = subprocess.run(  # nosec B603 - fixed argv from this repo, no shell
        args, cwd=REPO_ROOT, check=False
    )
    # Without --fix the script reports drift as a non-zero exit; before a
    # release that drift is EXPECTED, so it is informational here.
    if dry_run:
        return 0
    return result.returncode


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Cut a release (bump, commit, tag, push)."
    )
    parser.add_argument("--version", required=True, metavar="X.Y.Z.W")
    parser.add_argument("--message", default=None, help="Commit and tag message.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Run guards, change nothing."
    )
    parser.add_argument("--allow-untracked", action="store_true")
    args = parser.parse_args()

    version = args.version.lstrip("v")
    want = parse_version(version)
    if want is None:
        return fail(
            f"VERSION must be four numeric parts, e.g. 3.5.1.26 (got: {args.version}).",
            "Every tag in these repos is four-part; a short version would rewrite",
            "the .spec/APKBUILD markers to a value CI never builds.",
        )

    tag = f"v{version}"
    message = args.message or f"Release {tag}"

    guard = check_guards(version, want, args.allow_untracked)
    if guard:
        return guard

    if args.dry_run:
        has_markers = (REPO_ROOT / "scripts" / "check_version_drift.py").exists()
        if has_markers:
            print(
                "--- version markers that WOULD be bumped (drift here is expected) ---"
            )
        bump_markers(version, dry_run=True)
        bump = "bump the version markers, then " if has_markers else ""
        print(
            f"[dry-run] all guards passed.  A real run would {bump}commit any "
            f'changes as "{message}", tag {tag} on THAT commit, then push the '
            f"branch and the tag.  Nothing was changed."
        )
        return 0

    if bump_markers(version, dry_run=False):
        return fail("version-marker bump failed; nothing committed or tagged.")

    dirty = git("diff", "--quiet", "HEAD", check=False).returncode != 0
    if dirty:
        git("commit", "-a", "-m", message)
        print(f'Committed: "{message}"')
    else:
        print("Nothing to commit - tagging the current HEAD.")

    head = git("rev-parse", "--short", "HEAD").stdout.strip()
    git("tag", "-a", tag, "-m", message)
    print(f"=== {tag} tagged at {head} - pushing ===")

    for push in (["push"], ["push", "origin", tag]):
        result = git(*push, check=False, timeout=900)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        if result.returncode != 0:
            return fail(
                f"`git {' '.join(push)}` failed.",
                f"The commit and tag {tag} exist LOCALLY; fix the cause and re-push.",
                f"To undo the tag:  git tag -d {tag}",
            )

    print(f"[OK] {tag} pushed; the tag contains the commit it names.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
