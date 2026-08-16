#!/usr/bin/env bash
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
#
# Regenerate the apt repository metadata under repo/agent/deb.
#
# THE CANONICAL COPY.  Synced to sysmanage-docs and sysmanage by
# scripts/sync_repo_tooling.py -- do not hand-edit the copies.
#
# THREE publishers touch this repository and every one of them regenerates the
# metadata:
#   * sysmanage-agent's release workflow  -> repo/agent/deb
#   * sysmanage's release workflow        -> repo/server/deb
#   * sysmanage-docs' prune job           -> BOTH, and it runs LAST (fired by
#     repository_dispatch right after a release, plus a weekly cron) and mirrors
#     back with --delete.  Whatever the prune job generates is what the world
#     sees: a correct release-time Release was once overwritten within minutes,
#     every single release.
#
# That last point is why this file is synced rather than "kept byte-identical by
# convention".  The convention failed: the copies drifted by 69 lines, and the
# unsigned prune copy would have stripped the InRelease/Release.gpg that the
# release had just written -- silently un-signing the repo minutes after
# publication, on a weekly schedule even when nothing shipped.
#
# There used to be two implementations, and they
# drifted: the Makefile ran a bare `apt-ftparchive release .`, which emits a
# Release file containing ONLY Date + checksums.  apt needs Suite / Codename /
# Components / Architectures to fetch indices for a non-flat repo, so whichever
# writer ran last decided whether the repo worked at all.  Symptoms when it
# went wrong (2026-08, found while validating bare-metal provisioning):
#
#   W: Conflicting distribution: ... Release (expected stable but got )
#   E: Failed to fetch .../Packages.gz  Hash Sum mismatch
#   ... and then: "Unable to locate package sysmanage-agent"
#
# The hash mismatch came from the same split brain — one writer regenerated
# Packages while the Release checksums still described the other's output.
#
# SIGNING (added 2026-08-15).  The repo was published UNSIGNED and consumed with
# `[trusted=yes]`, i.e. apt was told to skip verification entirely -- on an
# install that runs as root, unattended, from a provisioning engine.  Transport
# security (HTTPS) is not a substitute: it authenticates the CDN, not the
# packages, and says nothing about what was published.
#
#   APT_SIGNING_KEY_ID   key to sign with.  When set, Release is clearsigned to
#                        InRelease and detached-signed to Release.gpg.
#   APT_SIGN_REQUIRED=1  fail rather than publish unsigned.  The release
#                        workflow sets this; local `make deploy-docs-repo` runs
#                        do not, so a developer without the key still works.
#
# Usage:  scripts/build-apt-repo.sh <path-to-repo/agent/deb>

set -euo pipefail

DEB_ROOT="${1:-}"
if [ -z "$DEB_ROOT" ] || [ ! -d "$DEB_ROOT" ]; then
    echo "ERROR: usage: $0 <path-to-repo/agent/deb>" >&2
    exit 1
fi

ARCHES="${APT_REPO_ARCHES:-amd64 arm64}"
SUITE="${APT_REPO_SUITE:-stable}"

# The Label is per-repository, and this script builds more than one: the agent
# repo lives at repo/agent/deb and the server repo at repo/server/deb.  It was
# hardcoded to "SysManage Agent", so the SERVER repo advertised itself as the
# agent -- visible to anyone running `apt policy`, and misleading in exactly the
# place a user checks when working out where a package came from.  Derive it
# from the directory holding the deb root; APT_REPO_LABEL overrides.
case "$(basename "$(dirname "$(cd "$DEB_ROOT" && pwd)")")" in
    agent)  DEFAULT_LABEL="SysManage Agent" ;;
    server) DEFAULT_LABEL="SysManage Server" ;;
    *)      DEFAULT_LABEL="SysManage" ;;
esac
LABEL="${APT_REPO_LABEL:-$DEFAULT_LABEL}"

command -v dpkg-scanpackages >/dev/null 2>&1 || {
    echo "ERROR: dpkg-scanpackages not found (install dpkg-dev)" >&2
    exit 1
}

cd "$DEB_ROOT"

echo "Regenerating apt metadata in $(pwd) (suite=$SUITE, arches=$ARCHES)"

# Per-arch indices from the shared pool.  -a <arch> selects only the .debs whose
# control Architecture matches, so each arch gets its own correct index.
for ARCH in $ARCHES; do
    mkdir -p "dists/$SUITE/main/binary-$ARCH"
    dpkg-scanpackages -a "$ARCH" pool/ /dev/null \
        > "dists/$SUITE/main/binary-$ARCH/Packages"
    # -n omits gzip's timestamp+name header.  Without it the .gz is
    # byte-different on every regeneration even when the content is identical,
    # while staying the SAME SIZE — which an `aws s3 sync --size-only` then
    # refuses to upload, leaving R2 serving an old Packages.gz under a Release
    # that describes the new one ("Hash Sum mismatch", forever).
    gzip -9nc "dists/$SUITE/main/binary-$ARCH/Packages" \
        > "dists/$SUITE/main/binary-$ARCH/Packages.gz"
    echo "  indexed $ARCH: $(grep -c '^Package:' "dists/$SUITE/main/binary-$ARCH/Packages" || true) package(s)"
done

cd "dists/$SUITE"

# Remove any previous Release BEFORE checksumming: apt-ftparchive walks the
# directory, so a stale Release left in place gets checksummed into its own
# successor (that is where the bogus 38-byte "Release" entry came from).
rm -f Release Release.gpg InRelease

ARCH_LIST="$(echo "$ARCHES" | tr ' ' ' ')"

if command -v apt-ftparchive >/dev/null 2>&1; then
    # Write OUTSIDE the scanned tree, then move in.  `> Release` would create
    # the (empty) target before apt-ftparchive walks the directory, so the tool
    # checksums its own output file — which is precisely how the published
    # Release ended up listing a bogus 38-byte "Release" entry.
    TMP_RELEASE="$(mktemp)"
    trap 'rm -f "$TMP_RELEASE"' EXIT
    # The -o options are what supply the headers a bare invocation omits.
    apt-ftparchive \
        -o "APT::FTPArchive::Release::Origin=SysManage" \
        -o "APT::FTPArchive::Release::Label=$LABEL" \
        -o "APT::FTPArchive::Release::Suite=$SUITE" \
        -o "APT::FTPArchive::Release::Codename=$SUITE" \
        -o "APT::FTPArchive::Release::Components=main" \
        -o "APT::FTPArchive::Release::Architectures=$ARCH_LIST" \
        release . > "$TMP_RELEASE"
    mv "$TMP_RELEASE" Release
    trap - EXIT
else
    # Fallback with no apt-ftparchive (non-Debian build host): same headers,
    # hashes computed over the files we just wrote.
    REL_FILES=""
    for ARCH in $ARCHES; do
        REL_FILES="$REL_FILES main/binary-$ARCH/Packages main/binary-$ARCH/Packages.gz"
    done
    {
        echo "Origin: SysManage"
        echo "Label: $LABEL"
        echo "Suite: $SUITE"
        echo "Codename: $SUITE"
        echo "Components: main"
        echo "Architectures: $ARCH_LIST"
        echo "Date: $(date -R -u)"
        for algo in "MD5Sum:md5sum" "SHA1:sha1sum" "SHA256:sha256sum" "SHA512:sha512sum"; do
            echo "${algo%%:*}"
            CMD="${algo##*:}"
            for f in $REL_FILES; do
                [ -f "$f" ] || continue
                "$CMD" "$f" | awk -v s="$(stat -c%s "$f")" '{printf " %s %16d %s\n", $1, s, $2}'
            done
        done
    } > Release
fi

# Fail loudly rather than publishing a repo apt will reject.
for required in Suite Codename Components Architectures; do
    grep -q "^$required:" Release || {
        echo "ERROR: generated Release is missing '$required:' — apt would refuse this repo" >&2
        exit 1
    }
done
grep -q "^ .* Release$" Release && {
    echo "ERROR: Release checksums itself — a stale Release was not removed" >&2
    exit 1
}

# --- signing ----------------------------------------------------------------
SIGN_KEY="${APT_SIGNING_KEY_ID:-}"
SIGN_REQUIRED="${APT_SIGN_REQUIRED:-0}"

if [ -n "$SIGN_KEY" ] && command -v gpg >/dev/null 2>&1; then
    # InRelease (inline signature) is what modern apt prefers; Release.gpg is
    # the detached form older clients still fetch.  Publish BOTH so no client
    # silently falls back to unverified.
    # APT_GPG_EXTRA carries --pinentry-mode loopback + --passphrase-file when
    # the key is passphrase-protected and no terminal exists (CI).  Unquoted on
    # purpose: it is a list of arguments, not one argument.
    # shellcheck disable=SC2086
    gpg --batch --yes ${APT_GPG_EXTRA:-} --local-user "$SIGN_KEY" --clearsign -o InRelease Release
    # shellcheck disable=SC2086
    gpg --batch --yes ${APT_GPG_EXTRA:-} --local-user "$SIGN_KEY" --detach-sign --armor -o Release.gpg Release

    # Verify what we just wrote rather than trusting gpg's exit code: a repo
    # that ships an unverifiable signature is worse than none, because the
    # client reports a security error instead of a missing file.
    gpg --batch --verify InRelease >/dev/null 2>&1 || {
        echo "ERROR: InRelease failed verification immediately after signing" >&2
        exit 1
    }
    gpg --batch --verify Release.gpg Release >/dev/null 2>&1 || {
        echo "ERROR: Release.gpg failed verification immediately after signing" >&2
        exit 1
    }
    echo "  signed with $SIGN_KEY (InRelease + Release.gpg, both verified)"
elif [ "$SIGN_REQUIRED" = "1" ]; then
    echo "ERROR: APT_SIGN_REQUIRED=1 but no signing key available." >&2
    echo "       Refusing to publish a repository apt cannot verify." >&2
    echo "       Set APT_SIGNING_KEY_ID (and import the key) before releasing." >&2
    exit 1
else
    echo "  [WARN] NOT SIGNED - no APT_SIGNING_KEY_ID set."
    echo "         Fine for a local build; a published repo must be signed, or"
    echo "         every consumer has to disable verification to install."
fi

echo "  Release headers:"
sed -n '1,7p' Release | sed 's/^/    /'
echo "apt metadata regenerated successfully"
