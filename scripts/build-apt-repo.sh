#!/bin/bash
# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.
#
# Regenerate the apt repository metadata under repo/agent/deb.
#
# THE SINGLE SOURCE OF TRUTH for this, called by both the release workflow and
# `make deploy-docs-repo`.  There used to be two implementations, and they
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
# Usage:  scripts/build-apt-repo.sh <path-to-repo/agent/deb>

set -euo pipefail

DEB_ROOT="${1:-}"
if [ -z "$DEB_ROOT" ] || [ ! -d "$DEB_ROOT" ]; then
    echo "ERROR: usage: $0 <path-to-repo/agent/deb>" >&2
    exit 1
fi

ARCHES="${APT_REPO_ARCHES:-amd64 arm64}"
SUITE="${APT_REPO_SUITE:-stable}"

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
    gzip -9c "dists/$SUITE/main/binary-$ARCH/Packages" \
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
        -o "APT::FTPArchive::Release::Label=SysManage Agent" \
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
        echo "Label: SysManage Agent"
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

echo "  Release headers:"
sed -n '1,7p' Release | sed 's/^/    /'
echo "apt metadata regenerated successfully"
