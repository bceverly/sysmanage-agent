#!/bin/sh
# Docker build script for Alpine .apk packages
# This script runs INSIDE the Alpine Docker container
# Environment variables: VERSION (required)
set -ex

# Get Alpine version for repository URLs
ALPINE_VER=$(cat /etc/alpine-release | cut -d. -f1,2)
echo "Building on Alpine $ALPINE_VER"

# Enable community repository (required for Python packages)
echo "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VER}/main" > /etc/apk/repositories
echo "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VER}/community" >> /etc/apk/repositories
cat /etc/apk/repositories

# Update package index
apk update

# Install build dependencies
apk add --no-cache \
  alpine-sdk \
  sudo \
  python3 \
  py3-pip

# Set up abuild user (required for building packages)
adduser -D builder
addgroup builder abuild
echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Create build directory structure
mkdir -p /home/builder/packages
mkdir -p /home/builder/aports/sysutils/sysmanage-agent

# Copy installer files
cp /workspace/installer/alpine/APKBUILD /home/builder/aports/sysutils/sysmanage-agent/
cp /workspace/installer/alpine/sysmanage-agent.initd /home/builder/aports/sysutils/sysmanage-agent/
cp /workspace/installer/alpine/sysmanage-agent.confd /home/builder/aports/sysutils/sysmanage-agent/
cp /workspace/installer/alpine/sysmanage-agent.post-install /home/builder/aports/sysutils/sysmanage-agent/

# Update version in APKBUILD
cd /home/builder/aports/sysutils/sysmanage-agent
sed -i "s/^pkgver=.*/pkgver=$VERSION/" APKBUILD

# Create a local source tarball from the workspace instead of downloading from GitHub.
# This allows building before the tag is pushed, or in air-gapped environments.
mkdir -p /tmp/sysmanage-agent-$VERSION
cp /workspace/main.py /tmp/sysmanage-agent-$VERSION/
cp -R /workspace/src /tmp/sysmanage-agent-$VERSION/
cp -R /workspace/alembic /tmp/sysmanage-agent-$VERSION/ 2>/dev/null || true
cp -R /workspace/database /tmp/sysmanage-agent-$VERSION/ 2>/dev/null || true
cp -R /workspace/i18n /tmp/sysmanage-agent-$VERSION/ 2>/dev/null || true
cp -R /workspace/security /tmp/sysmanage-agent-$VERSION/ 2>/dev/null || true
cp -R /workspace/sbom /tmp/sysmanage-agent-$VERSION/ 2>/dev/null || true
cp /workspace/alembic.ini /tmp/sysmanage-agent-$VERSION/ 2>/dev/null || true
cp /workspace/requirements.txt /tmp/sysmanage-agent-$VERSION/ 2>/dev/null || true
cp /workspace/sysmanage-agent-system.yaml /tmp/sysmanage-agent-$VERSION/ 2>/dev/null || true
cp /workspace/README.md /tmp/sysmanage-agent-$VERSION/ 2>/dev/null || true
cp /workspace/LICENSE /tmp/sysmanage-agent-$VERSION/ 2>/dev/null || true

# Create the tarball
DISTDIR="/var/cache/distfiles"
mkdir -p "$DISTDIR"
cd /tmp
tar czf "sysmanage-agent-$VERSION.tar.gz" "sysmanage-agent-$VERSION"
rm -rf "/tmp/sysmanage-agent-$VERSION"

# Place in both the APKBUILD dir (for abuild checksum) and distfiles (for abuild -r)
cp "sysmanage-agent-$VERSION.tar.gz" "$DISTDIR/"
cp "sysmanage-agent-$VERSION.tar.gz" /home/builder/aports/sysutils/sysmanage-agent/
rm "sysmanage-agent-$VERSION.tar.gz"

# Rewrite the APKBUILD source to use the local tarball (no URL, just filename)
cd /home/builder/aports/sysutils/sysmanage-agent
sed -i 's|^\(source="\).*|\1|' APKBUILD
sed -i '/^source="/,/"/{
  /\.tar\.gz::/d
}' APKBUILD
sed -i "s|^source=\"|source=\"\n\tsysmanage-agent-$VERSION.tar.gz|" APKBUILD

# Fix ownership
chown -R builder:builder /home/builder
chmod 777 "$DISTDIR"
chown -R builder:builder "$DISTDIR"

# Generate signing key (for local builds)
sudo -u builder abuild-keygen -a -i -n

# Generate checksums from the local tarball
sudo -u builder abuild checksum

# Build the package
sudo -u builder abuild -r

# Find and copy the built package
find /home/builder/packages -name "*.apk" -type f
cp /home/builder/packages/sysutils/$(uname -m)/*.apk /workspace/ || \
  cp /home/builder/packages/*/$(uname -m)/*.apk /workspace/ || \
  find /home/builder/packages -name "*.apk" -exec cp {} /workspace/ \;

echo "Build complete!"
