# SysManage Agent - Manual Release Guide

This document describes how to perform a manual release of the SysManage agent when
GitHub Actions CI/CD is unavailable (e.g., during GitHub outages or for air-gapped
environments).

## Overview

The normal release process is fully automated via GitHub Actions: pushing a tag
matching `v*.*.*` (e.g., `v1.2.3`) triggers builds across all platforms, publishes to
package repositories, and stages artifacts in sysmanage-docs. This manual process
replicates that pipeline using local machines.

**Key concept: Multi-machine additive workflow.** Each machine runs `make release-local`,
which builds packages for its native platform and stages them into a shared
sysmanage-docs repository. You run this on as many machines as needed to cover all
target platforms. Each run is additive -- existing packages from other platforms are
preserved.

## Prerequisites

### 1. Verify credentials

| Credential | Purpose | How to verify |
|------------|---------|---------------|
| GPG signing key | Signing DEB source packages | `gpg --list-secret-keys` |
| Launchpad PPA access | Ubuntu PPA uploads | Check `~/.dput.cf` or `~/.dput.d/` |
| OBS account | openSUSE Build Service | Check `~/.config/osc/oscrc` |
| COPR API token | Fedora COPR builds | Check `~/.config/copr` |
| Snap Store login | Snap publishing | `snapcraft whoami` |

### 2. Install deployment tools

```bash
cd ~/dev/sysmanage-agent
make deploy-check-deps
```

This checks for all required tools and prints install instructions for any that are
missing. The full list:

- **Launchpad**: `dch`, `debuild`, `debsign`, `dput`, `gpg`
  ```bash
  sudo apt-get install -y devscripts debhelper dh-python python3-all python3-setuptools dput-ng gnupg
  ```
- **OBS**: `osc`
  ```bash
  sudo apt-get install -y osc
  ```
- **COPR**: `copr-cli`, `rpmbuild`
  ```bash
  pip3 install copr-cli
  sudo apt-get install -y rpm    # or: sudo dnf install -y rpm-build
  ```
- **Snap Store**: `snapcraft`
  ```bash
  sudo snap install snapcraft --classic
  ```
- **Docs repo metadata**: `dpkg-scanpackages`, `createrepo_c`
  ```bash
  sudo apt-get install -y dpkg-dev
  sudo apt-get install -y createrepo-c    # or: sudo dnf install -y createrepo_c
  ```
- **Docker** (for Alpine builds): `docker`
  ```bash
  # See https://docs.docker.com/engine/install/
  ```
- **Flatpak** (optional): `flatpak`, `flatpak-builder`
  ```bash
  sudo apt-get install -y flatpak flatpak-builder
  ```
- **Release artifacts**: `sha256sum`, `cyclonedx-bom`
  ```bash
  pip3 install cyclonedx-bom
  ```

### 3. Clone or update sysmanage-docs

The docs repo is where all built packages are staged before being pushed to GitHub
Pages. By default, it is expected at `~/dev/sysmanage-docs`. Override with the
`DOCS_REPO` environment variable.

```bash
# First time:
cd ~/dev
git clone git@github.com:bceverly/sysmanage-docs.git

# Or if it already exists, pull latest:
cd ~/dev/sysmanage-docs
git pull
```

## Machine Matrix

### Minimum machines for a complete release

| Machine | OS | What gets built |
|---------|----|-----------------|
| Linux (Ubuntu/Debian) | Ubuntu 22.04+ | `.deb`, `.rpm`, `.snap`, Flatpak, Alpine `.apk` (via Docker), Launchpad PPA, OBS, COPR |
| macOS | macOS 13+ | macOS `.pkg` installer |
| Windows | Windows 10+ with WiX Toolset v4 | `.msi` (x64 + ARM64) |

### Full coverage (optional additional machines)

| Machine | OS | What gets built |
|---------|----|-----------------|
| FreeBSD | FreeBSD 13+ | FreeBSD `.pkg` |
| NetBSD | NetBSD 10+ | NetBSD `.tgz` |
| OpenBSD | OpenBSD 7.x | OpenBSD port |

On Linux, all deploy targets (Launchpad, OBS, COPR, Snap Store) are available. On
other platforms, only the native package build and docs-repo staging run.

## Step-by-Step Workflow

### Step 0: Prepare the release

Ensure all changes are merged to `main` and tests pass.

```bash
cd ~/dev/sysmanage-agent

# Verify you are on main and up to date
git checkout main
git pull origin main

# Run tests to confirm everything passes
make test
make lint
```

### Step 1: Tag the release

Tags must match the pattern `v*.*.*` (e.g., `v1.2.3`). This is the same tag format
that triggers the CI/CD pipeline.

```bash
# Create an annotated tag (recommended)
git tag -a v1.2.3 -m "Release v1.2.3"

# Or a lightweight tag
git tag v1.2.3

# Push the tag (if GitHub is reachable; otherwise push later)
git push origin v1.2.3
```

If you need to override the version detected from the tag, set the `VERSION`
environment variable for any command:

```bash
VERSION=1.2.3 make release-local
```

### Step 2: Run on Linux (primary build machine)

This is the main build machine. It handles the most targets.

```bash
cd ~/dev/sysmanage-agent
make release-local
```

The command is interactive -- it detects your OS and prompts before each step. Answer
`y` to execute a step or `n` to skip it. Here is what each step does:

**Step 1 -- Build packages for current platform:**
```bash
# On Ubuntu/Debian, this runs:
make installer-deb
# On CentOS/RHEL/Fedora:
make installer-rpm
# On openSUSE/SLES:
make installer-rpm    # (auto-detected)
```
Produces packages in `installer/dist/`.

**Step 2 -- Generate SBOM:**
```bash
make sbom
```
Creates SBOM files in CycloneDX format in the `sbom/` directory.

**Step 3 -- Generate checksums:**
```bash
make checksums
```
Creates `.sha256` files for every package in `installer/dist/`.

**Step 4 -- Generate release notes:**
```bash
make release-notes
```
Creates `installer/dist/release-notes-VERSION.md` with installation instructions
for every platform.

**Step 5 -- Stage to docs repo:**
```bash
make deploy-docs-repo
```
Copies packages from `installer/dist/` into `~/dev/sysmanage-docs/repo/agent/`
organized by platform (deb, rpm, mac, windows, freebsd, alpine, sbom).
Regenerates DEB and RPM repository metadata if the tools are available.

**Step 6 -- Deploy to Launchpad PPA (Ubuntu):**
```bash
make deploy-launchpad
```
Builds signed source packages for each Ubuntu release (questing, plucky, oracular,
noble, jammy) and uploads them via `dput` to `ppa:bceverly/sysmanage-agent`.
Override target releases: `LAUNCHPAD_RELEASES="noble jammy" make deploy-launchpad`
Override GPG key: `LAUNCHPAD_GPG_KEY=ABCDEF12 make deploy-launchpad`

**Step 7 -- Deploy to OBS (openSUSE):**
```bash
make deploy-obs
```
Checks out `home:USERNAME/sysmanage-agent` from OBS, creates source tarball,
updates the spec file version, and commits. OBS then builds RPMs automatically.
Override credentials: `OBS_USERNAME=user OBS_PASSWORD=pass make deploy-obs`

**Step 8 -- Deploy to COPR (Fedora):**
```bash
make deploy-copr
```
Creates an SRPM and uploads it to `USERNAME/sysmanage-agent` on Fedora COPR.
COPR builds RPMs for enabled chroots.
Override credentials: `COPR_LOGIN=x COPR_API_TOKEN=y COPR_USERNAME=z make deploy-copr`

**Step 9 -- Deploy to Snap Store:**
```bash
make deploy-snap
```
Builds a snap with `snapcraft pack` and uploads to the Snap Store **edge** channel.
Requires prior `snapcraft login`.

**Step 10 -- Build Alpine packages (Docker required):**
```bash
make installer-alpine
```
Pulls Alpine Docker images (3.19, 3.20, 3.21 by default) and runs `abuild` inside
each container. Produces `installer/dist/sysmanage-agent-VERSION-alpineXYZ.apk`.
Override versions: `ALPINE_VERSIONS="3.20 3.21" make installer-alpine`

**Step 11 -- Build Flatpak package:**
```bash
make flatpak
```
Builds a Flatpak using `flatpak-builder` with the Freedesktop Platform 24.08 runtime.
Requires `flatpak` and `flatpak-builder` to be installed.

If you prefer to run individual targets instead of the interactive pipeline:

```bash
cd ~/dev/sysmanage-agent
VERSION=1.2.3 make installer-deb
VERSION=1.2.3 make installer-alpine
VERSION=1.2.3 make flatpak
VERSION=1.2.3 make sbom
VERSION=1.2.3 make checksums
VERSION=1.2.3 make release-notes
VERSION=1.2.3 make deploy-docs-repo
VERSION=1.2.3 make deploy-launchpad
VERSION=1.2.3 make deploy-obs
VERSION=1.2.3 make deploy-copr
VERSION=1.2.3 make deploy-snap
```

### Step 3: Run on macOS

```bash
cd ~/dev/sysmanage-agent
make release-local
```

This detects macOS and runs:

```bash
make installer         # detects macOS, calls installer-pkg
make sbom
make checksums
make release-notes
make deploy-docs-repo  # stages .pkg to sysmanage-docs/repo/agent/mac/packages/VERSION/
```

Prerequisites: Xcode command-line tools (`xcode-select --install` for `pkgbuild`
and `productbuild`).

### Step 4: Run on Windows

From Git Bash or MSYS2 (requires WiX Toolset v4):

```bash
cd ~/dev/sysmanage-agent
make release-local
```

This detects MINGW/MSYS and runs:

```bash
make installer-msi-all  # builds .msi for x64 and ARM64 via PowerShell + WiX
make sbom
make checksums
make release-notes
make deploy-docs-repo   # stages .msi files to sysmanage-docs/repo/agent/windows/packages/VERSION/
```

### Step 5: Run on BSD machines (optional)

On each BSD machine:

```bash
cd ~/dev/sysmanage-agent
make release-local
```

The OS is auto-detected:

| OS | Build target | Output |
|----|-------------|--------|
| FreeBSD | `make installer-freebsd` | `installer/dist/*freebsd*.pkg` |
| NetBSD | `make installer-netbsd` | `installer/dist/*.tgz` |
| OpenBSD | `make installer-openbsd` | `installer/dist/*.tar.gz` |

Each then runs checksums, release-notes, and deploy-docs-repo to stage the
platform-specific packages.

### Step 6: Verify the docs repo

After running on all machines, verify that all platforms are represented:

```bash
cd ~/dev/sysmanage-docs

# Check each platform directory
ls -la repo/agent/deb/pool/main/
ls -la repo/agent/rpm/
ls -la repo/agent/mac/packages/
ls -la repo/agent/windows/packages/
ls -la repo/agent/freebsd/
ls -la repo/agent/alpine/
ls -la repo/agent/sbom/
```

### Step 7: Commit and push sysmanage-docs

When GitHub access is restored:

```bash
cd ~/dev/sysmanage-docs
git add repo/
git status              # review what will be committed
git commit -m "Release sysmanage-agent v1.2.3"
git push
```

## Running Individual Targets Without the Pipeline

You do not have to use `make release-local`. Every target can be run individually.

### Build a single package type

```bash
VERSION=1.2.3 make installer-deb
VERSION=1.2.3 make installer-alpine
VERSION=1.2.3 make installer-rpm
VERSION=1.2.3 make installer-pkg           # macOS
VERSION=1.2.3 make installer-msi-all       # Windows
VERSION=1.2.3 make installer-freebsd
VERSION=1.2.3 make installer-netbsd
VERSION=1.2.3 make installer-openbsd
VERSION=1.2.3 make snap
VERSION=1.2.3 make snap-strict
VERSION=1.2.3 make flatpak
```

### Publish to a single repository

```bash
VERSION=1.2.3 make deploy-launchpad
VERSION=1.2.3 make deploy-obs
VERSION=1.2.3 make deploy-copr
VERSION=1.2.3 make deploy-snap
VERSION=1.2.3 make deploy-docs-repo
```

### Generate artifacts only

```bash
make sbom                          # CycloneDX SBOM in sbom/
make checksums                     # SHA256 files in installer/dist/
VERSION=1.2.3 make release-notes  # Release notes in installer/dist/
```

## Target Reference

### Package Build Targets

| Target | Description | Platform | Output |
|--------|-------------|----------|--------|
| `installer` | Auto-detect platform and build | Any | Varies |
| `installer-deb` | Ubuntu/Debian `.deb` package | Linux | `installer/dist/*.deb` |
| `installer-alpine` | Alpine `.apk` packages via Docker | Linux (Docker) | `installer/dist/*alpine*.apk` |
| `installer-rpm` | CentOS/RHEL/Fedora `.rpm` package | Linux | `installer/dist/*.rpm` |
| `installer-pkg` | macOS `.pkg` installer | macOS | `installer/dist/*.pkg` |
| `installer-msi-all` | Windows `.msi` for x64 and ARM64 | Windows | `installer/dist/*.msi` |
| `installer-freebsd` | FreeBSD `.pkg` package | FreeBSD | `installer/dist/*.pkg` |
| `installer-netbsd` | NetBSD `.tgz` package | NetBSD | `installer/dist/*.tgz` |
| `installer-openbsd` | OpenBSD port | OpenBSD | `installer/dist/*.tar.gz` |
| `snap` | Snap package (classic confinement) | Linux | `*.snap` |
| `snap-strict` | Snap package (strict confinement) | Linux | `*.snap` |
| `flatpak` | Flatpak package | Linux | Flatpak bundle |

### Deploy Targets

| Target | Description | Credentials needed |
|--------|-------------|--------------------|
| `deploy-check-deps` | Verify all deployment tools installed | None |
| `checksums` | Generate SHA256 checksums for `installer/dist/` | None |
| `release-notes` | Generate release notes markdown | None |
| `deploy-launchpad` | Upload source packages to Launchpad PPA | GPG key, `~/.dput.cf` |
| `deploy-obs` | Upload to openSUSE Build Service | `~/.config/osc/oscrc` |
| `deploy-copr` | Build SRPM and upload to Fedora COPR | `~/.config/copr` |
| `deploy-snap` | Build and publish snap to Snap Store (edge channel) | `snapcraft login` |
| `deploy-docs-repo` | Stage all packages into sysmanage-docs | None (local) |
| `release-local` | Full interactive pipeline (combines above) | All of the above |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERSION` | Auto-detected from git tag | Override the release version (e.g., `VERSION=1.2.3`) |
| `DOCS_REPO` | `~/dev/sysmanage-docs` | Path to the sysmanage-docs repository |
| `ALPINE_VERSIONS` | `3.19 3.20 3.21` | Space-separated Alpine versions to build |
| `LAUNCHPAD_RELEASES` | `questing plucky oracular noble jammy` | Space-separated Ubuntu releases for PPA |
| `LAUNCHPAD_GPG_KEY` | Auto-detected from keyring | GPG key ID for signing source packages |
| `LAUNCHPAD_GPG_PASSPHRASE` | (none) | GPG passphrase for non-interactive signing |
| `OBS_USERNAME` | Read from `~/.config/osc/oscrc` | OBS username |
| `OBS_PASSWORD` | Read from `~/.config/osc/oscrc` | OBS password |
| `COPR_LOGIN` | Read from `~/.config/copr` | COPR login |
| `COPR_API_TOKEN` | Read from `~/.config/copr` | COPR API token |
| `COPR_USERNAME` | Read from `~/.config/copr` | COPR username |
| `GPG_KEY_ID` | Auto-detected from keyring | GPG key for signing packages |

### Alpine Package Build Details

The `installer-alpine` target uses Docker to replicate the CI/CD Alpine build:

1. Pulls `alpine:X.Y` Docker images for each configured version
2. Mounts the workspace and runs `installer/alpine/docker-build.sh` inside each container
3. The script installs `alpine-sdk`, `python3`, `py3-pip`
4. Copies `APKBUILD` and supporting files from `installer/alpine/`
5. Updates `pkgver`, generates a signing key, runs `abuild -r`
6. Extracts the `.apk` to the workspace root
7. The Makefile renames it to `sysmanage-agent-VERSION-alpineXYZ.apk` and moves it to `installer/dist/`

Requirements: Docker must be installed and the current user must have Docker
access (typically via the `docker` group).

```bash
# Build for all default Alpine versions:
make installer-alpine

# Build for specific versions:
ALPINE_VERSIONS="3.21" make installer-alpine

# With explicit version:
VERSION=1.2.3 ALPINE_VERSIONS="3.20 3.21" make installer-alpine
```

### Flatpak Build Details

The `flatpak` target builds a Flatpak package using `flatpak-builder`:

1. Verifies `flatpak` and `flatpak-builder` are installed
2. Configures Flathub repository (user installation) if not already present
3. Installs Freedesktop Platform 24.08 runtime and SDK if needed
4. Builds the Flatpak using the manifest in `installer/flatpak/`

Requirements: `flatpak` and `flatpak-builder` must be installed. Linux only.

```bash
# Install prerequisites:
sudo apt-get install -y flatpak flatpak-builder

# Build:
make flatpak
```
