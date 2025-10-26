# Flatpak Deployment Guide

This document explains how to deploy SysManage Agent Flatpak builds to Flathub.

## Overview

The workflow `test-flathub-deploy.yml` pushes the Flatpak manifest to your Flathub repository, where Flathub's build servers will automatically build and publish it.

## Required Secrets

### Flathub Token
- **Secret Name**: `FLATHUB_TOKEN`
- **Source**: GitHub Personal Access Token with repo access
- **Purpose**: Push to your Flathub repository at `github.com/flathub/org.sysmanage.Agent`
- **How to create**:
  1. Go to https://github.com/settings/tokens
  2. Click "Generate new token (classic)"
  3. Give it a name like "Flathub Deploy"
  4. Select scope: `repo` (full control of private repositories)
  5. Click "Generate token"
  6. Copy the token
  7. Go to your sysmanage-agent repo → Settings → Secrets and variables → Actions
  8. Click "New repository secret"
  9. Name: `FLATHUB_TOKEN`
  10. Value: paste the token
  11. Click "Add secret"

## Prerequisites

Before using this workflow, you need to:

### Step 1: Create a Flathub Repository

1. Fork the Flathub repository: https://github.com/flathub/flathub
2. Add your application manifest to the repository
3. Submit a pull request to Flathub

### Step 2: Flathub Requirements

Flathub requires:
- A manifest file (`org.sysmanage.Agent.yaml`)
- Desktop file (`org.sysmanage.Agent.desktop`)
- AppStream metadata (`org.sysmanage.Agent.metainfo.xml`)
- Icon file

**We already have all of these!** They're in `installer/flatpak/`

### Step 3: Flathub Submission Process

1. Create a new repository at https://github.com/flathub/org.sysmanage.Agent
2. Add the manifest files from `installer/flatpak/`
3. Submit for review: https://github.com/flathub/flathub/new/master
4. Once approved, Flathub will build and distribute your app automatically

## Current Workflow (GitHub Container Registry)

The current workflow publishes to **ghcr.io** which allows users to install from GitHub:

### Usage

1. **Trigger the workflow** manually from GitHub Actions:
   - Go to Actions → Test Flatpak Build and Deploy
   - Click "Run workflow"
   - Enter a version string (e.g., "1.0.0")

2. **The workflow will**:
   - Build the Flatpak
   - Publish to `ghcr.io/bceverly/sysmanage-agent:VERSION`
   - Upload the `.flatpak` bundle as an artifact

3. **Users can install** from GitHub Container Registry:
   ```bash
   # Method 1: Direct installation from ghcr.io (if Flatpak supports it)
   flatpak install --user ghcr.io/bceverly/sysmanage-agent

   # Method 2: Download and install the bundle
   # Download from GitHub Actions artifacts, then:
   flatpak install --user sysmanage-agent-VERSION.flatpak
   ```

## Switching to Flathub (Recommended)

For official public distribution, I recommend submitting to Flathub instead of using ghcr.io because:

1. **Better discovery**: Users can find your app in GNOME Software, KDE Discover, etc.
2. **Automatic updates**: Flathub handles updates for users
3. **Trusted source**: Users trust Flathub more than personal repositories
4. **No secrets needed**: Flathub builds from your public manifest

### Flathub Submission Checklist

- [ ] Review manifest at `installer/flatpak/org.sysmanage.Agent.yaml`
- [ ] Ensure desktop file is valid
- [ ] Ensure AppStream metadata is valid
- [ ] Test the Flatpak locally
- [ ] Create Flathub repository
- [ ] Submit for review

## Secrets Summary

**For ghcr.io (current workflow)**:
- ✅ No secrets required (uses automatic `GITHUB_TOKEN`)

**For Flathub (recommended)**:
- ✅ No secrets required (Flathub builds from public manifest)

## Testing

To test the workflow:

1. Push this workflow to your GitHub repository
2. Go to Actions → Test Flatpak Build and Deploy
3. Click "Run workflow"
4. Enter version "0.0.1-test"
5. Check the artifacts for the built `.flatpak` file

## Notes

- The workflow uses `ubuntu-22.04` which has Flatpak 1.12+
- The Freedesktop Platform 24.08 is used (latest stable)
- Python 3.12.7 is bundled in the Flatpak
- All dependencies are pre-downloaded for offline builds
