# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

#
# Build Windows MSI Installer for SysManage Agent
# Uses WiX Toolset v4 to create MSI package
#
# Usage:
#   .\build-msi.ps1                 # Builds x64 installer
#   .\build-msi.ps1 -Architecture x64    # Builds x64 installer
#   .\build-msi.ps1 -Architecture arm64  # Builds ARM64 installer
#

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Building Windows .msi Package ($Architecture) ===" -ForegroundColor Cyan
Write-Host ""

# Check for WiX Toolset
Write-Host "Checking build dependencies..."
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: WiX Toolset not found." -ForegroundColor Red
    Write-Host "Download from: https://wixtoolset.org/docs/intro/"
    Write-Host "Install WiX Toolset v4 or later"
    exit 1
}
Write-Host "[OK] Build tools available" -ForegroundColor Green
Write-Host ""

# Determine version from environment variable, git tag, or auto-generate
Write-Host "Determining version..."
$VERSION = ""

# First, check if VERSION environment variable is set (e.g., from CI/CD)
if ($env:VERSION) {
    $VERSION = $env:VERSION
    # Strip 'v' prefix if present
    $VERSION = $VERSION -replace '^v', ''
    Write-Host "Using version from environment: $VERSION" -ForegroundColor Green
} else {
    # Try to get from git tags
    try {
        $gitVersion = (git describe --tags --abbrev=0 2>&1 | Out-String).Trim()
        # Check if git command succeeded (no error message)
        if ($gitVersion -notmatch "^fatal:" -and $gitVersion -match "^v?(\d+\.\d+\.\d+)") {
            $VERSION = $Matches[1]
            Write-Host "Building version: $VERSION (from git tag)" -ForegroundColor Green
        }
    } catch {
        # Git command failed, will auto-generate below
    }
}

if ([string]::IsNullOrEmpty($VERSION)) {
    # Auto-generate version based on date/time to ensure upgrades work
    # Format: 0.1.BUILDNUM where BUILDNUM = days since 2025-01-01 * 100 + hour
    # This ensures each build gets a unique, incrementing version number
    $epoch = Get-Date "2025-01-01"
    $now = Get-Date
    $daysSinceEpoch = [int]($now - $epoch).TotalDays
    $hour = $now.Hour
    $buildNum = $daysSinceEpoch * 100 + $hour
    $VERSION = "0.1.$buildNum"
    Write-Host "No git tags found, auto-generated version: $VERSION" -ForegroundColor Yellow
}
Write-Host ""

# Get paths
$CurrentDir = Get-Location
$OutputDir = Join-Path $CurrentDir "installer\dist"
$WixSource = Join-Path $CurrentDir "installer\windows\sysmanage-agent.wxs"
$OutputMsi = Join-Path $OutputDir "sysmanage-agent-$VERSION-windows-$Architecture.msi"

# Create output directory
Write-Host "Creating output directory..."
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
Write-Host "[OK] Output directory ready: $OutputDir" -ForegroundColor Green
Write-Host ""

# Download NSSM if not already present
Write-Host "Checking for NSSM (Non-Sucking Service Manager)..." -ForegroundColor Cyan
$NssmDir = Join-Path $CurrentDir "installer\windows"
$NssmExe = Join-Path $NssmDir "nssm.exe"

if (-not (Test-Path $NssmExe)) {
    Write-Host "Downloading NSSM for bundling with installer..." -ForegroundColor Yellow

    # Determine architecture for NSSM download
    # NSSM uses "win64" for 64-bit and "win32" for 32-bit
    # Note: ARM64 systems can run win64 binaries via emulation
    $nssmArch = if ($Architecture -eq "x64" -or $Architecture -eq "arm64") { "win64" } else { "win32" }
    $nssmVersion = "2.24"

    # Multiple URLs to try (nssm.cc can be unreliable)
    # Note: archive.org URLs need 'id_/' suffix to return raw file instead of framed HTML
    $nssmUrls = @(
        "https://nssm.cc/release/nssm-$nssmVersion.zip",
        "https://web.archive.org/web/2024id_/https://nssm.cc/release/nssm-$nssmVersion.zip",
        "https://github.com/kirillkovalenko/nssm/releases/download/v$nssmVersion/nssm-$nssmVersion.zip"
    )

    $nssmZip = Join-Path $env:TEMP "nssm-download.zip"
    $nssmExtract = Join-Path $env:TEMP "nssm-extract"
    $downloadSuccess = $false

    # Retry configuration: up to 10 attempts with exponential backoff
    $maxRetries = 10
    $baseDelaySeconds = 5

    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        Write-Host "  Download attempt $attempt of $maxRetries..." -ForegroundColor Cyan

        foreach ($nssmUrl in $nssmUrls) {
            try {
                Write-Host "    Trying: $nssmUrl" -ForegroundColor Gray

                # Clean up any previous failed download
                if (Test-Path $nssmZip) {
                    Remove-Item -Path $nssmZip -Force -ErrorAction SilentlyContinue
                }

                Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing -TimeoutSec 60

                # Validate the downloaded file is actually a ZIP (starts with PK signature)
                $fileBytes = [System.IO.File]::ReadAllBytes($nssmZip)
                if ($fileBytes.Length -lt 4 -or $fileBytes[0] -ne 0x50 -or $fileBytes[1] -ne 0x4B) {
                    Write-Host "    Downloaded file is not a valid ZIP archive (got HTML or other content)" -ForegroundColor Yellow
                    continue
                }

                # Try to extract to verify the ZIP is valid
                if (Test-Path $nssmExtract) {
                    Remove-Item -Path $nssmExtract -Recurse -Force
                }
                $ProgressPreference = 'SilentlyContinue'
                Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force
                $ProgressPreference = 'Continue'

                # Verify nssm.exe exists in the extracted content
                $nssmSource = Join-Path $nssmExtract "nssm-$nssmVersion\$nssmArch\nssm.exe"
                if (-not (Test-Path $nssmSource)) {
                    Write-Host "    ZIP extracted but nssm.exe not found at expected path" -ForegroundColor Yellow
                    continue
                }

                Write-Host "    Downloaded and verified NSSM archive" -ForegroundColor Gray
                $downloadSuccess = $true
                break
            } catch {
                Write-Host "    Failed: $_" -ForegroundColor Yellow
                continue
            }
        }

        if ($downloadSuccess) {
            break
        }

        if ($attempt -lt $maxRetries) {
            # Exponential backoff: 5s, 10s, 20s, 40s, 80s, 160s, capped at 300s
            $delaySeconds = $baseDelaySeconds * [Math]::Pow(2, $attempt - 1)
            # Cap at 5 minutes max delay
            $delaySeconds = [Math]::Min($delaySeconds, 300)
            Write-Host "  All URLs failed. Waiting $delaySeconds seconds before retry..." -ForegroundColor Yellow
            Start-Sleep -Seconds $delaySeconds
        }
    }

    if (-not $downloadSuccess) {
        Write-Host "ERROR: Failed to download NSSM after $maxRetries attempts from all mirror URLs" -ForegroundColor Red
        Write-Host "Please manually download NSSM from https://nssm.cc/download" -ForegroundColor Red
        Write-Host "Extract nssm.exe ($nssmArch) to: $NssmExe" -ForegroundColor Red
        exit 1
    }

    # Copy the nssm.exe to the installer directory
    try {
        $nssmSource = Join-Path $nssmExtract "nssm-$nssmVersion\$nssmArch\nssm.exe"
        Copy-Item $nssmSource $NssmExe -Force
        Write-Host "[OK] NSSM downloaded and ready for bundling" -ForegroundColor Green

        # Clean up
        Remove-Item -Path $nssmZip -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "ERROR: Failed to copy NSSM: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[OK] NSSM already present" -ForegroundColor Green
}
Write-Host ""

# Download DSC v3 (the Windows configuration-management executor)
#
# WHY THIS IS VENDORED RATHER THAN INSTALLED ON DEMAND
# ----------------------------------------------------
# ansible-core declares "Operating System :: POSIX" and nothing else, so the
# pull-style config-management path (Phase 20.1) cannot use it on Windows.
# DSC v3 is a standalone engine: no WinRM listener, no LCM, no inbound port --
# which matters because the alternative (Invoke-DscResource on PS 5.1) goes
# through the local WS-Management stack and FAILS on a hardened box where WinRM
# is Stopped/Disabled.  Confirmed on Windows 11 Pro ARM64, 2026-08-26: with
# WinRM disabled, Invoke-DscResource could not connect while dsc.exe enumerated
# 25 resources and completed a full get/set/delete round trip on the same host
# in the same run.
#
# Shipping it in the MSI keeps the agent air-gap clean: a managed host must
# never need to reach github.com to become manageable.
Write-Host "Checking for DSC v3 (Windows config-management executor)..." -ForegroundColor Cyan
$DscVersion = "3.2.3"
$DscDir = Join-Path $CurrentDir "installer\windows\dsc"
$DscExe = Join-Path $DscDir "dsc.exe"

if (-not (Test-Path $DscExe)) {
    Write-Host "Downloading DSC v$DscVersion for bundling with installer..." -ForegroundColor Yellow

    # The release assets are per-TARGET-TRIPLE, so this must follow the MSI
    # architecture rather than the architecture of the machine doing the build:
    # the ARM64 MSI is cross-built on an x64 runner, and shipping an x86_64
    # dsc.exe inside it would run under emulation at best.
    $dscTarget = if ($Architecture -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
    $dscAsset = "DSC-$DscVersion-$dscTarget.zip"
    $dscUrl = "https://github.com/PowerShell/DSC/releases/download/v$DscVersion/$dscAsset"

    $dscZip = Join-Path $env:TEMP "dsc-download.zip"
    $dscExtract = Join-Path $env:TEMP "dsc-extract"
    $dscDownloaded = $false

    $maxRetries = 5
    $baseDelaySeconds = 5

    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        Write-Host "  Download attempt $attempt of $maxRetries : $dscUrl" -ForegroundColor Cyan
        try {
            if (Test-Path $dscZip) {
                Remove-Item -Path $dscZip -Force -ErrorAction SilentlyContinue
            }

            Invoke-WebRequest -Uri $dscUrl -OutFile $dscZip -UseBasicParsing -TimeoutSec 120

            # A GitHub error page is still a 200 with HTML in it; check for the
            # ZIP magic rather than trusting the status code.
            $fileBytes = [System.IO.File]::ReadAllBytes($dscZip)
            if ($fileBytes.Length -lt 4 -or $fileBytes[0] -ne 0x50 -or $fileBytes[1] -ne 0x4B) {
                Write-Host "    Downloaded file is not a valid ZIP archive" -ForegroundColor Yellow
                continue
            }

            if (Test-Path $dscExtract) {
                Remove-Item -Path $dscExtract -Recurse -Force
            }
            $ProgressPreference = 'SilentlyContinue'
            Expand-Archive -Path $dscZip -DestinationPath $dscExtract -Force
            $ProgressPreference = 'Continue'

            # dsc.exe needs its sibling resource manifests to enumerate
            # anything, so the whole extracted tree ships, not just the binary.
            $dscSource = Get-ChildItem -Path $dscExtract -Filter "dsc.exe" -Recurse -File | Select-Object -First 1
            if (-not $dscSource) {
                Write-Host "    ZIP extracted but dsc.exe not found inside" -ForegroundColor Yellow
                continue
            }

            $dscDownloaded = $true
            break
        } catch {
            Write-Host "    Failed: $_" -ForegroundColor Yellow
        }

        if ($attempt -lt $maxRetries) {
            $delaySeconds = [Math]::Min($baseDelaySeconds * [Math]::Pow(2, $attempt - 1), 120)
            Write-Host "  Waiting $delaySeconds seconds before retry..." -ForegroundColor Yellow
            Start-Sleep -Seconds $delaySeconds
        }
    }

    if (-not $dscDownloaded) {
        # Hard-fail rather than building an MSI that silently lacks the
        # executor.  The server reports Windows hosts as config-management
        # READY on the strength of this file being present; an installer that
        # quietly omits it would make that report a lie on every Windows host.
        Write-Host "ERROR: Failed to download DSC v$DscVersion after $maxRetries attempts" -ForegroundColor Red
        Write-Host "Expected asset: $dscAsset" -ForegroundColor Red
        Write-Host "Manually extract it to: $DscDir" -ForegroundColor Red
        exit 1
    }

    try {
        if (Test-Path $DscDir) {
            Remove-Item -Path $DscDir -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $DscDir | Out-Null
        Copy-Item -Path (Join-Path $dscSource.DirectoryName "*") -Destination $DscDir -Recurse -Force
        Write-Host "[OK] DSC v$DscVersion ($dscTarget) ready for bundling" -ForegroundColor Green

        Remove-Item -Path $dscZip -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $dscExtract -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "ERROR: Failed to stage DSC: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[OK] DSC already present" -ForegroundColor Green
}

if (-not (Test-Path $DscExe)) {
    Write-Host "ERROR: $DscExe is missing after staging" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Create ZIP of src directory for packaging
Write-Host "Preparing source files for packaging..." -ForegroundColor Cyan
$SrcDir = Join-Path $CurrentDir "src"
$SrcZip = Join-Path $CurrentDir "installer\windows\src.zip"

# Remove old ZIP if it exists
if (Test-Path $SrcZip) {
    Remove-Item -Path $SrcZip -Force
}

# Create ZIP file (suppress progress bar)
$ProgressPreference = 'SilentlyContinue'
Compress-Archive -Path "$SrcDir\*" -DestinationPath $SrcZip -Force
$ProgressPreference = 'Continue'
Write-Host "[OK] Source files packaged: $(([System.IO.FileInfo]$SrcZip).Length / 1MB | ForEach-Object { '{0:N2}' -f $_ }) MB" -ForegroundColor Green
Write-Host ""

# Build MSI package
Write-Host "Building MSI package..." -ForegroundColor Cyan
Push-Location (Join-Path $CurrentDir "installer\windows")
try {
    $wixArgs = @(
        "build"
        "-o"
        $OutputMsi
        "sysmanage-agent.wxs"
        "-arch"
        $Architecture
        "-d"
        "VERSION=$VERSION"
    )

    & wix @wixArgs

    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Build failed" -ForegroundColor Red
        exit 1
    }

    Write-Host ""
    Write-Host "[OK] Package built successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Package: $OutputMsi" -ForegroundColor Cyan
    Write-Host ""
    Get-Item $OutputMsi | Format-Table Name, Length, LastWriteTime -AutoSize
    Write-Host ""

    # Check if package is signed
    $signature = Get-AuthenticodeSignature $OutputMsi
    if ($signature.Status -eq "NotSigned") {
        Write-Host "[WARNING] MSI package is NOT SIGNED" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To sign the MSI (removes 'Unknown Publisher' warning):" -ForegroundColor Cyan
        Write-Host "  1. Obtain a code signing certificate" -ForegroundColor Gray
        Write-Host "  2. Install it in your certificate store" -ForegroundColor Gray
        Write-Host "  3. Run: signtool sign /a /t http://timestamp.digicert.com `"$OutputMsi`"" -ForegroundColor Gray
        Write-Host ""
        Write-Host "For testing, you can create a self-signed certificate:" -ForegroundColor Cyan
        Write-Host "  New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=SysManage' -CertStoreLocation Cert:\CurrentUser\My" -ForegroundColor Gray
        Write-Host ""
    } else {
        Write-Host "[OK] Package is signed by: $($signature.SignerCertificate.Subject)" -ForegroundColor Green
        Write-Host ""
    }

    Write-Host "Install with:" -ForegroundColor Yellow
    Write-Host "  msiexec /i `"$OutputMsi`""
    Write-Host ""
} finally {
    Pop-Location
}
