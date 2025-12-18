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
    $nssmUrls = @(
        "https://nssm.cc/release/nssm-$nssmVersion.zip",
        "https://web.archive.org/web/2024/https://nssm.cc/release/nssm-$nssmVersion.zip",
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
                Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing -TimeoutSec 60
                Write-Host "    Downloaded NSSM archive" -ForegroundColor Gray
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
            # Exponential backoff: 5s, 10s, 20s, 40s, 80s, 160s, 320s, 640s, 1280s
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

    try {
        # Extract NSSM
        if (Test-Path $nssmExtract) {
            Remove-Item -Path $nssmExtract -Recurse -Force
        }
        $ProgressPreference = 'SilentlyContinue'
        Expand-Archive -Path $nssmZip -DestinationPath $nssmExtract -Force
        $ProgressPreference = 'Continue'

        # Copy the appropriate architecture version
        $nssmSource = Join-Path $nssmExtract "nssm-$nssmVersion\$nssmArch\nssm.exe"
        if (Test-Path $nssmSource) {
            Copy-Item $nssmSource $NssmExe -Force
            Write-Host "[OK] NSSM downloaded and ready for bundling" -ForegroundColor Green
        } else {
            throw "NSSM executable not found in downloaded archive at: $nssmSource"
        }

        # Clean up
        Remove-Item -Path $nssmZip -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $nssmExtract -Recurse -Force -ErrorAction SilentlyContinue

    } catch {
        Write-Host "ERROR: Failed to extract NSSM: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[OK] NSSM already present" -ForegroundColor Green
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
