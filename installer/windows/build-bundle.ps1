# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

#
# Build the SysManage Agent WiX Bundle (Burn).
#
# The bundle chains  VC++ runtime -> Python -> agent MSI  so each installs in
# its own Windows Installer transaction.  That is the only way prerequisites
# can be installed at all: from inside the MSI they are refused with 1618.
#
# Usage:
#   .\build-bundle.ps1                       # x64, MSI auto-discovered
#   .\build-bundle.ps1 -Architecture arm64
#   .\build-bundle.ps1 -MsiPath ...\sysmanage-agent-3.5.1.0-windows-x64.msi
#
# Run build-msi.ps1 FIRST -- the bundle embeds the MSI it chains.
#

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64",

    [Parameter(Mandatory = $false)]
    [string]$MsiPath = "",

    # Optional integrity pin for the Python installer.  python.org serves
    # immutable versioned URLs, so a hash CAN be pinned here; it is off by
    # default only because the value has to be refreshed with every version
    # bump and a stale pin fails the build for the wrong reason.
    [Parameter(Mandatory = $false)]
    [string]$PythonSha256 = ""
)

$ErrorActionPreference = "Stop"

# Keep in step with check-python.ps1's Install-Python.  Both install the same
# interpreter; if they drift, a bundle install and an MSI install produce
# machines with different Pythons, which is the kind of difference nobody
# notices until a wheel fails to build on one of them.
$PythonVersion = "3.12.8"

Write-Host "=== Building SysManage Agent Bundle ($Architecture) ===" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: WiX Toolset not found. Install with:" -ForegroundColor Red
    Write-Host "  dotnet tool install --global wix --version 5.0.2"
    exit 1
}

# Bundles need the bootstrapper-application extension (the bal: namespace) and
# the util extension (registry searches).  Adding them is idempotent.
#
# The package is WixToolset.BootstrapperApplications.wixext, NOT the WiX v4 name
# WixToolset.Bal.wixext.  v5 renamed it, and the old name fails in a genuinely
# nasty way: `wix extension add` still exits 0, but the package it fetches
# contains WixToolset.BootstrapperApplications.wixext.dll while WiX looks for a
# DLL matching the name you asked for.  `wix extension list` then reports the
# extension as "(damaged)" and the build fails much later with WIX0144
# "could not be found", which points at the wrong problem entirely.
#
# Hence the explicit verification below: exit code 0 is NOT sufficient evidence
# that an extension is usable, so check the listing for "damaged" too.
$requiredExtensions = @(
    "WixToolset.BootstrapperApplications.wixext/5.0.2",
    "WixToolset.Util.wixext/5.0.2"
)
foreach ($ext in $requiredExtensions) {
    Write-Host "Ensuring WiX extension: $ext"
    & wix extension add -g $ext
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: could not add WiX extension $ext (exit $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }
}

$extList = (& wix extension list -g) -join "`n"
if ($extList -match 'damaged') {
    Write-Host "ERROR: a WiX extension is installed but damaged:" -ForegroundColor Red
    Write-Host $extList
    Write-Host "Remove ~/.wix/extensions and re-run." -ForegroundColor Yellow
    exit 1
}

# ---------------------------------------------------------------- version ---
$VERSION = ""
if ($env:VERSION) {
    $VERSION = $env:VERSION -replace '^v', ''
    Write-Host "Using version from environment: $VERSION" -ForegroundColor Green
} else {
    try {
        $gitVersion = (git describe --tags --abbrev=0 2>&1 | Out-String).Trim()
        if ($gitVersion -notmatch "^fatal:" -and $gitVersion -match "^v?(\d+\.\d+\.\d+(\.\d+)?)") {
            $VERSION = $Matches[1]
            Write-Host "Building version: $VERSION (from git tag)" -ForegroundColor Green
        }
    } catch { }
}
if ([string]::IsNullOrEmpty($VERSION)) {
    Write-Host "ERROR: no version. Set `$env:VERSION or build from a tagged checkout." -ForegroundColor Red
    exit 1
}

# -------------------------------------------------------------------- MSI ---
$CurrentDir = Get-Location
$OutputDir = Join-Path $CurrentDir "installer\dist"
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

if ([string]::IsNullOrEmpty($MsiPath)) {
    $MsiPath = Join-Path $OutputDir "sysmanage-agent-$VERSION-windows-$Architecture.msi"
}
if (-not (Test-Path $MsiPath)) {
    Write-Host "ERROR: MSI not found at $MsiPath" -ForegroundColor Red
    Write-Host "Run build-msi.ps1 -Architecture $Architecture first." -ForegroundColor Yellow
    exit 1
}
Write-Host "[OK] Chaining MSI: $MsiPath" -ForegroundColor Green

# ----------------------------------------------------------- prerequisites ---
$PrereqDir = Join-Path $CurrentDir "installer\windows\prereq"
if (-not (Test-Path $PrereqDir)) {
    New-Item -ItemType Directory -Path $PrereqDir -Force | Out-Null
}

function Assert-TrustedSignature {
    <#
    .SYNOPSIS
        Refuse to embed an unsigned or untrusted prerequisite.
    .DESCRIPTION
        These two payloads are executed elevated on every machine that installs
        the agent, so "we downloaded something from a URL" is not a good enough
        provenance story.  Authenticode is the check that actually means
        something on Windows, and it keeps working when a vendor rotates a
        download URL -- which the VC++ aka.ms link does routinely, and which is
        why that one cannot be pinned by hash.
    #>
    param([string]$Path, [string]$ExpectSubjectLike)

    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid') {
        throw "Signature on $Path is '$($sig.Status)', not Valid. Refusing to embed it."
    }
    $subject = $sig.SignerCertificate.Subject
    if ($subject -notlike $ExpectSubjectLike) {
        throw "Unexpected signer for $Path`n  got:      $subject`n  expected: $ExpectSubjectLike"
    }
    Write-Host "  [OK] signed by $subject" -ForegroundColor Green
}

function Get-Prereq {
    param(
        [string]$Url,
        [string]$OutFile,
        [string]$ExpectSubjectLike,
        [string]$Sha256 = ""
    )
    if (Test-Path $OutFile) {
        Write-Host "  cached: $OutFile" -ForegroundColor Gray
    } else {
        Write-Host "  downloading $Url" -ForegroundColor Gray
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 300
    }

    if ($Sha256) {
        $actual = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash
        if ($actual -ne $Sha256.ToUpper()) {
            Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
            throw "SHA-256 mismatch for $OutFile`n  got:      $actual`n  expected: $($Sha256.ToUpper())"
        }
        Write-Host "  [OK] sha256 $actual" -ForegroundColor Green
    }
    Assert-TrustedSignature -Path $OutFile -ExpectSubjectLike $ExpectSubjectLike
}

Write-Host ""
Write-Host "Fetching prerequisites (embedded, so the bundle works air-gapped)..." -ForegroundColor Cyan

if ($Architecture -eq "arm64") {
    $VcArch = "arm64"
    $VcUrl = "https://aka.ms/vs/17/release/vc_redist.arm64.exe"
    $PythonUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-arm64.exe"
} else {
    $VcArch = "x64"
    $VcUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    $PythonUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe"
}

$VcRedistPath = Join-Path $PrereqDir "vc_redist.$VcArch.exe"
$PythonPath = Join-Path $PrereqDir "python-$PythonVersion-$VcArch.exe"

Write-Host "Visual C++ Redistributable ($VcArch):"
Get-Prereq -Url $VcUrl -OutFile $VcRedistPath -ExpectSubjectLike "*Microsoft Corporation*"

Write-Host "Python $PythonVersion ($VcArch):"
Get-Prereq -Url $PythonUrl -OutFile $PythonPath -ExpectSubjectLike "*Python Software Foundation*" -Sha256 $PythonSha256

# ------------------------------------------------------------------ build ---
$OutputExe = Join-Path $OutputDir "sysmanage-agent-$VERSION-windows-$Architecture.exe"

Write-Host ""
Write-Host "Building bundle..." -ForegroundColor Cyan
Push-Location (Join-Path $CurrentDir "installer\windows")
try {
    $wixArgs = @(
        "build"
        "-o", $OutputExe
        "sysmanage-agent-bundle.wxs"
        "-arch", $Architecture
        "-ext", "WixToolset.BootstrapperApplications.wixext"
        "-ext", "WixToolset.Util.wixext"
        "-d", "VERSION=$VERSION"
        "-d", "MsiPath=$MsiPath"
        "-d", "VcRedistPath=$VcRedistPath"
        "-d", "PythonPath=$PythonPath"
        "-d", "PythonVersion=$PythonVersion"
        "-d", "VcArch=$VcArch"
    )
    & wix @wixArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Bundle build failed" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "[OK] Bundle built: $OutputExe" -ForegroundColor Green
Get-Item $OutputExe | Format-Table Name, Length, LastWriteTime -AutoSize
Write-Host "Install with:" -ForegroundColor Yellow
Write-Host "  $OutputExe /quiet"
Write-Host ""
