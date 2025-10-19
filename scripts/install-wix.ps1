#
# Install WiX Toolset for Windows MSI package building
#

$ErrorActionPreference = "Continue"

Write-Host "Checking for WiX Toolset..." -ForegroundColor Cyan

# Check if wix is already installed
if (Get-Command wix -ErrorAction SilentlyContinue) {
    $wixVersion = (wix --version 2>&1 | Out-String).Trim()
    Write-Host "[OK] WiX Toolset already installed: $wixVersion" -ForegroundColor Green
    exit 0
}

Write-Host "[INFO] WiX Toolset not found, attempting to install..." -ForegroundColor Yellow
Write-Host ""

# Check if winget is available
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "[WARNING] winget is not available on this system" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please install WiX Toolset manually:" -ForegroundColor White
    Write-Host "  Download from: https://github.com/wixtoolset/wix4/releases" -ForegroundColor Gray
    Write-Host "  Or visit: https://wixtoolset.org/docs/intro/" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

Write-Host "Attempting winget installation..." -ForegroundColor Cyan

# Try the direct install command with full output
Write-Host "Running: winget install WiXToolset.WiXCLI" -ForegroundColor Gray
Write-Host ""

$output = winget install WiXToolset.WiXCLI --accept-source-agreements --accept-package-agreements 2>&1
$exitCode = $LASTEXITCODE

Write-Host $output
Write-Host ""

if ($exitCode -eq 0) {
    Write-Host "[OK] WiX Toolset installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "[IMPORTANT] Please close and reopen your terminal/PowerShell session" -ForegroundColor Yellow
    Write-Host "            for WiX to be available in your PATH" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "After restarting your terminal, verify with: wix --version" -ForegroundColor Gray
    Write-Host ""
    exit 0
}

# Installation failed
Write-Host ""
Write-Host "[WARNING] winget installation failed with exit code: $exitCode" -ForegroundColor Yellow
Write-Host ""
Write-Host "Please try installing manually:" -ForegroundColor White
Write-Host ""
Write-Host "Option 1 - Try winget command manually:" -ForegroundColor Cyan
Write-Host "  winget install WiXToolset.WiXCLI" -ForegroundColor Gray
Write-Host ""
Write-Host "Option 2 - Try alternative package:" -ForegroundColor Cyan
Write-Host "  winget install WiXToolset.WiXToolset" -ForegroundColor Gray
Write-Host ""
Write-Host "Option 3 - Install as .NET tool (requires .NET SDK 6+):" -ForegroundColor Cyan
Write-Host "  dotnet tool install --global wix" -ForegroundColor Gray
Write-Host ""
Write-Host "Option 4 - Visit official documentation:" -ForegroundColor Cyan
Write-Host "  https://wixtoolset.org/docs/intro/" -ForegroundColor Gray
Write-Host ""

exit 1
