#
# Check for all prerequisites and install if missing
# - Administrative privileges
# - .NET Framework 4.5+
# - Visual C++ Redistributable (for cryptography package)
# - Python 3.9+
#

$ErrorActionPreference = "Stop"

# Log file
$LogPath = "C:\ProgramData\SysManage\logs"
$LogFile = Join-Path $LogPath "install.log"

# Create log directory if it doesn't exist
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Function to write log messages
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

Write-Log "=== Prerequisites Check ==="

# Detect system architecture
$SystemArch = $env:PROCESSOR_ARCHITECTURE
if ($SystemArch -eq "AMD64") {
    $Arch = "x64"
    $ArchDisplay = "x64"
} elseif ($SystemArch -eq "ARM64") {
    $Arch = "arm64"
    $ArchDisplay = "ARM64"
} else {
    Write-Log "WARNING: Unknown architecture: $SystemArch, defaulting to x64"
    $Arch = "x64"
    $ArchDisplay = "x64"
}
Write-Log "System architecture: $ArchDisplay"

# 1. Check for Administrative Privileges
Write-Log "Checking administrative privileges..."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Log "ERROR: This installer requires administrative privileges"
    Write-Log "Please run the installer as Administrator"
    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Red
    Write-Host "ERROR: Administrator rights required" -ForegroundColor Red
    Write-Host "=====================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please right-click the installer and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
Write-Log "Running with administrative privileges: OK"

# 2. Check for .NET Framework 4.5+
Write-Log "Checking .NET Framework..."
try {
    $netVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop
    $releaseKey = $netVersion.Release

    if ($releaseKey -ge 378389) {
        $netVersionStr = "4.5+"
        if ($releaseKey -ge 528040) { $netVersionStr = "4.8" }
        elseif ($releaseKey -ge 461808) { $netVersionStr = "4.7.2" }
        elseif ($releaseKey -ge 460798) { $netVersionStr = "4.7" }
        elseif ($releaseKey -ge 394802) { $netVersionStr = "4.6.2" }
        elseif ($releaseKey -ge 394254) { $netVersionStr = "4.6.1" }
        elseif ($releaseKey -ge 393295) { $netVersionStr = "4.6" }
        elseif ($releaseKey -ge 379893) { $netVersionStr = "4.5.2" }
        elseif ($releaseKey -ge 378675) { $netVersionStr = "4.5.1" }

        Write-Log ".NET Framework $netVersionStr detected: OK"
    } else {
        Write-Log "ERROR: .NET Framework 4.5+ is required but not found"
        Write-Log "Please install .NET Framework 4.8 from: https://dotnet.microsoft.com/download/dotnet-framework"
        exit 1
    }
} catch {
    Write-Log "WARNING: Could not detect .NET Framework version, assuming it's present"
}

# 3. Check for Visual C++ Redistributable
Write-Log "Checking Visual C++ Redistributable..."
$vcRedistInstalled = $false

# Check for VC++ 2015-2022 redistributable (needed for cryptography package)
$vcRedistKeys = @(
    "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
)

foreach ($key in $vcRedistKeys) {
    try {
        $vcRedist = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($vcRedist -and $vcRedist.Installed -eq 1) {
            Write-Log "Visual C++ Redistributable found: version $($vcRedist.Version)"
            $vcRedistInstalled = $true
            break
        }
    } catch {
        continue
    }
}

if (-not $vcRedistInstalled) {
    Write-Log "Visual C++ Redistributable not found - installing..."

    # Download VC++ Redistributable 2015-2022 (architecture-specific)
    if ($Arch -eq "arm64") {
        $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.arm64.exe"
        $vcRedistInstaller = "$env:TEMP\vc_redist.arm64.exe"
    } else {
        $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        $vcRedistInstaller = "$env:TEMP\vc_redist.x64.exe"
    }

    try {
        Write-Log "Downloading Visual C++ Redistributable ($ArchDisplay) from $vcRedistUrl..."
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($vcRedistUrl, $vcRedistInstaller)
        Write-Log "Download complete: $vcRedistInstaller"

        # Install silently
        Write-Log "Installing Visual C++ Redistributable ($ArchDisplay)..."
        $process = Start-Process -FilePath $vcRedistInstaller -ArgumentList "/install", "/quiet", "/norestart" -Wait -PassThru -WindowStyle Hidden

        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-Log "Visual C++ Redistributable installed successfully"
            Remove-Item $vcRedistInstaller -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "WARNING: Visual C++ Redistributable installation returned exit code $($process.ExitCode)"
            Write-Log "Installation may still succeed, continuing..."
        }
    } catch {
        Write-Log "WARNING: Failed to install Visual C++ Redistributable: $_"
        Write-Log "The cryptography package may fail to install without it"
        Write-Log "You can manually install it from: $vcRedistUrl"
    }
} else {
    Write-Log "Visual C++ Redistributable: OK"
}

# 4. Check for Python 3.9+
Write-Log "Checking Python..."

# Find Python executable
$PythonExe = $null
$PythonCommands = @("python", "python3", "py")

foreach ($cmd in $PythonCommands) {
    try {
        $testPath = (Get-Command $cmd -ErrorAction SilentlyContinue).Source
        if ($testPath) {
            # Verify it's Python 3.9+
            $version = & $cmd --version 2>&1
            if ($version -match "Python 3\.(\d+)") {
                $minor = [int]$Matches[1]
                if ($minor -ge 9) {
                    $PythonExe = $cmd
                    Write-Log "Found Python: $testPath (version: $version)"
                    exit 0
                }
            }
        }
    } catch {
        continue
    }
}

# Python not found - install it
Write-Log "Python 3.9+ not found - installing Python 3.12..."

# Download Python 3.12 installer (architecture-specific)
$PythonVersion = "3.12.8"

if ($Arch -eq "arm64") {
    $PythonInstaller = "$env:TEMP\python-$PythonVersion-arm64.exe"
    $PythonUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-arm64.exe"
} else {
    $PythonInstaller = "$env:TEMP\python-$PythonVersion-amd64.exe"
    $PythonUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe"
}

try {
    Write-Log "Downloading Python $PythonVersion ($ArchDisplay) from $PythonUrl..."

    # Use .NET WebClient for compatibility
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($PythonUrl, $PythonInstaller)

    Write-Log "Download complete: $PythonInstaller"

    # Install Python silently
    Write-Log "Installing Python $PythonVersion ($ArchDisplay)..."
    $installArgs = @(
        "/quiet"
        "InstallAllUsers=1"
        "PrependPath=1"
        "Include_test=0"
        "Include_launcher=1"
    )

    $process = Start-Process -FilePath $PythonInstaller -ArgumentList $installArgs -Wait -PassThru -WindowStyle Hidden

    if ($process.ExitCode -eq 0) {
        Write-Log "Python $PythonVersion ($ArchDisplay) installed successfully"

        # Clean up installer
        Remove-Item $PythonInstaller -Force

        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

        exit 0
    } else {
        Write-Log "ERROR: Python installation failed with exit code $($process.ExitCode)"
        exit 1
    }

} catch {
    Write-Log "ERROR: Failed to download or install Python: $_"
    exit 1
}
