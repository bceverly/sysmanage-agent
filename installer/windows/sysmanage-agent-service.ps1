#
# SysManage Agent - Windows Service Wrapper
# Runs the Python agent as a Windows Service
#

# Set error action preference
$ErrorActionPreference = "Stop"

# Get the installation directory
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set working directory
Set-Location $InstallDir

# Log file path
$LogPath = "C:\ProgramData\SysManage\logs"
$LogFile = Join-Path $LogPath "service.log"

# Create log directory if it doesn't exist
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Function to write log messages
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
}

Write-Log "=== SysManage Agent Service Starting ==="
Write-Log "Installation Directory: $InstallDir"

# Find Python executable
$PythonExe = $null

# Check virtual environment first
$VenvPython = Join-Path $InstallDir ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $PythonExe = $VenvPython
    Write-Log "Using virtual environment Python: $PythonExe"
} else {
    # Try to find system Python
    $PythonCommands = @("python", "python3", "py")
    foreach ($cmd in $PythonCommands) {
        try {
            $testPath = (Get-Command $cmd -ErrorAction SilentlyContinue).Source
            if ($testPath) {
                # Verify it's Python 3.10+
                $version = & $cmd --version 2>&1
                if ($version -match "Python 3\.([0-9]+)") {
                    $minor = [int]$Matches[1]
                    if ($minor -ge 10) {
                        $PythonExe = $testPath
                        Write-Log "Using system Python: $PythonExe (version: $version)"
                        break
                    }
                }
            }
        } catch {
            continue
        }
    }
}

if (-not $PythonExe) {
    Write-Log "ERROR: Python 3.10+ not found"
    exit 1
}

# Check if main.py exists
$MainScript = Join-Path $InstallDir "main.py"
if (-not (Test-Path $MainScript)) {
    Write-Log "ERROR: main.py not found at $MainScript"
    exit 1
}

Write-Log "Starting agent: $PythonExe $MainScript"

# Set environment variable for config path
$env:SYSMANAGE_CONFIG = "C:\ProgramData\SysManage\sysmanage-agent.yaml"

try {
    # Run the Python agent
    # The service will keep running as long as this process runs
    & $PythonExe $MainScript
    $exitCode = $LASTEXITCODE

    Write-Log "Agent exited with code: $exitCode"
    exit $exitCode

} catch {
    Write-Log "ERROR: Failed to start agent: $_"
    Write-Log "Exception: $($_.Exception.Message)"
    exit 1
}
