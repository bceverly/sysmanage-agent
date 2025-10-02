# SysManage Agent Runner for Windows (PowerShell)
# This script runs the SysManage Agent as a regular user (non-privileged)
# For operations requiring elevated privileges, use run-privileged.ps1

# Requires -Version 5.0

# Get the directory where this script is located
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
# Change to the project root directory (parent of scripts directory)
$AgentDir = Split-Path -Parent $ScriptDir
Set-Location $AgentDir

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " SysManage Agent Runner (PowerShell)" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Working directory: $AgentDir" -ForegroundColor Yellow
Write-Host ""

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Warn if running as administrator
if (Test-Administrator) {
    Write-Host "[WARNING] Running with administrator privileges" -ForegroundColor Yellow
    Write-Host "This script is designed to run as a regular user." -ForegroundColor Yellow
    Write-Host "For privileged operations, this is fine, but consider using run-privileged.ps1 instead." -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "[OK] Running as regular user (non-privileged)" -ForegroundColor Green
    Write-Host ""
}

# Check if virtual environment exists
$VenvPath = Join-Path $AgentDir ".venv"
if (-not (Test-Path $VenvPath)) {
    Write-Host "[ERROR] Virtual environment not found at: $VenvPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please run setup first:" -ForegroundColor Yellow
    Write-Host "   python -m venv .venv"
    Write-Host "   .venv\Scripts\pip install -r requirements.txt"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

$PythonExe = Join-Path $VenvPath "Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    Write-Host "[ERROR] Python executable not found in virtual environment" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Create logs directory if it doesn't exist
$LogsDir = Join-Path $AgentDir "logs"
if (-not (Test-Path $LogsDir)) {
    try {
        New-Item -ItemType Directory -Path $LogsDir | Out-Null
        Write-Host "[OK] Created logs directory" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Could not create logs directory: $_" -ForegroundColor Yellow
        Write-Host "Agent will continue but may not be able to write logs." -ForegroundColor Yellow
    }
}

# Stop any existing agent processes
Write-Host ""
Write-Host "Checking for existing agent processes..." -ForegroundColor Yellow

# Try to find existing Python processes running from this directory
$existingProcesses = Get-Process python -ErrorAction SilentlyContinue | 
    Where-Object { 
        try {
            $_.Path -like "*$AgentDir*"
        } catch {
            # May not have permission to access Path property
            $false
        }
    }

if ($existingProcesses) {
    Write-Host "Found existing Python processes. Attempting to stop agent..." -ForegroundColor Yellow
    
    # Try to use the stop script
    $StopScript = Join-Path $AgentDir "scripts\stop.cmd"
    if (Test-Path $StopScript) {
        & $StopScript
        Start-Sleep -Seconds 2
    } else {
        Write-Host "[WARNING] Cannot stop existing processes without privileges" -ForegroundColor Yellow
        Write-Host "You may need to run 'make stop' or manually stop the agent via Task Manager" -ForegroundColor Yellow
    }
}

# Check configuration file location
$ConfigFile = $null
$UserConfig = Join-Path $env:APPDATA "SysManage\sysmanage-agent.yaml"
$LocalConfig = Join-Path $AgentDir "sysmanage-agent.yaml"
$SystemConfig = "C:\ProgramData\SysManage\sysmanage-agent.yaml"

# Check in order of preference for non-privileged user
if (Test-Path $UserConfig) {
    $ConfigFile = $UserConfig
    Write-Host "[OK] Using user config: $ConfigFile" -ForegroundColor Green
} elseif (Test-Path $LocalConfig) {
    $ConfigFile = $LocalConfig
    Write-Host "[OK] Using local config: $ConfigFile" -ForegroundColor Green
} elseif (Test-Path $SystemConfig) {
    # Check if we can read the system config
    try {
        Get-Content $SystemConfig -ErrorAction Stop | Out-Null
        $ConfigFile = $SystemConfig
        Write-Host "[OK] Using system config: $ConfigFile" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] System config exists but cannot be read: $SystemConfig" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARNING] No configuration file found" -ForegroundColor Yellow
    Write-Host "Expected locations (in order of preference):" -ForegroundColor Yellow
    Write-Host "  - $UserConfig (user-specific)"
    Write-Host "  - $LocalConfig (development)"
    Write-Host "  - $SystemConfig (system-wide)"
}

# Get system information
$Hostname = [System.Net.Dns]::GetHostName()
$Platform = "Windows"
$Username = $env:USERNAME

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Starting SysManage Agent" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Host: $Hostname" -ForegroundColor White
Write-Host " User: $Username" -ForegroundColor White
Write-Host " Platform: $Platform" -ForegroundColor White
Write-Host " Python: $PythonExe" -ForegroundColor White
if ($ConfigFile) {
    Write-Host " Config: $ConfigFile" -ForegroundColor White
}
Write-Host " Time: $(Get-Date)" -ForegroundColor White
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# Set environment variables
$env:PYTHONPATH = $AgentDir
$env:PATH = "$VenvPath\Scripts;$env:PATH"

# Set non-privileged mode environment variable
$env:SYSMANAGE_NON_PRIVILEGED = "1"

# Run the agent in background
Write-Host "Starting agent as regular user in background..." -ForegroundColor Green
Write-Host "Note: Some features may be limited without admin privileges." -ForegroundColor Yellow
Write-Host "      For full functionality, use run-privileged.ps1" -ForegroundColor Yellow
Write-Host ""

# Agent log file path (Python logging handles the output)
$AgentLogFile = Join-Path $LogsDir "agent.log"

try {
    # Start the agent in background (Python logging handles file output)
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $PythonExe
    $processInfo.Arguments = "main.py"
    $processInfo.WorkingDirectory = $AgentDir
    $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $processInfo.CreateNoWindow = $true
    $processInfo.UseShellExecute = $false

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo
    $process.Start() | Out-Null

    $ProcessId = $process.Id
    
    # Wait a moment for the process to initialize
    Start-Sleep -Seconds 3
    
    # Check if process is still running
    $runningProcess = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($runningProcess) {
        Write-Host ""
        Write-Host "[OK] SysManage Agent started successfully in background!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Agent Information:" -ForegroundColor Cyan
        Write-Host "   [*] Process ID: $ProcessId" -ForegroundColor White
        Write-Host "   [*] Hostname: $Hostname" -ForegroundColor White
        Write-Host "   [*] Platform: $Platform" -ForegroundColor White
        if ($ConfigFile) {
            Write-Host "   [*] Config: $ConfigFile" -ForegroundColor White
        }
        Write-Host ""
        Write-Host "Logs:" -ForegroundColor Cyan
        Write-Host "   [i] Agent Log: $AgentLogFile" -ForegroundColor Yellow
        Write-Host "   [i] Live Log: Get-Content '$AgentLogFile' -Wait" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To stop the agent: make stop" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host ""
        Write-Host "[ERROR] Agent process terminated unexpectedly" -ForegroundColor Red
        
        # Check the log file for error messages
        if (Test-Path $AgentLogFile) {
            Write-Host "Recent log content:" -ForegroundColor Yellow
            Get-Content $AgentLogFile -Tail 10 | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
        }
        
        # Clean up temporary batch file
        if (Test-Path $BatchFile) {
            Remove-Item $BatchFile -Force -ErrorAction SilentlyContinue
        }
        
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }
    
} catch {
    Write-Host ""
    Write-Host "[ERROR] Failed to start agent: $_" -ForegroundColor Red
    
    # Clean up temporary batch file
    if (Test-Path $BatchFile) {
        Remove-Item $BatchFile -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}