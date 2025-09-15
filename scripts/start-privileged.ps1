# SysManage Agent Privileged Runner for Windows (PowerShell)
# This script runs the SysManage Agent with elevated privileges needed for
# package management operations (updates, installations, etc.)

# Requires -Version 5.0

# Get the absolute path to the agent directory (parent of scripts directory)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentDir = Split-Path -Parent $ScriptDir
Set-Location $AgentDir

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " SysManage Agent Privileged Runner (PowerShell)" -ForegroundColor Cyan
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

# Check if we're already running as administrator
if (-not (Test-Administrator)) {
    Write-Host "[!] This script requires administrator privileges" -ForegroundColor Red
    Write-Host ""
    Write-Host "Attempting to restart with elevated privileges..." -ForegroundColor Yellow
    Write-Host "You may see a User Account Control (UAC) prompt." -ForegroundColor Yellow
    Write-Host ""
    
    # Restart the script with elevated privileges
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs
    
    # Exit the non-elevated instance
    exit
}

Write-Host "[OK] Running with administrator privileges" -ForegroundColor Green

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
    New-Item -ItemType Directory -Path $LogsDir | Out-Null
    Write-Host "[OK] Created logs directory" -ForegroundColor Green
}

# Stop any existing agent processes
Write-Host ""
Write-Host "Checking for existing agent processes..." -ForegroundColor Yellow

$existingProcesses = Get-Process python -ErrorAction SilentlyContinue | 
    Where-Object { $_.Path -like "*$AgentDir*" }

if ($existingProcesses) {
    Write-Host "Found existing Python processes. Attempting to stop agent..." -ForegroundColor Yellow
    
    # Try to use the stop script
    $StopScript = Join-Path $AgentDir "stop.cmd"
    if (Test-Path $StopScript) {
        & $StopScript
        Start-Sleep -Seconds 2
    } else {
        # Fallback: Kill Python processes running main.py
        $mainProcesses = Get-WmiObject Win32_Process | 
            Where-Object { $_.Name -eq "python.exe" -and $_.CommandLine -like "*main.py*" }
        
        foreach ($proc in $mainProcesses) {
            try {
                Stop-Process -Id $proc.ProcessId -Force
                Write-Host "Stopped process with PID: $($proc.ProcessId)" -ForegroundColor Yellow
            } catch {
                Write-Warning "Failed to stop process $($proc.ProcessId): $_"
            }
        }
    }
    Write-Host "[OK] Existing processes stopped" -ForegroundColor Green
}

# Check configuration file location
$ConfigFile = $null
$SystemConfig = "C:\ProgramData\SysManage\sysmanage-agent.yaml"
$LocalConfig = Join-Path $AgentDir "sysmanage-agent.yaml"

if (Test-Path $SystemConfig) {
    $ConfigFile = $SystemConfig
    Write-Host "[OK] Using system config: $ConfigFile" -ForegroundColor Green
} elseif (Test-Path $LocalConfig) {
    $ConfigFile = $LocalConfig
    Write-Host "[OK] Using local config: $ConfigFile" -ForegroundColor Green
} else {
    Write-Host "[WARNING] No configuration file found" -ForegroundColor Yellow
    Write-Host "Expected locations:" -ForegroundColor Yellow
    Write-Host "  - $SystemConfig"
    Write-Host "  - $LocalConfig"
}

# Get system information
$Hostname = [System.Net.Dns]::GetHostName()
$Platform = "Windows"

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Starting SysManage Agent" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Host: $Hostname" -ForegroundColor White
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

# Run the agent with administrator privileges
Write-Host "Starting agent with administrator privileges..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the agent" -ForegroundColor Yellow
Write-Host ""

try {
    # Run the Python script
    $process = Start-Process -FilePath $PythonExe -ArgumentList "main.py" -NoNewWindow -PassThru -Wait
    
    # Check exit code
    if ($process.ExitCode -ne 0) {
        Write-Host ""
        Write-Host "[ERROR] Agent exited with error code: $($process.ExitCode)" -ForegroundColor Red
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit $process.ExitCode
    }
    
    Write-Host ""
    Write-Host "[OK] Agent stopped normally" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "[ERROR] Failed to start agent: $_" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Read-Host "Press Enter to exit"