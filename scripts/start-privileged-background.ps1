# SysManage Agent Privileged Background Runner for Windows (PowerShell)
# This script runs the SysManage Agent in the background with elevated privileges
# No console window will remain open after starting

# Requires -Version 5.0

param(
    [switch]$Silent = $false  # If true, suppress all notifications
)

# Get the absolute path to the project root directory (parent of scripts)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentDir = Split-Path -Parent $ScriptDir
Set-Location $AgentDir

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to write to log file
function Write-Log {
    param($Message, $Level = "INFO")
    $LogDir = Join-Path $AgentDir "logs"
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $LogFile = Join-Path $LogDir "agent_startup.log"
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp [$Level] $Message" | Out-File -FilePath $LogFile -Append
}

# Check if we're already running as administrator
if (-not (Test-Administrator)) {
    Write-Log "Requesting administrator privileges..." "INFO"
    
    # Restart the script with elevated privileges in hidden window
    $arguments = "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Silent) {
        $arguments += " -Silent"
    }
    
    Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden
    
    # Exit the non-elevated instance
    exit
}

Write-Log "Running with administrator privileges" "INFO"

# Check if virtual environment exists
$VenvPath = Join-Path $AgentDir ".venv"
if (-not (Test-Path $VenvPath)) {
    Write-Log "Virtual environment not found at: $VenvPath" "ERROR"
    if (-not $Silent) {
        # Show error notification
        [System.Windows.Forms.MessageBox]::Show(
            "Virtual environment not found. Please run setup first.",
            "SysManage Agent Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
    exit 1
}

$PythonExe = Join-Path $VenvPath "Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    Write-Log "Python executable not found in virtual environment" "ERROR"
    exit 1
}

# Create logs directory if it doesn't exist
$LogsDir = Join-Path $AgentDir "logs"
if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir | Out-Null
    Write-Log "Created logs directory" "INFO"
}

# Stop any existing agent processes
Write-Log "Checking for existing agent processes..." "INFO"

$existingProcesses = Get-WmiObject Win32_Process | 
    Where-Object { $_.Name -eq "python.exe" -and $_.CommandLine -like "*main.py*" }

foreach ($proc in $existingProcesses) {
    try {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        Write-Log "Stopped existing process with PID: $($proc.ProcessId)" "INFO"
    } catch {
        Write-Log "Failed to stop process $($proc.ProcessId): $_" "WARNING"
    }
}

# Wait a moment for processes to terminate
Start-Sleep -Seconds 2

# Check configuration file location
$ConfigFile = $null
$SystemConfig = "C:\ProgramData\SysManage\sysmanage-agent.yaml"
$LocalConfig = Join-Path $AgentDir "sysmanage-agent.yaml"

if (Test-Path $SystemConfig) {
    $ConfigFile = $SystemConfig
    Write-Log "Using system config: $ConfigFile" "INFO"
} elseif (Test-Path $LocalConfig) {
    $ConfigFile = $LocalConfig
    Write-Log "Using local config: $ConfigFile" "INFO"
} else {
    Write-Log "No configuration file found" "WARNING"
}

# Set environment variables
$env:PYTHONPATH = $AgentDir
$env:PATH = "$VenvPath\Scripts;$env:PATH"

Write-Log "Starting agent in background..." "INFO"
Write-Log "Python: $PythonExe" "INFO"

try {
    # Start the agent process in background (Python logging handles file output)
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $PythonExe
    $processInfo.Arguments = "main.py"
    $processInfo.WorkingDirectory = $AgentDir
    $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $processInfo.CreateNoWindow = $true
    $processInfo.UseShellExecute = $false

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo

    # Start the process
    $process.Start() | Out-Null

    # Store the process ID
    $ProcessId = $process.Id
    Write-Log "Agent started with PID: $ProcessId" "INFO"
    
    # Wait a moment to ensure it's running
    Start-Sleep -Seconds 2
    
    # Check if the process is still running
    $runningProcess = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($runningProcess) {
        Write-Log "Agent is running successfully in background" "SUCCESS"
        
        if (-not $Silent) {
            # Show success notification using Windows toast notification
            Add-Type -AssemblyName System.Windows.Forms
            $notification = New-Object System.Windows.Forms.NotifyIcon
            $notification.Icon = [System.Drawing.SystemIcons]::Information
            $notification.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
            $notification.BalloonTipTitle = "SysManage Agent Started"
            $notification.BalloonTipText = "Agent is running in background with administrator privileges (PID: $ProcessId)"
            $notification.Visible = $true
            $notification.ShowBalloonTip(5000)
            Start-Sleep -Seconds 5
            $notification.Dispose()
        }
    } else {
        Write-Log "Agent process terminated unexpectedly" "ERROR"

        # Check agent log for details
        $AgentLog = Join-Path $LogsDir "agent.log"
        if (Test-Path $AgentLog) {
            $lastError = Get-Content $AgentLog -Tail 10 | Out-String
            Write-Log "Last log output: $lastError" "ERROR"
        }
        
        if (-not $Silent) {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to start SysManage Agent. Check logs for details.",
                "SysManage Agent Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        exit 1
    }
    
} catch {
    Write-Log "Failed to start agent: $_" "ERROR"
    
    if (-not $Silent) {
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to start agent: $_",
            "SysManage Agent Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
    exit 1
}

# Script exits but agent continues running in background
Write-Log "Startup script completed - agent running in background" "INFO"
exit 0