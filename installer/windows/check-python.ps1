# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

#
# Check for all prerequisites and install if missing
# - Administrative privileges
# - .NET Framework 4.5+
# - Visual C++ Redistributable (for cryptography package)
# - Python 3.9+
#
# TWO CALLING CONTEXTS
# --------------------
# 1. From the MSI custom action, with -DeferToTask.  Prerequisites may only be
#    DETECTED here, never installed: the parent MSI holds the Windows Installer
#    mutex for as long as its custom actions run, and both the VC++
#    redistributable and the Python installer are themselves Windows Installer
#    packages, so a nested install is refused with 1618
#    (ERROR_INSTALL_ALREADY_RUNNING).  That is structural, not a race -- no
#    amount of sequencing or retrying inside the transaction can win.  When
#    something is missing this hands the work to a scheduled task that runs
#    once msiexec has exited.
#
# 2. Standalone, with no arguments -- from bootstrap-task.ps1, or from the Pro+
#    provisioning first-boot script, or by an operator recovering an install.
#    The MSI transaction is over, so everything installs normally.  This is the
#    historical behaviour and is deliberately the DEFAULT, so existing callers
#    (notably virtualization_engine's windows_unattend.pxi, which invokes this
#    script with no arguments) keep working untouched.
#

[CmdletBinding()]
param(
    # Set by the MSI custom action.  Detect only; delegate any actual install
    # to the deferred scheduled task.
    [switch]$DeferToTask
)

$ErrorActionPreference = "Stop"

# Log file
$LogPath = "C:\ProgramData\SysManage\logs"
$LogFile = Join-Path $LogPath "install.log"
$InstallDir = "C:\Program Files\SysManage Agent"
$TaskName = "SysManage-Agent-Bootstrap"

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

# Shared state vocabulary and Python discovery.  Dot-sourced so there is one
# definition of "is Python present" rather than a copy per script.
$StateHelper = Join-Path $InstallDir 'bootstrap-state.ps1'
if (Test-Path $StateHelper) {
    . $StateHelper
} else {
    # Running from a source checkout rather than an install; fall back to the
    # sibling file so the script is still usable standalone.
    $sibling = Join-Path $PSScriptRoot 'bootstrap-state.ps1'
    if (Test-Path $sibling) { . $sibling }
}

Write-Log "=== Prerequisites Check ==="
if ($DeferToTask) {
    Write-Log "Mode: detect-only (running inside the MSI transaction)"
} else {
    Write-Log "Mode: install (running outside any MSI transaction)"
}

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

function Test-VcRedist {
    # VC++ 2015-2022 runtime, needed by the cryptography wheel.
    foreach ($key in @(
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
    )) {
        try {
            $vcRedist = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($vcRedist -and $vcRedist.Installed -eq 1) {
                Write-Log "Visual C++ Redistributable found: version $($vcRedist.Version)"
                return $true
            }
        } catch {
            continue
        }
    }
    return $false
}

function Install-VcRedist {
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

        Write-Log "Installing Visual C++ Redistributable ($ArchDisplay)..."
        $process = Start-Process -FilePath $vcRedistInstaller -ArgumentList "/install", "/quiet", "/norestart" -Wait -PassThru -WindowStyle Hidden

        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-Log "Visual C++ Redistributable installed successfully"
            Remove-Item $vcRedistInstaller -Force -ErrorAction SilentlyContinue
        } elseif ($process.ExitCode -eq 1618) {
            # The signature of running inside a live MSI transaction.  Name it
            # explicitly: this exact code, silently swallowed, is what made the
            # original failure so hard to attribute.
            Write-Log "ERROR: Visual C++ Redistributable refused with 1618 (another install is in progress)."
            Write-Log "ERROR: This means a nested install was attempted; it must be deferred instead."
        } else {
            Write-Log "WARNING: Visual C++ Redistributable installation returned exit code $($process.ExitCode)"
            Write-Log "Installation may still succeed, continuing..."
        }
    } catch {
        Write-Log "WARNING: Failed to install Visual C++ Redistributable: $_"
        Write-Log "The cryptography package may fail to install without it"
    }
}

function Install-Python {
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
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($PythonUrl, $PythonInstaller)
        Write-Log "Download complete: $PythonInstaller"

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
            Remove-Item $PythonInstaller -Force -ErrorAction SilentlyContinue
            if (Get-Command Update-SmProcessPath -ErrorAction SilentlyContinue) {
                Update-SmProcessPath
            }
            return $true
        }

        if ($process.ExitCode -eq 1618) {
            Write-Log "ERROR: Python installer refused with 1618 (another install is in progress)."
            Write-Log "ERROR: A nested install was attempted; it must be deferred instead."
        } else {
            Write-Log "WARNING: Python installer returned exit code $($process.ExitCode)"
        }
        Write-Log "WARNING: SysManage Agent service will not start until Python 3.9+ is installed."
        Write-Log "WARNING: Install Python from https://www.python.org/downloads/ then restart the service:"
        Write-Log "WARNING:   sc.exe start SysManageAgent"
        return $false
    } catch {
        Write-Log "WARNING: Failed to download or install Python: $_"
        Write-Log "WARNING: SysManage Agent service will not start until Python 3.9+ is installed."
        Write-Log "WARNING: Install Python from https://www.python.org/downloads/ then restart the service:"
        Write-Log "WARNING:   sc.exe start SysManageAgent"
        return $false
    }
}

function Register-BootstrapTask {
    <#
    .SYNOPSIS
        Hand the remaining prerequisite work to a task that outlives msiexec.
    .DESCRIPTION
        Two triggers on purpose:
          * the immediate Start, so a normal install finishes within a minute
            of msiexec returning rather than at the next reboot;
          * AtStartup, so a machine that reboots (or whose Python download
            failed for want of a network) retries by itself instead of sitting
            broken until somebody notices.
        bootstrap-task.ps1 removes the task once it reaches Complete.
    #>
    $taskScript = Join-Path $InstallDir 'bootstrap-task.ps1'
    if (-not (Test-Path $taskScript)) {
        Write-Log "ERROR: $taskScript is missing; cannot defer the bootstrap."
        return $false
    }

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$taskScript`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force `
            -Description 'Finishes the SysManage Agent install (Python, venv, service) after msiexec exits.' | Out-Null
        Write-Log "Registered scheduled task '$TaskName'."

        # Kick it off now; the task itself waits for msiexec to exit.
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Log "Started '$TaskName'; it will wait for msiexec to exit before installing Python."
        return $true
    } catch {
        Write-Log "ERROR: Could not register or start '$TaskName': $_"
        return $false
    }
}

# 3 + 4. Visual C++ Redistributable and Python.
$vcPresent = Test-VcRedist
if (-not $vcPresent) { Write-Log "Visual C++ Redistributable: NOT present" }

$pythonPath = if (Get-Command Find-SmPython -ErrorAction SilentlyContinue) {
    Find-SmPython
} else {
    $null
}
if ($pythonPath) {
    Write-Log "Found Python: $pythonPath"
} else {
    Write-Log "Python 3.9+: NOT present"
}

if ($DeferToTask) {
    # Inside the MSI transaction.  Nothing may be installed here.
    if ($pythonPath -and $vcPresent) {
        Write-Log "All prerequisites already present; the MSI can finish the install itself."
        if (Get-Command Set-SmBootstrapState -ErrorAction SilentlyContinue) {
            Set-SmBootstrapState -State 'Running' `
                -Detail 'Prerequisites already present; installing in-transaction.'
        }
        exit 0
    }

    $missing = @()
    if (-not $pythonPath) { $missing += 'Python 3.9+' }
    if (-not $vcPresent) { $missing += 'Visual C++ 2015-2022 Redistributable' }
    $missingText = $missing -join ' and '

    Write-Log "Missing prerequisite(s): $missingText"
    Write-Log "These CANNOT be installed from inside the MSI (nested installs are refused with 1618)."

    if (Register-BootstrapTask) {
        if (Get-Command Set-SmBootstrapState -ErrorAction SilentlyContinue) {
            Set-SmBootstrapState -State 'Pending' `
                -Detail "Waiting on $missingText. Task '$TaskName' will finish the install once msiexec exits."
        }
    } else {
        if (Get-Command Set-SmBootstrapState -ErrorAction SilentlyContinue) {
            Set-SmBootstrapState -State 'Failed' `
                -Detail ("Missing $missingText and the deferred bootstrap task could not be registered. " +
                         "Install Python 3.9+ then re-run the MSI.")
        }
    }
    # Always 0: the CA is Return="check", and a non-zero here rolls the whole
    # install back (PR #375773 burn).  The state key carries the bad news.
    exit 0
}

# Standalone mode -- the MSI transaction is over, so install for real.
if (-not $vcPresent) {
    Write-Log "Visual C++ Redistributable not found - installing..."
    Install-VcRedist
} else {
    Write-Log "Visual C++ Redistributable: OK"
}

if ($pythonPath) {
    Write-Log "Python 3.9+ already present: $pythonPath"
    exit 0
}

Write-Log "Python 3.9+ not found - installing Python 3.12..."
Install-Python | Out-Null

# Soft-fail by design even when the install did not work: the caller
# (bootstrap-task.ps1, or the provisioning first-boot script) inspects for
# Python itself and records the durable state.  Exiting non-zero here would
# only re-create the rollback problem for the MSI path.
exit 0
