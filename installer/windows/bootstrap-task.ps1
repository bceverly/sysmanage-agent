# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

#
# Deferred bootstrap -- finishes the install AFTER msiexec has exited.
#
# THE PROBLEM THIS SOLVES
# -----------------------
# Installing Python from inside an MSI custom action can never work.  The
# Python installer is itself a Windows Installer package, the parent MSI still
# holds the Windows Installer mutex while its custom actions run, and a nested
# install is refused with 1618 (ERROR_INSTALL_ALREADY_RUNNING).  It is not a
# race that better sequencing or a retry loop can win -- for the whole time our
# custom action is alive, the mutex is by definition held.
#
# So on any Windows host without Python 3.9+ -- which is every freshly
# provisioned one -- the chain was: Python install refused -> no interpreter ->
# no venv -> create-service.ps1 has nothing to point a service at -> no service.
# And the MSI still exited 0, because service registration was deliberately made
# non-fatal (winget-pkgs PR #375773: Return="check" was rolling the entire
# install back).  Net effect: msiexec says "Installation completed
# successfully", Get-Service SysManageAgent says the service does not exist,
# and nothing ever enrols.
#
# This script is registered as a SYSTEM scheduled task by check-python.ps1 and
# runs once msiexec is gone, where installing Python is an ordinary operation.
#
# WHY A TASK AND NOT JUST THE BUNDLE
# ----------------------------------
# The WiX bundle (sysmanage-agent-bundle.wxs) chains Python BEFORE the MSI and
# is the better experience where it applies.  But the bundle is a separate
# artifact that a user has to choose: winget installs the MSI, `msiexec /i`
# installs the MSI, and the Pro+ provisioning path installs the MSI.  Fixing
# only the bundle would leave every one of those paths broken.  The MSI has to
# be able to finish on its own.
#
# IDEMPOTENT AND SELF-DISARMING
# -----------------------------
# Safe to run repeatedly.  It exits early if the service is already registered,
# and unregisters its own scheduled task once it reaches Complete, so it does
# not linger on a healthy machine.  On failure it deliberately LEAVES the task
# registered (with a boot trigger) so a transient cause -- no network for the
# Python download, a reboot mid-way -- gets another attempt rather than
# stranding the host forever.

[CmdletBinding()]
param(
    # Seconds to wait for the parent msiexec to exit before giving up.  Ten
    # minutes: a slow MSI on a slow disk, with headroom.  Waiting too long is
    # harmless (we are a background task); waiting too little reintroduces the
    # 1618 this exists to avoid.
    [int]$MsiWaitSeconds = 600
)

$ErrorActionPreference = 'Continue'

$InstallDir = 'C:\Program Files\SysManage Agent'
$LogPath = 'C:\ProgramData\SysManage\logs'
$LogFile = Join-Path $LogPath 'bootstrap.log'
$TaskName = 'SysManage-Agent-Bootstrap'
$ServiceName = 'SysManageAgent'

if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    try { $line | Out-File -FilePath $LogFile -Append -Encoding UTF8 } catch { }
    Write-Host $Message
}

# Shared state vocabulary + Python discovery.  Dot-sourced rather than copied.
$StateHelper = Join-Path $InstallDir 'bootstrap-state.ps1'
if (Test-Path $StateHelper) {
    . $StateHelper
} else {
    Write-Log "FATAL: $StateHelper is missing; cannot record state."
    exit 0
}

function Unregister-BootstrapTask {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        Write-Log "Unregistered scheduled task '$TaskName'."
    } catch {
        Write-Log "Could not unregister '$TaskName' (harmless): $_"
    }
}

function Test-MsiInstallerBusy {
    <#
    .SYNOPSIS
        Is a Windows Installer transaction actually in progress right now?
    .DESCRIPTION
        Asks the thing that decides: the global _MSIExecute mutex.  That mutex
        IS what returns 1618 to a nested install, so it is the only signal that
        answers the question we care about.

        The obvious alternative -- "wait until no msiexec.exe is running" -- is
        wrong, and measurably so.  msiexec's SERVICE process deliberately stays
        resident for about ten minutes after an install completes, so that test
        stays true long after the transaction has ended.  Measured on a clean
        Windows Server 2022: the install finished at 14:32:22 and an msiexec
        process was still there 300 seconds later with the mutex long released.
        A bootstrap gated on that spent ten minutes asleep before doing thirty
        seconds of work.
    #>
    $mutex = $null
    try {
        $mutex = [System.Threading.Mutex]::OpenExisting('Global\_MSIExecute')
    } catch [System.Threading.WaitHandleCannotBeOpenedException] {
        # No mutex at all: nothing is installing.
        return $false
    } catch {
        # Cannot tell (permissions, an odd SKU).  Report not-busy rather than
        # block forever -- a 1618 here costs one retry, a hang costs the host.
        Write-Log "Could not query the installer mutex ($_); assuming idle."
        return $false
    }

    try {
        if ($mutex.WaitOne(0)) {
            # We got it, so nobody else holds it.  Release immediately: we only
            # ever wanted to look.
            [void]$mutex.ReleaseMutex()
            return $false
        }
        return $true
    } finally {
        $mutex.Dispose()
    }
}

function Wait-ForMsiExec {
    <#
    .SYNOPSIS
        Block until no Windows Installer transaction holds the mutex.
    .DESCRIPTION
        The whole point of this script.  The task is started by a custom action
        of the very MSI that is still committing, so installing Python straight
        away would hit exactly the 1618 we are escaping.
    #>
    param([int]$TimeoutSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $announced = $false
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-MsiInstallerBusy)) {
            if ($announced) { Write-Log 'Installer mutex released; continuing.' }
            return $true
        }
        if (-not $announced) {
            Write-Log 'A Windows Installer transaction is in progress; waiting for it to finish...'
            $announced = $true
        }
        Start-Sleep -Seconds 3
    }
    Write-Log "WARNING: installer mutex still held after ${TimeoutSeconds}s; proceeding anyway."
    return $false
}

function Invoke-Step {
    <#
    .SYNOPSIS
        Run one of the agent's own installer scripts, in-process.
    .DESCRIPTION
        Reuses check-python.ps1 / install.ps1 / create-service.ps1 rather than
        reimplementing the bootstrap, so the Python version, the dependency set
        and the service definition stay owned by exactly one place.  Each of
        them hardcodes its install directory, so they are re-runnable
        standalone -- which is what makes this possible at all.
    #>
    param([string]$ScriptName)

    $path = Join-Path $InstallDir $ScriptName
    if (-not (Test-Path $path)) {
        Write-Log "WARNING: $ScriptName not found at $path; skipping."
        return $false
    }
    Write-Log "--- running $ScriptName ---"
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $path 2>&1 |
            ForEach-Object { Write-Log "    $_" }
        Write-Log "--- $ScriptName finished (exit $LASTEXITCODE) ---"
        return $true
    } catch {
        Write-Log "ERROR: $ScriptName threw: $_"
        return $false
    }
}

Write-Log '=== SysManage Agent deferred bootstrap ==='

# Already healthy?  Nothing to do -- and say so, so a stale Pending cannot
# outlive the condition that caused it.
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Log "Service '$ServiceName' already exists ($($existing.Status)); nothing to bootstrap."
    Set-SmBootstrapState -State 'Complete' -Detail 'Service was already registered.'
    Unregister-BootstrapTask
    exit 0
}

Set-SmBootstrapState -State 'Running' -Detail 'Deferred bootstrap started.'

Wait-ForMsiExec -TimeoutSeconds $MsiWaitSeconds | Out-Null

# 1. Python (and the VC++ redistributable the cryptography wheel needs).
#    OUTSIDE the MSI transaction, so the nested-install refusal cannot happen.
$python = Find-SmPython
if ($python) {
    Write-Log "Python already present: $python"
} else {
    Write-Log 'No Python 3.9+ found; installing prerequisites.'
    Invoke-Step 'check-python.ps1' | Out-Null
    Update-SmProcessPath
    $python = Find-SmPython
    if (-not $python) {
        $detail = 'Python 3.9+ could not be installed automatically. ' +
                  'Install Python from https://www.python.org/downloads/ then run: ' +
                  "schtasks /run /tn $TaskName"
        Write-Log "ERROR: $detail"
        # Task deliberately LEFT registered: its boot trigger retries after the
        # operator fixes the cause (usually no network to python.org).
        Set-SmBootstrapState -State 'Failed' -Detail $detail
        exit 0
    }
    Write-Log "Python installed: $python"
}

# 2. venv + dependencies.
Invoke-Step 'install.ps1' | Out-Null

$venv = Join-Path $InstallDir '.venv\Scripts\python.exe'
if (-not (Test-Path $venv)) {
    $detail = "Virtual environment was not created at $venv. See $LogFile."
    Write-Log "ERROR: $detail"
    Set-SmBootstrapState -State 'Failed' -Detail $detail
    exit 0
}

# 3. Register (and start) the Windows service.
Invoke-Step 'create-service.ps1' | Out-Null

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Log "Service '$ServiceName' registered; status $($svc.Status)."
    Set-SmBootstrapState -State 'Complete' `
        -Detail "Service registered and $($svc.Status)."
    Unregister-BootstrapTask
} else {
    $detail = "create-service.ps1 ran but '$ServiceName' is still absent. See $LogFile."
    Write-Log "ERROR: $detail"
    Set-SmBootstrapState -State 'Failed' -Detail $detail
}

# Never non-zero: a failed bootstrap is a recorded state, not a crashed task.
# Task Scheduler's own "last result" is a poor place to express this -- the
# registry key and the event log are where it belongs.
exit 0
