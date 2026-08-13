# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

#
# Shared bootstrap-state helpers, dot-sourced by the installer scripts.
#
# WHY THIS FILE EXISTS
# --------------------
# "The MSI succeeded but the service is absent" used to be a SILENT state.
# msiexec returned 0, Add/Remove Programs showed the agent installed, and the
# only evidence that nothing would ever enrol was a WARNING buried in
# install.log.  Nothing a fleet tool could query, and nothing that would ever
# reach an operator who did not already suspect a problem.
#
# Every installer script now records where it got to, in two places that
# outlive the install:
#
#   * HKLM:\SOFTWARE\SysManage\Agent  -- machine-readable, survives reboots,
#     and is what a management tool (including SysManage itself, once a host
#     enrols) can read to answer "did this install actually finish?".
#   * The Application event log, source "SysManageAgent" -- what an
#     administrator looks at without being told to.
#
# Deliberately DUPLICATED nowhere else: the three installer scripts and the
# scheduled-task bootstrap all dot-source this file rather than each writing
# their own registry keys, because divergent copies of a status vocabulary are
# how "Complete" comes to mean two different things.

Set-Variable -Name SM_STATE_KEY -Scope Script -Option Constant `
    -Value 'HKLM:\SOFTWARE\SysManage\Agent' -ErrorAction SilentlyContinue

# The state vocabulary.  Kept small on purpose -- an operator should be able to
# tell "fine" from "needs me" without a lookup table.
#
#   Pending   the MSI landed the files but the bootstrap has not run yet.
#             Expected, briefly, on any host that had no Python at install time.
#   Running   the deferred bootstrap is working right now.
#   Complete  Python, the venv and the service are all present.
#   Failed    the bootstrap ran and could not finish.  Detail says why.
#
# ``Pending`` that never becomes ``Complete`` is the exact failure this whole
# mechanism exists to make visible.

function Write-SmEventLog {
    param(
        [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$EntryType = 'Information',
        [int]$EventId = 1000
    )
    try {
        # Registering a source needs admin; every caller here runs elevated
        # (MSI custom action as SYSTEM, or the SYSTEM scheduled task).  Guarded
        # anyway so a logging failure can never be what breaks an install.
        if (-not [System.Diagnostics.EventLog]::SourceExists('SysManageAgent')) {
            New-EventLog -LogName Application -Source 'SysManageAgent' -ErrorAction Stop
        }
        Write-EventLog -LogName Application -Source 'SysManageAgent' `
            -EntryType $EntryType -EventId $EventId -Message $Message -ErrorAction Stop
    } catch {
        # Never throw from telemetry.
        Write-Host "event log unavailable: $_"
    }
}

function Set-SmBootstrapState {
    <#
    .SYNOPSIS
        Record how far the install got, durably and machine-readably.
    .PARAMETER State
        One of Pending / Running / Complete / Failed.
    .PARAMETER Detail
        Human-readable reason.  This is what an operator reads first, so it
        should say what to DO, not merely what happened.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Pending', 'Running', 'Complete', 'Failed')]
        [string]$State,
        [string]$Detail = ''
    )
    try {
        if (-not (Test-Path $SM_STATE_KEY)) {
            New-Item -Path $SM_STATE_KEY -Force | Out-Null
        }
        New-ItemProperty -Path $SM_STATE_KEY -Name 'BootstrapState' `
            -Value $State -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $SM_STATE_KEY -Name 'BootstrapDetail' `
            -Value $Detail -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $SM_STATE_KEY -Name 'BootstrapTimestamp' `
            -Value ([DateTime]::UtcNow.ToString('o')) -PropertyType String -Force | Out-Null
    } catch {
        Write-Host "WARNING: could not record bootstrap state '$State': $_"
    }

    $entryType = switch ($State) {
        'Failed'  { 'Error' }
        'Pending' { 'Warning' }
        default   { 'Information' }
    }
    Write-SmEventLog -Message "SysManage Agent bootstrap: $State. $Detail" `
        -EntryType $entryType -EventId 1000
}

function Get-SmBootstrapState {
    try {
        $v = Get-ItemProperty -Path $SM_STATE_KEY -Name 'BootstrapState' -ErrorAction Stop
        return $v.BootstrapState
    } catch {
        return $null
    }
}

function Find-SmPython {
    <#
    .SYNOPSIS
        Return the path to a usable Python 3.9+, or $null.
    .DESCRIPTION
        One implementation, dot-sourced by every caller.  There used to be two
        near-identical copies of this loop (check-python.ps1 and install.ps1)
        which is precisely the duplicated-table defect the Phase 19 roadmap
        calls out: a fix to one silently missed the other.

        Searches PATH first, then the well-known per-machine install
        directories.  The directory sweep matters because a Python installed
        moments ago by the bootstrap is on the MACHINE path, which an
        already-running process does not see until PATH is re-read.
    #>
    foreach ($cmd in 'python', 'python3', 'py') {
        try {
            $src = (Get-Command $cmd -ErrorAction SilentlyContinue).Source
            if (-not $src) { continue }
            $version = & $cmd --version 2>&1
            if ($version -match 'Python 3\.(\d+)' -and [int]$Matches[1] -ge 9) {
                return $src
            }
        } catch {
            continue
        }
    }

    # PATH missed it -- look where the all-users installer actually puts it.
    foreach ($root in 'C:\Program Files\Python*', 'C:\Program Files (x86)\Python*') {
        foreach ($dir in (Get-Item $root -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
            $exe = Join-Path $dir.FullName 'python.exe'
            if (-not (Test-Path $exe)) { continue }
            try {
                $version = & $exe --version 2>&1
                if ($version -match 'Python 3\.(\d+)' -and [int]$Matches[1] -ge 9) {
                    return $exe
                }
            } catch {
                continue
            }
        }
    }
    return $null
}

function Update-SmProcessPath {
    <#
    .SYNOPSIS
        Re-read PATH from the registry into this process.
    .DESCRIPTION
        A Python installed by a child process lands on the machine PATH, but
        this process inherited its environment at start and will never see it.
        Skipping this is why an install could put Python on disk and still
        report "Python 3.9+ not found on PATH" seconds later.
    #>
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ';'
}
