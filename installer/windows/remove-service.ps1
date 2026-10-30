# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

#
# Remove Windows Service for SysManage Agent
#

# -PurgeRuntime: a full uninstall (not the uninstall half of an upgrade).
# Then the agent's own runtime files go too -- its logs and its local
# database -- so nothing is left in Program Files.  An upgrade must keep them:
# agent.db holds the host's identity token, and losing it would re-register
# the host as a new one.
param([switch]$PurgeRuntime)

$ErrorActionPreference = "Continue"

# Service details
$ServiceName = "SysManageAgent"
$BootstrapTask = "SysManage-Agent-Bootstrap"

# An uninstall must not leave a task behind that would reinstall Python and
# re-register the service on the next boot.  Removing the state key too, so a
# stale "Pending" cannot outlive the product that wrote it.
try {
    Unregister-ScheduledTask -TaskName $BootstrapTask -Confirm:$false -ErrorAction SilentlyContinue
} catch { }
try {
    Remove-Item -Path 'HKLM:\SOFTWARE\SysManage\Agent' -Recurse -Force -ErrorAction SilentlyContinue
} catch { }

$InstallDir = "C:\Program Files\SysManage Agent"

# Log files
$LogPath = "C:\ProgramData\SysManage\logs"
$LogFile = Join-Path $LogPath "uninstall.log"
$TranscriptFile = Join-Path $LogPath "remove-service-transcript.log"

# Ensure log directory exists
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Start transcript to capture ALL output
Start-Transcript -Path $TranscriptFile -Append

# Function to write log messages
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

$ServiceRemoved = $false

Write-Log "=== Removing Windows Service ==="

try {
    # Check if service exists
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if (-not $service) {
        Write-Log "Service '$ServiceName' does not exist. Nothing to remove."
        $ServiceRemoved = $true
    } else {
        Write-Log "Found service: $ServiceName (Status: $($service.Status))"

        # Stop the service if it's running
        if ($service.Status -eq 'Running') {
            Write-Log "Stopping service..."
            try {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
                Write-Log "Service stopped successfully"
            } catch {
                Write-Log "WARNING: Failed to stop service gracefully: $_"
                Write-Log "Attempting to force stop..."
                sc.exe stop $ServiceName 2>&1 | Out-File -FilePath $LogFile -Append
                Start-Sleep -Seconds 2
            }
        }

        # Try to remove using NSSM first (current method)
        $nssmPath = Join-Path $InstallDir "nssm.exe"
        if (Test-Path $nssmPath) {
            Write-Log "Attempting to remove service using NSSM..."
            try {
                & $nssmPath remove $ServiceName confirm 2>&1 | Out-File -FilePath $LogFile -Append

                # Wait for service to be deleted
                Start-Sleep -Seconds 2

                # Verify service is gone
                $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                if (-not $service) {
                    Write-Log "Service removed successfully using NSSM"
                    $ServiceRemoved = $true
                } else {
                    Write-Log "NSSM removal completed but service still exists, trying sc.exe..."
                }
            } catch {
                Write-Log "NSSM removal failed: $_"
            }
        } else {
            Write-Log "NSSM not found at $nssmPath, trying sc.exe..."
        }

        # Fall back to sc.exe if NSSM didn't work
        if (-not $ServiceRemoved) {
            Write-Log "Attempting to remove service using sc.exe..."
            $output = sc.exe delete $ServiceName 2>&1 | Out-String
            $exitCode = $LASTEXITCODE

            Write-Log "sc.exe output: $output"
            Write-Log "Exit code: $exitCode"

            # Wait a moment for service to be deleted
            Start-Sleep -Seconds 2

            # Verify service is gone
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (-not $service) {
                Write-Log "Service removed successfully using sc.exe"
                $ServiceRemoved = $true
            } else {
                Write-Log "WARNING: Service still exists after sc.exe delete"
            }
        }

        # Final verification
        Start-Sleep -Seconds 1
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Log "VERIFIED: Service '$ServiceName' has been removed"
            $ServiceRemoved = $true
        } else {
            Write-Log "ERROR: Service '$ServiceName' still exists!"
            Write-Log "Current status: $($service.Status)"
        }
    }

} catch {
    Write-Log "ERROR: Exception during service removal: $_"
    Write-Log "Stack trace: $($_.ScriptStackTrace)"
} finally {
    Stop-Transcript

    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Yellow
    if ($ServiceRemoved) {
        Write-Host "Service removed successfully!" -ForegroundColor Green
    } else {
        Write-Host "Service removal FAILED" -ForegroundColor Red
        Write-Host "You may need to manually remove it:" -ForegroundColor Yellow
        Write-Host "  sc.exe delete $ServiceName" -ForegroundColor Gray
    }
    Write-Host "=====================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Log files:" -ForegroundColor Cyan
    Write-Host "  $LogFile" -ForegroundColor Gray
    Write-Host "  $TranscriptFile" -ForegroundColor Gray
    Write-Host ""
}

# Files the agent made after the install, which Windows Installer never owned
# and so would never remove.  Measured on a clean uninstall: 59.4 MB of .venv
# and src left in C:\Program Files\SysManage Agent; and on x13s (2026-10-30)
# the folder outlived the uninstall holding logs\ and agent.db.  Removed only
# now, after the service is stopped and gone: deleting a venv whose python.exe
# still hosts the service leaves a half-removed directory that the next
# install then fails to overwrite.  The configuration in C:\ProgramData\SysManage
# is the operator's and is never touched.
$Leftovers = @('.venv', 'src', '__pycache__')
if ($PurgeRuntime) {
    $Leftovers += @('logs', 'agent.db', 'agent.db-wal', 'agent.db-shm', 'agent.db-journal')
}
foreach ($leftover in $Leftovers) {
    $path = Join-Path $InstallDir $leftover
    if (-not (Test-Path -LiteralPath $path)) { continue }
    try {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        Write-Log "Removed leftover $leftover"
    } catch {
        # Never fatal: a locked file must not fail the uninstall.
        Write-Log "Could not remove $leftover (leaving it): $_"
    }
}

if ($ServiceRemoved) {
    Write-Log "Windows Service removal complete"
    exit 0
} else {
    Write-Log "Windows Service removal FAILED"
    exit 0  # Exit with 0 to not block uninstall
}
