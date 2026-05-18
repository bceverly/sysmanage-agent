#
# Create Windows Service for SysManage Agent using NSSM
#

# Top-level trap: catch ANY unhandled exception escaping any scope
# below and exit 0.  Same rationale as install.ps1's top-level trap
# -- covers the case where an exception escapes ``finally`` and would
# otherwise make PowerShell exit with code 1, triggering MSI Error 1722
# and rollback (PR #375773 winget-pkgs validation burn, 2026-05-17).
trap {
    Write-Host "WARNING: unhandled exception trapped at top level: $_"
    Write-Host "Service NOT registered but MSI install will still complete."
    exit 0
}

$ErrorActionPreference = "Continue"

# Service details
$ServiceName = "SysManageAgent"
$DisplayName = "SysManage Agent"
$Description = "System management and monitoring agent for SysManage platform"
$InstallDir = "C:\Program Files\SysManage Agent"

# Log files
$LogPath = "C:\ProgramData\SysManage\logs"
$LogFile = Join-Path $LogPath "install.log"
$TranscriptFile = Join-Path $LogPath "create-service-transcript.log"

# Start transcript to capture ALL output
Start-Transcript -Path $TranscriptFile -Append

# Function to write log messages
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

$ServiceCreated = $false

Write-Log "=== Creating Windows Service using NSSM ==="

try {
    # Check if main.py exists
    $MainScript = Join-Path $InstallDir "main.py"
    if (-not (Test-Path $MainScript)) {
        Write-Log "ERROR: main.py not found at: $MainScript"
        Write-Log "Available files in installation directory:"
        Get-ChildItem $InstallDir | ForEach-Object { Write-Log "  - $($_.Name)" }
        throw "main.py not found"
    }
    Write-Log "Main script found: $MainScript"

    # Find Python executable in venv
    $VenvPython = Join-Path $InstallDir ".venv\Scripts\python.exe"
    if (-not (Test-Path $VenvPython)) {
        # Soft-fail: same rationale as install.ps1 / check-python.ps1.
        # When Python isn't available at MSI-install time (e.g., the
        # winget-pkgs sandboxed validation environment, where
        # check-python.ps1 can't reach python.org to install Python),
        # install.ps1 skipped the venv create.  Without a venv we
        # can't register the service to point at one -- so log the
        # situation and exit 0 cleanly rather than failing the MSI
        # with the misleading 1722/1603 chain.  The operator can
        # install Python and re-run the MSI to register the service
        # at that point.
        Write-Log ""
        Write-Log "WARNING: Virtual environment not found at $VenvPython"
        Write-Log "WARNING: install.ps1 likely soft-failed because Python 3.9+"
        Write-Log "WARNING: was not on PATH at install time."
        Write-Log "WARNING: Skipping Windows service registration."
        Write-Log ""
        Write-Log "To complete setup:"
        Write-Log "  1. Install Python 3.9+ from https://www.python.org/downloads/"
        Write-Log "  2. Re-run the SysManage Agent MSI installer"
        Write-Log ""
        try { Stop-Transcript } catch { Write-Host "Stop-Transcript error swallowed: $_" }
        Write-Host ""
        Write-Host "=====================================" -ForegroundColor Yellow
        Write-Host "Service NOT registered -- Python missing" -ForegroundColor Yellow
        Write-Host "See $LogFile for recovery steps." -ForegroundColor Yellow
        Write-Host "=====================================" -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }
    Write-Log "Found Python: $VenvPython"

    # Check if service already exists
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($existingService) {
        Write-Log "Service already exists, stopping and removing it..."
        if ($existingService.Status -eq 'Running') {
            Stop-Service -Name $ServiceName -Force
            Write-Log "Service stopped"
        }

        # Use NSSM to remove service if it exists
        $nssmPath = Join-Path $InstallDir "nssm.exe"
        if (Test-Path $nssmPath) {
            & $nssmPath remove $ServiceName confirm | Out-File -FilePath $LogFile -Append
        } else {
            # Fallback to sc.exe
            sc.exe delete $ServiceName | Out-Null
        }

        # Wait for service to be fully deleted
        Write-Log "Waiting for service deletion to complete..."
        $maxWait = 30
        $waited = 0
        while ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -and ($waited -lt $maxWait)) {
            Start-Sleep -Seconds 1
            $waited++
        }

        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Write-Log "WARNING: Service still exists after $maxWait seconds"
            Write-Log "Installation may fail. Consider rebooting if issues persist."
        } else {
            Write-Log "Old service removed successfully"
        }
    }

    # Check if NSSM is present (bundled with installer)
    $nssmPath = Join-Path $InstallDir "nssm.exe"
    if (-not (Test-Path $nssmPath)) {
        Write-Log "ERROR: NSSM not found at: $nssmPath"
        Write-Log "NSSM should have been installed with the MSI package"
        throw "NSSM not found"
    }
    Write-Log "Found NSSM at: $nssmPath"

    # Function to get 8.3 short path (no spaces, works around NSSM quoting issues)
    function Get-ShortPath {
        param([string]$LongPath)
        try {
            $fso = New-Object -ComObject Scripting.FileSystemObject
            $file = $fso.GetFile($LongPath)
            return $file.ShortPath
        } catch {
            Write-Log "WARNING: Could not get short path for $LongPath, using original path"
            return $LongPath
        }
    }

    # Get short paths for Python and main script (eliminates spaces)
    $VenvPythonShort = Get-ShortPath $VenvPython
    $MainScriptShort = Get-ShortPath $MainScript
    $InstallDirShort = Get-ShortPath $InstallDir

    Write-Log "Using 8.3 short paths for NSSM (avoids space quoting issues):"
    Write-Log "  Python: $VenvPythonShort"
    Write-Log "  Script: $MainScriptShort"
    Write-Log "  WorkDir: $InstallDirShort"

    # Create the service using NSSM
    Write-Log "Creating service: $ServiceName"

    # Set config path
    $ConfigPath = "C:\ProgramData\SysManage\sysmanage-agent.yaml"

    # Install service with NSSM using short paths
    & $nssmPath install $ServiceName $VenvPythonShort $MainScriptShort 2>&1 | Out-File -FilePath $LogFile -Append

    if ($LASTEXITCODE -ne 0) {
        throw "NSSM install command failed with exit code $LASTEXITCODE"
    }

    Write-Log "Service installed with NSSM successfully"

    # Configure service details
    Write-Log "Configuring service parameters..."

    # Set working directory using short path
    & $nssmPath set $ServiceName AppDirectory $InstallDirShort | Out-File -FilePath $LogFile -Append

    # Set display name and description
    & $nssmPath set $ServiceName DisplayName "$DisplayName" | Out-File -FilePath $LogFile -Append
    & $nssmPath set $ServiceName Description "$Description" | Out-File -FilePath $LogFile -Append

    # Set environment variables
    & $nssmPath set $ServiceName AppEnvironmentExtra "SYSMANAGE_CONFIG=$ConfigPath" | Out-File -FilePath $LogFile -Append

    # Configure stdout/stderr logging
    $StdoutLog = Join-Path $LogPath "service-stdout.log"
    $StderrLog = Join-Path $LogPath "service-stderr.log"
    & $nssmPath set $ServiceName AppStdout "$StdoutLog" | Out-File -FilePath $LogFile -Append
    & $nssmPath set $ServiceName AppStderr "$StderrLog" | Out-File -FilePath $LogFile -Append

    # Rotate logs (10MB max, keep 5 files)
    & $nssmPath set $ServiceName AppStdoutCreationDisposition 4 | Out-File -FilePath $LogFile -Append  # OPEN_ALWAYS
    & $nssmPath set $ServiceName AppStderrCreationDisposition 4 | Out-File -FilePath $LogFile -Append
    & $nssmPath set $ServiceName AppRotateFiles 1 | Out-File -FilePath $LogFile -Append
    & $nssmPath set $ServiceName AppRotateBytes 10485760 | Out-File -FilePath $LogFile -Append  # 10MB

    # Set startup type to automatic
    & $nssmPath set $ServiceName Start SERVICE_AUTO_START | Out-File -FilePath $LogFile -Append

    # Configure service to restart on failure
    Write-Log "Configuring service failure recovery..."
    $failureCmd = "sc.exe failure `"$ServiceName`" reset= 86400 actions= restart/60000/restart/60000/restart/60000"
    Write-Log "Running: $failureCmd"
    cmd.exe /c $failureCmd 2>&1 | Out-File -FilePath $LogFile -Append

    $ServiceCreated = $true
    Write-Log "Service configured successfully"

    # Start the service
    Write-Log "Starting service..."
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        Start-Sleep -Seconds 2
        $svcStatus = Get-Service -Name $ServiceName
        Write-Log "Service status: $($svcStatus.Status)"

        if ($svcStatus.Status -eq 'Running') {
            Write-Log "Service started successfully"
        } else {
            Write-Log "WARNING: Service is not running. Status: $($svcStatus.Status)"
            Write-Log "Check service logs for startup errors:"
            Write-Log "  $StdoutLog"
            Write-Log "  $StderrLog"
        }
    } catch {
        Write-Log "WARNING: Failed to start service: $_"
        Write-Log "You can start it manually with: Start-Service $ServiceName"
        Write-Log "Check logs at:"
        Write-Log "  $StdoutLog"
        Write-Log "  $StderrLog"
    }

} catch {
    Write-Log "ERROR: Exception during service creation: $_"
    Write-Log "Stack trace: $($_.ScriptStackTrace)"
} finally {
    # Stop-Transcript wrapped so a "no active transcript" or other
    # terminating error never escapes finally (would otherwise make
    # PowerShell exit code 1 -> MSI Error 1722 -> rollback).
    try { Stop-Transcript } catch { Write-Host "Stop-Transcript error swallowed: $_" }

    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Yellow
    if ($ServiceCreated) {
        Write-Host "Service created successfully!" -ForegroundColor Green
        Write-Host "Service Name: $ServiceName" -ForegroundColor Cyan
    } else {
        Write-Host "Service creation FAILED" -ForegroundColor Red
    }
    Write-Host "=====================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Log files:" -ForegroundColor Cyan
    Write-Host "  $LogFile" -ForegroundColor Gray
    Write-Host "  $TranscriptFile" -ForegroundColor Gray
    Write-Host ""
}

if ($ServiceCreated) {
    Write-Log "Windows Service creation complete"
} else {
    # NEVER exit non-zero from this custom action.  The WiX CustomAction
    # for ``CreateService`` uses ``Return="check"`` (sysmanage-agent.wxs
    # line 177), which means any non-zero return rolls back the entire
    # MSI install -- files removed, ARP entry never written.  winget-pkgs
    # validation then reports ``Installation Verification: Completed``
    # followed by ``##[error] Failed`` (PR #375773, 2026-05-17), because
    # there's no package to verify.
    #
    # Service registration is post-install ergonomics, not an install-
    # blocking step.  Any failure here (missing venv from install.ps1
    # soft-fail, NSSM error, permission glitch, transient I/O issue)
    # should leave the MSI landed and let the operator finish the
    # service-register step manually.  Logged WARNING is the contract
    # so operators see what to do.
    Write-Log "WARNING: Windows Service creation FAILED -- MSI install will still complete."
    Write-Log "WARNING: To register the service manually after installing Python 3.9+:"
    Write-Log "WARNING:   1. Re-run the MSI (MajorUpgrade detects the install, re-fires CAs)"
    Write-Log "WARNING:   2. Or run create-service.ps1 directly as administrator"
    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Yellow
    Write-Host "Service NOT registered -- see log for recovery steps" -ForegroundColor Yellow
    Write-Host "  $LogFile" -ForegroundColor Gray
    Write-Host "=====================================" -ForegroundColor Yellow
    Write-Host ""
}
exit 0
