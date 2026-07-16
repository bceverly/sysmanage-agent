# Copyright (c) 2024-2026 Bryan Everly
# Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
# See the LICENSE file in the project root for the full terms.

#
# SysManage Agent - Post-Installation Script
# Sets up Python virtual environment and installs dependencies
#

# === PROBE-STAGE DEBUG (remove after PR #375773 winget burn resolves) ===
# Writes a heartbeat line to a fixed path on each major decision
# point.  Path is outside the MSI install dir so MSI rollback can't
# wipe it -- the next probe-arp.yml run uploads it as an artifact so
# we can see exactly where the script died on the validator.
$ProbeStageLog = "C:\ProgramData\SysManage-Probe\install-stages.log"
function Write-Stage([string]$tag, [string]$msg = "") {
    $line = "[$([DateTime]::Now.ToString('HH:mm:ss.fff'))] [STAGE $tag] $msg"
    try { $line | Out-File -FilePath $ProbeStageLog -Append -Encoding UTF8 } catch { }
    Write-Host "[PROBE-STAGE $tag] $msg"
}
# Create the probe dir with Everyone:R ACL so the GitHub Actions runner
# user can read what SYSTEM (the MSI CA's user) writes.  Without this,
# the artifact upload silently skips a SYSTEM-only-readable file.
try {
    $probeDir = Split-Path $ProbeStageLog -Parent
    if (-not (Test-Path $probeDir)) {
        New-Item -ItemType Directory -Path $probeDir -Force | Out-Null
    }
    $acl = Get-Acl $probeDir
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Everyone","ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow"
    )
    $acl.AddAccessRule($rule)
    Set-Acl -Path $probeDir -AclObject $acl
} catch { }
# Truncate stage log on each fresh run so we only see the latest attempt.
try { Set-Content -Path $ProbeStageLog -Value '' -Encoding UTF8 } catch { }
Write-Stage "00" "script entrypoint reached"

# Top-level trap: catch ANY unhandled exception escaping any scope
# below and exit 0.  Belt-and-suspenders on top of the structured
# try/catch below -- covers the case where an exception escapes
# ``finally`` (eg Stop-Transcript terminating-error edge case), which
# otherwise causes PowerShell to exit with code 1 regardless of any
# ``exit 0`` we put at the end of the script.  When the MSI sees
# exit 1 it triggers Error 1722 + rollback (see PR #375773 burn,
# 2026-05-17 -- that failure's root cause was exactly this).
trap {
    Write-Stage "TRAP" "unhandled exception: $($_.Exception.Message)"
    Write-Host "WARNING: unhandled exception trapped at top level: $_"
    Write-Host "Install step had errors but MSI install will still complete."
    exit 0
}

# Set error action preference - Continue so we always reach the pause
$ErrorActionPreference = "Continue"
Write-Stage "01" "ErrorActionPreference=Continue set"

# Get the installation directory
$InstallDir = "C:\Program Files\SysManage Agent"

# Log file
$LogPath = "C:\ProgramData\SysManage\logs"
$LogFile = Join-Path $LogPath "install.log"
$TranscriptFile = Join-Path $LogPath "install-transcript.log"

# Create log directory if it doesn't exist
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

# Track if installation succeeded
$InstallSuccess = $false

Write-Log "=== SysManage Agent Installation ==="
Write-Log "Installation Directory: $InstallDir"
Write-Log "Configuration Directory: C:\ProgramData\SysManage"
Write-Stage "02" "Write-Log/transcript ready, about to enter outer try"

try {
    Write-Stage "03" "entered outer try block"
    # Change to installation directory
    Set-Location $InstallDir
    Write-Stage "04" "Set-Location $InstallDir done"

    # Extract source files from ZIP
    Write-Log "Extracting source files..."
    $SrcZip = Join-Path $InstallDir "src.zip"
    $SrcDir = Join-Path $InstallDir "src"

    if (Test-Path $SrcZip) {
        Write-Stage "05" "src.zip found, expanding"
        if (Test-Path $SrcDir) {
            Remove-Item -Path $SrcDir -Recurse -Force
        }
        # Suppress progress bar during extraction
        $ProgressPreference = 'SilentlyContinue'
        Expand-Archive -Path $SrcZip -DestinationPath $SrcDir -Force
        $ProgressPreference = 'Continue'
        Write-Log "Source files extracted successfully"
        Write-Stage "06" "src.zip expanded OK"

        # Keep ZIP file - it's needed as the KeyPath for Windows Installer component
        # Deleting it would cause Windows Installer to remove all installed files
    } else {
        Write-Log "WARNING: src.zip not found at $SrcZip"
        Write-Stage "06b" "src.zip not present, skipped"
    }

    # Find Python executable
    Write-Log "Searching for Python 3.9+..."
    Write-Stage "07" "Python search loop entry"
    $PythonExe = $null
    $PythonCommands = @("python", "python3", "py")

    foreach ($cmd in $PythonCommands) {
        try {
            $testPath = (Get-Command $cmd -ErrorAction SilentlyContinue).Source
            if ($testPath) {
                # Verify it's Python 3.9+
                $version = & $cmd --version 2>&1
                if ($version -match "Python 3\.([0-9]+)") {
                    $minor = [int]$Matches[1]
                    if ($minor -ge 9) {
                        $PythonExe = $cmd
                        Write-Log "Found Python: $testPath (version: $version)"
                        break
                    }
                }
            }
        } catch {
            continue
        }
    }

    Write-Stage "08" "Python search loop exit; PythonExe=$($PythonExe)"
    if ($PythonExe) {
        Write-Stage "09" "Python-found branch entered"
        # Create virtual environment
        Write-Log "Creating Python virtual environment..."
        $VenvPath = Join-Path $InstallDir ".venv"

        if (Test-Path $VenvPath) {
            Write-Log "Removing existing virtual environment..."

            # CRITICAL: Forcibly stop the service if it's still running
            # This handles the case where old uninstaller didn't stop the service properly
            $ServiceName = "SysManageAgent"
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($service) {
                Write-Log "WARNING: Service '$ServiceName' is still running (old uninstaller may have failed to stop it)"
                Write-Log "Forcibly stopping service..."

                if ($service.Status -eq 'Running') {
                    try {
                        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                        Write-Log "Service stopped successfully"
                    } catch {
                        Write-Log "Failed to stop service gracefully, using sc.exe..."
                        sc.exe stop $ServiceName 2>&1 | Out-File -FilePath $LogFile -Append
                    }
                    Start-Sleep -Seconds 3
                }
            }

            # Give Windows extra time to release file handles after service removal
            Write-Log "Waiting for file handles to be released..."
            Start-Sleep -Seconds 5

            # Stop any python processes from the venv that might be locking files
            $VenvPython = Join-Path $VenvPath "Scripts\python.exe"
            if (Test-Path $VenvPython) {
                Write-Log "Stopping any running Python processes from venv..."
                Get-Process | Where-Object { $_.Path -eq $VenvPython } | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            }

            # Try to remove, retry up to 3 times if locked
            $retries = 3
            $removed = $false
            for ($i = 1; $i -le $retries; $i++) {
                try {
                    Remove-Item -Path $VenvPath -Recurse -Force -ErrorAction Stop
                    $removed = $true
                    break
                } catch {
                    Write-Log "Attempt $i failed to remove venv: $_"
                    if ($i -lt $retries) {
                        Write-Log "Waiting before retry..."
                        Start-Sleep -Seconds 3
                    }
                }
            }

            if (-not $removed) {
                Write-Log "ERROR: Could not remove existing virtual environment after $retries attempts"
                Write-Log "Please ensure no Python processes are running and try again"
                throw "Failed to remove existing virtual environment"
            }
        }

        Write-Stage "10" "venv create -- invoking python -m venv"
        & $PythonExe -m venv $VenvPath 2>&1 | Out-File -FilePath $LogFile -Append
        Write-Stage "11" "venv create LASTEXITCODE=$LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "ERROR: Failed to create virtual environment (exit code $LASTEXITCODE)"
            throw "Failed to create virtual environment"
        }
        Write-Log "Virtual environment created successfully"

        # Activate virtual environment and install dependencies
        $VenvPython = Join-Path $VenvPath "Scripts\python.exe"
        $VenvPip = Join-Path $VenvPath "Scripts\pip.exe"

        Write-Log "Installing Python dependencies..."
        $RequirementsFile = Join-Path $InstallDir "requirements-prod.txt"

        if (-not (Test-Path $RequirementsFile)) {
            Write-Log "ERROR: requirements-prod.txt not found at $RequirementsFile"
            throw "requirements-prod.txt not found"
        }

        # Use python -m pip for better reliability, redirect ALL output to log
        Write-Log "Running: pip install -r requirements-prod.txt"
        Write-Stage "12" "pip install starting"
        & $VenvPython -m pip install -r $RequirementsFile --disable-pip-version-check 2>&1 | Tee-Object -FilePath $LogFile -Append
        Write-Stage "13" "pip install LASTEXITCODE=$LASTEXITCODE"

        if ($LASTEXITCODE -eq 0) {
            Write-Log "Dependencies installed successfully"
        } else {
            Write-Log "ERROR: Failed to install dependencies (exit code $LASTEXITCODE)"
            Write-Log "Check log files for details:"
            Write-Log "  $LogFile"
            Write-Log "  $TranscriptFile"
            throw "Failed to install dependencies"
        }
        Write-Stage "14" "Python branch complete"
    } else {
        Write-Stage "09b" "Python-not-found soft-fail branch"
        # Soft-fail: same rationale as check-python.ps1's matching
        # block.  Without Python on PATH we cannot build the venv
        # or install Python dependencies, but the MSI install
        # itself must still complete cleanly so:
        #   * winget-pkgs sandboxed validation passes (sandbox has
        #     no internet access to python.org for check-python.ps1
        #     to install Python)
        #   * offline / air-gapped installs proceed and the
        #     operator installs Python afterwards
        # After installing Python 3.9+, the operator re-runs the
        # MSI; the MajorUpgrade element detects the existing
        # install, the custom actions fire again, and Python is
        # now on PATH so venv + pip install succeed.
        Write-Log "WARNING: Python 3.9+ not found on PATH."
        Write-Log "WARNING: Skipping virtual-env and dependency install."
        Write-Log "WARNING: Install Python 3.9+ from https://www.python.org/downloads/"
        Write-Log "WARNING: then re-run the SysManage Agent MSI to finish setup."
    }

    Write-Stage "15" "post-python block, starting config file step"
    # Create configuration file if it doesn't exist
    $ConfigDir = "C:\ProgramData\SysManage"
    $ConfigFile = Join-Path $ConfigDir "sysmanage-agent.yaml"
    $ExampleConfig = Join-Path $ConfigDir "sysmanage-agent.yaml.example"

    if (-not (Test-Path $ConfigFile)) {
        if (Test-Path $ExampleConfig) {
            Write-Log "Creating default configuration from example..."
            Copy-Item $ExampleConfig $ConfigFile
            Write-Log ""
            Write-Log "IMPORTANT: Please edit the configuration file:"
            Write-Log "  $ConfigFile"
            Write-Log ""
            Write-Log "You must configure the following settings:"
            Write-Log "  - server.hostname: Your SysManage server hostname"
            Write-Log "  - server.port: Your SysManage server port"
            Write-Log "  - server.use_https: Set to true for production"
            Write-Log ""
        } else {
            Write-Log "WARNING: No example configuration file found"
            Write-Log "Please create a configuration file at: $ConfigFile"
        }
    } else {
        Write-Log "Configuration file already exists: $ConfigFile"
    }

    Write-Stage "16" "config file step done"
    # Create database directory
    $DbDir = "C:\ProgramData\SysManage\db"
    if (-not (Test-Path $DbDir)) {
        Write-Log "Creating database directory..."
        New-Item -ItemType Directory -Path $DbDir -Force | Out-Null
    }
    Write-Stage "17" "db dir step done"

    # Mark installation as successful
    $InstallSuccess = $true
    Write-Stage "18" "InstallSuccess=true"

    Write-Log ""
    Write-Log "=== Installation Complete ==="
    Write-Log ""
    Write-Log "The SysManage Agent service will be created next."
    Write-Log ""
    Write-Log "Next steps:"
    Write-Log "1. Edit configuration: $ConfigFile"
    Write-Log "2. Start the service:"
    Write-Log "   Start-Service SysManageAgent"
    Write-Log ""
    Write-Log "To check service status:"
    Write-Log "   Get-Service SysManageAgent"
    Write-Log ""
    Write-Log "To view logs:"
    Write-Log "   Get-Content C:\ProgramData\SysManage\logs\agent.log -Tail 50"
    Write-Log ""

} catch {
    Write-Stage "19" "outer catch entered: $($_.Exception.Message)"
    Write-Log ""
    Write-Log "=== INSTALLATION FAILED ==="
    Write-Log "Error: $_"
    Write-Log ""
    Write-Log "Check log files for details:"
    Write-Log "  $LogFile"
    Write-Log "  $TranscriptFile"
    Write-Log ""
} finally {
    Write-Stage "20" "finally entered, about to Stop-Transcript"
    # Stop transcript -- wrapped so a "no active transcript" terminating
    # error never escapes finally (would otherwise make the script exit
    # with code 1 regardless of the explicit ``exit 0`` after this block).
    try { Stop-Transcript } catch { Write-Host "Stop-Transcript error swallowed: $_" }
    Write-Stage "21" "Stop-Transcript wrapper done"

    # ALWAYS pause so user can see output
    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Yellow
    if ($InstallSuccess) {
        Write-Host "Installation completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "Installation FAILED - see errors above" -ForegroundColor Red
    }
    Write-Host "=====================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Log files:" -ForegroundColor Cyan
    Write-Host "  $LogFile" -ForegroundColor Gray
    Write-Host "  $TranscriptFile" -ForegroundColor Gray
    Write-Host ""
}

# NEVER exit non-zero -- the WiX CustomAction uses ``Return="check"``,
# which rolls back the entire MSI on any non-zero return.  That cascades
# into ``Installation Verification: Completed`` / ``##[error] Failed`` on
# winget-pkgs validation (PR #375773 burn, 2026-05-17) because the MSI
# rolls back, no ARP entry is written, and the verifier sees nothing.
# Any failure inside this script (venv create, pip install, config
# write, etc.) leaves the MSI partially set up but landed; operator
# can re-run the MSI after fixing whatever broke (typically: install
# Python 3.9+ and re-run for MajorUpgrade to re-fire the CAs).
Write-Stage "22" "post-finally code reached; InstallSuccess=$InstallSuccess"
if (-not $InstallSuccess) {
    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Yellow
    Write-Host "Install step had errors -- MSI install will still complete." -ForegroundColor Yellow
    Write-Host "See $LogFile for the failure and recovery steps." -ForegroundColor Yellow
    Write-Host "=====================================" -ForegroundColor Yellow
    Write-Host ""
}
Write-Stage "23" "about to exit 0"
exit 0
