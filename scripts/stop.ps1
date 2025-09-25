# SysManage Agent Stop Script
# Stops all running SysManage agent processes

Write-Host "Stopping SysManage Agent..." -ForegroundColor Yellow

# Stop Python processes running the agent
$agentProcesses = @()

# Method 1: Find processes by command line using WMI (works for non-privileged processes)
$wmiProcesses = Get-WmiObject Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue
foreach ($wmiProcess in $wmiProcesses) {
    if ($wmiProcess.CommandLine -like "*main.py*") {
        # Convert WMI process to Get-Process object for consistent handling
        try {
            $process = Get-Process -Id $wmiProcess.ProcessId -ErrorAction Stop
            $agentProcesses += $process
            Write-Host "  Found agent process: PID $($wmiProcess.ProcessId) - $($wmiProcess.CommandLine)" -ForegroundColor Cyan
        }
        catch {
            Write-Host "  Found agent but couldn't access process: PID $($wmiProcess.ProcessId)" -ForegroundColor Yellow
        }
    }
}

# Method 2: Check for inaccessible Python processes (likely privileged agents)
$pythonProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue
$currentDir = (Get-Location).Path
$suspiciousProcesses = @()

# Only consider processes suspicious if we're in a sysmanage-agent directory
$isAgentDirectory = $currentDir -like "*sysmanage-agent*"

foreach ($process in $pythonProcesses) {
    $isAccessible = $false
    $isAgent = $false

    # Try to read process path
    try {
        $processPath = $process.Path

        # Check if path is accessible and not empty
        if ($processPath -and $processPath.Trim() -ne "") {
            $isAccessible = $true

            # Check if it's in the sysmanage-agent directory
            if ($processPath -like "*sysmanage-agent*") {
                $agentProcesses += $process
                $isAgent = $true
                Write-Host "  Found agent by path: PID $($process.Id)" -ForegroundColor Cyan
            }
        } else {
            # Empty path - privileged process
            $isAccessible = $false
        }
    }
    catch {
        # Can't read path - this is suspicious for a privileged process
        $isAccessible = $false
    }

    # Only consider inaccessible processes suspicious if:
    # 1. We can't access their info AND
    # 2. We're in a sysmanage-agent directory AND
    # 3. They're not already identified as agents
    if (-not $isAccessible -and -not $isAgent -and $isAgentDirectory) {
        $suspiciousProcesses += $process
    }
}

# Method 3: Handle potentially privileged agent processes
if ($suspiciousProcesses.Count -gt 0) {
    Write-Host ""
    Write-Host "Found $($suspiciousProcesses.Count) inaccessible Python process(es) (potentially privileged agents):" -ForegroundColor Yellow

    foreach ($process in $suspiciousProcesses) {
        Write-Host "  PID $($process.Id) - Started: $($process.StartTime)" -ForegroundColor Yellow

        # Ask user for confirmation since we can't verify these are agents
        $confirmation = Read-Host "  Kill potentially privileged agent PID $($process.Id)? (y/N)"
        if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
            $agentProcesses += $process
            Write-Host "    Added to kill list" -ForegroundColor Cyan
        } else {
            Write-Host "    Skipped" -ForegroundColor Gray
        }
    }
}

if ($agentProcesses) {
    Write-Host "Found $($agentProcesses.Count) agent process(es), stopping them..." -ForegroundColor Yellow

    $failedProcesses = @()

    foreach ($process in $agentProcesses) {
        try {
            Write-Host "  Stopping PID $($process.Id): $($process.ProcessName)" -ForegroundColor Gray
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
        }
        catch {
            Write-Host "  Failed to stop PID $($process.Id): $($_.Exception.Message)" -ForegroundColor Red
            $failedProcesses += $process
        }
    }

    # If we failed to stop some processes, they might be privileged
    if ($failedProcesses.Count -gt 0) {
        Write-Host ""
        Write-Host "Some processes could not be stopped (likely privileged)." -ForegroundColor Yellow
        Write-Host "Attempting to stop with elevated privileges..." -ForegroundColor Yellow

        # Try using taskkill which can sometimes work better for privileged processes
        $stillFailed = @()
        foreach ($process in $failedProcesses) {
            try {
                $result = Start-Process "taskkill" -ArgumentList "/PID $($process.Id) /F" -Wait -PassThru -WindowStyle Hidden
                if ($result.ExitCode -eq 0) {
                    Write-Host "  Successfully stopped privileged process PID $($process.Id)" -ForegroundColor Green
                } else {
                    Write-Host "  Still failed to stop privileged process PID $($process.Id)" -ForegroundColor Red
                    $stillFailed += $process
                }
            }
            catch {
                Write-Host "  Could not kill privileged process PID $($process.Id): $($_.Exception.Message)" -ForegroundColor Red
                $stillFailed += $process
            }
        }

        # If we still have failed processes, offer to restart with admin privileges
        if ($stillFailed.Count -gt 0) {
            Write-Host ""
            Write-Host "Failed to stop $($stillFailed.Count) privileged process(es)." -ForegroundColor Red
            Write-Host "These processes require Administrator privileges to stop." -ForegroundColor Yellow
            Write-Host ""
            $elevated = Read-Host "Restart this script as Administrator to kill privileged processes? (y/N)"

            if ($elevated -eq 'y' -or $elevated -eq 'Y') {
                Write-Host "Restarting as Administrator..." -ForegroundColor Yellow

                # Create a simple script to kill the specific PIDs
                $pidsToKill = ($stillFailed | ForEach-Object { $_.Id }) -join ","
                $elevatedScript = @"
Write-Host 'Running with Administrator privileges...' -ForegroundColor Green
Write-Host 'Killing PIDs: $pidsToKill' -ForegroundColor Yellow
'$pidsToKill' -split ',' | ForEach-Object {
    try {
        Stop-Process -Id `$_ -Force
        Write-Host "  Killed PID `$_" -ForegroundColor Green
    }
    catch {
        Write-Host "  Failed to kill PID `$_" -ForegroundColor Red
    }
}
Write-Host 'Done. Press Enter to close...' -ForegroundColor Cyan
Read-Host
exit
"@

                # Run the elevated script
                Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -Command `"$elevatedScript`"" -Verb RunAs
            }
        }
    }

    Start-Sleep -Seconds 2
}
else {
    Write-Host "No agent processes found." -ForegroundColor Green
}

# Verify no processes are still running
$remainingProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*main.py*" -or 
    $_.CommandLine -like "*sysmanage-agent*" -or
    $_.Path -like "*sysmanage-agent*"
}

if ($remainingProcesses) {
    Write-Host "Warning: $($remainingProcesses.Count) agent process(es) still running" -ForegroundColor Red
    foreach ($process in $remainingProcesses) {
        Write-Host "  PID $($process.Id): $($process.ProcessName)" -ForegroundColor Red
    }
}
else {
    Write-Host ""
    Write-Host "[OK] SysManage Agent stopped successfully!" -ForegroundColor Green
}