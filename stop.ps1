# SysManage Agent Stop Script
# Stops all running SysManage agent processes

Write-Host "Stopping SysManage Agent..." -ForegroundColor Yellow

# Stop Python processes running the agent
$agentProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*main.py*" -or 
    $_.CommandLine -like "*sysmanage-agent*" -or
    $_.Path -like "*sysmanage-agent*"
}

if ($agentProcesses) {
    Write-Host "Found $($agentProcesses.Count) agent process(es), stopping them..." -ForegroundColor Yellow
    foreach ($process in $agentProcesses) {
        try {
            Write-Host "  Stopping PID $($process.Id): $($process.ProcessName)" -ForegroundColor Gray
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
        }
        catch {
            Write-Host "  Failed to stop PID $($process.Id): $($_.Exception.Message)" -ForegroundColor Red
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