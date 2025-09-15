@echo off
REM SysManage Agent Stop Script for Windows
REM Stops the SysManage agent daemon

setlocal EnableDelayedExpansion

echo Stopping SysManage Agent...

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

set "STOPPED_COUNT=0"

REM First, try to stop using PID file if it exists
if exist logs\agent.pid (
    set /p AGENT_PID=<logs\agent.pid
    if not "!AGENT_PID!"=="" (
        tasklist /FI "PID eq !AGENT_PID!" 2>NUL | find "!AGENT_PID!" >NUL
        if not errorlevel 1 (
            echo Stopping SysManage Agent ^(PID: !AGENT_PID!^)...
            taskkill /PID !AGENT_PID! /F >NUL 2>&1
            if not errorlevel 1 (
                echo Agent stopped successfully via PID file
                set /a STOPPED_COUNT+=1
            ) else (
                echo Warning: Could not stop agent process ^(PID: !AGENT_PID!^)
            )
        ) else (
            echo Agent PID file found but process not running
        )
    )
    del logs\agent.pid >NUL 2>&1
)

REM Method 1: Kill Python processes running main.py
echo Searching for Python processes running main.py...
for /f "skip=1 tokens=2" %%p in ('wmic process where "name='python.exe'" get processid 2^>nul') do (
    set "pid=%%p"
    if not "!pid!"=="" if not "!pid!"=="ProcessId" (
        REM Check if this PID is running main.py
        wmic process where "processid=!pid!" get commandline 2>nul | findstr /i "main.py" >nul 2>&1
        if not errorlevel 1 (
            echo Found main.py process ^(PID: !pid!^), stopping...
            taskkill /PID !pid! /F >NUL 2>&1
            if not errorlevel 1 (
                echo Successfully stopped process ^(PID: !pid!^)
                set /a STOPPED_COUNT+=1
            ) else (
                echo Warning: Failed to stop process !pid!
            )
        )
    )
)

REM Method 2: If no main.py processes found, kill all python.exe processes
if !STOPPED_COUNT! EQU 0 (
    echo No main.py processes found. Checking all python.exe processes...
    for /f "tokens=2" %%p in ('tasklist ^| findstr "python.exe" 2^>nul') do (
        set "pid=%%p"
        if not "!pid!"=="" (
            echo Stopping Python process ^(PID: !pid!^)...
            taskkill /PID !pid! /F >NUL 2>&1
            if not errorlevel 1 (
                echo Successfully stopped process ^(PID: !pid!^)
                set /a STOPPED_COUNT+=1
            ) else (
                echo Warning: Failed to stop process !pid!
            )
        )
    )
)

REM Clean up log directory markers
if exist logs (
    del logs\agent.pid >NUL 2>&1
    del logs\agent.marker >NUL 2>&1
)

REM Wait a moment for processes to fully terminate
timeout /t 2 /nobreak >NUL

echo.
if !STOPPED_COUNT! GTR 0 (
    echo [OK] Successfully stopped !STOPPED_COUNT! process^(es^)
    echo.
    echo Wait a few moments and check your server dashboard to confirm the agent is offline.
) else (
    echo [INFO] No SysManage Agent processes were found or stopped.
    echo.
    echo If the server still shows the agent as online:
    echo 1. The agent may be running with different privileges
    echo 2. Try running this script as Administrator
    echo 3. Check Task Manager for python.exe or pythonw.exe processes
    echo 4. Restart the computer to ensure all processes are stopped
)

echo.
echo To verify the agent is stopped, check:
echo - Server dashboard should show agent as offline
echo - Task Manager should show no python.exe processes from this directory
echo - Log files in logs\ directory should stop being updated
echo - Run: tasklist ^| findstr python

echo.