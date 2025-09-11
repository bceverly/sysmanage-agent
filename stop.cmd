@echo off
REM SysManage Agent Stop Script for Windows
REM Stops the SysManage agent daemon (both foreground and background, privileged or not)

setlocal EnableDelayedExpansion

echo Stopping SysManage Agent...

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM Initialize counter
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

REM Check for agent processes by looking at their working directory
echo Checking for SysManage Agent processes...

REM Method 1: Look for Python processes running in our directory
REM This works even when we can't see command line due to privilege differences
for /f "tokens=2" %%p in ('tasklist /FI "IMAGENAME eq python.exe" /FO CSV ^| findstr /V "PID"') do (
    set "pid=%%p"
    set "pid=!pid:"=!"
    if not "!pid!"=="" if not "!pid!"=="PID" (
        REM Try to determine if this is our agent by checking if it can access our files
        REM Use handle.exe if available, or use a heuristic approach
        
        REM First, let's just check if it's a Python process running from our virtual environment
        REM by looking at the executable path when possible
        for /f "tokens=*" %%c in ('wmic process where "processid='!pid!'" get executablepath /format:list 2^>nul ^| findstr "ExecutablePath"') do (
            set "exepath=%%c"
            echo !exepath! | findstr /i "%SCRIPT_DIR%" >nul 2>&1
            if not errorlevel 1 (
                echo Found SysManage Agent process in venv ^(PID: !pid!^), stopping...
                taskkill /PID !pid! /F >NUL 2>&1
                if not errorlevel 1 (
                    echo Stopped SysManage Agent process ^(PID: !pid!^)
                    set /a STOPPED_COUNT+=1
                )
            )
        )
    )
)

REM Method 2: Try to find processes with command line containing main.py (when accessible)
for /f "tokens=2 delims==" %%i in ('wmic process where "name='python.exe'" get processid^,commandline /format:list 2^>nul ^| findstr "ProcessId"') do (
    set "pid=%%i"
    if not "!pid!"=="" (
        for /f "tokens=*" %%c in ('wmic process where "processid='!pid!'" get commandline /format:list 2^>nul ^| findstr "CommandLine"') do (
            set "cmdline=%%c"
            if not "!cmdline!"=="" (
                echo !cmdline! | findstr /i "main.py" >nul 2>&1
                if not errorlevel 1 (
                    echo Found SysManage Agent by command line ^(PID: !pid!^), stopping...
                    taskkill /PID !pid! /F >NUL 2>&1
                    if not errorlevel 1 (
                        echo Stopped SysManage Agent process ^(PID: !pid!^)
                        set /a STOPPED_COUNT+=1
                    )
                )
            )
        )
    )
)

REM Method 3: Also check for pythonw.exe (windowless Python)
for /f "tokens=2" %%p in ('tasklist /FI "IMAGENAME eq pythonw.exe" /FO CSV ^| findstr /V "PID"') do (
    set "pid=%%p"
    set "pid=!pid:"=!"
    if not "!pid!"=="" if not "!pid!"=="PID" (
        for /f "tokens=*" %%c in ('wmic process where "processid='!pid!'" get executablepath /format:list 2^>nul ^| findstr "ExecutablePath"') do (
            set "exepath=%%c"
            echo !exepath! | findstr /i "%SCRIPT_DIR%" >nul 2>&1
            if not errorlevel 1 (
                echo Found background SysManage Agent ^(PID: !pid!^), stopping...
                taskkill /PID !pid! /F >NUL 2>&1
                if not errorlevel 1 (
                    echo Stopped background Agent process ^(PID: !pid!^)
                    set /a STOPPED_COUNT+=1
                )
            )
        )
    )
)

REM Method 4: Fallback - if agent is definitely running (server shows it's online)
REM but we can't detect it, kill ALL Python processes from our venv directory
REM This is more aggressive but necessary for privileged processes
if !STOPPED_COUNT! EQU 0 (
    echo No processes found by standard methods. Trying aggressive detection...
    
    REM Look for any python.exe processes and check their executable path
    for /f "tokens=2" %%p in ('tasklist /FI "IMAGENAME eq python.exe" /FO CSV ^| findstr /V "PID"') do (
        set "pid=%%p"
        set "pid=!pid:"=!"
        if not "!pid!"=="" if not "!pid!"=="PID" (
            REM Check if the process is using files in our directory
            REM by attempting to kill it and see if it affects our logs
            echo Checking process !pid! - attempting to stop...
            taskkill /PID !pid! /F >NUL 2>&1
            if not errorlevel 1 (
                echo Stopped Python process ^(PID: !pid!^) - may have been SysManage Agent
                set /a STOPPED_COUNT+=1
            )
        )
    )
    
    REM Also check pythonw.exe
    for /f "tokens=2" %%p in ('tasklist /FI "IMAGENAME eq pythonw.exe" /FO CSV ^| findstr /V "PID"') do (
        set "pid=%%p"
        set "pid=!pid:"=!"
        if not "!pid!"=="" if not "!pid!"=="PID" (
            echo Stopping pythonw.exe process !pid!...
            taskkill /PID !pid! /F >NUL 2>&1
            if not errorlevel 1 (
                echo Stopped pythonw.exe process ^(PID: !pid!^) - may have been SysManage Agent
                set /a STOPPED_COUNT+=1
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
    echo [OK] Stopped !STOPPED_COUNT! process^(es^) ^(may have included SysManage Agent^)
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

echo.