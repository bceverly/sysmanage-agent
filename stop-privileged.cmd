@echo off
REM SysManage Agent Privileged Stop Script for Windows
REM This script stops SysManage agents running with administrator privileges
REM It requests elevation to properly access privileged processes

setlocal EnableDelayedExpansion

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM Check if we're already running as administrator
net session >nul 2>&1
if %errorlevel% == 0 (
    echo [OK] Running with administrator privileges
    goto :stop_agents
) else (
    echo [!] This script requires administrator privileges to stop privileged agents
    echo.
    echo Requesting elevation...
    
    REM Create a temporary VBScript to elevate privileges
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\stop_elevate.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~f0"" %*", "", "runas", 1 >> "%temp%\stop_elevate.vbs"
    
    REM Run the VBScript to elevate
    cscript //nologo "%temp%\stop_elevate.vbs"
    
    REM Clean up
    del "%temp%\stop_elevate.vbs"
    
    REM Exit the non-elevated instance
    exit /b
)

:stop_agents
echo ===============================================
echo  SysManage Agent Privileged Stop Script
echo ===============================================
echo.
echo Stopping all SysManage Agent processes with administrator privileges...

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
                echo [OK] Agent stopped via PID file
                set /a STOPPED_COUNT+=1
            )
        )
    )
    del logs\agent.pid >NUL 2>&1
)

REM Now use WMIC to find all Python processes with command line access
echo Scanning for Python processes running main.py...

REM Method 1: Direct command line matching (works with admin privileges)
for /f "skip=1 tokens=*" %%i in ('wmic process where "name='python.exe'" get processid^,commandline /format:csv 2^>nul') do (
    for /f "tokens=1,2,3 delims=," %%a in ("%%i") do (
        set "node=%%a"
        set "cmdline=%%b"
        set "pid=%%c"
        
        if not "!cmdline!"=="" (
            echo !cmdline! | findstr /i "main.py" >nul 2>&1
            if not errorlevel 1 (
                echo Found Agent process ^(PID: !pid!^): !cmdline!
                taskkill /PID !pid! /F >NUL 2>&1
                if not errorlevel 1 (
                    echo [OK] Stopped Agent process ^(PID: !pid!^)
                    set /a STOPPED_COUNT+=1
                )
            )
        )
    )
)

REM Method 2: Check pythonw.exe (background processes)
for /f "skip=1 tokens=*" %%i in ('wmic process where "name='pythonw.exe'" get processid^,commandline /format:csv 2^>nul') do (
    for /f "tokens=1,2,3 delims=," %%a in ("%%i") do (
        set "node=%%a"
        set "cmdline=%%b"  
        set "pid=%%c"
        
        if not "!cmdline!"=="" (
            echo !cmdline! | findstr /i "main.py" >nul 2>&1
            if not errorlevel 1 (
                echo Found background Agent process ^(PID: !pid!^): !cmdline!
                taskkill /PID !pid! /F >NUL 2>&1
                if not errorlevel 1 (
                    echo [OK] Stopped background Agent process ^(PID: !pid!^)
                    set /a STOPPED_COUNT+=1
                )
            )
        )
    )
)

REM Method 3: Look for processes using executables from our venv directory
echo Checking for Python processes from virtual environment...

for /f "skip=1 tokens=*" %%i in ('wmic process where "name='python.exe' or name='pythonw.exe'" get processid^,executablepath /format:csv 2^>nul') do (
    for /f "tokens=1,2,3 delims=," %%a in ("%%i") do (
        set "node=%%a"
        set "exepath=%%b"
        set "pid=%%c"
        
        if not "!exepath!"=="" (
            echo !exepath! | findstr /i "%SCRIPT_DIR%" >nul 2>&1
            if not errorlevel 1 (
                echo Found Python process from our venv ^(PID: !pid!^): !exepath!
                taskkill /PID !pid! /F >NUL 2>&1
                if not errorlevel 1 (
                    echo [OK] Stopped venv Python process ^(PID: !pid!^)
                    set /a STOPPED_COUNT+=1
                )
            )
        )
    )
)

REM Clean up markers
if exist logs (
    del logs\agent.pid >NUL 2>&1
    del logs\agent.marker >NUL 2>&1
)

REM Wait for processes to terminate
timeout /t 2 /nobreak >NUL

echo.
echo ===============================================
echo  Stop Results
echo ===============================================
if !STOPPED_COUNT! GTR 0 (
    echo [SUCCESS] Stopped !STOPPED_COUNT! SysManage Agent process^(es^)
    echo.
    echo The agent should now appear as offline on your server dashboard.
    echo Wait 30-60 seconds for the server to detect the disconnection.
) else (
    echo [INFO] No running SysManage Agent processes were found.
    echo.
    echo This could mean:
    echo - The agent is not currently running
    echo - The agent is running as a different user
    echo - The agent process has a different name
)

echo.
echo To verify the agent is stopped:
echo 1. Check the server dashboard - agent should show as offline
echo 2. Check Task Manager for python.exe processes  
echo 3. Look at log files - they should stop being updated

echo.
pause