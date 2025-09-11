@echo off
REM SysManage Agent Stop Script for Windows
REM Stops the SysManage agent daemon

echo Stopping SysManage Agent...

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM Function to kill process by PID file
if exist logs\agent.pid (
    set /p AGENT_PID=<logs\agent.pid
    if not "%AGENT_PID%"=="" (
        tasklist /FI "PID eq %AGENT_PID%" 2>NUL | find "%AGENT_PID%" >NUL
        if not errorlevel 1 (
            echo Stopping SysManage Agent ^(PID: %AGENT_PID%^)...
            taskkill /PID %AGENT_PID% /F >NUL 2>&1
            if not errorlevel 1 (
                echo Agent stopped successfully
            ) else (
                echo Warning: Could not stop agent process ^(PID: %AGENT_PID%^)
            )
        ) else (
            echo Agent PID file found but process not running
        )
    )
    del logs\agent.pid >NUL 2>&1
)

REM Function to kill agent processes by pattern
echo Checking for Python processes running main.py...

REM Find and kill any Python processes that might be running main.py
REM This is tricky on Windows, so we'll use tasklist and filter

REM Kill python.exe processes (check command line if possible)
for /f "skip=1 tokens=2" %%p in ('tasklist /FI "IMAGENAME eq python.exe" /FO CSV') do (
    set "pid=%%p"
    set "pid=!pid:"=!"
    if not "!pid!"=="" (
        REM Try to kill the process - if it's our main.py it should die
        taskkill /PID !pid! /F >NUL 2>&1
        if not errorlevel 1 (
            echo Stopped Python process ^(PID: !pid!^)
        )
    )
)

REM Kill python3.exe processes
for /f "skip=1 tokens=2" %%p in ('tasklist /FI "IMAGENAME eq python3.exe" /FO CSV') do (
    set "pid=%%p"
    set "pid=!pid:"=!"
    if not "!pid!"=="" (
        taskkill /PID !pid! /F >NUL 2>&1
        if not errorlevel 1 (
            echo Stopped Python3 process ^(PID: !pid!^)
        )
    )
)

REM Clean up log directory if it exists
if exist logs (
    del logs\agent.pid >NUL 2>&1
    del logs\agent.marker >NUL 2>&1
)

REM Final verification - check if any Python processes are still running
set PYTHON_COUNT=0
for /f %%i in ('tasklist /FI "IMAGENAME eq python.exe" ^| find /C "python.exe"') do set /a PYTHON_COUNT+=%%i
for /f %%i in ('tasklist /FI "IMAGENAME eq python3.exe" ^| find /C "python3.exe"') do set /a PYTHON_COUNT+=%%i

timeout /t 1 >NUL

if %PYTHON_COUNT% EQU 0 (
    echo.
    echo [OK] SysManage Agent stopped successfully!
) else (
    echo.
    echo [WARNING] %PYTHON_COUNT% Python process^(es^) may still be running
    echo.
    echo To manually check for processes:
    echo   tasklist ^| find "python"
    echo.
    echo To manually kill Python processes:
    echo   taskkill /IM python.exe /F
    echo   taskkill /IM python3.exe /F
)

echo.