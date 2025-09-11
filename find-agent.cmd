@echo off
REM SysManage Agent Detection Script
REM Finds ALL processes that could be the agent, including hidden ones

setlocal EnableDelayedExpansion

echo ===============================================
echo  SysManage Agent Detection Script  
echo ===============================================
echo.

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo Script directory: %SCRIPT_DIR%
echo.

echo === METHOD 1: All Python processes (any name) ===
tasklist | findstr /i python
if errorlevel 1 echo No processes with 'python' in the name found.
echo.

echo === METHOD 2: Processes by executable name ===
echo Python.exe processes:
tasklist /FI "IMAGENAME eq python.exe" 2>nul
echo.
echo Pythonw.exe processes:  
tasklist /FI "IMAGENAME eq pythonw.exe" 2>nul
echo.
echo Python3.exe processes:
tasklist /FI "IMAGENAME eq python3.exe" 2>nul
echo.

echo === METHOD 3: All processes with full command lines ===
echo Scanning for main.py in command lines...
for /f "skip=1 tokens=*" %%i in ('wmic process get name^,processid^,commandline /format:csv 2^>nul') do (
    for /f "tokens=1,2,3,4* delims=," %%a in ("%%i") do (
        set "node=%%a"
        set "cmdline=%%b"
        set "name=%%c"
        set "pid=%%d"
        
        if not "!cmdline!"=="" (
            echo !cmdline! | findstr /i "main.py" >nul 2>&1
            if not errorlevel 1 (
                echo FOUND: !name! ^(PID: !pid!^)
                echo   Command: !cmdline!
                echo.
            )
        )
    )
)

echo === METHOD 4: Processes using files from our directory ===
echo Looking for processes with executable paths in our directory...
for /f "skip=1 tokens=*" %%i in ('wmic process get name^,processid^,executablepath /format:csv 2^>nul') do (
    for /f "tokens=1,2,3,4 delims=," %%a in ("%%i") do (
        set "node=%%a"
        set "exepath=%%b"
        set "name=%%c"
        set "pid=%%d"
        
        if not "!exepath!"=="" (
            echo !exepath! | findstr /i "%SCRIPT_DIR%" >nul 2>&1
            if not errorlevel 1 (
                echo FOUND: !name! ^(PID: !pid!^)
                echo   Path: !exepath!
                echo.
            )
        )
    )
)

echo === METHOD 5: Check Windows Services ===
echo Checking for SysManage-related services...
sc query | findstr /i sysmanage
if errorlevel 1 echo No SysManage services found.
echo.

echo === METHOD 6: Network connections ===
echo Checking for network connections from this machine...
echo Looking for connections that might be the agent...
netstat -ano | findstr ESTABLISHED | findstr /v ":80 \|:443 \|:53 \|:22 "
echo.

echo === METHOD 7: Check scheduled tasks ===
echo Checking for scheduled tasks related to SysManage...
schtasks /query | findstr /i sysmanage
if errorlevel 1 echo No SysManage scheduled tasks found.
echo.

echo === METHOD 8: Process tree analysis ===
echo Looking for child processes that might be the agent...
wmic process where "name like '%python%'" get processid,parentprocessid,name,commandline /format:csv

echo.
echo === METHOD 9: Check for processes holding files ===
if exist logs\agent_output.log (
    echo Checking what processes have agent_output.log open...
    handle.exe "%SCRIPT_DIR%logs\agent_output.log" 2>nul
    if errorlevel 1 echo Handle.exe not available - install Sysinternals Suite for better detection
)
echo.

echo === METHOD 10: Alternative Python installations ===
echo Checking for Python in alternative locations...
if exist "C:\Python*\python.exe" (
    for /d %%d in (C:\Python*) do (
        echo Found Python installation: %%d
        tasklist | findstr /i "%%~nxd"
    )
)

echo Checking AppData Python installations...
if exist "%LOCALAPPDATA%\Programs\Python" (
    echo Found Python in AppData
    dir "%LOCALAPPDATA%\Programs\Python" /s /b | findstr python.exe
)

echo.
echo === METHOD 11: Check startup locations ===
echo Checking startup folders and registry for auto-start entries...
echo.
echo Startup folder contents:
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul

echo.
echo Registry run keys:
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul | findstr /i python
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 2>nul | findstr /i python

echo.
echo === SUMMARY ===
echo If no agent processes were found above but the server shows it's online:
echo.
echo Possible causes:
echo 1. Agent is running under a different user account
echo 2. Agent is installed as a Windows service  
echo 3. Agent executable was renamed
echo 4. Agent is running from a different directory
echo 5. Agent is running via Task Scheduler
echo 6. Multiple machines with same hostname
echo 7. Server cache showing stale data
echo.
echo Next steps:
echo 1. Restart this computer to ensure ALL processes stop
echo 2. Check server logs for the agent's IP address
echo 3. Check if you have other computers with the same name
echo 4. Wait 5-10 minutes for server to detect disconnection
echo.

pause