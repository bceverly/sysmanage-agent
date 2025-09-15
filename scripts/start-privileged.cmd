@echo off
REM SysManage Agent Privileged Runner for Windows
REM This script runs the SysManage Agent with elevated privileges needed for
REM package management operations (updates, installations, etc.)

setlocal EnableDelayedExpansion

REM Get the absolute path to the script directory
set "AGENT_DIR=%~dp0"
cd /d "%AGENT_DIR%"

echo ===============================================
echo  SysManage Agent Privileged Runner (Windows)
echo ===============================================
echo.
echo Working directory: %AGENT_DIR%
echo.

REM Check if we're already running as administrator
net session >nul 2>&1
if %errorlevel% == 0 (
    echo [OK] Running with administrator privileges
    goto :run_agent
) else (
    echo [!] This script requires administrator privileges
    echo.
    echo Attempting to restart with elevated privileges...
    echo You may see a User Account Control (UAC) prompt.
    echo.
    
    REM Create a temporary VBScript to elevate privileges
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\elevate.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~f0"" %*", "", "runas", 1 >> "%temp%\elevate.vbs"
    
    REM Run the VBScript to elevate
    cscript //nologo "%temp%\elevate.vbs"
    
    REM Clean up
    del "%temp%\elevate.vbs"
    
    REM Exit the non-elevated instance
    exit /b
)

:run_agent
REM Check if virtual environment exists
if not exist ".venv" (
    echo [ERROR] Virtual environment not found at: %AGENT_DIR%.venv
    echo.
    echo Please run setup first:
    echo    python -m venv .venv
    echo    .venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Python executable not found in virtual environment
    echo.
    pause
    exit /b 1
)

REM Create logs directory if it doesn't exist
if not exist "logs" (
    mkdir logs
    echo [OK] Created logs directory
)

REM Stop any existing agent processes
echo.
echo Checking for existing agent processes...
tasklist /FI "IMAGENAME eq python.exe" 2>nul | find /i "python.exe" >nul
if %errorlevel% == 0 (
    echo Found existing Python processes. Attempting to stop agent...
    
    REM Try to use the stop script
    if exist "stop.cmd" (
        call stop.cmd
        timeout /t 2 /nobreak >nul
    ) else (
        REM Fallback: Kill all Python processes running main.py
        for /f "tokens=2" %%i in ('wmic process where "name='python.exe' and commandline like '%%main.py%%'" get processid /value 2^>nul ^| find "="') do (
            set pid=%%i
            taskkill /F /PID !pid! >nul 2>&1
            echo Stopped process with PID: !pid!
        )
    )
    echo [OK] Existing processes stopped
)

REM Check configuration file location
set "CONFIG_FILE="
if exist "C:\ProgramData\SysManage\sysmanage-agent.yaml" (
    set "CONFIG_FILE=C:\ProgramData\SysManage\sysmanage-agent.yaml"
    echo [OK] Using system config: !CONFIG_FILE!
) else if exist ".\sysmanage-agent.yaml" (
    set "CONFIG_FILE=.\sysmanage-agent.yaml"
    echo [OK] Using local config: !CONFIG_FILE!
) else (
    echo [WARNING] No configuration file found
    echo Expected locations:
    echo   - C:\ProgramData\SysManage\sysmanage-agent.yaml
    echo   - .\sysmanage-agent.yaml
)

REM Get system information
for /f "tokens=*" %%i in ('hostname') do set HOSTNAME=%%i
echo.
echo ===============================================
echo  Starting SysManage Agent
echo ===============================================
echo  Host: %HOSTNAME%
echo  Platform: Windows
echo  Python: .venv\Scripts\python.exe
echo  Config: %CONFIG_FILE%
echo  Time: %date% %time%
echo ===============================================
echo.

REM Set environment variables
set "PYTHONPATH=%AGENT_DIR%"
set "PATH=%AGENT_DIR%.venv\Scripts;%PATH%"

REM Run the agent with administrator privileges
echo Starting agent with administrator privileges...
echo Press Ctrl+C to stop the agent
echo.

".venv\Scripts\python.exe" main.py

REM Check exit code
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Agent exited with error code: %errorlevel%
    echo.
    pause
    exit /b %errorlevel%
)

echo.
echo [OK] Agent stopped normally
pause