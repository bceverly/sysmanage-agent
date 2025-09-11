@echo off
REM SysManage Agent Privileged Background Runner for Windows
REM This script runs the SysManage Agent in the background with elevated privileges
REM No console window will remain open after starting

setlocal EnableDelayedExpansion

REM Get the absolute path to the script directory
set "AGENT_DIR=%~dp0"
cd /d "%AGENT_DIR%"

REM Check if we're already running as administrator
net session >nul 2>&1
if %errorlevel% == 0 (
    goto :run_agent_background
) else (
    echo [!] Requesting administrator privileges...
    
    REM Create a temporary VBScript to elevate privileges silently
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\elevate_bg.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~f0"" %*", "", "runas", 0 >> "%temp%\elevate_bg.vbs"
    
    REM Run the VBScript to elevate (0 = hidden window)
    cscript //nologo "%temp%\elevate_bg.vbs"
    
    REM Clean up
    del "%temp%\elevate_bg.vbs"
    
    REM Exit the non-elevated instance
    exit /b
)

:run_agent_background
REM Check if virtual environment exists
if not exist ".venv" (
    REM Log error to file since we're running without a window
    echo [%date% %time%] ERROR: Virtual environment not found at: %AGENT_DIR%.venv > "%AGENT_DIR%logs\startup_error.log"
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [%date% %time%] ERROR: Python executable not found in virtual environment > "%AGENT_DIR%logs\startup_error.log"
    exit /b 1
)

REM Create logs directory if it doesn't exist
if not exist "logs" (
    mkdir logs
)

REM Create a startup log
echo [%date% %time%] Starting SysManage Agent in background with elevated privileges > "%AGENT_DIR%logs\agent_startup.log"
echo Working directory: %AGENT_DIR% >> "%AGENT_DIR%logs\agent_startup.log"

REM Stop any existing agent processes
for /f "tokens=2" %%i in ('wmic process where "name='python.exe' and commandline like '%%main.py%%'" get processid /value 2^>nul ^| find "="') do (
    set pid=%%i
    taskkill /F /PID !pid! >nul 2>&1
    echo [%date% %time%] Stopped existing process with PID: !pid! >> "%AGENT_DIR%logs\agent_startup.log"
)

REM Check configuration file location
set "CONFIG_FILE="
if exist "C:\ProgramData\SysManage\sysmanage-agent.yaml" (
    set "CONFIG_FILE=C:\ProgramData\SysManage\sysmanage-agent.yaml"
    echo [%date% %time%] Using system config: !CONFIG_FILE! >> "%AGENT_DIR%logs\agent_startup.log"
) else if exist ".\sysmanage-agent.yaml" (
    set "CONFIG_FILE=.\sysmanage-agent.yaml"
    echo [%date% %time%] Using local config: !CONFIG_FILE! >> "%AGENT_DIR%logs\agent_startup.log"
) else (
    echo [%date% %time%] WARNING: No configuration file found >> "%AGENT_DIR%logs\agent_startup.log"
)

REM Set environment variables
set "PYTHONPATH=%AGENT_DIR%"
set "PATH=%AGENT_DIR%.venv\Scripts;%PATH%"

REM Start the agent in background using START command with /B flag
REM Output is redirected to log files
echo [%date% %time%] Launching agent process... >> "%AGENT_DIR%logs\agent_startup.log"

start /B "" "%AGENT_DIR%.venv\Scripts\python.exe" "%AGENT_DIR%main.py" > "%AGENT_DIR%logs\agent_output.log" 2>&1

REM Give it a moment to start
timeout /t 2 /nobreak >nul

REM Check if the process started successfully
tasklist /FI "IMAGENAME eq python.exe" 2>nul | find /i "python.exe" >nul
if %errorlevel% == 0 (
    echo [%date% %time%] Agent started successfully in background >> "%AGENT_DIR%logs\agent_startup.log"
    
    REM Show a brief notification using msg command (Windows 7+)
    msg * /TIME:5 "SysManage Agent started in background with administrator privileges"
) else (
    echo [%date% %time%] ERROR: Failed to start agent >> "%AGENT_DIR%logs\agent_startup.log"
)

REM Exit immediately - agent continues running in background
exit /b