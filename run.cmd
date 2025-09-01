@echo off
REM SysManage Agent Startup Script for Windows
REM Starts the SysManage agent daemon

echo Starting SysManage Agent...

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

REM Create logs directory if it doesn't exist
if not exist logs mkdir logs

REM Function to get configuration value from sysmanage-agent.yaml
REM Note: This uses Python to parse YAML since Windows doesn't have native YAML support

REM Function to check for running agent processes
echo Checking for existing SysManage Agent processes...

REM Check for existing Python processes running main.py
for /f "tokens=2" %%i in ('tasklist /FI "IMAGENAME eq python.exe" /FO CSV ^| find "python.exe" ^| find /C /V ""') do set PYTHON_COUNT=%%i
for /f "tokens=2" %%i in ('tasklist /FI "IMAGENAME eq python3.exe" /FO CSV ^| find "python3.exe" ^| find /C /V ""') do set PYTHON3_COUNT=%%i

if exist logs\agent.pid (
    set /p AGENT_PID=<logs\agent.pid
    tasklist /FI "PID eq %AGENT_PID%" 2>NUL | find "%AGENT_PID%" >NUL
    if not errorlevel 1 (
        echo Warning: Found existing agent process ^(PID: %AGENT_PID%^)
        echo Stopping existing process...
        call stop.cmd
        timeout /t 2 >NUL
    )
)

REM Stop any existing agent processes
echo Stopping any existing SysManage Agent processes...
call stop.cmd >NUL 2>&1

REM Check for Python 3 (try python3 first, then python)
python3 --version >NUL 2>&1
if errorlevel 1 (
    python --version | find "Python 3" >NUL 2>&1
    if errorlevel 1 (
        echo ERROR: Python 3 is required but not installed
        pause
        exit /b 1
    )
    set PYTHON_CMD=python
) else (
    set PYTHON_CMD=python3
)

REM Check if main.py exists
if not exist main.py (
    echo ERROR: main.py not found in current directory
    pause
    exit /b 1
)

REM Install Python dependencies if requirements.txt exists
if exist requirements.txt (
    echo Checking Python dependencies...
    
    REM Check if virtual environment exists and activate it
    if exist .venv\Scripts\activate.bat (
        echo Activating virtual environment...
        call .venv\Scripts\activate.bat
    ) else if exist venv\Scripts\activate.bat (
        echo Activating virtual environment...
        call venv\Scripts\activate.bat
    )
    
    REM Install dependencies if required modules are not available
    %PYTHON_CMD% -c "import websockets, yaml, aiohttp" >NUL 2>&1
    if errorlevel 1 (
        echo Installing required Python packages...
        pip install -r requirements.txt
    )
)

REM Get system information and configuration for startup message
for /f "delims=" %%i in ('%PYTHON_CMD% -c "import socket; print(socket.getfqdn())" 2^>NUL') do set HOSTNAME=%%i
if "%HOSTNAME%"=="" set HOSTNAME=unknown

for /f "delims=" %%i in ('%PYTHON_CMD% -c "import platform; print(platform.system())" 2^>NUL') do set PLATFORM=%%i
if "%PLATFORM%"=="" set PLATFORM=unknown

REM Get server configuration from client.yaml if it exists
if exist sysmanage-agent.yaml (
    for /f "delims=" %%i in ('%PYTHON_CMD% -c "import yaml; config=yaml.safe_load(open('sysmanage-agent.yaml')); print(config['server']['hostname'])" 2^>NUL') do set SERVER_HOST=%%i
    if "%%i"=="" set SERVER_HOST=unknown
    
    for /f "delims=" %%i in ('%PYTHON_CMD% -c "import yaml; config=yaml.safe_load(open('sysmanage-agent.yaml')); print(config['server']['port'])" 2^>NUL') do set SERVER_PORT=%%i
    if "%%i"=="" set SERVER_PORT=unknown
    
    for /f "delims=" %%i in ('%PYTHON_CMD% -c "import yaml; config=yaml.safe_load(open('sysmanage-agent.yaml')); print('https' if config['server']['use_https'] else 'http')" 2^>NUL') do set USE_HTTPS=%%i
    if "%%i"=="" set USE_HTTPS=unknown
) else (
    echo Warning: sysmanage-agent.yaml configuration file not found!
    set SERVER_HOST=unknown
    set SERVER_PORT=unknown
    set USE_HTTPS=unknown
)

echo Agent Details:
echo   🖥️  Hostname: %HOSTNAME%
echo   🔧 Platform: %PLATFORM%
echo   📁 Directory: %SCRIPT_DIR%
echo   🌐 Server: %USE_HTTPS%://%SERVER_HOST%:%SERVER_PORT%

REM Start the agent in background
echo Starting SysManage Agent daemon...
start /B %PYTHON_CMD% main.py > logs\agent.log 2>&1

REM Get the PID of the started process (Windows doesn't make this easy)
REM We'll use a small delay and then find the newest python process
timeout /t 2 >NUL

REM Save a marker for process identification
echo %DATE% %TIME% > logs\agent.marker

REM Check if the process seems to be running by checking if log file is being written
timeout /t 3 >NUL

if exist logs\agent.log (
    echo.
    echo ✅ SysManage Agent startup initiated!
    echo.
    echo Agent Information:
    echo   🖥️  Hostname: %HOSTNAME%
    echo   🔗 Server: %USE_HTTPS%://%SERVER_HOST%:%SERVER_PORT%
    echo.
    echo Logs:
    echo   📄 Agent Log: type logs\agent.log
    echo   📄 Live Log: Get-Content logs\agent.log -Wait ^(PowerShell^)
    echo.
    echo To stop the agent: stop.cmd
    echo.
    echo Note: Check logs\agent.log to verify successful startup
) else (
    echo.
    echo ❌ ERROR: SysManage Agent may have failed to start!
    echo.
    echo Check for error messages above or try running:
    echo   %PYTHON_CMD% main.py
    echo.
    pause
    exit /b 1
)