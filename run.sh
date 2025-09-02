#!/bin/sh

# SysManage Agent Startup Script
# Starts the SysManage agent daemon

echo "Starting SysManage Agent..."

# Get the directory where this script is located
# Use $0 instead of BASH_SOURCE for better shell compatibility
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Create logs directory if it doesn't exist
mkdir -p logs

# Function to check if agent is already running
check_agent_running() {
    if [ -f "logs/agent.pid" ]; then
        local pid=$(cat logs/agent.pid)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            return 0  # Agent is running
        else
            # PID file exists but process is dead, clean it up
            rm -f logs/agent.pid
        fi
    fi
    return 1  # Agent is not running
}

# Function to check for running agent processes
check_existing_processes() {
    local found_processes=false
    
    # Check for agent processes by pattern (cross-platform approach)
    local agent_pids=""
    if command -v pgrep >/dev/null 2>&1; then
        # Use pgrep if available (Linux, modern macOS, some BSD)
        agent_pids=$(pgrep -f "python3.*main.py" 2>/dev/null | grep -v $$) # Exclude this script's PID
    else
        # Fallback: use ps and grep for older systems
        agent_pids=$(ps -ef 2>/dev/null | grep "python3.*main.py" | grep -v grep | grep -v $$ | awk '{print $2}')
    fi
    
    if [ -n "$agent_pids" ]; then
        echo "⚠️  Found existing agent processes:"
        echo "$agent_pids" | while read pid; do
            if [ -n "$pid" ]; then
                local cmd=$(ps -p "$pid" -o command= 2>/dev/null | cut -c1-80)
                if [ -z "$cmd" ]; then
                    # Fallback for systems where ps -p doesn't work the same way
                    cmd=$(ps -ef 2>/dev/null | awk -v p="$pid" '$2==p {for(i=8;i<=NF;i++) printf "%s ", $i; print ""}' | cut -c1-80)
                fi
                echo "   PID $pid: $cmd"
            fi
        done
        found_processes=true
    fi
    
    # Check PID file
    if [ -f "logs/agent.pid" ]; then
        local pid_file_pid=$(cat logs/agent.pid 2>/dev/null)
        if [ -n "$pid_file_pid" ] && kill -0 "$pid_file_pid" 2>/dev/null; then
            echo "⚠️  Found agent process from PID file (PID: $pid_file_pid)"
            found_processes=true
        fi
    fi
    
    if [ "$found_processes" = true ]; then
        echo "Attempting to stop existing processes..."
        return 0  # Found processes
    else
        echo "No existing SysManage Agent processes found"
        return 1  # No processes found
    fi
}

# Stop any existing agent
if check_existing_processes; then
    sh ./stop.sh
    sleep 2
    
    # Verify they were stopped
    if check_existing_processes >/dev/null 2>&1; then
        echo "❌ ERROR: Failed to stop existing agent processes. Please manually stop them before continuing."
        echo ""
        echo "To manually check for agent processes:"
        echo "  ps -ef | grep 'python3.*main.py'"
        echo ""
        echo "To manually kill all agent processes:"
        if command -v pkill >/dev/null 2>&1; then
            echo "  pkill -f 'python3.*main.py'"
        else
            echo "  kill \$(ps -ef | grep 'python3.*main.py' | grep -v grep | awk '{print \$2}')"
        fi
        exit 1
    else
        echo "✅ Successfully stopped existing processes"
    fi
fi

# Check for Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: Python 3 is required but not installed"
    exit 1
fi

# Check if main.py exists
if [ ! -f "main.py" ]; then
    echo "ERROR: main.py not found in current directory"
    exit 1
fi

# Install Python dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "Checking Python dependencies..."
    
    # Check if virtual environment exists and activate it
    if [ -d ".venv" ]; then
        echo "Activating virtual environment..."
        . .venv/bin/activate
    elif [ -d "venv" ]; then
        echo "Activating virtual environment..."
        . venv/bin/activate
    fi
    
    # Install dependencies if required modules are not available
    if ! python3 -c "import websockets, yaml, aiohttp" >/dev/null 2>&1; then
        echo "Installing required Python packages..."
        
        # Check if we're on OpenBSD and if Rust is available
        if [ "$(uname)" = "OpenBSD" ]; then
            if command -v rustc >/dev/null 2>&1; then
                echo "Detected OpenBSD with Rust - using full requirements.txt..."
                pip3 install -r requirements.txt
            elif [ -f "requirements-openbsd.txt" ]; then
                echo "Detected OpenBSD without Rust - using simplified requirements..."
                echo "⚠️  WARNING: Running without full cryptography support may reduce security!"
                echo "   To get full security features, install Rust with: pkg_add rust"
                pip3 install -r requirements-openbsd.txt
            else
                echo "Attempting to install full requirements (may fail without Rust)..."
                pip3 install -r requirements.txt
            fi
        else
            pip3 install -r requirements.txt
        fi
    fi
fi

# Get system information and configuration for startup message
HOSTNAME=$(python3 -c "import socket; print(socket.getfqdn())" 2>/dev/null || echo "unknown")
PLATFORM=$(python3 -c "import platform; print(platform.system())" 2>/dev/null || echo "unknown")

# Function to get configuration value from config file with priority
get_config_value() {
    local key=$1
    local config_file=""
    
    # Use same priority as ConfigManager: /etc/sysmanage-agent.yaml then ./sysmanage-agent.yaml
    if [ -f "/etc/sysmanage-agent.yaml" ]; then
        config_file="/etc/sysmanage-agent.yaml"
    elif [ -f "./sysmanage-agent.yaml" ]; then
        config_file="./sysmanage-agent.yaml"
    else
        return 1
    fi
    
    python3 -c "
import yaml
import sys
try:
    with open('$config_file', 'r') as f:
        config = yaml.safe_load(f)
    keys = '$key'.split('.')
    value = config
    for k in keys:
        value = value[k]
    print(value)
except:
    sys.exit(1)
" 2>/dev/null
}

# Determine which config file to use and get server configuration
CONFIG_FILE=""
if [ -f "/etc/sysmanage-agent.yaml" ]; then
    CONFIG_FILE="/etc/sysmanage-agent.yaml"
elif [ -f "./sysmanage-agent.yaml" ]; then
    CONFIG_FILE="./sysmanage-agent.yaml"
fi

if [ -n "$CONFIG_FILE" ]; then
    echo "Using configuration file: $CONFIG_FILE"
    SERVER_HOST=$(get_config_value "server.hostname")
    if [ $? -ne 0 ] || [ -z "$SERVER_HOST" ]; then
        SERVER_HOST="unknown"
    fi
    
    SERVER_PORT=$(get_config_value "server.port")
    if [ $? -ne 0 ] || [ -z "$SERVER_PORT" ]; then
        SERVER_PORT="unknown"
    fi
    
    USE_HTTPS_BOOL=$(get_config_value "server.use_https")
    if [ $? -ne 0 ] || [ -z "$USE_HTTPS_BOOL" ]; then
        USE_HTTPS="unknown"
    elif [ "$USE_HTTPS_BOOL" = "True" ] || [ "$USE_HTTPS_BOOL" = "true" ]; then
        USE_HTTPS="https"
    else
        USE_HTTPS="http"
    fi
else
    echo "⚠️  WARNING: Configuration file not found! Expected /etc/sysmanage-agent.yaml or ./sysmanage-agent.yaml"
    SERVER_HOST="unknown"
    SERVER_PORT="unknown"
    USE_HTTPS="unknown"
fi

echo "Agent Details:"
echo "  🖥️  Hostname: $HOSTNAME"
echo "  🔧 Platform: $PLATFORM"
echo "  📁 Directory: $SCRIPT_DIR"
echo "  🌐 Server: $USE_HTTPS://$SERVER_HOST:$SERVER_PORT"

# Start the agent in background
echo "Starting SysManage Agent daemon..."
nohup python3 main.py > logs/agent.log 2>&1 &
AGENT_PID=$!

# Save PID
echo $AGENT_PID > logs/agent.pid

# Give it a moment to start
sleep 2

# Check if the process is still running
if kill -0 "$AGENT_PID" 2>/dev/null; then
    echo ""
    echo "✅ SysManage Agent is successfully running!"
    echo ""
    echo "Agent Information:"
    echo "  🆔 Process ID: $AGENT_PID"
    echo "  🖥️  Hostname: $HOSTNAME" 
    echo "  🔗 Server: $USE_HTTPS://$SERVER_HOST:$SERVER_PORT"
    echo ""
    echo "Logs:"
    echo "  📄 Agent Log: tail -f logs/agent.log"
    echo ""
    echo "To stop the agent: ./stop.sh"
    echo ""
else
    echo ""
    echo "❌ ERROR: SysManage Agent failed to start!"
    echo ""
    echo "Check the log file for details:"
    echo "  tail logs/agent.log"
    echo ""
    # Clean up PID file
    rm -f logs/agent.pid
    exit 1
fi