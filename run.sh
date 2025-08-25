#!/bin/bash

# SysManage Agent Startup Script
# Starts the SysManage agent daemon

echo "Starting SysManage Agent..."

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# Stop any existing agent
echo "Stopping any existing SysManage Agent processes..."
./stop.sh >/dev/null 2>&1

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
        source .venv/bin/activate
    elif [ -d "venv" ]; then
        echo "Activating virtual environment..."
        source venv/bin/activate
    fi
    
    # Install dependencies if required modules are not available
    if ! python3 -c "import websockets, yaml, aiohttp" >/dev/null 2>&1; then
        echo "Installing required Python packages..."
        pip3 install -r requirements.txt
    fi
fi

# Get system information and configuration for startup message
HOSTNAME=$(python3 -c "import socket; print(socket.getfqdn())" 2>/dev/null || echo "unknown")
PLATFORM=$(python3 -c "import platform; print(platform.system())" 2>/dev/null || echo "unknown")

# Get server configuration from client.yaml if it exists
if [ -f "client.yaml" ]; then
    SERVER_HOST=$(python3 -c "import yaml; print(yaml.safe_load(open('client.yaml'))['server']['hostname'])" 2>/dev/null || echo "unknown")
    SERVER_PORT=$(python3 -c "import yaml; print(yaml.safe_load(open('client.yaml'))['server']['port'])" 2>/dev/null || echo "unknown")
    USE_HTTPS=$(python3 -c "import yaml; print('https' if yaml.safe_load(open('client.yaml'))['server']['use_https'] else 'http')" 2>/dev/null || echo "unknown")
else
    echo "⚠️  WARNING: client.yaml configuration file not found!"
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