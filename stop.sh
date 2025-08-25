#!/bin/bash

# SysManage Agent Stop Script
# Stops the SysManage agent daemon

echo "Stopping SysManage Agent..."

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Function to kill process by PID file
kill_by_pidfile() {
    local pidfile=$1
    
    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "Stopping SysManage Agent (PID: $pid)..."
            
            # First try graceful shutdown
            kill "$pid"
            
            # Wait up to 10 seconds for graceful shutdown
            local count=0
            while [ $count -lt 10 ] && kill -0 "$pid" 2>/dev/null; do
                sleep 1
                count=$((count + 1))
                echo -n "."
            done
            echo
            
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                echo "Force stopping SysManage Agent..."
                kill -9 "$pid" 2>/dev/null
                sleep 1
            fi
            
            # Verify it's stopped
            if kill -0 "$pid" 2>/dev/null; then
                echo "⚠️  Warning: Agent process may still be running (PID: $pid)"
                return 1
            else
                echo "Agent stopped successfully"
            fi
        else
            echo "Agent PID file found but process not running"
        fi
        rm -f "$pidfile"
    else
        echo "No PID file found, checking for running processes..."
    fi
}

# Function to kill agent processes by pattern
kill_by_pattern() {
    local pattern="python3.*main.py"
    
    local pids=$(pgrep -f "$pattern" 2>/dev/null | grep -v $$) # Exclude this script's PID
    if [ -n "$pids" ]; then
        echo "Found SysManage Agent processes, stopping them..."
        echo "$pids" | while read pid; do
            if [ -n "$pid" ]; then
                echo "Stopping agent process (PID: $pid)..."
                kill "$pid" 2>/dev/null
            fi
        done
        
        # Wait a moment
        sleep 2
        
        # Force kill if still running
        local remaining_pids=$(pgrep -f "$pattern" 2>/dev/null | grep -v $$)
        if [ -n "$remaining_pids" ]; then
            echo "Force stopping remaining agent processes..."
            echo "$remaining_pids" | while read pid; do
                if [ -n "$pid" ]; then
                    kill -9 "$pid" 2>/dev/null
                fi
            done
        fi
    fi
}

# Try to stop using PID file first
killed_by_pid=false
if kill_by_pidfile "logs/agent.pid"; then
    killed_by_pid=true
fi

# Fallback: kill by process pattern if PID method didn't work or find any processes
if [ "$killed_by_pid" = false ]; then
    kill_by_pattern
fi

# Clean up log directory if it exists but is empty (except for log files)
if [ -d "logs" ]; then
    # Remove PID file if it still exists
    rm -f logs/agent.pid
    
    # Check if there are only log files left
    if [ -n "$(find logs -name "*.pid" -o -name "processes.env" 2>/dev/null)" ]; then
        find logs -name "*.pid" -delete 2>/dev/null
        find logs -name "processes.env" -delete 2>/dev/null
    fi
fi

# Final verification
sleep 1
remaining_processes=$(pgrep -f "python3.*main.py" 2>/dev/null | grep -v $$ | wc -l)

if [ "$remaining_processes" -eq 0 ]; then
    echo ""
    echo "✅ SysManage Agent stopped successfully!"
else
    echo ""
    echo "⚠️  Warning: $remaining_processes agent process(es) may still be running"
    echo ""
    echo "To manually check for agent processes:"
    echo "  ps aux | grep 'python3.*main.py'"
    echo ""
    echo "To manually kill all agent processes:"
    echo "  pkill -f 'python3.*main.py'"
fi

echo ""