#!/bin/bash

echo "🔄 Restarting SysManage Agents..."

# Kill any existing agent processes
echo "Stopping existing agents..."
pkill -f "python.*main.py"
sleep 2

# Make sure they're really gone
pkill -9 -f "python.*main.py" 2>/dev/null || true
sleep 1

# Start fresh agent
echo "Starting fresh agent..."
nohup python main.py > agent.log 2>&1 &

echo "✅ Agent restarted. Check agent.log for output."
echo "Monitor with: tail -f agent.log"