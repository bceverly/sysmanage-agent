#!/bin/bash
#
# SysManage Agent - Systemd User Service Uninstallation Script
# This script stops and removes the SysManage Agent systemd user service
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== SysManage Agent Systemd Service Uninstallation ==="
echo ""

SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_FILE="$SYSTEMD_USER_DIR/sysmanage-agent.service"

# Check if service file exists
if [ ! -f "$SERVICE_FILE" ]; then
    echo -e "${YELLOW}Warning: Service file not found: $SERVICE_FILE${NC}"
    echo "The service may not be installed or has already been removed"
    exit 0
fi

# Stop the service
echo -e "${YELLOW}Stopping sysmanage-agent service...${NC}"
if systemctl --user is-active --quiet sysmanage-agent.service; then
    systemctl --user stop sysmanage-agent.service
    echo -e "${GREEN}✓ Service stopped${NC}"
else
    echo "Service is not running"
fi

# Disable the service
echo -e "${YELLOW}Disabling sysmanage-agent service...${NC}"
if systemctl --user is-enabled --quiet sysmanage-agent.service 2>/dev/null; then
    systemctl --user disable sysmanage-agent.service
    echo -e "${GREEN}✓ Service disabled${NC}"
else
    echo "Service is not enabled"
fi

# Remove the service file
echo -e "${YELLOW}Removing service file...${NC}"
rm -f "$SERVICE_FILE"
echo -e "${GREEN}✓ Service file removed: $SERVICE_FILE${NC}"

# Reload systemd user daemon
echo -e "${YELLOW}Reloading systemd user daemon...${NC}"
systemctl --user daemon-reload

echo ""
echo -e "${GREEN}=== Uninstallation Complete ===${NC}"
echo ""
echo "The systemd service has been removed."
echo ""
echo "Note: User linger was NOT disabled. If you want to disable it, run:"
echo "  sudo loginctl disable-linger $USER"
echo ""
echo "To uninstall the Flatpak package itself, run:"
echo "  make flatpak-uninstall"
echo ""
