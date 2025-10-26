#!/bin/bash
#
# SysManage Agent - Systemd User Service Installation Script
# This script installs and enables the SysManage Agent as a systemd user service
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== SysManage Agent Systemd Service Installation ==="
echo ""

# Check if Flatpak is installed
if ! command -v flatpak >/dev/null 2>&1; then
    echo -e "${RED}Error: flatpak command not found${NC}"
    echo "Please install Flatpak first"
    exit 1
fi

# Check if SysManage Agent Flatpak is installed
if ! flatpak list --user | grep -q "org.sysmanage.Agent"; then
    echo -e "${RED}Error: SysManage Agent Flatpak is not installed${NC}"
    echo "Please install it first with: make flatpak-install"
    exit 1
fi

# Create systemd user directory if it doesn't exist
SYSTEMD_USER_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"

# Create the systemd service file
SERVICE_FILE="$SYSTEMD_USER_DIR/sysmanage-agent.service"
echo -e "${YELLOW}Creating systemd user service file...${NC}"
cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=SysManage Agent (Flatpak)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/flatpak run org.sysmanage.Agent
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF

echo -e "${GREEN}✓ Service file created: $SERVICE_FILE${NC}"

# Reload systemd user daemon
echo -e "${YELLOW}Reloading systemd user daemon...${NC}"
systemctl --user daemon-reload

# Enable linger so service starts at boot
echo -e "${YELLOW}Enabling user linger (requires sudo)...${NC}"
if sudo loginctl enable-linger "$USER"; then
    echo -e "${GREEN}✓ User linger enabled${NC}"
else
    echo -e "${RED}Warning: Could not enable linger${NC}"
    echo "The service will only run while you're logged in"
    echo "To enable boot-time start, run manually: sudo loginctl enable-linger $USER"
fi

# Enable the service
echo -e "${YELLOW}Enabling sysmanage-agent service...${NC}"
systemctl --user enable sysmanage-agent.service
echo -e "${GREEN}✓ Service enabled${NC}"

# Start the service
echo -e "${YELLOW}Starting sysmanage-agent service...${NC}"
systemctl --user start sysmanage-agent.service
echo -e "${GREEN}✓ Service started${NC}"

echo ""
echo -e "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "Service status:"
systemctl --user status sysmanage-agent.service --no-pager || true
echo ""
echo "Useful commands:"
echo "  Check status:  systemctl --user status sysmanage-agent"
echo "  View logs:     journalctl --user -u sysmanage-agent -f"
echo "  Restart:       systemctl --user restart sysmanage-agent"
echo "  Stop:          systemctl --user stop sysmanage-agent"
echo "  Uninstall:     ~/.local/bin/sysmanage-service-uninstall.sh"
echo ""
