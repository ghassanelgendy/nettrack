#!/bin/bash
# NetTrack Installation Script

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0;m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}             NetTrack Installer for Linux           ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Check if script is run with sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run this installer with sudo:${NC}"
  echo -e "  sudo ./install.sh"
  exit 1
fi

# 1. Install dependencies
echo -e "\n${BLUE}[1/5] Checking dependencies (nethogs)...${NC}"
if ! command -v nethogs &> /dev/null; then
  echo -e "nethogs not found. Installing nethogs..."
  if command -v apt-get &> /dev/null; then
    apt-get update && apt-get install -y nethogs
  elif command -v pacman &> /dev/null; then
    pacman -S --noconfirm nethogs
  elif command -v dnf &> /dev/null; then
    dnf install -y nethogs
  else
    echo -e "${RED}Error: Could not install nethogs automatically. Please install it manually.${NC}"
    exit 1
  fi
else
  echo -e "${GREEN}nethogs is already installed.${NC}"
fi

# 2. Setup database directory
echo -e "\n${BLUE}[2/5] Creating database directory...${NC}"
mkdir -p /var/lib/nettrack
chmod 755 /var/lib/nettrack
echo -e "${GREEN}Database directory created at /var/lib/nettrack${NC}"

# 3. Setup systemd service
echo -e "\n${BLUE}[3/5] Creating Systemd service...${NC}"
CAT_SERVICE_PATH="/etc/systemd/system/nettrack.service"
cat << 'EOF' > "$CAT_SERVICE_PATH"
[Unit]
Description=NetTrack Network Usage Tracking Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/ghesso/nettrack/nettrack_daemon.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}Systemd service file created at $CAT_SERVICE_PATH${NC}"

# 4. Install global CLI command wrapper
echo -e "\n${BLUE}[4/5] Creating global CLI executable...${NC}"
CLI_WRAPPER="/usr/local/bin/nettrack"
cat << 'EOF' > "$CLI_WRAPPER"
#!/bin/bash
python3 /home/ghesso/nettrack/nettrack_cli.py "$@"
EOF
chmod +x "$CLI_WRAPPER"
echo -e "${GREEN}CLI wrapper installed at $CLI_WRAPPER${NC}"

# 5. Enable and start daemon service
echo -e "\n${BLUE}[5/5] Enabling and starting service...${NC}"
systemctl daemon-reload
systemctl enable nettrack.service
systemctl restart nettrack.service

if systemctl is-active --quiet nettrack.service; then
  echo -e "${GREEN}Service started successfully!${NC}"
else
  echo -e "${RED}Warning: Service is not running. Check status with: systemctl status nettrack.service${NC}"
fi

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN}        Installation complete!                      ${NC}"
echo -e " Run '${BLUE}nettrack${NC}' to view today's usage."
echo -e " Run '${BLUE}nettrack --week${NC}' to view weekly usage."
echo -e " Run '${BLUE}nettrack --month${NC}' to view monthly usage."
echo -e " Run '${BLUE}nettrack --web${NC}' to launch the local web server dashboard."
echo -e "${GREEN}====================================================${NC}"
