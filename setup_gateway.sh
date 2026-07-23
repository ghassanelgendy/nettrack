#!/bin/bash
# Check if root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./setup_gateway.sh)"
  exit 1
fi

# Detect primary network interface
IFACE=$(ip -o -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
if [ -z "$IFACE" ]; then
  IFACE="eno1"
fi

echo "Detected primary interface: $IFACE"

echo "Creating nettrack-gateway systemd service for boot persistence..."
cat <<EOF > /etc/systemd/system/nettrack-gateway.service
[Unit]
Description=NetTrack Gateway NAT Router Setup
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/sysctl -w net.ipv4.ip_forward=1
ExecStart=/sbin/iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
ExecStop=/sbin/iptables -t nat -D POSTROUTING -o $IFACE -j MASQUERADE

[Install]
WantedBy=multi-user.target
EOF

echo "Creating nettrack-portal systemd service for Captive Portal..."
cat <<EOF > /etc/systemd/system/nettrack-portal.service
[Unit]
Description=NetTrack Captive Portal Firewall Daemon
After=network.target nettrack-gateway.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/ghesso/nettrack/nettrack_portal.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "Creating nettrack-web systemd service for Web Dashboard..."
cat <<EOF > /etc/systemd/system/nettrack-web.service
[Unit]
Description=NetTrack Web Dashboard Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/ghesso/nettrack/nettrack_cli.py --web
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "Creating nettrack-dns systemd service for DNS Proxy Firewall..."
cat <<EOF > /etc/systemd/system/nettrack-dns.service
[Unit]
Description=NetTrack DNS Proxy Firewall
After=network.target nettrack-gateway.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /home/ghesso/nettrack/nettrack_dns.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start the services
echo "Enabling and starting nettrack services..."
systemctl daemon-reload
systemctl enable nettrack-gateway.service
systemctl restart nettrack-gateway.service

systemctl enable nettrack-portal.service
systemctl restart nettrack-portal.service

systemctl enable nettrack-web.service
systemctl restart nettrack-web.service

systemctl enable nettrack-dns.service
systemctl restart nettrack-dns.service

# Also ensure main nettrack services are enabled to start on boot
echo "Ensuring NetTrack daemons are enabled on boot..."
systemctl enable nettrack.service
systemctl enable nettrack-device.service

echo ""
echo "========================================================"
echo "          CAPTIVE PORTAL SETUP COMPLETE"
echo "========================================================"
echo "Your server is configured to act as a Captive Portal."
echo "The Web Dashboard (port 6054) will now run automatically on boot."
echo "Unregistered devices will be blocked and redirected to:"
echo "http://192.168.1.100:6054/register"
echo "========================================================"
