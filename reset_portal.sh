#!/bin/bash
# Check if root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./reset_portal.sh)"
  exit 1
fi

DB_PATH="/var/lib/nettrack/nettrack.db"

echo "Clearing all registered devices, labels, and traffic data from database..."
sqlite3 "$DB_PATH" "DELETE FROM devices; DELETE FROM device_macs; DELETE FROM device_ips; DELETE FROM users; DELETE FROM lowend_requests; DELETE FROM device_usage; DELETE FROM hourly_usage; DELETE FROM dns_logs;"

echo "Restarting portal firewall to block everyone and force login..."
systemctl restart nettrack-portal.service
systemctl restart nettrack-web.service

echo ""
echo "========================================================"
echo "          PORTAL RESET COMPLETE"
echo "========================================================"
echo "All devices have been logged out."
echo "All labels and registrations have been cleared."
echo "Everyone is now forced to register again to get internet."
echo "========================================================"
