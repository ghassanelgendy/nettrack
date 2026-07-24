#!/usr/bin/env python3
import os
import sys
import time
import sqlite3
import subprocess

DB_PATH = "/var/lib/nettrack/nettrack.db"
PORT = 6054
SERVER_IP = "192.168.1.100"

def get_primary_interface():
    try:
        res = subprocess.run("ip -o -4 route show default", shell=True, capture_output=True, text=True)
        parts = res.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eno1"

IFACE = get_primary_interface()

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
        return True
    except Exception as e:
        return False

def init_firewall():
    print(f"[portal] Initializing Captive Portal firewall on {IFACE}...", flush=True)
    
    # Clean up custom chains
    run_cmd("iptables -F NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -F NETTRACK-PORTAL-ALLOW 2>/dev/null")
    run_cmd("iptables -t nat -F NETTRACK-PORTAL-NAT 2>/dev/null")
    
    run_cmd(f"iptables -D FORWARD -i {IFACE} -j NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -D FORWARD -j NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -t nat -D PREROUTING -j NETTRACK-PORTAL-NAT 2>/dev/null")
    
    run_cmd("iptables -X NETTRACK-PORTAL-ALLOW 2>/dev/null")
    run_cmd("iptables -X NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -t nat -X NETTRACK-PORTAL-NAT 2>/dev/null")
    
    # Create custom chains
    run_cmd("iptables -N NETTRACK-PORTAL")
    run_cmd("iptables -N NETTRACK-PORTAL-ALLOW")
    run_cmd("iptables -t nat -N NETTRACK-PORTAL-NAT")
    
    # Link chains
    run_cmd("iptables -A NETTRACK-PORTAL -j NETTRACK-PORTAL-ALLOW")
    run_cmd("iptables -I FORWARD 1 -s 192.168.1.0/24 -j NETTRACK-PORTAL")
    run_cmd("iptables -I FORWARD 1 -d 192.168.1.0/24 -j NETTRACK-PORTAL")
    run_cmd("iptables -t nat -I PREROUTING 1 -j NETTRACK-PORTAL-NAT")
    
    # Input rules for DNS and Web
    run_cmd("iptables -D INPUT -p tcp --dport 6054 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 1 -p tcp --dport 6054 -j ACCEPT")
    
    # Allow returning DNS replies to unregistered clients
    run_cmd("iptables -A NETTRACK-PORTAL -p udp --sport 53 -j ACCEPT")
    run_cmd("iptables -A NETTRACK-PORTAL -p tcp --sport 53 -j ACCEPT")
    
    # Allow DNS forwarding
    run_cmd("iptables -A NETTRACK-PORTAL -p udp --dport 53 -j ACCEPT")
    run_cmd("iptables -A NETTRACK-PORTAL -p tcp --dport 53 -j ACCEPT")
    
    # Allow DHCP forwarding (essential when clients send unicast renewals through the gateway)
    run_cmd("iptables -A NETTRACK-PORTAL -p udp --dport 67:68 -j ACCEPT")
    run_cmd("iptables -A NETTRACK-PORTAL -p udp --sport 67:68 -j ACCEPT")
    
    # Allow local server portal page access
    run_cmd(f"iptables -A NETTRACK-PORTAL -d {SERVER_IP} -p tcp --dport {PORT} -j ACCEPT")
    
    # Block other internet forwarding by default
    run_cmd("iptables -A NETTRACK-PORTAL -j DROP")

last_allowed_ips = set()

def update_allowed_ips():
    global last_allowed_ips
    import datetime
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        today_start = datetime.date.today().strftime('%Y-%m-%d 00:00:00')
        month_start = datetime.date.today().replace(day=1).strftime('%Y-%m-%d 00:00:00')
        
        # Get all registered devices along with their usage and limits
        cursor.execute("""
            SELECT 
                rd.ip_address,
                ug.daily_limit_bytes,
                ug.monthly_limit_bytes,
                COALESCE((SELECT SUM(du.sent_bytes + du.received_bytes) FROM device_usage du WHERE du.mac_address = rd.mac_address AND du.timestamp >= ?), 0) AS daily_used,
                COALESCE((SELECT SUM(du.sent_bytes + du.received_bytes) FROM device_usage du WHERE du.mac_address = rd.mac_address AND du.timestamp >= ?), 0) AS monthly_used
            FROM registered_devices rd
            JOIN users u ON rd.username = u.username
            LEFT JOIN user_groups ug ON u.group_id = ug.id;
        """, (today_start, month_start))
        
        current_ips = set()
        for ip, d_limit, m_limit, d_used, m_used in cursor.fetchall():
            # If no limit is set (NULL), they are unlimited.
            # Otherwise, verify they haven't exceeded either limit.
            daily_ok = (d_limit is None or d_used < d_limit)
            monthly_ok = (m_limit is None or m_used < m_limit)
            if daily_ok and monthly_ok:
                current_ips.add(ip)
                
        conn.close()
    except Exception as e:
        print(f"[portal] DB read error: {e}", file=sys.stderr, flush=True)
        return
        
    if current_ips == last_allowed_ips:
        return
        
    print(f"[portal] Syncing firewall rules. Allowed IPs: {current_ips}", flush=True)
    
    # Clean Allow and NAT-redirect chains
    run_cmd("iptables -F NETTRACK-PORTAL-ALLOW 2>/dev/null")
    run_cmd("iptables -t nat -F NETTRACK-PORTAL-NAT 2>/dev/null")
    
    # Re-apply allow rules
    for ip in sorted(current_ips):
        run_cmd(f"iptables -A NETTRACK-PORTAL-ALLOW -s {ip} -j ACCEPT")
        run_cmd(f"iptables -A NETTRACK-PORTAL-ALLOW -d {ip} -j ACCEPT")
        run_cmd(f"iptables -t nat -A NETTRACK-PORTAL-NAT -s {ip} -j RETURN")
        
    # Block & Redirect HTTP to Portal Webpage for unregistered
    run_cmd(f"iptables -t nat -A NETTRACK-PORTAL-NAT -d {SERVER_IP} -j RETURN")
    run_cmd(f"iptables -t nat -A NETTRACK-PORTAL-NAT -p tcp --dport 80 -j DNAT --to-destination {SERVER_IP}:{PORT}")
    
    last_allowed_ips = current_ips

def cleanup():
    print("[portal] Cleaning up firewall rules...", flush=True)
    run_cmd("iptables -D INPUT -p tcp --dport 6054 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -D FORWARD -s 192.168.1.0/24 -j NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -D FORWARD -d 192.168.1.0/24 -j NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -t nat -D PREROUTING -j NETTRACK-PORTAL-NAT 2>/dev/null")
    run_cmd("iptables -F NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -F NETTRACK-PORTAL-ALLOW 2>/dev/null")
    run_cmd("iptables -X NETTRACK-PORTAL-ALLOW 2>/dev/null")
    run_cmd("iptables -X NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -t nat -F NETTRACK-PORTAL-NAT 2>/dev/null")
    run_cmd("iptables -t nat -X NETTRACK-PORTAL-NAT 2>/dev/null")

def main():
    if os.getuid() != 0:
        print("[portal] Error: must run as root.", file=sys.stderr)
        sys.exit(1)
        
    # Make sure DB exists
    if not os.path.exists(DB_PATH):
        import init_db
        init_db.init_database()
        
    init_firewall()
    
    try:
        while True:
            update_allowed_ips()
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()

if __name__ == "__main__":
    main()
