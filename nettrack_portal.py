#!/usr/bin/env python3
"""
NetTrack Captive Portal Daemon
==============================
Manages iptables firewall rules dynamically to block internet access for
unregistered devices and redirect them to the NetTrack registration page.
"""

import os
import sys
import time
import sqlite3
import subprocess

DB_PATH = "/var/lib/nettrack/nettrack.db"
PORTAL_PORT = 6054
SERVER_IP = "192.168.1.100"

def get_primary_interface():
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "route", "show", "default"],
            capture_output=True, text=True
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eno1"

IFACE = get_primary_interface()

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        # Check if it was just a silent clean-up delete rule (which returns exit code 1 if rule doesn't exist)
        if "delete" not in cmd.lower() and " 2>/dev/null" not in cmd:
            print(f"[portal] Command failed: {cmd}\nExit code: {e.returncode}\nStderr: {e.stderr}", file=sys.stderr, flush=True)
        return False
    except Exception as e:
        print(f"[portal] Command error: {cmd}\nException: {e}", file=sys.stderr, flush=True)
        return False

last_allowed_ips = None

def init_firewall():
    global last_allowed_ips
    last_allowed_ips = None
    print(f"[portal] Initializing Captive Portal firewall on {IFACE}...", flush=True)
    run_cmd("/home/ghesso/nettrack/debug_iptables.sh")
    
    # 1. Clean up existing custom chains to avoid duplicates
    run_cmd("iptables -F NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -F NETTRACK-PORTAL-ALLOW 2>/dev/null")
    run_cmd("iptables -t nat -F NETTRACK-PORTAL-NAT 2>/dev/null")
    
    run_cmd(f"iptables -D FORWARD -i {IFACE} -j NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -D FORWARD -j NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -t nat -D PREROUTING -j NETTRACK-PORTAL-NAT 2>/dev/null")
    
    run_cmd("iptables -X NETTRACK-PORTAL-ALLOW 2>/dev/null")
    run_cmd("iptables -X NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -t nat -X NETTRACK-PORTAL-NAT 2>/dev/null")
    
    # 2. Create custom chains
    run_cmd("iptables -N NETTRACK-PORTAL")
    run_cmd("iptables -N NETTRACK-PORTAL-ALLOW")
    run_cmd("iptables -t nat -N NETTRACK-PORTAL-NAT")
    
    # Link filter allow chain to execute first in FORWARD
    run_cmd("iptables -A NETTRACK-PORTAL -j NETTRACK-PORTAL-ALLOW")
    
    # 3. Insert chains at the very top of FORWARD and PREROUTING
    # Restrict to incoming physical interface only, so virtual bridges (Docker/Tailscale) bypass captive blocks
    run_cmd(f"iptables -I FORWARD 1 -i {IFACE} -j NETTRACK-PORTAL")
    run_cmd("iptables -t nat -I PREROUTING 1 -j NETTRACK-PORTAL-NAT")
    
    # Allow port 6054 in INPUT chain (bypasses UFW/firewalls for the local portal web server)
    run_cmd("iptables -D INPUT -p tcp --dport 6054 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 1 -p tcp --dport 6054 -j ACCEPT")
    
    # Allow port 6053 in INPUT chain (bypasses UFW/firewalls for the local DNS proxy server)
    run_cmd("iptables -D INPUT -p udp --dport 6053 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 1 -p udp --dport 6053 -j ACCEPT")
    run_cmd("iptables -D INPUT -p tcp --dport 6053 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 1 -p tcp --dport 6053 -j ACCEPT")
    
    # 4. Allow DNS queries (vital so registration page domain name can resolve)
    run_cmd("iptables -A NETTRACK-PORTAL -p udp --dport 53 -j ACCEPT")
    run_cmd("iptables -A NETTRACK-PORTAL -p tcp --dport 53 -j ACCEPT")
    
    # 5. Allow access to local server web dashboard/registration portal
    run_cmd(f"iptables -A NETTRACK-PORTAL -d {SERVER_IP} -p tcp --dport {PORTAL_PORT} -j ACCEPT")
    
    # 7. Block all other internet forwarding (like HTTPS on 443) by default for unregistered
    run_cmd(f"iptables -A NETTRACK-PORTAL -o {IFACE} -j DROP")

def update_allowed_ips():
    global last_allowed_ips
    import datetime
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Midnight timestamp today
        midnight = int(datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        
        # Query registered approved devices and their limits
        cursor.execute("""
        SELECT 
            di.ip_address, 
            u.username AS label,
            COALESCE(u.daily_limit_mb, 2048) * 1024 * 1024 AS limit_bytes,
            COALESCE(
                (SELECT SUM(sent_bytes + received_bytes) 
                 FROM device_usage 
                 WHERE (ip_address = di.ip_address OR mac_address = dm.mac_address) 
                   AND hour_timestamp >= ?), 
                0
            ) AS total_today
        FROM devices d
        JOIN users u ON d.user_id = u.id
        JOIN device_macs dm ON dm.device_id = d.id
        JOIN device_ips di ON di.device_id = d.id
        WHERE d.approved = 1
          AND di.ip_address != '' AND di.ip_address IS NOT NULL
          AND dm.mac_address NOT IN (SELECT mac_address FROM blocked_devices);
        """, (midnight,))
        
        rows = cursor.fetchall()
        registered_ips = set()
        
        for ip, label, limit_bytes, total_today in rows:
            if total_today < limit_bytes:
                registered_ips.add(ip)
            else:
                print(f"[portal] Blocking {ip} ({label}) - daily limit exceeded ({total_today}/{limit_bytes} bytes)", flush=True)
        
        # Also always allow the server itself
        registered_ips.add(SERVER_IP)
        
        conn.close()
    except Exception as exc:
        print(f"[portal] DB query error: {exc}", file=sys.stderr, flush=True)
        return

    # Check if the set of allowed IPs has changed to avoid pegging CPU with redundant iptables updates
    if last_allowed_ips == registered_ips:
        return
    
    last_allowed_ips = registered_ips
    print(f"[portal] Updating firewall: {len(registered_ips)} allowed IPs: {sorted(list(registered_ips))}", flush=True)


    # Flush allowed rules from custom chains
    run_cmd("iptables -F NETTRACK-PORTAL-ALLOW")
    run_cmd("iptables -t nat -F NETTRACK-PORTAL-NAT")
    
    # 1. Populate the NAT chain with DNS redirection first
    run_cmd(f"iptables -t nat -A NETTRACK-PORTAL-NAT -p udp --dport 53 -j DNAT --to-destination {SERVER_IP}:6053")
    run_cmd(f"iptables -t nat -A NETTRACK-PORTAL-NAT -p tcp --dport 53 -j DNAT --to-destination {SERVER_IP}:6053")
    
    # 2. Add allow rules for all registered IPs
    for ip in sorted(registered_ips):
        # Allow internet traffic forwarding (Filter table)
        run_cmd(f"iptables -A NETTRACK-PORTAL-ALLOW -s {ip} -j ACCEPT")
        run_cmd(f"iptables -A NETTRACK-PORTAL-ALLOW -d {ip} -j ACCEPT")
        # Bypass HTTP redirection (NAT table - RETURN from NETTRACK-PORTAL-NAT back to PREROUTING)
        run_cmd(f"iptables -t nat -A NETTRACK-PORTAL-NAT -s {ip} -j RETURN")
        
    # 3. Add HTTP redirect rule at the very end of the NAT chain for unregistered/blocked devices
    run_cmd(f"iptables -t nat -A NETTRACK-PORTAL-NAT -p tcp --dport 80 -j DNAT --to-destination {SERVER_IP}:{PORTAL_PORT}")

def cleanup():
    print("[portal] Cleaning up firewall rules...", flush=True)
    run_cmd("iptables -D INPUT -p tcp --dport 6054 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -D INPUT -p udp --dport 6053 -j ACCEPT 2>/dev/null")
    run_cmd("iptables -D INPUT -p tcp --dport 6053 -j ACCEPT 2>/dev/null")
    run_cmd(f"iptables -D FORWARD -i {IFACE} -j NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -D FORWARD -j NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -t nat -D PREROUTING -j NETTRACK-PORTAL-NAT 2>/dev/null")
    run_cmd("iptables -F NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -F NETTRACK-PORTAL-ALLOW 2>/dev/null")
    run_cmd("iptables -X NETTRACK-PORTAL-ALLOW 2>/dev/null")
    run_cmd("iptables -X NETTRACK-PORTAL 2>/dev/null")
    run_cmd("iptables -t nat -F NETTRACK-PORTAL-NAT 2>/dev/null")
    run_cmd("iptables -t nat -X NETTRACK-PORTAL-NAT 2>/dev/null")

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create normalized tables first
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            daily_limit_mb INTEGER DEFAULT 2048
        );
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            device_name TEXT NOT NULL,
            floor TEXT NOT NULL DEFAULT '',
            device_type TEXT NOT NULL DEFAULT '',
            cookie_uuid TEXT,
            is_low_end INTEGER DEFAULT 0,
            approved INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_macs (
            mac_address TEXT PRIMARY KEY,
            device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE
        );
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_ips (
            ip_address TEXT PRIMARY KEY,
            device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
            mac_address TEXT REFERENCES device_macs(mac_address) ON DELETE SET NULL,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS registered_devices (
            device_uuid TEXT PRIMARY KEY,
            label       TEXT NOT NULL,
            floor       TEXT NOT NULL,
            device_type TEXT NOT NULL
        );
        """)
        
        # User limits table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_limits (
            label TEXT PRIMARY KEY,
            daily_limit_mb INTEGER DEFAULT 2048
        );
        """)
        
        # Blocked devices table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_devices (
            mac_address TEXT PRIMARY KEY,
            reason      TEXT,
            blocked_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"[portal] DB init error: {exc}", file=sys.stderr, flush=True)

if __name__ == "__main__":
    if os.getuid() != 0:
        print("[portal] Error: must run as root.", file=sys.stderr)
        sys.exit(1)
        
    init_db()
    init_firewall()
    
    print("[portal] Captive portal running. Monitoring registrations...", flush=True)
    
    try:
        while True:
            update_allowed_ips()
            # Check every 1 second for new registrations
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()
