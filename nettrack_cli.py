#!/usr/bin/env python3
import os
import sys
import sqlite3
import datetime
import argparse
import urllib.parse
import subprocess
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler

DB_PATH = "/var/lib/nettrack/nettrack.db"
dns_cache = {}

def get_website_domain(ip):
    if not ip or ip == "0.0.0.0":
        return ""
    if ip.startswith("192.168.1.") or ip == "127.0.0.1":
        return "Local Network"
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        socket.setdefaulttimeout(0.5)
        hostname, _, _ = socket.gethostbyaddr(ip)
        dns_cache[ip] = hostname
        return hostname
    except Exception:
        dns_cache[ip] = ip
        return ip

def format_bytes(n):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"

def normalize_mac(mac):
    try:
        parts = mac.split(':')
        if len(parts) == 6:
            return ":".join(f"{int(p, 16):02x}" for p in parts)
    except Exception:
        pass
    return mac.lower().strip()

def get_mac_from_arp(ip):
    # Try resolving MAC from DHCP leases first to get the client's real MAC
    try:
        if os.path.exists("/var/lib/misc/dnsmasq.leases"):
            with open("/var/lib/misc/dnsmasq.leases", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[2] == ip:
                        return normalize_mac(parts[1])
    except Exception:
        pass

    # Fallback to local ARP table
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == ip:
                mac = parts[3]
                if mac and mac != "00:00:00:00:00:00":
                    return normalize_mac(mac)
    except Exception:
        pass
    return "unknown"

def get_active_leases():
    leases = []
    try:
        if os.path.exists("/var/lib/misc/dnsmasq.leases"):
            with open("/var/lib/misc/dnsmasq.leases", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        leases.append({
                            'mac': normalize_mac(parts[1]),
                            'ip': parts[2],
                            'hostname': parts[3]
                        })
    except Exception:
        pass
    return leases

def get_static_reservations():
    reservations = []
    try:
        if os.path.exists("/etc/nettrack_static_leases.conf"):
            with open("/etc/nettrack_static_leases.conf", "r") as f:
                for line in f:
                    if line.startswith("dhcp-host="):
                        val = line.strip().split("=")[1]
                        parts = val.split(",")
                        if len(parts) >= 2:
                            mac = normalize_mac(parts[0])
                            ip = parts[1]
                            hostname = parts[2] if len(parts) >= 3 else "Unknown"
                            reservations.append({'mac': mac, 'ip': ip, 'hostname': hostname})
    except Exception:
        pass
    return reservations

def get_billing_start():
    import datetime
    today = datetime.date.today()
    if today.day >= 28:
        start_date = today.replace(day=28)
    else:
        if today.month == 1:
            start_date = today.replace(year=today.year - 1, month=12, day=28)
        else:
            start_date = today.replace(month=today.month - 1, day=28)
    return start_date.strftime('%Y-%m-%d 00:00:00')

def get_effective_user_limits():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Fetch global pool
        cursor.execute("SELECT value FROM settings WHERE key = 'global_pool_bytes';")
        row = cursor.fetchone()
        global_pool = int(row[0]) if row else 1073741824000
        
        # Fetch all users with their group default limits, custom limits, and addons
        cursor.execute("""
            SELECT 
                u.username,
                ug.monthly_limit_bytes AS group_monthly,
                u.monthly_limit_bytes AS custom_monthly,
                COALESCE((SELECT SUM(addon_bytes) FROM user_addons WHERE username = u.username), 0) AS addons
            FROM users u
            LEFT JOIN user_groups ug ON u.group_id = ug.id;
        """)
        users_data = cursor.fetchall()
        conn.close()
        
        specific_users = {}
        default_users = {}
        total_specific = 0
        total_default_original = 0
        sum_group_defaults = 0
        
        for username, group_monthly, custom_monthly, addons in users_data:
            group_monthly = group_monthly or 0
            if custom_monthly is not None:
                specific_users[username] = (custom_monthly, addons)
                total_specific += custom_monthly + addons
            else:
                default_users[username] = (group_monthly, addons)
                total_default_original += group_monthly + addons
                sum_group_defaults += group_monthly
                
        total_allocated = total_specific + total_default_original
        effective_limits = {}
        
        if total_allocated > global_pool:
            # Redistribute remaining pool to default users relatively
            remaining_pool = max(global_pool - total_specific, 0)
            
            for username, (custom_monthly, addons) in specific_users.items():
                effective_limits[username] = custom_monthly + addons
                
            for username, (group_monthly, addons) in default_users.items():
                if sum_group_defaults > 0:
                    share = (group_monthly / sum_group_defaults) * remaining_pool
                else:
                    share = 0
                effective_limits[username] = int(share) + addons
        else:
            for username, group_monthly, custom_monthly, addons in users_data:
                base = custom_monthly if custom_monthly is not None else (group_monthly or 0)
                effective_limits[username] = base + addons
                
        return effective_limits
    except Exception as e:
        print(f"[web] Error calculating effective limits: {e}")
        return {}

class WebServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def get_registered_user(self, ip, mac):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM registered_devices WHERE mac_address = ?;", (mac,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return row[0]
        except Exception:
            pass
        return None

    def check_device_limits(self, ip, mac):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            today_start = datetime.date.today().strftime('%Y-%m-%d 00:00:00')
            month_start = get_billing_start()
            
            cursor.execute("""
                SELECT 
                    rd.username,
                    COALESCE(u.daily_limit_bytes, ug.daily_limit_bytes) AS d_limit,
                    COALESCE((SELECT SUM(du.sent_bytes + du.received_bytes) FROM device_usage du WHERE du.mac_address = rd.mac_address AND du.timestamp >= ?), 0) AS daily_used,
                    COALESCE((SELECT SUM(du.sent_bytes + du.received_bytes) FROM device_usage du WHERE du.mac_address = rd.mac_address AND du.timestamp >= ?), 0) AS monthly_used,
                    EXISTS(SELECT 1 FROM quota_bypasses WHERE mac_address = rd.mac_address) AS warning_bypassed
                FROM registered_devices rd
                JOIN users u ON rd.username = u.username
                LEFT JOIN user_groups ug ON u.group_id = ug.id
                WHERE rd.mac_address = ?;
            """, (today_start, month_start, mac))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                username, d_limit, d_used, m_used, warning_bypassed = row
                effective_limits = get_effective_user_limits()
                m_limit = effective_limits.get(username)
                
                # Check 100% daily
                if d_limit is not None and d_limit > 0 and d_used >= d_limit:
                    return True, f"Daily limit of {format_bytes(d_limit)} exceeded (Used: {format_bytes(d_used)})", False
                # Check 100% monthly
                if m_limit is not None and m_limit > 0 and m_used >= m_limit:
                    return True, f"Monthly limit of {format_bytes(m_limit)} exceeded (Used: {format_bytes(m_used)})", False
                # Check 80% daily
                if d_limit is not None and d_limit > 0 and d_used >= d_limit * 0.8 and not warning_bypassed:
                    return True, f"You have reached {int((d_used/d_limit)*100)}% of your daily quota ({format_bytes(d_used)} of {format_bytes(d_limit)}).", True
                # Check 80% monthly
                if m_limit is not None and m_limit > 0 and m_used >= m_limit * 0.8 and not warning_bypassed:
                    return True, f"You have reached {int((m_used/m_limit)*100)}% of your monthly quota ({format_bytes(m_used)} of {format_bytes(m_limit)}).", True
        except Exception as e:
            print(f"[web] Error checking limits: {e}")
        return False, "", False

    def serve_limited_page(self, reason, show_skip=False, mac=""):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        skip_button_html = ""
        if show_skip and mac:
            skip_button_html = f"""
            <div style="margin-top:20px; border-top:1px solid #ccc; padding-top:15px; text-align:center;">
                <p style="font-size:13px; color:#555;">You can bypass this warning temporarily and continue using the internet up to 100% of your quota.</p>
                <a href="/api/bypass_warning?mac={mac}" style="display: inline-block; background: #6366f1; color: #fff; text-decoration: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; font-family: monospace; font-size:14px; border:1px solid rgba(0,0,0,0.1); box-shadow: 2px 2px 0px #000; transition: background 0.2s;">SKIP WARNING & CONTINUE</a>
            </div>
            """
            
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Usage Warning / Limited</title>
    <style>
        body {{ font-family: monospace; background: #fafafa; color: #111; padding: 40px; text-align: center; }}
        .container {{ max-width: 450px; margin: 0 auto; background: #fff; border: 1px solid #ccc; padding: 25px; text-align: left; box-shadow: 2px 2px 0px #000; }}
        h2 {{ border-bottom: 2px solid #000; padding-bottom: 10px; margin-top: 0; font-size: 16px; text-transform: uppercase; }}
        p {{ line-height: 1.5; font-size: 14px; }}
        .reason {{ background: #eee; padding: 10px; border-left: 3px solid #000; font-size: 13px; margin: 15px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Usage Restriction</h2>
        <p>Access to the internet has been restricted for this device due to quota limits.</p>
        <div class="reason">
            <strong>Warning/Limit:</strong> {reason}
        </div>
        {skip_button_html}
        <p style="font-size:12px; color:#777; margin-top:20px;">Please contact the network administrator to request a limit increase or buy a monthly addon package.</p>
    </div>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

    def do_GET(self):
        client_ip = self.client_address[0]
        client_mac = get_mac_from_arp(client_ip)
        
        registered_user = self.get_registered_user(client_ip, client_mac)
        is_local = (client_ip == "127.0.0.1" or client_ip == "192.168.1.100")
        
        if not registered_user and not is_local:
            if self.path == "/" or self.path == "/register":
                self.serve_registration_page(client_ip, client_mac)
            else:
                self.send_response(302)
                self.send_header("Location", "http://192.168.1.100:6054/")
                self.end_headers()
            return

        if registered_user and not is_local:
            is_limited, reason, show_skip = self.check_device_limits(client_ip, client_mac)
            if is_limited:
                self.serve_limited_page(reason, show_skip, client_mac)
                return

        if self.path == "/":
            if registered_user and registered_user.lower() == "ghassan":
                self.serve_admin_dashboard(registered_user)
            elif is_local:
                self.serve_admin_dashboard("Admin")
            else:
                self.serve_client_status_page(registered_user, client_ip, client_mac)
        elif self.path == "/vault":
            self.serve_vault_page()
        elif self.path.startswith("/api/deassociate"):
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            mac_to_remove = params.get('mac', [''])[0].strip().lower()
            if mac_to_remove:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM registered_devices WHERE mac_address = ?;", (mac_to_remove,))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path.startswith("/api/bypass_warning"):
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            mac = normalize_mac(params.get('mac', [''])[0].strip())
            if mac:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("INSERT OR REPLACE INTO quota_bypasses (mac_address) VALUES (?);", (mac,))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print(f"Error inserting bypass: {e}")
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path.startswith("/api/dhcp/preserve_device"):
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            mac = normalize_mac(params.get('mac', [''])[0].strip())
            ip = params.get('ip', [''])[0].strip()
            name = params.get('name', [''])[0].strip() or "client"
            
            # Sanitize name to be a valid hostname
            hostname = "".join(c if c.isalnum() or c == '-' else '-' for c in name).strip('-').lower() or "device"
            
            if mac and ip:
                try:
                    if os.path.exists("/etc/nettrack_static_leases.conf"):
                        with open("/etc/nettrack_static_leases.conf", "r") as f:
                            lines = f.readlines()
                        with open("/etc/nettrack_static_leases.conf", "w") as f:
                            for line in lines:
                                if not line.startswith(f"dhcp-host={mac}"):
                                    f.write(line)
                                    
                    with open("/etc/nettrack_static_leases.conf", "a") as f:
                        f.write(f"dhcp-host={mac},{ip},{hostname},infinite\n")
                        
                    subprocess.run("systemctl restart dnsmasq", shell=True)
                except Exception as e:
                    print(f"Error preserving static lease: {e}")
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            
        elif self.path.startswith("/api/dhcp/remove"):
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            mac_to_remove = normalize_mac(params.get('mac', [''])[0].strip())
            
            if mac_to_remove and os.path.exists("/etc/nettrack_static_leases.conf"):
                try:
                    with open("/etc/nettrack_static_leases.conf", "r") as f:
                        lines = f.readlines()
                    with open("/etc/nettrack_static_leases.conf", "w") as f:
                        for line in lines:
                            if not line.startswith(f"dhcp-host={mac_to_remove}"):
                                f.write(line)
                    subprocess.run("systemctl restart dnsmasq", shell=True)
                except Exception as e:
                    print(f"Error removing static lease: {e}")
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path.startswith("/api/dhcp/clear_lease"):
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            mac = normalize_mac(params.get('mac', [''])[0].strip())
            if mac:
                try:
                    subprocess.run("systemctl stop dnsmasq", shell=True)
                    leases_file = "/var/lib/misc/dnsmasq.leases"
                    if os.path.exists(leases_file):
                        with open(leases_file, "r") as f:
                            lines = f.readlines()
                        with open(leases_file, "w") as f:
                            for line in lines:
                                parts = line.strip().split()
                                if len(parts) >= 2 and normalize_mac(parts[1]) != mac:
                                    f.write(line)
                    subprocess.run("systemctl start dnsmasq", shell=True)
                except Exception as e:
                    print(f"Error clearing dynamic lease: {e}")
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        client_ip = self.client_address[0]
        client_mac = get_mac_from_arp(client_ip)
        
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)

        if self.path == "/register":
            username = params.get('username', [''])[0].strip()
            password = params.get('password', [''])[0].strip()
            
            # Enforce password policy:
            # - 'Ghassan' (case-insensitive) requires '1234G'
            # - All other users require '123'
            expected_password = "1234G" if username.lower() == "ghassan" else "123"
            if password != expected_password:
                self.serve_registration_page(client_ip, client_mac, f"Invalid password for user {username}.")
                return
                
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                
                cursor.execute("SELECT id FROM user_groups WHERE name = 'Standard';")
                std_group = cursor.fetchone()
                std_group_id = std_group[0] if std_group else None
                
                cursor.execute("SELECT password FROM users WHERE username = ?;", (username,))
                row = cursor.fetchone()
                
                if row:
                    if row[0] != password:
                        # Automatically update user password in DB to match the rule policy
                        cursor.execute("UPDATE users SET password = ? WHERE username = ?;", (password, username))
                else:
                    cursor.execute("INSERT INTO users (username, password, group_id) VALUES (?, ?, ?);", (username, password, std_group_id))
                
                cursor.execute("""
                INSERT OR REPLACE INTO registered_devices (mac_address, ip_address, username)
                VALUES (?, ?, ?);
                """, (client_mac, client_ip, username))
                
                conn.commit()
                conn.close()
                
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                
            except Exception as e:
                self.serve_registration_page(client_ip, client_mac, f"Database error: {e}")
                
        elif self.path == "/groups/create":
            name = params.get('name', [''])[0].strip()
            daily_gb = float(params.get('daily_gb', [2])[0])
            monthly_gb = float(params.get('monthly_gb', [60])[0])
            
            daily_bytes = int(daily_gb * 1024 * 1024 * 1024)
            monthly_bytes = int(monthly_gb * 1024 * 1024 * 1024)
            
            if name:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO user_groups (name, daily_limit_bytes, monthly_limit_bytes)
                        VALUES (?, ?, ?);
                    """, (name, daily_bytes, monthly_bytes))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            
        elif self.path == "/users/assign":
            username = params.get('username', [''])[0].strip()
            group_id = params.get('group_id', [''])[0].strip()
            
            if username and group_id:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET group_id = ? WHERE username = ?;", (group_id, username))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            
        elif self.path == "/device/rename":
            mac = normalize_mac(params.get('mac', [''])[0].strip())
            name = params.get('name', [''])[0].strip()
            
            if mac and name:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("UPDATE registered_devices SET device_name = ? WHERE mac_address = ?;", (name, mac))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            
        elif self.path == "/dhcp/reserve":
            mac = normalize_mac(params.get('mac', [''])[0].strip())
            ip = params.get('ip', [''])[0].strip()
            hostname = params.get('hostname', [''])[0].strip()
            
            if mac and ip and hostname:
                try:
                    # Remove any existing lease for this MAC
                    if os.path.exists("/etc/nettrack_static_leases.conf"):
                        with open("/etc/nettrack_static_leases.conf", "r") as f:
                            lines = f.readlines()
                        with open("/etc/nettrack_static_leases.conf", "w") as f:
                            for line in lines:
                                if not line.startswith(f"dhcp-host={mac}"):
                                    f.write(line)
                                    
                    # Append new reservation
                    with open("/etc/nettrack_static_leases.conf", "a") as f:
                        f.write(f"dhcp-host={mac},{ip},{hostname},infinite\n")
                        
                    # Restart dnsmasq to apply DHCP bindings
                    subprocess.run("systemctl restart dnsmasq", shell=True)
                except Exception as e:
                    print(f"Error writing static reservation: {e}")
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            
        elif self.path == "/users/configure_limits":
            username = params.get('username', [''])[0].strip()
            daily_gb_str = params.get('daily_gb', [''])[0].strip()
            monthly_gb_str = params.get('monthly_gb', [''])[0].strip()
            suggested_daily_gb_str = params.get('suggested_daily_gb', [''])[0].strip()
            suggested_monthly_gb_str = params.get('suggested_monthly_gb', [''])[0].strip()
            
            daily_bytes = int(float(daily_gb_str) * 1024 * 1024 * 1024) if daily_gb_str else None
            monthly_bytes = int(float(monthly_gb_str) * 1024 * 1024 * 1024) if monthly_gb_str else None
            suggested_daily_bytes = int(float(suggested_daily_gb_str) * 1024 * 1024 * 1024) if suggested_daily_gb_str else None
            suggested_monthly_bytes = int(float(suggested_monthly_gb_str) * 1024 * 1024 * 1024) if suggested_monthly_gb_str else None
            
            if username:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE users 
                        SET daily_limit_bytes = ?, monthly_limit_bytes = ?, 
                            suggested_daily_limit_bytes = ?, suggested_monthly_limit_bytes = ?
                        WHERE username = ?;
                    """, (daily_bytes, monthly_bytes, suggested_daily_bytes, suggested_monthly_bytes, username))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print(f"Error configuring user limits: {e}")
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()

        elif self.path == "/users/buy_addon":
            username = params.get('username', [''])[0].strip()
            addon_gb = float(params.get('addon_gb', [0])[0])
            addon_bytes = int(addon_gb * 1024 * 1024 * 1024)
            
            if username and addon_bytes > 0:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO user_addons (username, addon_bytes)
                        VALUES (?, ?);
                    """, (username, addon_bytes))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print(f"Error buying addon: {e}")
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path == "/settings/update":
            global_pool_gb = float(params.get('global_pool_gb', [1000])[0])
            global_pool_bytes = int(global_pool_gb * 1024 * 1024 * 1024)
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('global_pool_bytes', ?);", (str(global_pool_bytes),))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Error updating global pool setting: {e}")
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def serve_registration_page(self, ip, mac, error_msg=None):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        error_html = f'<div style="color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2); background: rgba(239, 68, 68, 0.05); padding: 10px; border-radius: 6px; font-size: 13px; font-weight: 600; margin-bottom: 15px;">{error_msg}</div>' if error_msg else ''
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Network Access Authentication</title>
    <style>
        body {{
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #0f172a;
            color: #f1f5f9;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
            box-sizing: border-box;
        }}
        .card {{
            background: rgba(30, 41, 59, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 30px;
            width: 100%;
            max-width: 380px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(12px);
        }}
        .header {{
            text-align: center;
            margin-bottom: 24px;
        }}
        .header svg {{
            width: 48px;
            height: 48px;
            fill: none;
            stroke: #6366f1;
            stroke-width: 2;
            stroke-linecap: round;
            stroke-linejoin: round;
            margin-bottom: 12px;
        }}
        .header h2 {{
            margin: 0;
            font-size: 20px;
            font-weight: 700;
            letter-spacing: 0.5px;
            color: #fff;
        }}
        .header p {{
            margin: 6px 0 0 0;
            font-size: 13px;
            color: #94a3b8;
        }}
        .field {{
            margin-bottom: 18px;
        }}
        label {{
            display: block;
            font-size: 11px;
            font-weight: 600;
            color: #94a3b8;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        input[type="text"], input[type="password"] {{
            width: 100%;
            padding: 10px 12px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 6px;
            color: #fff;
            font-size: 14px;
            box-sizing: border-box;
            outline: none;
            transition: border-color 0.2s;
        }}
        input[type="text"]:focus, input[type="password"]:focus {{
            border-color: #6366f1;
        }}
        input[type="submit"] {{
            background: #6366f1;
            color: #fff;
            border: none;
            padding: 12px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: background 0.2s;
            margin-top: 10px;
        }}
        input[type="submit"]:hover {{
            background: #4f46e5;
        }}
        .meta-info {{
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 20px;
            font-family: monospace;
            font-size: 12px;
            color: #94a3b8;
            line-height: 1.6;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <svg viewBox="0 0 24 24">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
            <h2>Portal Authentication</h2>
            <p>Please register this device to access the network</p>
        </div>
        {error_html}
        <div class="meta-info">
            IP: {ip}<br>
            MAC: {mac}
        </div>
        <form method="POST" action="/register">
            <div class="field">
                <label for="username">Username / Name</label>
                <input type="text" id="username" name="username" required autocomplete="off">
            </div>
            <div class="field">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <input type="submit" value="Authenticate Device">
        </form>
    </div>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

    def serve_client_status_page(self, username, ip, mac):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        daily_used, monthly_used = 0, 0
        d_limit, m_limit = None, None
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            today_start = datetime.date.today().strftime('%Y-%m-%d 00:00:00')
            month_start = datetime.date.today().replace(day=1).strftime('%Y-%m-%d 00:00:00')
            
            cursor.execute("""
                SELECT 
                    ug.daily_limit_bytes,
                    ug.monthly_limit_bytes,
                    COALESCE((SELECT SUM(du.sent_bytes + du.received_bytes) FROM device_usage du WHERE du.mac_address = rd.mac_address AND du.timestamp >= ?), 0) AS daily_used,
                    COALESCE((SELECT SUM(du.sent_bytes + du.received_bytes) FROM device_usage du WHERE du.mac_address = rd.mac_address AND du.timestamp >= ?), 0) AS monthly_used
                FROM registered_devices rd
                JOIN users u ON rd.username = u.username
                LEFT JOIN user_groups ug ON u.group_id = ug.id
                WHERE rd.mac_address = ?;
            """, (today_start, month_start, mac))
            row = cursor.fetchone()
            conn.close()
            if row:
                d_limit, m_limit, daily_used, monthly_used = row
        except Exception:
            pass

        d_limit_str = format_bytes(d_limit) if d_limit else "Unlimited"
        m_limit_str = format_bytes(m_limit) if m_limit else "Unlimited"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Network Access Status</title>
    <style>
        body {{
            margin: 0;
            font-family: monospace;
            background: #0f172a;
            color: #f1f5f9;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
            box-sizing: border-box;
        }}
        .card {{
            background: rgba(30, 41, 59, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 30px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(12px);
        }}
        .header {{
            text-align: center;
            margin-bottom: 24px;
        }}
        .status-badge {{
            display: inline-block;
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.4);
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-bottom: 15px;
            text-transform: uppercase;
        }}
        h2 {{ margin: 0; font-size: 18px; font-weight: 700; color: #fff; }}
        p {{ margin: 6px 0 0 0; font-size: 13px; color: #94a3b8; }}
        .stats-section {{
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            font-size: 13px;
        }}
        .stat-row {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }}
        .stat-row:last-child {{ margin-bottom: 0; }}
        .stat-label {{ color: #94a3b8; }}
        .stat-value {{ font-weight: bold; color: #fff; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <div class="status-badge">Connected</div>
            <h2>Device Status</h2>
            <p>Welcome back, <strong>{username}</strong></p>
        </div>
        <div class="stats-section">
            <div class="stat-row">
                <span class="stat-label">Device IP</span>
                <span class="stat-value">{ip}</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Device MAC</span>
                <span class="stat-value">{mac}</span>
            </div>
        </div>
        <div class="stats-section">
            <div class="stat-row">
                <span class="stat-label">Daily Usage</span>
                <span class="stat-value">{format_bytes(daily_used)} / {d_limit_str}</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Monthly Usage</span>
                <span class="stat-value">{format_bytes(monthly_used)} / {m_limit_str}</span>
            </div>
        </div>
    </div>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

    def serve_admin_dashboard(self, current_user):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        devices_list = []
        process_list = []
        groups_list = []
        users_list = []
        overall_today = 0
        overall_mtd = 0
        overall_total = 0
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Fetch groups
            cursor.execute("SELECT id, name, daily_limit_bytes, monthly_limit_bytes FROM user_groups;")
            groups_data = cursor.fetchall()
            for gid, name, dl, ml in groups_data:
                # Sum the usage of all devices owned by users in this group since month_start
                month_start_temp = get_billing_start()
                cursor.execute("""
                    SELECT SUM(du.sent_bytes + du.received_bytes)
                    FROM device_usage du
                    JOIN registered_devices rd ON du.mac_address = rd.mac_address
                    JOIN users u ON rd.username = u.username
                    WHERE u.group_id = ? AND du.timestamp >= ?;
                """, (gid, month_start_temp))
                group_usage = cursor.fetchone()[0] or 0
                
                # Count distinct users and devices in this group
                cursor.execute("SELECT COUNT(DISTINCT username) FROM users WHERE group_id = ?;", (gid,))
                user_count = cursor.fetchone()[0] or 0
                cursor.execute("SELECT COUNT(*) FROM registered_devices rd JOIN users u ON rd.username = u.username WHERE u.group_id = ?;", (gid,))
                device_count = cursor.fetchone()[0] or 0
                
                groups_list.append({
                    'id': gid, 'name': name,
                    'daily': format_bytes(dl) if dl else "Unlimited",
                    'monthly': format_bytes(ml) if ml else "Unlimited",
                    'usage': format_bytes(group_usage),
                    'users_devices': f"{user_count} Users / {device_count} Devices"
                })
                
            # Fetch users with limits, suggested limits, and addons
            cursor.execute("""
                SELECT 
                    u.username, 
                    g.name, 
                    g.id,
                    u.daily_limit_bytes,
                    u.monthly_limit_bytes,
                    COALESCE((SELECT SUM(addon_bytes) FROM user_addons WHERE username = u.username), 0) AS total_addons
                FROM users u 
                LEFT JOIN user_groups g ON u.group_id = g.id;
            """)
            # Fetch global pool setting
            cursor.execute("SELECT value FROM settings WHERE key = 'global_pool_bytes';")
            gp_row = cursor.fetchone()
            global_pool_bytes = int(gp_row[0]) if gp_row else 1073741824000
            
            # Fetch total allocated bytes (intended)
            cursor.execute("""
                SELECT SUM(
                    COALESCE(u.monthly_limit_bytes, ug.monthly_limit_bytes) + 
                    COALESCE((SELECT SUM(addon_bytes) FROM user_addons WHERE username = u.username), 0)
                ) FROM users u 
                LEFT JOIN user_groups ug ON u.group_id = ug.id;
            """)
            total_allocated_bytes = cursor.fetchone()[0] or 0

            # Fetch total assigned specifically to users (excluding group defaults)
            cursor.execute("""
                SELECT SUM(
                    COALESCE(u.monthly_limit_bytes, 0) + 
                    COALESCE((SELECT SUM(addon_bytes) FROM user_addons WHERE username = u.username), 0)
                ) FROM users u 
                WHERE u.monthly_limit_bytes IS NOT NULL;
            """)
            sum_specific_user_bytes = cursor.fetchone()[0] or 0
            specific_remaining_bytes = max(global_pool_bytes - sum_specific_user_bytes, 0)
            specific_remaining_gb = specific_remaining_bytes / (1024 * 1024 * 1024)

            # Get effective redistributed limits
            effective_limits = get_effective_user_limits()

            # Fetch users with limits, suggested limits, and addons
            cursor.execute("""
                SELECT 
                    u.username, 
                    g.name, 
                    g.id,
                    u.daily_limit_bytes,
                    u.monthly_limit_bytes,
                    COALESCE((SELECT SUM(addon_bytes) FROM user_addons WHERE username = u.username), 0) AS total_addons
                FROM users u 
                LEFT JOIN user_groups g ON u.group_id = g.id;
            """)
            for row in cursor.fetchall():
                username, gname, gid, dl, ml, addons = row
                
                # Dynamic heuristic suggestion: average daily usage of user's devices over past 7 days * 1.5
                cursor.execute("SELECT mac_address FROM registered_devices WHERE username = ?;", (username,))
                macs = [r[0] for r in cursor.fetchall()]
                if macs:
                    placeholders = ",".join(["?"] * len(macs))
                    cursor.execute(f"""
                        SELECT SUM(sent_bytes + received_bytes)
                        FROM device_usage
                        WHERE mac_address IN ({placeholders})
                          AND timestamp >= datetime('now', '-7 days');
                    """, macs)
                    total_7days = cursor.fetchone()[0] or 0
                    avg_daily = total_7days / 7.0
                    heuristic_daily = max(int(avg_daily * 1.5), 2 * 1024*1024*1024) # minimum 2 GB
                    heuristic_monthly = max(int(avg_daily * 30 * 1.5), 60 * 1024*1024*1024) # minimum 60 GB
                else:
                    heuristic_daily = 2 * 1024*1024*1024
                    heuristic_monthly = 60 * 1024*1024*1024

                # Determine if user limit got redistributed
                actual_monthly = effective_limits.get(username, 0)
                is_redistributed = (ml is None) and (total_allocated_bytes > global_pool_bytes)
                
                monthly_limit_str = format_bytes(actual_monthly)
                if is_redistributed:
                    monthly_limit_str += " (Redistributed)"

                users_list.append({
                    'username': username,
                    'group_name': gname or "None",
                    'group_id': gid,
                    'daily_limit': format_bytes(dl) if dl else "Group Default",
                    'monthly_limit': monthly_limit_str,
                    'suggested_daily': format_bytes(heuristic_daily),
                    'suggested_monthly': format_bytes(heuristic_monthly),
                    'addons': format_bytes(addons) if addons else "0 B"
                })
                
            distribution_list = []
            for u in users_list:
                actual_alloc = effective_limits.get(u['username'], 0)
                share_pct = (actual_alloc / global_pool_bytes) * 100 if global_pool_bytes > 0 else 0
                
                distribution_list.append({
                    'username': u['username'],
                    'total_alloc': actual_alloc,
                    'allocation_str': format_bytes(actual_alloc) if actual_alloc > 0 else "Unlimited",
                    'share_str': f"{share_pct:.1f}%" if actual_alloc > 0 else "N/A"
                })
            distribution_list.sort(key=lambda x: x['total_alloc'], reverse=True)
            
            distribution_rows_html = "".join([f"""
            <tr>
                <td><strong>{d['username']}</strong></td>
                <td>{d['allocation_str']}</td>
                <td>{d['share_str']}</td>
            </tr>""" for d in distribution_list])
            
            # Fetch registered devices
            cursor.execute("SELECT mac_address, ip_address, username, registered_at, device_name FROM registered_devices;")
            registered_devices = cursor.fetchall()
            
            # Fetch aggregate device usage
            cursor.execute("""
                SELECT mac_address, SUM(sent_bytes), SUM(received_bytes)
                FROM device_usage GROUP BY mac_address;
            """)
            device_traffic = {row[0]: (row[1], row[2]) for row in cursor.fetchall()}
            
            for mac, ip, user, reg_at, dname in registered_devices:
                sent, recv = device_traffic.get(mac, (0, 0))
                devices_list.append({
                    'mac': mac, 'ip': ip, 'user': user, 'reg_at': reg_at, 'name': dname or "Unnamed Device",
                    'sent': format_bytes(sent), 'recv': format_bytes(recv),
                    'total_bytes': sent + recv
                })
                
            # Fetch process usage
            cursor.execute("""
                SELECT process_name, SUM(sent_bytes), SUM(received_bytes)
                FROM hourly_usage GROUP BY process_name
                ORDER BY (SUM(sent_bytes) + SUM(received_bytes)) DESC LIMIT 10;
            """)
            for row in cursor.fetchall():
                process_list.append({
                    'name': row[0], 'sent': format_bytes(row[1]), 'recv': format_bytes(row[2]),
                    'total': format_bytes(row[1] + row[2])
                })
                
            # Calculate today and month start
            today_start = datetime.date.today().strftime('%Y-%m-%d 00:00:00')
            month_start = get_billing_start()
            
            # Fetch overall usage (Today)
            cursor.execute("SELECT SUM(sent_bytes + received_bytes) FROM device_usage WHERE timestamp >= ?;", (today_start,))
            overall_today = cursor.fetchone()[0] or 0
            
            # Fetch Month-to-Date (MTD) usage
            cursor.execute("SELECT SUM(sent_bytes + received_bytes) FROM device_usage WHERE timestamp >= ?;", (month_start,))
            overall_mtd = cursor.fetchone()[0] or 0
            
            # Fetch Total usage (all time)
            cursor.execute("SELECT SUM(sent_bytes + received_bytes) FROM device_usage;")
            overall_total = cursor.fetchone()[0] or 0

            conn.close()
        except Exception as e:
            print(f"[web] DB read error: {e}", file=sys.stderr)

        # Get active leases and static reservations
        active_leases = get_active_leases()
        static_reservations = get_static_reservations()

        # Group and sort devices by user and overall usage
        user_to_devices = {}
        for dev in devices_list:
            user = dev['user']
            if user not in user_to_devices:
                user_to_devices[user] = []
            user_to_devices[user].append(dev)

        # Sort devices within each user by overall usage (total_bytes) descending
        for user in user_to_devices:
            user_to_devices[user].sort(key=lambda x: x['total_bytes'], reverse=True)

        # Calculate user total usages
        user_totals = {}
        for user, devs in user_to_devices.items():
            user_totals[user] = sum(d['total_bytes'] for d in devs)

        # Sort users by overall usage descending
        sorted_users = sorted(user_to_devices.keys(), key=lambda u: user_totals[u], reverse=True)

        device_rows = []
        for user in sorted_users:
            user_safe = "".join(c for c in user if c.isalnum())
            # Header row for the user group
            device_rows.append(f"""
            <tr class="user-header" data-user="{user_safe}" style="cursor: pointer; background: rgba(99, 102, 241, 0.15); border-left: 4px solid #6366f1; user-select: none;">
                <td colspan="5" style="padding: 10px 16px; font-weight: bold; color: #a5b4fc;">
                    <span class="toggle-icon" style="display:inline-block; width:12px; margin-right:5px;">▼</span>
                    User: {user} &mdash; Total Usage: {format_bytes(user_totals[user])}
                </td>
            </tr>
            """)
            # Device rows under this user
            for dev in user_to_devices[user]:
                device_rows.append(f"""
                <tr class="device-row user-{user_safe}">
                    <td style="padding-left: 30px;">
                        <span style="font-weight:bold; color:#fff;">{dev['name']}</span><br>
                        <span style="font-size:12px; color:rgba(255,255,255,0.4)">{dev['ip']}</span>
                    </td>
                    <td><code style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; cursor: pointer; vertical-align: middle;" title="Double-click to de-authorize" ondblclick="if(confirm('Are you sure you want to de-authorize this device?')){{ performApiAction('/api/deassociate?mac={dev['mac']}'); }}">{dev['mac']}</code></td>
                    <td>{dev['user']}</td>
                    <td>
                        <div>{dev['sent']} / {dev['recv']}</div>
                        <div style="font-size: 11px; color: #10b981; font-weight: bold; margin-top: 2px;">Total: {format_bytes(dev['total_bytes'])}</div>
                    </td>
                    <td>
                        <!-- Rename Device -->
                        <form method="POST" action="/device/rename" style="display:inline-block; margin-right:5px; vertical-align:middle;">
                            <input type="hidden" name="mac" value="{dev['mac']}">
                            <input type="text" name="name" placeholder="Rename..." required style="padding:4px 8px; font-size:11px; width:80px; background:rgba(0,0,0,0.3); color:#fff; border:1px solid rgba(255,255,255,0.1); border-radius:4px; vertical-align:middle;">
                            <input type="submit" value="Rename" style="padding:4px 8px; font-size:11px; background:#6366f1; color:#fff; border:none; border-radius:4px; cursor:pointer; vertical-align:middle;">
                        </form>
                        <button onclick="performApiAction('/api/dhcp/preserve_device?mac={dev['mac']}&ip={dev['ip']}&name={urllib.parse.quote(dev['name'])}')" style="display:inline-block; font-size:11px; padding:5px 10px; background:#10b981; color:#fff; border:none; border-radius:4px; font-weight:bold; cursor:pointer; vertical-align:middle; font-family:monospace;">Preserve IP</button>
                    </td>
                </tr>""")

        device_rows_html = "".join(device_rows)

        process_rows_html = "".join([f"""
        <tr>
            <td><strong>{proc['name']}</strong></td>
            <td>{proc['sent']}</td>
            <td>{proc['recv']}</td>
            <td>{proc['total']}</td>
        </tr>""" for proc in process_list])

        group_rows_html = "".join([f"""
        <tr>
            <td><strong>{g['name']}</strong></td>
            <td>{g['daily']}</td>
            <td>{g['monthly']}</td>
            <td><strong>{g['usage']}</strong></td>
            <td>{g['users_devices']}</td>
        </tr>""" for g in groups_list])

        user_rows_html = "".join([f"""
        <tr>
            <td><strong>{u['username']}</strong></td>
            <td>{u['group_name']}</td>
            <td>{u['daily_limit']}</td>
            <td>{u['monthly_limit']}</td>
            <td>{u['suggested_daily']} / {u['suggested_monthly']}</td>
            <td>{u['addons']}</td>
        </tr>""" for u in users_list])

        active_leases_html = "".join([f"""
        <tr>
            <td><strong>{l['hostname']}</strong></td>
            <td><code>{l['mac']}</code></td>
            <td><code>{l['ip']}</code></td>
            <td><button onclick="performApiAction('/api/dhcp/clear_lease?mac={l['mac']}')" class="btn-danger" style="padding:4px 8px; font-size:11px; cursor:pointer; font-family:monospace;">Clear</button></td>
        </tr>""" for l in active_leases])

        static_leases_html = "".join([f"""
        <tr>
            <td><strong>{r['hostname']}</strong></td>
            <td><code>{r['mac']}</code></td>
            <td><code>{r['ip']}</code></td>
            <td><button onclick="performApiAction('/api/dhcp/remove?mac={r['mac']}')" class="btn-danger" style="padding:4px 8px; font-size:11px; cursor:pointer; font-family:monospace;">Remove</button></td>
        </tr>""" for r in static_reservations])

        group_options = "".join([f'<option value="{g["id"]}">{g["name"]}</option>' for g in groups_list])
        user_options = "".join([f'<option value="{u["username"]}">{u["username"]}</option>' for u in users_list])

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>NetTrack Admin Portal</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-color: #f1f5f9;
            --accent-color: #6366f1;
        }}
        body {{
            margin: 0;
            font-family: monospace;
            background: var(--bg-color);
            color: var(--text-color);
            min-height: 100vh;
        }}
        .header {{
            backdrop-filter: blur(12px);
            background: rgba(11, 15, 25, 0.8);
            border-bottom: 1px solid var(--border-color);
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ margin: 0; font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }}
        .header .user {{ font-size: 14px; color: rgba(255,255,255,0.6); }}
        .container {{ max-width: 1400px; margin: 30px auto; padding: 0 20px; }}
        .grid {{ display: grid; grid-template-columns: 1fr; gap: 30px; }}
        @media(min-width: 1000px) {{
            .grid {{ grid-template-columns: 2fr 1fr; }}
        }}
        .card {{
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
            margin-bottom: 30px;
        }}
        .card h2 {{ margin-top: 0; font-size: 18px; font-weight: 600; margin-bottom: 20px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; margin-bottom: 15px; }}
        th, td {{ padding: 12px 16px; border-bottom: 1px solid var(--border-color); font-size: 13px; }}
        th {{ color: rgba(255,255,255,0.6); font-weight: 500; }}
        .btn-danger {{
            background: rgba(244, 63, 94, 0.2);
            color: #f43f5e;
            border: 1px solid rgba(244, 63, 94, 0.4);
            padding: 6px 12px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.2s ease;
        }}
        .btn-danger:hover {{ background: #f43f5e; color: #fff; }}
        .form-group {{ margin-bottom: 15px; }}
        .form-group label {{ display: block; font-size: 11px; color: rgba(255,255,255,0.6); margin-bottom: 5px; text-transform: uppercase; }}
        .form-group input, .form-group select {{ width: 100%; padding: 8px; box-sizing: border-box; background: rgba(0,0,0,0.2); border: 1px solid var(--border-color); color: #fff; border-radius: 6px; font-family: monospace; }}
        .btn-submit {{ background: var(--accent-color); color: #fff; border: none; padding: 10px; border-radius: 6px; font-weight: 600; cursor: pointer; width: 100%; margin-top: 10px; font-family: monospace; }}
        .btn-submit:hover {{ background: #4f46e5; }}
        
        /* Overall usage stats layout */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
            display: flex;
            flex-direction: column;
            position: relative;
            overflow: hidden;
        }}
        .stat-card::after {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
        }}
        .stat-card.today::after {{ background: linear-gradient(90deg, #6366f1, #a855f7); }}
        .stat-card.mtd::after {{ background: linear-gradient(90deg, #10b981, #3b82f6); }}
        .stat-card.total::after {{ background: linear-gradient(90deg, #f59e0b, #ef4444); }}
        .stat-card.pool::after {{ background: linear-gradient(90deg, #3b82f6, #06b6d4); }}
        .stat-card.allocated::after {{ background: linear-gradient(90deg, #ec4899, #f43f5e); }}
        
        .stat-card .label {{
            font-size: 11px;
            color: rgba(255, 255, 255, 0.5);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
            font-weight: 600;
        }}
        .stat-card .value {{
            font-size: 24px;
            font-weight: bold;
            color: #fff;
        }}
        
        /* Collapsible User Headers */
        .user-header .toggle-icon {{
            display: inline-block;
            transition: transform 0.2s ease;
        }}
        .user-header.collapsed .toggle-icon {{
            transform: rotate(-90deg);
        }}
        
        /* Sleek Toast Alerts */
        #toast {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #10b981;
            color: #fff;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 13px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            transform: translateY(100px);
            opacity: 0;
            transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.3s ease;
            z-index: 10000;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        #toast.error {{
            background: #ef4444;
        }}
        #toast.show {{
            transform: translateY(0);
            opacity: 1;
        }}
    </style>
</head>
<body>
    <div id="toast">Saved successfully!</div>
    <div class="header">
        <h1>NetTrack Portal</h1>
        <div>
            <a href="/vault" style="background:#6366f1; color:#fff; text-decoration:none; padding:8px 16px; border-radius:6px; font-size:13px; font-weight:600; margin-right:15px; border: 1px solid rgba(255,255,255,0.1); transition: opacity 0.2s;">Open Vault</a>
            <span class="user" style="font-size: 14px; color: rgba(255,255,255,0.6);">Logged in: <strong>{current_user}</strong></span>
        </div>
    </div>
    <div class="container">
        <!-- Usage Metrics Counters -->
        <div class="stats-grid" id="stats-grid-container">
            <div class="stat-card today">
                <span class="label">Today's Usage (Overall)</span>
                <span class="value">{format_bytes(overall_today)}</span>
            </div>
            <div class="stat-card mtd">
                <span class="label">Cycle Usage (Since 28th)</span>
                <span class="value">{format_bytes(overall_mtd)}</span>
            </div>
            <div class="stat-card total">
                <span class="label">Total Lifetime Usage</span>
                <span class="value">{format_bytes(overall_total)}</span>
            </div>
            <div class="stat-card pool">
                <span class="label">Global ISP Pool Limit</span>
                <span class="value">{format_bytes(global_pool_bytes)}</span>
                <div style="font-size:11px; color:rgba(255,255,255,0.4); margin-top:5px;">Remaining: {format_bytes(max(global_pool_bytes - overall_mtd, 0))}</div>
            </div>
            <div class="stat-card allocated">
                <span class="label">Total Allocated Bandwidth</span>
                <span class="value">{format_bytes(total_allocated_bytes)}</span>
                <div style="font-size:11px; color:rgba(255,255,255,0.4); margin-top:5px;">Over-allocated: {format_bytes(max(total_allocated_bytes - global_pool_bytes, 0)) if total_allocated_bytes > global_pool_bytes else "0 B"}</div>
            </div>
        </div>

        <div class="grid">
            <div>
                <div class="card" id="devices-card-container">
                    <h2>Authorized Local Devices</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Name & IP Address</th>
                                <th>MAC Address</th>
                                <th>Owner</th>
                                <th>Aggregate Sent/Recv</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {device_rows_html or '<tr><td colspan="5" style="text-align:center;">No devices authorized.</td></tr>'}
                        </tbody>
                    </table>
                </div>

                <!-- DHCP Administration UI -->
                <div class="card" id="leases-card-container">
                    <h2>Dynamic DHCP Client Leases</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Hostname</th>
                                <th>MAC Address</th>
                                <th>Assigned IP</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {active_leases_html or '<tr><td colspan="4" style="text-align:center;">No active dynamic DHCP leases.</td></tr>'}
                        </tbody>
                    </table>
                </div>

                <div class="card" id="reservations-card-container">
                    <h2>Static IP DHCP Reservations (Preserved IPs)</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Reserved Name</th>
                                <th>MAC Address</th>
                                <th>Static IP Address</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {static_leases_html or '<tr><td colspan="4" style="text-align:center;">No static IP reservations configured.</td></tr>'}
                        </tbody>
                    </table>
                </div>
                
                <div class="card" id="groups-card-container">
                    <h2>Package / User Groups</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Group Name</th>
                                <th>Daily Limit</th>
                                <th>Monthly Limit</th>
                                <th>Consolidated Usage</th>
                                <th>Users / Devices</th>
                            </tr>
                        </thead>
                        <tbody>
                            {group_rows_html or '<tr><td colspan="5" style="text-align:center;">No groups defined.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div>
                <div class="card">
                    <h2>Create Static DHCP Reservation</h2>
                    <form method="POST" action="/dhcp/reserve">
                        <div class="form-group">
                            <label>Hostname / Name</label>
                            <input type="text" name="hostname" placeholder="e.g., ghassan-phone" required>
                        </div>
                        <div class="form-group">
                            <label>MAC Address</label>
                            <input type="text" name="mac" placeholder="e.g., 5a:2c:16:58:56:54" required>
                        </div>
                        <div class="form-group">
                            <label>Static IP Address</label>
                            <input type="text" name="ip" placeholder="e.g., 192.168.1.150" required>
                        </div>
                        <button type="submit" class="btn-submit">Preserve IP Reservation</button>
                    </form>
                </div>

                <div class="card">
                    <h2>Assign User to Group</h2>
                    <form method="POST" action="/users/assign">
                        <div class="form-group">
                            <label>User</label>
                            <select name="username" required>
                                {user_options or '<option value="">No users</option>'}
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Group</label>
                            <select name="group_id" required>
                                {group_options or '<option value="">No groups</option>'}
                            </select>
                        </div>
                        <button type="submit" class="btn-submit">Assign Group</button>
                    </form>
                </div>

                <div class="card">
                    <h2>Create User Group</h2>
                    <form method="POST" action="/groups/create">
                        <div class="form-group">
                            <label>Group Name</label>
                            <input type="text" name="name" placeholder="e.g., Guest" required>
                        </div>
                        <div class="form-group">
                            <label>Daily Limit (GB)</label>
                            <input type="number" name="daily_gb" step="any" value="2.0" required>
                        </div>
                        <div class="form-group">
                            <label>Monthly Limit (GB)</label>
                            <input type="number" name="monthly_gb" step="any" value="60" required>
                        </div>
                        <button type="submit" class="btn-submit">Create Group</button>
                    </form>
                </div>

                <div class="card">
                    <h2>Configure Global ISP Bucket Pool</h2>
                    <form method="POST" action="/settings/update">
                        <div class="form-group">
                            <label>Global ISP Bucket Size (GB)</label>
                            <input type="number" name="global_pool_gb" step="any" value="{global_pool_bytes / (1024*1024*1024)}" required>
                        </div>
                        <button type="submit" class="btn-submit">Update Global Pool</button>
                    </form>
                </div>

                <div class="card" id="distribution-card-container">
                    <h2>Global Pool Distribution Breakdown</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>User</th>
                                <th>Monthly Allocation</th>
                                <th>Share of Pool</th>
                            </tr>
                        </thead>
                        <tbody>
                            {distribution_rows_html or '<tr><td colspan="3" style="text-align:center;">No distributions computed.</td></tr>'}
                        </tbody>
                    </table>
                </div>

                <div class="card" id="configure-limits-card-container">
                    <h2>Configure User Limits & Bucket</h2>
                    <form method="POST" action="/users/configure_limits">
                        <div class="form-group">
                            <label>Select User</label>
                            <select name="username" required>
                                {user_options or '<option value="">No users</option>'}
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Custom Daily Limit (GB) &mdash; Leave blank for group default</label>
                            <input type="number" name="daily_gb" step="any" placeholder="e.g., 5.0">
                        </div>
                        <div class="form-group">
                            <label>Custom Monthly Limit / Bucket (GB) &mdash; Leave blank for group default</label>
                            <input type="number" name="monthly_gb" step="any" placeholder="e.g., 100.0">
                            <small style="color: rgba(255,255,255,0.5); display:block; margin-top:5px;">
                                Remaining unassigned pool capacity: <strong>{specific_remaining_gb:.2f} GB</strong> (counting custom user limits only)
                            </small>
                        </div>
                        <p style="font-size: 11px; color:#10b981; margin-top:5px; margin-bottom:10px;">
                            * Heuristic suggested quotas are dynamically calculated in the Registered Users table below based on past week usage!
                        </p>
                        <button type="submit" class="btn-submit">Save User Limits</button>
                    </form>
                </div>

                <div class="card">
                    <h2>Buy Bandwidth Addons</h2>
                    <form method="POST" action="/users/buy_addon">
                        <div class="form-group">
                            <label>Select User</label>
                            <select name="username" required>
                                {user_options or '<option value="">No users</option>'}
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Addon Package</label>
                            <select name="addon_gb" required>
                                <option value="1">1 GB Addon</option>
                                <option value="5">5 GB Addon</option>
                                <option value="10">10 GB Addon</option>
                                <option value="50">50 GB Addon</option>
                                <option value="100">100 GB Addon</option>
                            </select>
                        </div>
                        <button type="submit" class="btn-submit">Purchase Addon</button>
                    </form>
                </div>

                <div class="card" id="users-card-container">
                    <h2>Registered Users</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Assigned Group</th>
                                <th>Custom Daily</th>
                                <th>Custom Monthly</th>
                                <th>Suggested D/M</th>
                                <th>Addons</th>
                            </tr>
                        </thead>
                        <tbody>
                            {user_rows_html or '<tr><td colspan="6" style="text-align:center;">No users registered yet.</td></tr>'}
                        </tbody>
                    </table>
                </div>

                <div class="card" id="processes-card-container">
                    <h2>Server Process Usage</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Application</th>
                                <th>Sent</th>
                                <th>Recv</th>
                                <th>Total</th>
                            </tr>
                        </thead>
                        <tbody>
                            {process_rows_html or '<tr><td colspan="4" style="text-align:center;">No process records yet.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const collapsedUsers = new Set();

        function showToast(message, isError = false) {{
            const toast = document.getElementById("toast");
            toast.textContent = message;
            toast.className = isError ? "error show" : "show";
            setTimeout(() => {{
                toast.classList.remove("show");
            }}, 3000);
        }}

        function setupCollapsibleHeaders() {{
            document.querySelectorAll(".user-header").forEach(header => {{
                const username = header.getAttribute("data-user");
                
                if (collapsedUsers.has(username)) {{
                    header.classList.add("collapsed");
                    document.querySelectorAll(`.device-row.user-${{username}}`).forEach(r => r.style.display = "none");
                }}
                
                header.onclick = function() {{
                    if (collapsedUsers.has(username)) {{
                        collapsedUsers.delete(username);
                        header.classList.remove("collapsed");
                        document.querySelectorAll(`.device-row.user-${{username}}`).forEach(r => r.style.display = "table-row");
                    }} else {{
                        collapsedUsers.add(username);
                        header.classList.add("collapsed");
                        document.querySelectorAll(`.device-row.user-${{username}}`).forEach(r => r.style.display = "none");
                    }}
                }};
            }});
        }}

        function refreshDashboard() {{
            fetch("/")
            .then(res => res.text())
            .then(html => {{
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, "text/html");
                
                const newStats = doc.getElementById("stats-grid-container");
                if (newStats) document.getElementById("stats-grid-container").innerHTML = newStats.innerHTML;
                
                const targets = [
                    "devices-card-container",
                    "leases-card-container",
                    "reservations-card-container",
                    "groups-card-container",
                    "distribution-card-container",
                    "configure-limits-card-container",
                    "users-card-container",
                    "processes-card-container"
                ];
                
                targets.forEach(id => {{
                    const fresh = doc.getElementById(id);
                    if (fresh) document.getElementById(id).innerHTML = fresh.innerHTML;
                }});
                
                const userSelects = document.querySelectorAll("select[name='username']");
                const freshUserSelect = doc.querySelector("select[name='username']");
                if (freshUserSelect) {{
                    userSelects.forEach(select => {{
                        const val = select.value;
                        select.innerHTML = freshUserSelect.innerHTML;
                        select.value = val;
                    }});
                }}
                
                const groupSelects = document.querySelectorAll("select[name='group_id']");
                const freshGroupSelect = doc.querySelector("select[name='group_id']");
                if (freshGroupSelect) {{
                    groupSelects.forEach(select => {{
                        const val = select.value;
                        select.innerHTML = freshGroupSelect.innerHTML;
                        select.value = val;
                    }});
                }}
                
                setupCollapsibleHeaders();
            }})
            .catch(err => console.error("Error refreshing dashboard:", err));
        }}

        function performApiAction(url) {{
            if (url.includes("deassociate") && !confirm("Are you sure you want to de-authorize this device?")) {{
                return;
            }}
            fetch(url)
            .then(response => {{
                if (response.ok) {{
                    showToast("Action completed successfully!");
                    refreshDashboard();
                }} else {{
                    showToast("Error processing action.", true);
                }}
            }})
            .catch(err => showToast("Network error: " + err, true));
        }}

        document.addEventListener("submit", function(e) {{
            const form = e.target;
            e.preventDefault();
            
            fetch(form.action, {{
                method: "POST",
                body: new URLSearchParams(new FormData(form))
            }})
            .then(response => {{
                if (response.ok) {{
                    showToast("Saved successfully!");
                    form.querySelectorAll("input[type='text'], input[type='number']").forEach(input => {{
                        if (input.name !== "global_pool_gb" && !input.readOnly) {{
                            input.value = "";
                        }}
                    }});
                    refreshDashboard();
                }} else {{
                    showToast("Error submitting form.", true);
                }}
            }})
            .catch(err => showToast("Network error: " + err, true));
        }});

        setupCollapsibleHeaders();
    </script>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

    def serve_vault_page(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        # Load registered device metadata (MAC -> Name, Owner)
        device_map = {}
        try:
            main_conn = sqlite3.connect("/var/lib/nettrack/nettrack.db")
            main_cursor = main_conn.cursor()
            main_cursor.execute("SELECT mac_address, device_name, username FROM registered_devices;")
            for mac, dname, uname in main_cursor.fetchall():
                normalized = mac.lower().strip()
                device_map[normalized] = (dname or "Unnamed Device", uname or "Admin")
            main_conn.close()
        except Exception as e:
            print(f"[web] Device map read error: {e}", file=sys.stderr)
            
        vault_rows_html = ""
        try:
            conn = sqlite3.connect("/var/lib/nettrack/vault.db")
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, src_mac, src_ip, dst_mac, dst_ip, bytes FROM raw_traffic ORDER BY id DESC LIMIT 200;")
            rows = cursor.fetchall()
            conn.close()
            
            for timestamp, src_mac, src_ip, dst_mac, dst_ip, size in rows:
                src_mac_norm = src_mac.lower().strip()
                dst_mac_norm = dst_mac.lower().strip()
                
                # Map MAC address to Device Name and Owner
                src_dev, src_owner = device_map.get(src_mac_norm, (None, None))
                dst_dev, dst_owner = device_map.get(dst_mac_norm, (None, None))
                
                # Determine device and owner representing this flow
                device_display = "Unknown Device"
                owner_display = "Unknown Owner"
                if src_dev:
                    device_display = src_dev
                    owner_display = src_owner
                elif dst_dev:
                    device_display = dst_dev
                    owner_display = dst_owner
                
                src_domain = get_website_domain(src_ip)
                dst_domain = get_website_domain(dst_ip)
                
                # Highlight resolved domains/websites beautifully
                src_display = f"<code>{src_ip}</code>"
                if src_domain != src_ip:
                    src_display = f"<strong style='color:#a855f7; font-size:13px;'>{src_domain}</strong><br><span style='font-size:11px; color:rgba(255,255,255,0.5)'>{src_ip}</span>"
                
                dst_display = f"<code>{dst_ip}</code>"
                if dst_domain != dst_ip:
                    dst_display = f"<strong style='color:#10b981; font-size:13px;'>{dst_domain}</strong><br><span style='font-size:11px; color:rgba(255,255,255,0.5)'>{dst_ip}</span>"
                
                vault_rows_html += f"""
                <tr>
                    <td>{timestamp}</td>
                    <td>
                        <span style="font-weight:bold; color:#fff;">{device_display}</span><br>
                        <span style="font-size:11px; color:#6366f1; font-weight:bold;">Owner: {owner_display}</span>
                    </td>
                    <td>
                        {src_display}<br>
                        <span style="font-size:10px; color:rgba(255,255,255,0.4)">{src_mac}</span>
                    </td>
                    <td>
                        {dst_display}<br>
                        <span style="font-size:10px; color:rgba(255,255,255,0.4)">{dst_mac}</span>
                    </td>
                    <td>{format_bytes(size)}</td>
                </tr>
                """
        except Exception as e:
            vault_rows_html = f'<tr><td colspan="5" style="text-align:center; color:red">Error loading vault: {e}</td></tr>'

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>NetTrack Packet Vault</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-color: #f1f5f9;
            --accent-color: #6366f1;
        }}
        body {{
            margin: 0;
            font-family: monospace;
            background: var(--bg-color);
            color: var(--text-color);
            min-height: 100vh;
        }}
        .header {{
            backdrop-filter: blur(12px);
            background: rgba(11, 15, 25, 0.8);
            border-bottom: 1px solid var(--border-color);
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ margin: 0; font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }}
        .container {{ max-width: 1200px; margin: 30px auto; padding: 0 20px; }}
        .card {{
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
            margin-bottom: 30px;
        }}
        .card h2 {{ margin-top: 0; font-size: 18px; font-weight: 600; margin-bottom: 20px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th, td {{ padding: 12px 16px; border-bottom: 1px solid var(--border-color); font-size: 14px; }}
        th {{ color: rgba(255,255,255,0.6); font-weight: 500; }}
        .btn-back {{
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 8px 16px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 13px;
            font-weight: 600;
        }}
        .btn-back:hover {{ background: rgba(255, 255, 255, 0.2); }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Packet Vault</h1>
        <a href="/" class="btn-back">Back to Dashboard</a>
    </div>
    <div class="container">
        <div class="card">
            <h2>Real-time Connection Log (Last 200 Packets)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Device & Owner</th>
                        <th>Source</th>
                        <th>Destination (Website)</th>
                        <th>Payload Size</th>
                    </tr>
                </thead>
                <tbody>
                    {vault_rows_html or '<tr><td colspan="5" style="text-align:center;">No traffic recorded yet.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

def run_web_server(port):
    server = HTTPServer(('0.0.0.0', port), WebServerHandler)
    print(f"[web] Admin Web Dashboard and Captive Portal listening on http://localhost:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--web", type=int, nargs='?', const=6054, help="Run web server portal dashboard.")
    args = parser.parse_args()
    
    if args.web is not None:
        run_web_server(args.web)
    else:
        print("=== NetTrack CLI Dashboard ===")
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address, mac_address, username FROM registered_devices;")
            rows = cursor.fetchall()
            print(f"Total authorized devices: {len(rows)}")
            for ip, mac, user in rows:
                print(f" - {ip} ({mac}): {user}")
            conn.close()
        except Exception as e:
            print(f"Database error: {e}")

if __name__ == "__main__":
    main()
