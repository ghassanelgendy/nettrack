#!/usr/bin/env python3
import os
import sys
import sqlite3
import datetime
import argparse
import urllib.parse
import subprocess
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import resource

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

def get_dnsmasq_leases_path():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = 'dnsmasq_leases_path';")
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            return row[0]
    except Exception:
        pass
    return "/var/lib/misc/dnsmasq.leases"

def get_static_leases_path():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = 'static_leases_path';")
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            return row[0]
    except Exception:
        pass
    return "/etc/nettrack_static_leases.conf"

import re as _re

MAC_PATTERN = _re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')

def is_valid_mac(mac):
    """Return True only for properly-formatted 6-octet MAC addresses."""
    return bool(MAC_PATTERN.match(mac.lower().strip()))

def write_static_lease(mac, ip, hostname):
    """
    Safely write a single DHCP static lease to the nettrack leases file.
    - Validates the MAC address format.
    - Removes any existing entry for this MAC.
    - Makes the hostname unique if another device already uses it.
    - Verifies dnsmasq accepts the config before restarting.
    Returns (success: bool, message: str).
    """
    import subprocess, os, re, tempfile

    # 1. Validate MAC
    if not is_valid_mac(mac):
        return False, f"Invalid MAC address '{mac}' – lease not written"

    static_path = get_static_leases_path()

    # 2. Read existing lines, dropping any entry for this MAC
    existing_lines = []
    if os.path.exists(static_path):
        with open(static_path, 'r') as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith(f'dhcp-host={mac}'):
                    existing_lines.append(stripped)

    # 3. Deduplicate hostname – if another entry uses the same name, append last IP octet
    used_names = set()
    for line in existing_lines:
        parts = line.split(',')
        if len(parts) >= 3:
            used_names.add(parts[2].lower())
    unique_hostname = hostname
    if unique_hostname.lower() in used_names:
        last_octet = ip.rsplit('.', 1)[-1] if '.' in ip else '0'
        unique_hostname = f"{hostname}-{last_octet}"
    # Final safety: still clash after suffix? add MAC tail
    if unique_hostname.lower() in used_names:
        mac_tail = mac.replace(':', '')[-4:]
        unique_hostname = f"{hostname}-{mac_tail}"

    # 4. Build the new line
    new_line = f'dhcp-host={mac},{ip},{unique_hostname},infinite'
    new_lines = existing_lines + [new_line]

    # 5. Write to a temp file and validate with dnsmasq --test
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write('\n'.join(new_lines) + '\n')

        # dnsmasq --test only validates syntax; pipe conf file in via dhcp-hostsfile
        result = subprocess.run(
            ['dnsmasq', '--test', f'--dhcp-hostsfile={tmp_path}'],
            capture_output=True, text=True
        )
        os.unlink(tmp_path)

        if result.returncode != 0:
            err = (result.stderr or result.stdout).strip()
            return False, f"dnsmasq validation failed: {err}"

        # 6. Commit
        with open(static_path, 'w') as f:
            f.write('\n'.join(new_lines) + '\n')

        subprocess.run('systemctl restart dnsmasq', shell=True)
        return True, f"Lease for {mac} -> {ip} ({unique_hostname}) written OK"

    except Exception as e:
        return False, f"Exception writing lease: {e}"


def get_billing_cycle_day():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = 'billing_cycle_day';")
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            return int(row[0])
    except Exception:
        pass
    return 28

def get_day_suffix(day):
    if 11 <= day <= 13:
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")

def get_cycle_end_day_desc(day):
    if day == 1:
        return "last day of month"
    end_day = day - 1
    return f"{end_day}{get_day_suffix(end_day)}"

def get_billing_cycle_range_str():
    import datetime
    try:
        start_str = get_billing_start()
        start_dt = datetime.datetime.strptime(start_str, '%Y-%m-%d %H:%M:%S')
        cycle_day = get_billing_cycle_day()
        
        def get_last_day_of_month(year, month):
            if month == 12:
                return 31
            return (datetime.date(year, month + 1, 1) - datetime.timedelta(days=1)).day
            
        def get_valid_day(year, month, target_day):
            last_day = get_last_day_of_month(year, month)
            return min(target_day, last_day)
            
        if start_dt.month == 12:
            next_year = start_dt.year + 1
            next_month = 1
        else:
            next_year = start_dt.year
            next_month = start_dt.month + 1
            
        next_threshold_day = get_valid_day(next_year, next_month, cycle_day)
        next_cycle_start = datetime.date(next_year, next_month, next_threshold_day)
        end_date = next_cycle_start - datetime.timedelta(days=1)
        
        start_day = start_dt.day
        end_day = end_date.day
        
        start_suffix = get_day_suffix(start_day)
        end_suffix = get_day_suffix(end_day)
        
        start_month_str = start_dt.strftime('%b')
        end_month_str = end_date.strftime('%b')
        
        if start_dt.year != end_date.year:
            return f"{start_month_str} {start_day}{start_suffix}, {start_dt.year} - {end_month_str} {end_day}{end_suffix}, {end_date.year}"
        elif start_month_str != end_month_str:
            return f"{start_month_str} {start_day}{start_suffix} - {end_month_str} {end_day}{end_suffix}"
        else:
            return f"{start_month_str} {start_day}{start_suffix} - {end_day}{end_suffix}"
    except Exception:
        day = get_billing_cycle_day()
        return f"{day}{get_day_suffix(day)} - {get_cycle_end_day_desc(day)}"

def get_mac_from_arp(ip):
    # Try resolving MAC from DHCP leases first to get the client's real MAC
    try:
        leases_path = get_dnsmasq_leases_path()
        if os.path.exists(leases_path):
            with open(leases_path, "r") as f:
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
        leases_path = get_dnsmasq_leases_path()
        if os.path.exists(leases_path):
            with open(leases_path, "r") as f:
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
        static_path = get_static_leases_path()
        if os.path.exists(static_path):
            with open(static_path, "r") as f:
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

def get_vault_db_path():
    import sys
    for idx, arg in enumerate(sys.argv):
        if arg == "--vault-db" and idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = 'vault_db_path';")
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            return row[0]
    except Exception:
        pass
    return "/var/lib/nettrack/vault.db"

def get_local_midnight_in_utc():
    import datetime
    now_local = datetime.datetime.now()
    if now_local.tzinfo is not None:
        local_midnight = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        utc_midnight = local_midnight.astimezone(datetime.timezone.utc)
    else:
        local_midnight = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        local_midnight_tz = local_midnight.astimezone()
        utc_midnight = local_midnight_tz.astimezone(datetime.timezone.utc)
    return utc_midnight.strftime('%Y-%m-%d %H:%M:%S')

def get_billing_start():
    import datetime
    cycle_day = get_billing_cycle_day()
    
    # Get current local date
    now_local = datetime.datetime.now()
    today = now_local.date()
    
    def get_last_day_of_month(year, month):
        if month == 12:
            return 31
        return (datetime.date(year, month + 1, 1) - datetime.timedelta(days=1)).day
        
    def get_valid_day(year, month, target_day):
        last_day = get_last_day_of_month(year, month)
        return min(target_day, last_day)

    current_threshold_day = get_valid_day(today.year, today.month, cycle_day)
    
    if today.day >= current_threshold_day:
        start_date = today.replace(day=current_threshold_day)
    else:
        if today.month == 1:
            prev_year = today.year - 1
            prev_month = 12
        else:
            prev_year = today.year
            prev_month = today.month - 1
        prev_threshold_day = get_valid_day(prev_year, prev_month, cycle_day)
        start_date = datetime.date(prev_year, prev_month, prev_threshold_day)
        
    local_start_dt = datetime.datetime.combine(start_date, datetime.time.min)
    if now_local.tzinfo is not None:
        local_start_dt = local_start_dt.replace(tzinfo=now_local.tzinfo)
        utc_start_dt = local_start_dt.astimezone(datetime.timezone.utc)
    else:
        local_start_dt_tz = local_start_dt.astimezone()
        utc_start_dt = local_start_dt_tz.astimezone(datetime.timezone.utc)
        
    return utc_start_dt.strftime('%Y-%m-%d %H:%M:%S')

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
    # Short timeout so stale/slow connections don't block the thread pool
    timeout = 30

    def log_message(self, format, *args):
        return

    def handle_error(self):
        """Suppress noisy but harmless connection-reset errors from logs."""
        import traceback
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
            return
        traceback.print_exc()

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
            
            today_start = get_local_midnight_in_utc()
            month_start = get_billing_start()
            
            cursor.execute("""
                SELECT 
                    rd.username,
                    COALESCE(u.daily_limit_bytes, ug.daily_limit_bytes) AS d_limit,
                    COALESCE((
                        SELECT SUM(du.sent_bytes + du.received_bytes) 
                        FROM device_usage du 
                        WHERE LOWER(du.mac_address) IN (
                            SELECT LOWER(mac_address) 
                            FROM registered_devices 
                            WHERE LOWER(username) = LOWER(rd.username)
                        ) AND du.timestamp >= ?
                    ), 0) AS daily_used,
                    COALESCE((
                        SELECT SUM(du.sent_bytes + du.received_bytes) 
                        FROM device_usage du 
                        WHERE LOWER(du.mac_address) IN (
                            SELECT LOWER(mac_address) 
                            FROM registered_devices 
                            WHERE LOWER(username) = LOWER(rd.username)
                        ) AND du.timestamp >= ?
                    ), 0) AS monthly_used,
                    EXISTS(SELECT 1 FROM quota_bypasses WHERE LOWER(mac_address) = LOWER(rd.mac_address)) AS warning_bypassed
                FROM registered_devices rd
                JOIN users u ON rd.username = u.username
                LEFT JOIN user_groups ug ON u.group_id = ug.id
                WHERE LOWER(rd.mac_address) = LOWER(?);
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
        elif self.path == "/settings/migrate_vault":
            try:
                dest_dirs = ["/logs", "/mnt/sdc1", "/mnt/sda6", "/mnt/sda5"]
                target_dir = None
                for d in dest_dirs:
                    if os.path.exists(d):
                        test_file = os.path.join(d, ".write_test")
                        try:
                            with open(test_file, "w") as f:
                                f.write("test")
                            os.remove(test_file)
                            target_dir = d
                            break
                        except Exception:
                            continue
                
                if not target_dir:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"No writeable secondary drive found.")
                    return
                
                old_path = get_vault_db_path()
                new_path = os.path.join(target_dir, "vault.db")
                default_path = "/var/lib/nettrack/vault.db"
                
                src_path = None
                if os.path.exists(old_path) and os.path.getsize(old_path) > 0:
                    src_path = old_path
                elif os.path.exists(default_path) and os.path.getsize(default_path) > 0:
                    src_path = default_path
                
                if not src_path:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Active vault.db not found.")
                    return
                
                if os.path.abspath(src_path) == os.path.abspath(new_path):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Vault is already on the target drive.")
                    return
                
                # Transactional SQLite backup
                src_conn = sqlite3.connect(src_path)
                dst_conn = sqlite3.connect(f"file:{new_path}?nolock=1", uri=True)
                src_conn.backup(dst_conn)
                dst_conn.close()
                src_conn.close()
                
                # Verify
                if not os.path.exists(new_path) or os.path.getsize(new_path) == 0:
                    raise Exception("Migration verification failed: destination file empty.")
                
                # Update setting
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('vault_db_path', ?);", (new_path,))
                conn.commit()
                conn.close()
                
                # Delete the old file from SSD
                try:
                    os.remove(src_path)
                except Exception as e:
                    print(f"Error removing old vault: {e}")
                
                # Restart services in background using docker chroot escape
                import subprocess
                subprocess.Popen([
                    "docker", "run", "--rm", "--privileged", "--net=host", "--pid=host", "-v", "/:/host", "redis:6.2-alpine",
                    "chroot", "/host", "systemctl", "restart", "nettrack.service", "nettrack-portal.service", "nettrack-web.service", "nettrack-device.service"
                ])
                
                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"Successfully migrated logs to {new_path}".encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Migration failed: {e}".encode("utf-8"))
        elif self.path == "/vault":
            self.serve_vault_page()
        elif self.path.startswith("/user/"):
            username = urllib.parse.unquote(self.path[6:].split("?")[0])
            self.serve_user_profile_page(username)
        elif self.path.startswith("/api/user/"):
            username = urllib.parse.unquote(self.path[10:].split("?")[0])
            self.serve_user_api(username)
        elif self.path.startswith("/api/dashboard"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            period = qs.get('period', ['day'])[0]
            self.serve_dashboard_api(period)
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
                    
                    # Signal portal process to sync rules immediately
                    try:
                        import signal
                        import subprocess
                        pid_str = subprocess.check_output(["pgrep", "-f", "nettrack_portal.py"]).decode().strip()
                        for pid in pid_str.split():
                            if pid:
                                os.kill(int(pid), signal.SIGUSR1)
                    except Exception as sig_err:
                        print(f"Error signaling portal: {sig_err}")
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
                ok, msg = write_static_lease(mac, ip, hostname)
                if not ok:
                    print(f"[dhcp/preserve_device] {msg}", file=sys.stderr)
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            
        elif self.path.startswith("/api/dhcp/remove"):
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            mac_to_remove = normalize_mac(params.get('mac', [''])[0].strip())
            
            static_path = get_static_leases_path()
            if mac_to_remove and os.path.exists(static_path):
                try:
                    with open(static_path, "r") as f:
                        lines = f.readlines()
                    with open(static_path, "w") as f:
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
        
        content_length = int(self.headers.get('Content-Length', 0) or 0)
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)

        # ── JSON API routes for user profile page ──────────────────────────
        if self.path.startswith("/api/user/") and self.path.endswith("/set_limits"):
            import json
            parts = self.path.split("/")  # ['', 'api', 'user', '<name>', 'set_limits']
            username = urllib.parse.unquote(parts[3]) if len(parts) >= 5 else ""
            daily_gb_str   = params.get('daily_gb',   [''])[0].strip()
            monthly_gb_str = params.get('monthly_gb', [''])[0].strip()
            group_id_str   = params.get('group_id',   [''])[0].strip()
            resp = {"ok": False, "error": ""}
            try:
                daily_bytes   = int(float(daily_gb_str) * 1024**3)   if daily_gb_str   else None
                monthly_bytes = int(float(monthly_gb_str) * 1024**3) if monthly_gb_str else None
                group_id      = int(group_id_str)                     if group_id_str   else None
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users SET daily_limit_bytes=?, monthly_limit_bytes=?
                    WHERE username=?;
                """, (daily_bytes, monthly_bytes, username))
                if group_id is not None:
                    cursor.execute("UPDATE users SET group_id=? WHERE username=?;", (group_id, username))
                conn.commit()
                conn.close()
                resp["ok"] = True
            except Exception as e:
                resp["error"] = str(e)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())
            return

        if self.path.startswith("/api/user/") and self.path.endswith("/add_quota"):
            import json
            parts = self.path.split("/")
            username = urllib.parse.unquote(parts[3]) if len(parts) >= 5 else ""
            addon_gb_str = params.get('addon_gb', ['0'])[0].strip()
            resp = {"ok": False, "error": ""}
            try:
                addon_bytes = int(float(addon_gb_str) * 1024**3)
                if addon_bytes <= 0:
                    raise ValueError("Addon must be > 0 GB")
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO user_addons (username, addon_bytes) VALUES (?, ?);
                """, (username, addon_bytes))
                conn.commit()
                # Return new addon total
                cursor.execute("SELECT COALESCE(SUM(addon_bytes),0) FROM user_addons WHERE username=?;", (username,))
                total_addon = cursor.fetchone()[0]
                conn.close()
                resp["ok"] = True
                resp["total_addon_bytes"] = total_addon
            except Exception as e:
                resp["error"] = str(e)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())
            return

        if self.path.startswith("/api/user/") and self.path.endswith("/clear_quota"):
            import json
            parts = self.path.split("/")
            username = urllib.parse.unquote(parts[3]) if len(parts) >= 5 else ""
            resp = {"ok": False, "error": ""}
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM user_addons WHERE username=?;", (username,))
                conn.commit()
                conn.close()
                resp["ok"] = True
            except Exception as e:
                resp["error"] = str(e)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())
            return
        # ───────────────────────────────────────────────────────────────────

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
                ok, msg = write_static_lease(mac, ip, hostname)
                if not ok:
                    print(f"[dhcp/reserve] {msg}", file=sys.stderr)
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
        elif self.path == "/settings/paths":
            vault_path = params.get('vault_path', [''])[0].strip()
            leases_path = params.get('leases_path', [''])[0].strip()
            static_leases_path = params.get('static_leases_path', [''])[0].strip()
            
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                if vault_path:
                    # Make sure the parent folder exists and is writable
                    parent_dir = os.path.dirname(os.path.abspath(vault_path))
                    os.makedirs(parent_dir, exist_ok=True)
                    
                    old_path = get_vault_db_path()
                    if os.path.abspath(old_path) != os.path.abspath(vault_path):
                        if os.path.exists(old_path) and not os.path.exists(vault_path):
                            print(f"[web] Auto-migrating vault database from {old_path} to {vault_path} during path settings change...")
                            try:
                                src_conn = sqlite3.connect(old_path)
                                dst_conn = sqlite3.connect(f"file:{vault_path}?nolock=1", uri=True)
                                src_conn.backup(dst_conn)
                                dst_conn.close()
                                src_conn.close()
                                os.remove(old_path)
                            except Exception as ex:
                                print(f"Error during settings vault migration: {ex}")
                                
                    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('vault_db_path', ?);", (vault_path,))
                if leases_path:
                    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dnsmasq_leases_path', ?);", (leases_path,))
                if static_leases_path:
                    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('static_leases_path', ?);", (static_leases_path,))
                conn.commit()
                conn.close()
                
                # Restart services in the background using docker chroot escape
                import subprocess
                subprocess.Popen([
                    "docker", "run", "--rm", "--privileged", "--net=host", "--pid=host", "-v", "/:/host", "redis:6.2-alpine",
                    "chroot", "/host", "systemctl", "restart", "nettrack.service", "nettrack-portal.service", "nettrack-web.service", "nettrack-device.service"
                ])
            except Exception as e:
                print(f"Error updating system paths: {e}")
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            
        elif self.path == "/settings/cycle_day":
            cycle_day_str = params.get('cycle_day', ['28'])[0].strip()
            try:
                cycle_day = int(cycle_day_str)
                if 1 <= cycle_day <= 31:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('billing_cycle_day', ?);", (str(cycle_day),))
                    conn.commit()
                    conn.close()
            except Exception as e:
                print(f"Error updating cycle day: {e}")
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
            today_start = get_local_midnight_in_utc()
            month_start = get_billing_start()
            
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
            
            # Calculate today and month start using UTC to align with database timestamps
            today_start = get_local_midnight_in_utc()
            month_start = get_billing_start()

            # Fetch registered devices
            cursor.execute("SELECT mac_address, ip_address, username, registered_at, device_name, last_seen FROM registered_devices;")
            registered_devices = cursor.fetchall()
            
            # Fetch monthly/cycle device usage (since month_start)
            cursor.execute("""
                SELECT mac_address, SUM(sent_bytes), SUM(received_bytes)
                FROM device_usage 
                WHERE timestamp >= ?
                GROUP BY mac_address;
            """, (month_start,))
            device_traffic = {row[0].lower().strip(): (row[1], row[2]) for row in cursor.fetchall()}

            # Fetch today's device usage
            cursor.execute("""
                SELECT mac_address, SUM(sent_bytes + received_bytes)
                FROM device_usage 
                WHERE timestamp >= ?
                GROUP BY mac_address;
            """, (today_start,))
            device_today_traffic = {row[0].lower().strip(): row[1] for row in cursor.fetchall()}
            
            # Build set of currently-online MACs from active DHCP leases
            active_leases_for_online = get_active_leases()
            online_macs = {l['mac'].lower().strip() for l in active_leases_for_online}
            
            for mac, ip, user, reg_at, dname, last_seen in registered_devices:
                mac_norm = mac.lower().strip()
                sent, recv = device_traffic.get(mac_norm, (0, 0))
                today_bytes = device_today_traffic.get(mac_norm, 0)
                is_online = mac_norm in online_macs
                devices_list.append({
                    'mac': mac, 'ip': ip, 'user': user, 'reg_at': reg_at, 'name': dname or "Unnamed Device",
                    'sent': format_bytes(sent), 'recv': format_bytes(recv),
                    'total_bytes': sent + recv,
                    'today_bytes': today_bytes,
                    'last_seen': last_seen or '',
                    'is_online': is_online
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
            user_devs = user_to_devices[user]
            online_count = sum(1 for d in user_devs if d['is_online'])
            online_badge = f'<span style="background:#10b981; color:#fff; font-size:10px; padding:1px 7px; border-radius:10px; margin-left:8px; font-weight:600;">{online_count} online</span>' if online_count else ''

            # Compute monthly usage alert badge
            user_limit_bytes = effective_limits.get(user, 0)
            user_used_bytes = user_totals[user]
            if user_limit_bytes and user_limit_bytes > 0:
                usage_pct = (user_used_bytes / user_limit_bytes) * 100
            else:
                usage_pct = 0
            if usage_pct >= 100:
                usage_alert_badge = f'<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(239,68,68,0.18);color:#f87171;border:1px solid rgba(239,68,68,0.45);font-size:10px;padding:2px 8px;border-radius:10px;margin-left:8px;font-weight:700;animation:pulse-red 1.4s infinite;">🔴 {usage_pct:.0f}% — LIMIT REACHED</span>'
            elif usage_pct >= 75:
                usage_alert_badge = f'<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(245,158,11,0.15);color:#fbbf24;border:1px solid rgba(245,158,11,0.4);font-size:10px;padding:2px 8px;border-radius:10px;margin-left:8px;font-weight:700;">⚠️ {usage_pct:.0f}% used</span>'
            else:
                usage_alert_badge = ''

            # Header row for the user group — clickable link to user profile
            device_rows.append(f"""
            <tr class="user-header" data-user="{user_safe}" style="background: rgba(99, 102, 241, 0.15); border-left: 4px solid #6366f1; user-select: none;">
                <td colspan="6" style="padding: 10px 16px; font-weight: bold; color: #a5b4fc;">
                    <span class="toggle-icon" style="display:inline-block; width:12px; margin-right:5px; cursor:pointer;">▼</span>
                    <a href="/user/{user}" style="color:#a5b4fc; text-decoration:none;" onclick="event.stopPropagation();">👤 {user}</a>
                    {online_badge}
                    {usage_alert_badge}
                    <span style="color:rgba(255,255,255,0.5); font-weight:400; margin-left:12px;">Total: {format_bytes(user_totals[user])}</span>
                </td>
            </tr>
            """)
            # Device rows under this user
            for dev in user_devs:
                name_escaped = dev['name'].replace("'", "\\'")
                online_dot = '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#10b981;margin-right:5px;box-shadow:0 0 5px #10b981;"></span>' if dev['is_online'] else '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#6b7280;margin-right:5px;"></span>'
                last_seen_display = f'<div style="font-size:10px;color:rgba(255,255,255,0.35);margin-top:2px;">Last seen: <span class="utc-time" data-utc="{dev["last_seen"]}">{dev["last_seen"] or "never"}</span></div>' if dev['last_seen'] else '<div style="font-size:10px;color:rgba(255,255,255,0.25);margin-top:2px;">Last seen: never</div>'
                device_rows.append(f"""
                <tr class="device-row user-{user_safe}">
                    <td style="padding-left: 30px;">
                        {online_dot}<span style="font-weight:bold; color:#fff;">{dev['name']}</span><br>
                        <span style="font-size:12px; color:rgba(255,255,255,0.4)">{dev['ip']}</span>
                        {last_seen_display}
                    </td>
                    <td><code style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; cursor: pointer; vertical-align: middle;" title="Double-click to de-authorize" ondblclick="if(confirm('Are you sure you want to de-authorize this device?')){{ performApiAction('/api/deassociate?mac={dev['mac']}'); }}">{dev['mac']}</code></td>
                    <td><a href="/user/{dev['user']}" style="color:#a5b4fc; text-decoration:none;">{dev['user']}</a></td>
                    <td>
                        <div>Today: <span style="font-weight:bold; color:#a5b4fc;">{format_bytes(dev['today_bytes'])}</span></div>
                        <div style="font-size: 11px; color: rgba(255,255,255,0.4); margin-top: 2px;">Cycle: {format_bytes(dev['total_bytes'])} ({dev['sent']} ↑ / {dev['recv']} ↓)</div>
                    </td>
                    <td style="text-align:center;">
                        {'<span style="color:#10b981;font-size:11px;font-weight:600;">● Online</span>' if dev['is_online'] else '<span style="color:#6b7280;font-size:11px;">○ Offline</span>'}
                    </td>
                    <td>
                        <div class="dropdown">
                            <button class="dropdown-btn" onclick="toggleDropdown(event, this)">&#8942;</button>
                            <div class="dropdown-content">
                                <a onclick="renameDevice('{dev['mac']}', '{name_escaped}')">Rename Device</a>
                                <a onclick="performApiAction('/api/dhcp/preserve_device?mac={dev['mac']}&ip={dev['ip']}&name={urllib.parse.quote(dev['name'])}'); closeAllDropdowns();">Preserve IP</a>
                                <a class="text-danger" onclick="performApiAction('/api/deassociate?mac={dev['mac']}'); closeAllDropdowns();">De-authorize</a>
                            </div>
                        </div>
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
        vault_db_path_val = get_vault_db_path()

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
        .table-responsive {{
            width: 100%;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; margin-bottom: 15px; }}
        th, td {{ padding: 12px 16px; border-bottom: 1px solid var(--border-color); font-size: 13px; }}
        th {{ color: rgba(255,255,255,0.6); font-weight: 500; }}
        
        @media(max-width: 768px) {{
            .header {{
                flex-direction: column;
                align-items: stretch;
                padding: 15px 20px;
                gap: 12px;
            }}
            .header div {{
                display: flex;
                flex-direction: column;
                gap: 8px;
                width: 100%;
            }}
            .header div a {{
                margin-right: 0 !important;
                text-align: center;
                display: block;
            }}
            .header .user {{
                text-align: center;
                display: block;
            }}
            .container {{
                margin: 15px auto;
                padding: 0 10px;
            }}
            .card {{
                padding: 16px;
                margin-bottom: 20px;
            }}
            .card h2 {{
                font-size: 16px;
                margin-bottom: 15px;
            }}
            th, td {{
                padding: 8px 10px;
                font-size: 12px;
            }}
            .stats-grid {{
                grid-template-columns: 1fr;
                gap: 12px;
            }}
            .stat-card {{
                padding: 16px;
            }}
            .stat-card .value {{
                font-size: 20px;
            }}
        }}
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
        .period-btn {{
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            color: rgba(255,255,255,0.55);
            font-size: 12px;
            font-weight: 600;
            padding: 6px 14px;
            cursor: pointer;
            font-family: inherit;
            transition: all 0.2s;
        }}
        .period-btn:hover {{
            background: rgba(99,102,241,0.2);
            border-color: rgba(99,102,241,0.4);
            color: #a5b4fc;
        }}
        .period-btn.active {{
            background: linear-gradient(135deg, #6366f1, #4f46e5);
            border-color: transparent;
            color: #fff;
            box-shadow: 0 2px 12px rgba(99,102,241,0.4);
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
        
        /* Dropdown Actions Menu */
        .dropdown {{
            position: relative;
            display: inline-block;
        }}
        .dropdown-btn {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #f1f5f9;
            font-size: 18px;
            cursor: pointer;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            line-height: 1;
            transition: all 0.2s ease;
        }}
        .dropdown-btn:hover {{
            background: rgba(255, 255, 255, 0.15);
            border-color: rgba(255, 255, 255, 0.2);
            color: #fff;
            transform: scale(1.05);
        }}
        .dropdown-content {{
            display: none;
            position: absolute;
            right: 0;
            background: #1e293b;
            min-width: 150px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
            z-index: 1000;
            margin-top: 4px;
            overflow: hidden;
        }}
        .dropdown-content a {{
            color: #e2e8f0;
            padding: 10px 16px;
            text-decoration: none;
            display: block;
            font-size: 12px;
            transition: all 0.2s ease;
            cursor: pointer;
            font-family: monospace;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }}
        .dropdown-content a:last-child {{
            border-bottom: none;
        }}
        .dropdown-content a:hover {{
            background: rgba(99, 102, 241, 0.2);
            color: #fff;
        }}
        .dropdown-content a.text-danger {{
            color: #f43f5e;
        }}
        .dropdown-content a.text-danger:hover {{
            background: rgba(244, 63, 94, 0.2);
            color: #ff859b;
        }}
        .dropdown.show .dropdown-content {{
            display: block;
            animation: fadeInDropdown 0.15s cubic-bezier(0.16, 1, 0.3, 1);
        }}
        @keyframes fadeInDropdown {{
            from {{
                opacity: 0;
                transform: translateY(-8px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}
        
        /* Tabs navigation */
        .tabs-nav {{
            display: flex;
            gap: 10px;
            margin-bottom: 25px;
            overflow-x: auto;
            padding-bottom: 5px;
            border-bottom: 1px solid var(--border-color);
            -webkit-overflow-scrolling: touch;
        }}
        .tabs-nav::-webkit-scrollbar {{
            height: 4px;
        }}
        .tabs-nav::-webkit-scrollbar-thumb {{
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
        }}
        .tab-btn {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            color: rgba(255, 255, 255, 0.6);
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: 600;
            font-family: monospace;
            cursor: pointer;
            transition: all 0.2s ease;
            white-space: nowrap;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        .tab-btn svg {{
            opacity: 0.7;
            transition: opacity 0.2s;
        }}
        .tab-btn:hover {{
            background: rgba(255, 255, 255, 0.08);
            color: #fff;
        }}
        .tab-btn:hover svg {{
            opacity: 1;
        }}
        .tab-btn.active {{
            background: var(--accent-color);
            color: #fff;
            border-color: var(--accent-color);
            box-shadow: 0 4px 14px 0 rgba(99, 102, 241, 0.4);
        }}
        .tab-btn.active svg {{
            opacity: 1;
        }}
        .tab-content {{
            display: none;
            animation: fadeInTab 0.3s ease;
        }}
        .tab-content.active {{
            display: block;
        }}
        @keyframes fadeInTab {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        @keyframes pulse-red {{
            0%, 100% {{ box-shadow: 0 0 0 0 rgba(239,68,68,0.5); opacity: 1; }}
            50% {{ box-shadow: 0 0 0 5px rgba(239,68,68,0); opacity: 0.8; }}
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
        <!-- Tabs Navigation -->
        <div class="tabs-nav">
            <button class="tab-btn active" onclick="switchTab('dashboard')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect><rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect></svg>
                Dashboard
            </button>
            <button class="tab-btn" onclick="switchTab('users')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
                Users & Quotas
            </button>
            <button class="tab-btn" onclick="switchTab('dhcp')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
                DHCP Server
            </button>
            <button class="tab-btn" onclick="switchTab('system')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                System Settings
            </button>
        </div>

        <!-- 1. Dashboard Tab -->
        <div id="tab-dashboard" class="tab-content active">
            <!-- Period Selector -->
            <div style="display:flex; align-items:center; gap:12px; margin-bottom:18px; flex-wrap:wrap;">
                <span style="font-size:12px; color:rgba(255,255,255,0.4); font-weight:600; text-transform:uppercase; letter-spacing:.06em;">View Period:</span>
                <div id="period-selector" style="display:flex; gap:6px; flex-wrap:wrap;">
                    <button class="period-btn" data-period="day" onclick="setPeriod('day')">Today</button>
                    <button class="period-btn" data-period="week" onclick="setPeriod('week')">Last 7 Days</button>
                    <button class="period-btn" data-period="month" onclick="setPeriod('month')">This Cycle</button>
                    <button class="period-btn" data-period="6month" onclick="setPeriod('6month')">6 Months</button>
                    <button class="period-btn" data-period="all" onclick="setPeriod('all')">All Time</button>
                </div>
                <span id="period-label" style="font-size:11px; color:rgba(255,255,255,0.35); margin-left:auto;"></span>
            </div>

            <!-- Usage Metrics Counters (updated dynamically by period) -->
            <div class="stats-grid" id="stats-grid-container">
                <div class="stat-card today">
                    <span class="label">Period Usage</span>
                    <span class="value" id="stat-period-total">{format_bytes(overall_today)}</span>
                </div>
                <div class="stat-card mtd">
                    <span class="label">Daily Average</span>
                    <span class="value" id="stat-daily-avg">{format_bytes(overall_today)}</span>
                </div>
                <div class="stat-card total">
                    <span class="label">Cycle Usage ({get_billing_cycle_range_str()})</span>
                    <span class="value" id="stat-cycle">{format_bytes(overall_mtd)}</span>
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

            <!-- Usage Trend Chart -->
            <div class="card" style="margin-bottom:20px; padding:18px 22px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h2 style="margin:0;">Usage Trend</h2>
                    <span id="trend-range-label" style="font-size:11px; color:rgba(255,255,255,0.35);"></span>
                </div>
                <div id="trend-chart-wrap" style="height:100px; display:flex; align-items:flex-end; gap:2px; padding-bottom:16px;">
                    <span style="color:rgba(255,255,255,0.25); font-size:12px; margin:auto;">Loading&hellip;</span>
                </div>

                <!-- User Breakdown (period-aware) -->
                <div style="margin-top:16px;">
                    <div style="font-size:11px; font-weight:600; color:rgba(255,255,255,0.35); text-transform:uppercase; letter-spacing:.06em; margin-bottom:10px;">Users in Period</div>
                    <div id="user-period-list" style="display:flex; flex-direction:column; gap:8px;"></div>
                </div>
            </div>

            <div class="grid">
                <div>
                    <div class="card" id="devices-card-container">
                        <h2>Authorized Local Devices</h2>
                        <div class="table-responsive">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Name & IP Address</th>
                                        <th>MAC Address</th>
                                        <th>Owner</th>
                                        <th>Usage (Today / Cycle)</th>
                                        <th>Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {device_rows_html or '<tr><td colspan="6" style="text-align:center;">No devices authorized.</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div>
                    <div class="card" id="processes-card-container">
                        <h2>Server Process Usage</h2>
                        <div class="table-responsive">
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
        </div>

        <!-- 2. Users & Quotas Tab -->
        <div id="tab-users" class="tab-content">
            <div class="grid">
                <div>
                    <div class="card" id="users-card-container">
                        <h2>Registered Users</h2>
                        <div class="table-responsive">
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
                    </div>

                    <div class="card" id="groups-card-container">
                        <h2>Package / User Groups</h2>
                        <div class="table-responsive">
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
                </div>

                <div>
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
                                * Heuristic suggested quotas are dynamically calculated in the Registered Users table based on past week usage!
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
                </div>
            </div>
        </div>

        <!-- 3. DHCP Server Tab -->
        <div id="tab-dhcp" class="tab-content">
            <div class="grid">
                <div>
                    <!-- DHCP Administration UI -->
                    <div class="card" id="leases-card-container">
                        <h2>Dynamic DHCP Client Leases</h2>
                        <div class="table-responsive">
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
                    </div>

                    <div class="card" id="reservations-card-container">
                        <h2>Static IP DHCP Reservations (Preserved IPs)</h2>
                        <div class="table-responsive">
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
                </div>
            </div>
        </div>

        <!-- 4. System Settings Tab -->
        <div id="tab-system" class="tab-content">
            <div class="grid">
                <div>
                    <div class="card" id="distribution-card-container">
                        <h2>Global Pool Distribution Breakdown</h2>
                        <div class="table-responsive">
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
                    </div>
                </div>

                <div>
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

                    <div class="card" id="system-paths-card-container">
                        <h2>Configure System Paths</h2>
                        <form method="POST" action="/settings/paths">
                            <div class="form-group">
                                <label>Vault SQLite Database Path</label>
                                <input type="text" name="vault_path" value="{vault_db_path_val}" required>
                            </div>
                            <div class="form-group">
                                <label>Dnsmasq DHCP Leases Path</label>
                                <input type="text" name="leases_path" value="{get_dnsmasq_leases_path()}" required>
                            </div>
                            <div class="form-group">
                                <label>Static Leases Configuration Path</label>
                                <input type="text" name="static_leases_path" value="{get_static_leases_path()}" required>
                            </div>
                            <button type="submit" class="btn-submit">Save & Restart Services</button>
                        </form>
                        <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid var(--border-color);">
                            <label style="display:block; font-size:12px; color:rgba(255,255,255,0.6); margin-bottom:8px;">Move active logs from SSD to first writeable HDD partition:</label>
                            <button onclick="performApiAction('/settings/migrate_vault')" class="btn-submit" style="background:#a855f7;">Migrate Logs to HDD & Free SSD</button>
                        </div>
                    </div>

                    <div class="card" id="cycle-day-card-container">
                        <h2>Configure Billing Cycle</h2>
                        <form method="POST" action="/settings/cycle_day">
                            <div class="form-group">
                                <label>Rollover Day of Month (1-31)</label>
                                <input type="number" name="cycle_day" min="1" max="31" value="{get_billing_cycle_day()}" required>
                                <div style="font-size:11px; color:rgba(255,255,255,0.4); margin-top:5px;">Cycle: {get_billing_cycle_day()}{get_day_suffix(get_billing_cycle_day())} to {get_cycle_end_day_desc(get_billing_cycle_day())}</div>
                            </div>
                            <button type="submit" class="btn-submit">Update Billing Cycle Day</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let activeTab = 'dashboard';
        
        function switchTab(tabId) {{
            activeTab = tabId;
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            
            const selectedContent = document.getElementById('tab-' + tabId);
            if (selectedContent) {{
                selectedContent.classList.add('active');
            }}
            
            const selectedBtn = Array.from(document.querySelectorAll('.tab-btn')).find(btn => btn.getAttribute('onclick').includes(tabId));
            if (selectedBtn) {{
                selectedBtn.classList.add('active');
            }}
            
            localStorage.setItem('nettrack_active_tab', tabId);
        }}
        
        document.addEventListener('DOMContentLoaded', () => {{
            const savedTab = localStorage.getItem('nettrack_active_tab');
            if (savedTab) {{
                switchTab(savedTab);
            }}
        }});

        const collapsedUsers = new Set();

        function showToast(message, isError = false) {{
            const toast = document.getElementById("toast");
            toast.textContent = message;
            toast.className = isError ? "error show" : "show";
            setTimeout(() => {{
                toast.classList.remove("show");
            }}, 3000);
        }}

        function renameDevice(mac, currentName) {{
            const newName = prompt("Enter new name for the device:", currentName);
            if (newName === null) return;
            if (newName.trim() === "") {{
                showToast("Device name cannot be empty.", true);
                return;
            }}
            
            const params = new URLSearchParams();
            params.append("mac", mac);
            params.append("name", newName);
            
            fetch("/device/rename", {{
                method: "POST",
                headers: {{
                    "Content-Type": "application/x-www-form-urlencoded"
                }},
                body: params
            }})
            .then(response => {{
                if (response.ok) {{
                    showToast("Device renamed successfully!");
                    refreshDashboard();
                }} else {{
                    showToast("Error renaming device.", true);
                }}
            }})
            .catch(err => showToast("Network error: " + err, true));
        }}

        function toggleDropdown(event, btn) {{
            event.stopPropagation();
            const parent = btn.parentElement;
            const wasShown = parent.classList.contains("show");
            
            closeAllDropdowns();
            
            if (!wasShown) {{
                parent.classList.add("show");
            }}
        }}

        function closeAllDropdowns() {{
            document.querySelectorAll(".dropdown").forEach(d => {{
                d.classList.remove("show");
            }});
        }}

        document.addEventListener("click", function(e) {{
            if (!e.target.closest(".dropdown")) {{
                closeAllDropdowns();
            }}
        }});

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
                    "system-paths-card-container",
                    "cycle-day-card-container",
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

        // ── Period Selector ─────────────────────────────────────────────────
        function fmtBytesD(b) {{
            if (!b || b === 0) return '0 B';
            const u = ['B','KB','MB','GB','TB']; let i = 0;
            while (b >= 1024 && i < u.length-1) {{ b /= 1024; i++; }}
            return b.toFixed(2) + ' ' + u[i];
        }}

        function setPeriod(p) {{
            localStorage.setItem('nettrack_period', p);
            document.querySelectorAll('.period-btn').forEach(function(btn) {{
                btn.classList.toggle('active', btn.dataset.period === p);
            }});
            loadPeriodData(p);
        }}

        function loadPeriodData(p) {{
            const lbl = document.getElementById('period-label');
            if (lbl) lbl.textContent = 'Loading…';
            fetch('/api/dashboard?period=' + encodeURIComponent(p))
                .then(function(r) {{ return r.json(); }})
                .then(function(d) {{ renderPeriodData(d); }})
                .catch(function(e) {{ console.error('Period load error', e); }});
        }}

        function renderPeriodData(d) {{
            // Update stat cards
            const tot = document.getElementById('stat-period-total');
            const avg = document.getElementById('stat-daily-avg');
            const cyc = document.getElementById('stat-cycle');
            const lbl = document.getElementById('period-label');
            if (tot) tot.textContent = fmtBytesD(d.overall_bytes);
            if (avg) avg.textContent = fmtBytesD(d.daily_avg_bytes) + '/day';
            if (lbl) lbl.textContent = d.label + ' · ' + d.days + ' day' + (d.days !== 1 ? 's' : '');

            // Trend chart
            renderTrendChart(d);

            // User breakdown
            renderUserPeriodList(d);
        }}

        function renderTrendChart(d) {{
            const wrap = document.getElementById('trend-chart-wrap');
            const rangeEl = document.getElementById('trend-range-label');
            if (!wrap) return;
            const CHART_H = 80;

            if (d.period === 'day') {{
                // Hourly bars
                const pts = d.hourly_chart || [];
                const maxV = Math.max(1, Math.max.apply(null, pts.map(function(p) {{ return p.bytes; }})));
                if (rangeEl) rangeEl.textContent = 'Hourly breakdown — Today';
                wrap.innerHTML = pts.map(function(p) {{
                    const px = p.bytes > 0 ? Math.max(Math.round((p.bytes/maxV)*CHART_H), 2) : 0;
                    const c = p.bytes > 0 ? 'linear-gradient(180deg,#818cf8,#4338ca)' : 'rgba(255,255,255,0.06)';
                    return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:2px;height:100%;">' +
                        '<div style="width:100%;border-radius:3px 3px 0 0;height:' + px + 'px;min-height:' + (p.bytes>0?'2':'0') + 'px;background:' + c + ';"></div>' +
                        '<div style="font-size:7px;color:rgba(255,255,255,0.3);">' + p.hour + '</div></div>';
                }}).join('');
            }} else {{
                // Daily bars
                const pts = d.daily_chart || [];
                const maxV = Math.max(1, Math.max.apply(null, pts.map(function(p) {{ return p.bytes; }})));
                if (rangeEl) rangeEl.textContent = d.label + ' — daily breakdown';
                if (pts.length === 0) {{
                    wrap.innerHTML = '<span style="color:rgba(255,255,255,0.25);font-size:12px;margin:auto;">No data for this period</span>';
                    return;
                }}
                wrap.innerHTML = pts.map(function(p) {{
                    const px = Math.max(Math.round((p.bytes/maxV)*CHART_H), 2);
                    const shortDate = p.date ? p.date.slice(5) : '';  // MM-DD
                    return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:2px;height:100%;min-width:4px;" title="' + p.date + ': ' + fmtBytesD(p.bytes) + '">' +
                        '<div style="width:100%;border-radius:3px 3px 0 0;height:' + px + 'px;background:linear-gradient(180deg,#818cf8,#4338ca);cursor:pointer;" onclick="void(0)"></div>' +
                        (pts.length <= 31 ? '<div style="font-size:7px;color:rgba(255,255,255,0.3);transform:rotate(-45deg);transform-origin:center top;margin-top:2px;">' + shortDate + '</div>' : '') +
                    '</div>';
                }}).join('');
            }}
        }}

        function renderUserPeriodList(d) {{
            const el = document.getElementById('user-period-list');
            if (!el) return;
            if (!d.users || d.users.length === 0) {{
                el.innerHTML = '<span style="color:rgba(255,255,255,0.3);font-size:12px;">No usage data for this period.</span>';
                return;
            }}
            const maxUser = Math.max(1, Math.max.apply(null, d.users.map(function(u) {{ return u.bytes; }})));
            el.innerHTML = d.users.map(function(u) {{
                const pct = Math.min((u.bytes / maxUser) * 100, 100);
                const lim = u.monthly_limit;
                const limPct = lim ? Math.min((u.bytes / lim) * 100, 100) : 0;
                const limColor = limPct > 90 ? '#ef4444' : limPct > 70 ? '#f59e0b' : '#10b981';
                const onlineDot = u.online_devices > 0
                    ? '<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:#10b981;box-shadow:0 0 4px #10b981;margin-right:5px;"></span>'
                    : '<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:#4b5563;margin-right:5px;"></span>';
                return '<div style="display:flex;align-items:center;gap:10px;">' +
                    '<a href="/user/' + encodeURIComponent(u.username) + '" style="width:90px;font-size:12px;font-weight:600;color:#a5b4fc;text-decoration:none;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + onlineDot + u.username + '</a>' +
                    '<div style="flex:1;height:8px;background:rgba(255,255,255,0.06);border-radius:4px;overflow:hidden;">' +
                        '<div style="height:100%;width:' + pct + '%;background:linear-gradient(90deg,#6366f1,#818cf8);border-radius:4px;transition:width .6s;"></div>' +
                    '</div>' +
                    '<span style="width:80px;text-align:right;font-size:11px;color:rgba(255,255,255,0.6);">' + fmtBytesD(u.bytes) + '</span>' +
                    (lim ? '<span style="font-size:10px;color:' + limColor + ';width:35px;text-align:right;">' + limPct.toFixed(0) + '%</span>' : '<span style="width:35px;"></span>') +
                '</div>';
            }}).join('');
        }}

        // Init period selector from localStorage
        (function() {{
            const saved = localStorage.getItem('nettrack_period') || 'day';
            document.querySelectorAll('.period-btn').forEach(function(btn) {{
                btn.classList.toggle('active', btn.dataset.period === saved);
            }});
            loadPeriodData(saved);
        }})();
        // ───────────────────────────────────────────────────────────────────

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

    def serve_dashboard_api(self, period):
        """Returns JSON with period-scoped dashboard stats."""
        import json
        from datetime import datetime, timedelta, timezone

        # Determine the start timestamp string for the period
        now_utc = datetime.now(timezone.utc)
        if period == 'day':
            start_dt = datetime(now_utc.year, now_utc.month, now_utc.day, tzinfo=timezone.utc)
            label = "Today"
        elif period == 'week':
            start_dt = now_utc - timedelta(days=7)
            label = "Last 7 Days"
        elif period == 'month':
            start_dt = get_billing_start_dt() if hasattr(self, '_get_billing_start_dt') else (now_utc - timedelta(days=30))
            # Use billing cycle start
            try:
                from datetime import datetime as _dt
                ms = get_billing_start()  # already a string like "2026-06-28 ..."
                start_dt = datetime.fromisoformat(ms).replace(tzinfo=timezone.utc)
            except Exception:
                start_dt = now_utc - timedelta(days=30)
            label = "This Billing Cycle"
        elif period == '6month':
            start_dt = now_utc - timedelta(days=183)
            label = "Last 6 Months"
        else:  # 'all'
            start_dt = datetime(2000, 1, 1, tzinfo=timezone.utc)
            label = "All Time"

        start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        days_in_period = max((now_utc - start_dt).days, 1)

        result = {
            "period": period, "label": label, "start": start_str,
            "days": days_in_period,
            "overall_bytes": 0, "daily_avg_bytes": 0,
            "users": [], "top_domains": [],
            "daily_chart": [],  # [{date, bytes}] for week/month/6month
            "hourly_chart": [], # [{hour, bytes}] for day
        }

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # Overall total for period
            cursor.execute("SELECT COALESCE(SUM(sent_bytes+received_bytes),0) FROM device_usage WHERE timestamp>=?;", (start_str,))
            result["overall_bytes"] = cursor.fetchone()[0]
            result["daily_avg_bytes"] = result["overall_bytes"] // days_in_period if days_in_period > 0 else 0

            # Per-user breakdown
            cursor.execute("""
                SELECT rd.username,
                       COALESCE(SUM(du.sent_bytes+du.received_bytes),0) as total,
                       u.daily_limit_bytes, u.monthly_limit_bytes,
                       ug.daily_limit_bytes, ug.monthly_limit_bytes
                FROM registered_devices rd
                JOIN device_usage du ON LOWER(du.mac_address)=LOWER(rd.mac_address)
                LEFT JOIN users u ON rd.username=u.username
                LEFT JOIN user_groups ug ON u.group_id=ug.id
                WHERE du.timestamp>=?
                GROUP BY rd.username
                ORDER BY total DESC;
            """, (start_str,))
            active_leases = get_active_leases()
            online_macs = {l['mac'].lower().strip() for l in active_leases}

            # Count online devices per user
            cursor.execute("SELECT mac_address, username FROM registered_devices;")
            mac_to_user = {r[0].lower(): r[1] for r in cursor.fetchall()}
            online_per_user = {}
            for mac in online_macs:
                u = mac_to_user.get(mac)
                if u:
                    online_per_user[u] = online_per_user.get(u, 0) + 1

            # Also get addon bytes per user
            cursor.execute("SELECT username, COALESCE(SUM(addon_bytes),0) FROM user_addons GROUP BY username;")
            addon_map = {r[0]: r[1] for r in cursor.fetchall()}

            for row in cursor.fetchall() if False else []:
                pass

            cursor.execute("""
                SELECT rd.username,
                       COALESCE(SUM(du.sent_bytes+du.received_bytes),0) as total,
                       u.daily_limit_bytes, u.monthly_limit_bytes,
                       ug.daily_limit_bytes, ug.monthly_limit_bytes
                FROM registered_devices rd
                JOIN device_usage du ON LOWER(du.mac_address)=LOWER(rd.mac_address)
                LEFT JOIN users u ON rd.username=u.username
                LEFT JOIN user_groups ug ON u.group_id=ug.id
                WHERE du.timestamp>=?
                GROUP BY rd.username
                ORDER BY total DESC;
            """, (start_str,))
            for uname, total_b, udl, uml, gdl, gml in cursor.fetchall():
                eff_daily = udl or gdl
                eff_monthly = (uml or gml or 0) + addon_map.get(uname, 0)
                result["users"].append({
                    "username": uname,
                    "bytes": total_b,
                    "daily_avg": total_b // days_in_period,
                    "online_devices": online_per_user.get(uname, 0),
                    "daily_limit": eff_daily,
                    "monthly_limit": eff_monthly if eff_monthly > 0 else None,
                })

            # Daily chart (for week / month / 6month / all)
            if period != 'day':
                cursor.execute("""
                    SELECT DATE(timestamp) as d, SUM(sent_bytes+received_bytes)
                    FROM device_usage WHERE timestamp>=?
                    GROUP BY d ORDER BY d;
                """, (start_str,))
                result["daily_chart"] = [{"date": r[0], "bytes": r[1]} for r in cursor.fetchall()]
            else:
                # Hourly chart for today
                cursor.execute("""
                    SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hr, SUM(sent_bytes+received_bytes)
                    FROM device_usage WHERE timestamp>=?
                    GROUP BY hr ORDER BY hr;
                """, (start_str,))
                hourly = {h: 0 for h in range(24)}
                for hr, b in cursor.fetchall():
                    hourly[hr] = b
                result["hourly_chart"] = [{"hour": h, "bytes": b} for h, b in hourly.items()]

            conn.close()

            # Vault: top domains for period
            try:
                vault_conn = sqlite3.connect(get_vault_db_path())
                vc = vault_conn.cursor()
                vc.execute("""
                    SELECT dst_ip, SUM(bytes) as tb FROM raw_traffic
                    WHERE timestamp>=? GROUP BY dst_ip ORDER BY tb DESC LIMIT 15;
                """, (start_str,))
                for dst_ip, b in vc.fetchall():
                    result["top_domains"].append({"domain": get_website_domain(dst_ip), "ip": dst_ip, "bytes": b})
                vault_conn.close()
            except Exception:
                pass

        except Exception as e:
            result["error"] = str(e)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def serve_user_api(self, username):
        """Returns JSON with user entity data including vault analytics."""
        import json
        result = {"username": username, "devices": [], "vault": {"top_domains": [], "hourly_pattern": [], "top_ips": []}}
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            today_start = get_local_midnight_in_utc()
            month_start = get_billing_start()

            # Devices
            cursor.execute("""
                SELECT rd.mac_address, rd.ip_address, rd.device_name, rd.last_seen, rd.registered_at,
                       COALESCE(SUM(du.sent_bytes + du.received_bytes), 0) AS total,
                       COALESCE((SELECT SUM(sent_bytes+received_bytes) FROM device_usage
                                 WHERE LOWER(mac_address)=LOWER(rd.mac_address) AND timestamp >= ?), 0) AS today,
                       COALESCE((SELECT SUM(sent_bytes+received_bytes) FROM device_usage
                                 WHERE LOWER(mac_address)=LOWER(rd.mac_address) AND timestamp >= ?), 0) AS cycle
                FROM registered_devices rd
                LEFT JOIN device_usage du ON LOWER(du.mac_address) = LOWER(rd.mac_address)
                WHERE rd.username = ?
                GROUP BY rd.mac_address;
            """, (today_start, month_start, username))
            active_leases = get_active_leases()
            online_macs = {l['mac'].lower().strip() for l in active_leases}
            for row in cursor.fetchall():
                mac, ip, dname, last_seen, reg_at, total_b, today_b, cycle_b = row
                result["devices"].append({
                    "mac": mac, "ip": ip, "name": dname or "Unnamed Device",
                    "last_seen": last_seen or "", "registered_at": reg_at or "",
                    "is_online": mac.lower().strip() in online_macs,
                    "today_bytes": today_b, "cycle_bytes": cycle_b, "total_bytes": total_b
                })

            # User limits + group info
            cursor.execute("""
                SELECT u.daily_limit_bytes, u.monthly_limit_bytes, u.group_id,
                       ug.name, ug.daily_limit_bytes, ug.monthly_limit_bytes
                FROM users u LEFT JOIN user_groups ug ON u.group_id = ug.id
                WHERE u.username = ?;
            """, (username,))
            lrow = cursor.fetchone()
            if lrow:
                udl, uml, gid, gname, gdl, gml = lrow
                result["limits"] = {
                    "daily_bytes": udl or gdl,
                    "monthly_bytes": uml or gml,
                    "custom_daily_bytes": udl,
                    "custom_monthly_bytes": uml,
                    "group": gname or "None",
                    "group_id": gid
                }

            # Addon total
            cursor.execute("SELECT COALESCE(SUM(addon_bytes),0) FROM user_addons WHERE username=?;", (username,))
            result["addon_bytes"] = cursor.fetchone()[0]

            # All groups for the dropdown
            cursor.execute("SELECT id, name, daily_limit_bytes, monthly_limit_bytes FROM user_groups ORDER BY name;")
            result["groups"] = [{"id": r[0], "name": r[1], "daily_bytes": r[2], "monthly_bytes": r[3]} for r in cursor.fetchall()]

            conn.close()

            # Vault analytics
            vault_conn = sqlite3.connect(get_vault_db_path())
            vcursor = vault_conn.cursor()
            user_macs = [d['mac'].lower().strip() for d in result["devices"]]
            if user_macs:
                placeholders = ",".join("?" for _ in user_macs)
                # Top destinations
                vcursor.execute(f"""
                    SELECT dst_ip, SUM(bytes) as total_bytes FROM raw_traffic
                    WHERE LOWER(src_mac) IN ({placeholders})
                    GROUP BY dst_ip ORDER BY total_bytes DESC LIMIT 20;
                """, user_macs)
                for dst_ip, b in vcursor.fetchall():
                    domain = get_website_domain(dst_ip)
                    result["vault"]["top_domains"].append({"domain": domain, "ip": dst_ip, "bytes": b})

                # Hourly usage pattern (last 7 days)
                vcursor.execute(f"""
                    SELECT strftime('%H', timestamp) as hr, SUM(bytes)
                    FROM raw_traffic
                    WHERE LOWER(src_mac) IN ({placeholders})
                      AND timestamp >= datetime('now', '-7 days')
                    GROUP BY hr ORDER BY hr;
                """, user_macs)
                hourly = {str(h).zfill(2): 0 for h in range(24)}
                for hr, b in vcursor.fetchall():
                    hourly[hr] = b
                result["vault"]["hourly_pattern"] = [{"hour": int(h), "bytes": b} for h, b in hourly.items()]
            vault_conn.close()
        except Exception as e:
            result["error"] = str(e)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode("utf-8"))

    def serve_user_profile_page(self, username):
        """Renders a full user entity profile page."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{username} &mdash; NetTrack Profile</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #080d1a;
            --card: rgba(18, 26, 46, 0.85);
            --border: rgba(255,255,255,0.07);
            --accent: #6366f1;
            --green: #10b981;
            --text: #e2e8f0;
            --muted: rgba(255,255,255,0.45);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh;
                background-image: radial-gradient(ellipse at 20% 20%, rgba(99,102,241,0.08) 0%, transparent 60%),
                                  radial-gradient(ellipse at 80% 80%, rgba(16,185,129,0.05) 0%, transparent 60%); }}
        .header {{ padding: 18px 32px; background: rgba(8,13,26,0.9); border-bottom: 1px solid var(--border);
                   backdrop-filter: blur(16px); display: flex; align-items: center; gap: 16px; }}
        .back-btn {{ color: var(--accent); text-decoration: none; font-size: 13px; font-weight: 500;
                     padding: 7px 14px; border: 1px solid rgba(99,102,241,0.3); border-radius: 8px;
                     transition: all 0.2s; }}
        .back-btn:hover {{ background: rgba(99,102,241,0.15); }}
        .header-title {{ font-size: 18px; font-weight: 700; }}
        .container {{ max-width: 1200px; margin: 28px auto; padding: 0 24px; }}
        .profile-hero {{ background: var(--card); border: 1px solid var(--border); border-radius: 16px;
                         padding: 28px 32px; margin-bottom: 24px; backdrop-filter: blur(12px);
                         display: flex; align-items: center; gap: 28px; flex-wrap: wrap; }}
        .avatar {{ width: 72px; height: 72px; border-radius: 50%;
                   background: linear-gradient(135deg, #6366f1, #8b5cf6);
                   display: flex; align-items: center; justify-content: center;
                   font-size: 30px; font-weight: 700; color: #fff; flex-shrink: 0; }}
        .hero-info {{ flex: 1; }}
        .hero-info h1 {{ font-size: 24px; font-weight: 700; }}
        .hero-info .sub {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
        .hero-stats {{ display: flex; gap: 24px; flex-wrap: wrap; }}
        .hstat {{ text-align: center; }}
        .hstat .val {{ font-size: 22px; font-weight: 700; color: var(--accent); }}
        .hstat .lbl {{ font-size: 11px; color: var(--muted); margin-top: 2px; }}
        .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }}
        @media(max-width: 768px) {{ .grid2 {{ grid-template-columns: 1fr; }} }}
        .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 14px;
                 padding: 22px; backdrop-filter: blur(12px); }}
        .card h2 {{ font-size: 14px; font-weight: 600; color: var(--muted); text-transform: uppercase;
                    letter-spacing: 0.08em; margin-bottom: 16px; }}
        .device-item {{ display: flex; align-items: center; gap: 12px; padding: 12px;
                        border-radius: 10px; background: rgba(255,255,255,0.04);
                        border: 1px solid var(--border); margin-bottom: 10px; }}
        .dev-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
        .dev-dot.online {{ background: var(--green); box-shadow: 0 0 8px var(--green); }}
        .dev-dot.offline {{ background: #4b5563; }}
        .dev-info {{ flex: 1; }}
        .dev-name {{ font-weight: 600; font-size: 14px; }}
        .dev-meta {{ font-size: 11px; color: var(--muted); margin-top: 2px; }}
        .dev-usage {{ text-align: right; font-size: 12px; }}
        .dev-usage .today {{ color: var(--accent); font-weight: 600; font-size: 14px; }}
        .limit-bar {{ margin-top: 8px; }}
        .bar-row {{ display: flex; justify-content: space-between; font-size: 11px; color: var(--muted); margin-bottom: 4px; }}
        .bar-bg {{ height: 6px; background: rgba(255,255,255,0.08); border-radius: 3px; overflow: hidden; }}
        .bar-fill {{ height: 100%; border-radius: 3px; transition: width 0.6s ease; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; font-size: 11px; color: var(--muted); font-weight: 600;
              text-transform: uppercase; letter-spacing: 0.07em; padding: 8px 10px;
              border-bottom: 1px solid var(--border); }}
        td {{ padding: 9px 10px; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,0.04); }}
        tr:last-child td {{ border-bottom: none; }}
        .domain-badge {{ display: inline-block; padding: 2px 8px; border-radius: 6px;
                         background: rgba(99,102,241,0.15); color: #a5b4fc; font-size: 12px; }}
        .chart-wrap {{ position: relative; height: 140px; display: flex; align-items: flex-end;
                       gap: 2px; padding-bottom: 16px; }}
        .bar-col {{ flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; gap: 2px; height: 100%; }}
        .bar-col .bar {{ width: 100%; border-radius: 3px 3px 0 0; background: linear-gradient(180deg, #818cf8, #4338ca);
                         transition: height 0.5s ease; min-height: 2px; }}
        .bar-col .bar-lbl {{ font-size: 7px; color: var(--muted); white-space: nowrap; }}
        .status-online {{ color: var(--green); font-weight: 600; font-size: 12px; }}
        .status-offline {{ color: #6b7280; font-size: 12px; }}
        .loading {{ text-align: center; padding: 48px; color: var(--muted); }}
        .spinner {{ display: inline-block; width: 28px; height: 28px; border: 3px solid rgba(99,102,241,0.2);
                    border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        .pulse {{ animation: pulse 2s ease-in-out infinite; }}
        @keyframes fadeIn {{ from {{ opacity:0; transform:translateY(6px); }} to {{ opacity:1; transform:none; }} }}
        .form-group {{ display:flex; flex-direction:column; gap:5px; }}
        .form-label {{ font-size:11px; font-weight:600; color:var(--muted); text-transform:uppercase; letter-spacing:0.06em; }}
        .form-input {{ background:rgba(255,255,255,0.05); border:1px solid var(--border); border-radius:8px;
                       color:var(--text); padding:9px 12px; font-size:13px; font-family:'Inter',sans-serif;
                       transition:border-color 0.2s; outline:none; width:100%; }}
        .form-input:focus {{ border-color:rgba(99,102,241,0.5); background:rgba(99,102,241,0.05); }}
        select.form-input {{ cursor:pointer; }}
        .btn-action {{ background:linear-gradient(135deg, #6366f1, #4f46e5); color:#fff; border:none;
                       border-radius:8px; padding:10px 20px; font-size:13px; font-weight:600;
                       cursor:pointer; font-family:'Inter',sans-serif; transition:opacity 0.2s; }}
        .btn-action:hover {{ opacity:0.85; }}
        @keyframes pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
    </style>
</head>
<body>
<div class="header">
    <a href="/" class="back-btn">&larr; Dashboard</a>
    <div class="header-title">User Profile</div>
</div>
<div class="container">
    <div id="profile-content">
        <div class="loading"><div class="spinner"></div><br><span style="margin-top:12px;display:block;">Loading profile&hellip;</span></div>
    </div>
</div>
<script>
    const username = {repr(username)};
    
    function fmtBytes(b) {{
        if (!b || b === 0) return '0 B';
        const units = ['B','KB','MB','GB','TB'];
        let i = 0;
        while (b >= 1024 && i < units.length - 1) {{ b /= 1024; i++; }}
        return b.toFixed(2) + ' ' + units[i];
    }}
    function timeSince(utcStr) {{
        if (!utcStr) return 'never';
        const t = new Date(utcStr.replace(' ', 'T') + 'Z');
        const diff = Math.floor((Date.now() - t) / 1000);
        if (diff < 60) return diff + 's ago';
        if (diff < 3600) return Math.floor(diff/60) + 'm ago';
        if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
        return Math.floor(diff/86400) + 'd ago';
    }}

    let profileData = null;

    function showToast(msg, isError) {{
        const t = document.createElement('div');
        const bg = isError ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)';
        const border = isError ? 'rgba(239,68,68,0.4)' : 'rgba(16,185,129,0.4)';
        const color = isError ? '#fca5a5' : '#6ee7b7';
        t.style.cssText = 'position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:10px;font-size:13px;font-weight:600;z-index:9999;backdrop-filter:blur(12px);background:' + bg + ';border:1px solid ' + border + ';color:' + color;
        t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(function() {{ t.remove(); }}, 3000);
    }}

    function postForm(url, params) {{
        const parts = [];
        for (const k in params) {{ parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(params[k])); }}
        return fetch(url, {{method:'POST', headers:{{'Content-Type':'application/x-www-form-urlencoded'}}, body:parts.join('&')}}).then(function(r) {{ return r.json(); }});
    }}

    function reload() {{
        fetch('/api/user/' + encodeURIComponent(username))
            .then(function(r) {{ return r.json(); }})
            .then(function(data) {{ renderProfile(data); }});
    }}

    function setLimits() {{
        const daily_gb   = document.getElementById('inp-daily').value.trim();
        const monthly_gb = document.getElementById('inp-monthly').value.trim();
        const group_id   = document.getElementById('inp-group').value;
        postForm('/api/user/' + encodeURIComponent(username) + '/set_limits', {{daily_gb:daily_gb, monthly_gb:monthly_gb, group_id:group_id}})
            .then(function(r) {{
                if (r.ok) {{ showToast('Limits saved!', false); reload(); }}
                else showToast(r.error || 'Error saving limits', true);
            }}).catch(function(e) {{ showToast('Network error: ' + e, true); }});
    }}

    function addQuota() {{
        const addon_gb = document.getElementById('inp-addon').value.trim();
        if (!addon_gb || parseFloat(addon_gb) <= 0) {{ showToast('Enter a valid GB amount', true); return; }}
        postForm('/api/user/' + encodeURIComponent(username) + '/add_quota', {{addon_gb:addon_gb}})
            .then(function(r) {{
                if (r.ok) {{ showToast('+' + addon_gb + ' GB quota added!', false); document.getElementById('inp-addon').value=''; reload(); }}
                else showToast(r.error || 'Error adding quota', true);
            }}).catch(function(e) {{ showToast('Network error: ' + e, true); }});
    }}

    function clearQuota() {{
        if (!confirm('Clear ALL quota addons for this user?')) return;
        postForm('/api/user/' + encodeURIComponent(username) + '/clear_quota', {{}})
            .then(function(r) {{
                if (r.ok) {{ showToast('All quota addons cleared.', false); reload(); }}
                else showToast(r.error || 'Error clearing quota', true);
            }}).catch(function(e) {{ showToast('Network error: ' + e, true); }});
    }}

    function renderProfile(data) {{
        profileData = data;
        const onlineDevices = data.devices.filter(function(d) {{ return d.is_online; }});
        const totalToday = data.devices.reduce(function(a, d) {{ return a + d.today_bytes; }}, 0);
        const totalCycle = data.devices.reduce(function(a, d) {{ return a + d.cycle_bytes; }}, 0);
        const limits = data.limits || {{}};
        const addonBytes = data.addon_bytes || 0;
        const effectiveMonthly = limits.monthly_bytes ? limits.monthly_bytes + addonBytes : null;
        const dailyUsedPct = limits.daily_bytes ? Math.min((totalToday / limits.daily_bytes) * 100, 100) : 0;
        const cycleUsedPct = effectiveMonthly ? Math.min((totalCycle / effectiveMonthly) * 100, 100) : 0;
        function barColor(pct) {{ return pct > 90 ? '#ef4444' : pct > 70 ? '#f59e0b' : '#10b981'; }}

        // Hourly chart
        const CHART_H = 120;
        const maxHr = Math.max.apply(null, [1].concat(data.vault.hourly_pattern.map(function(h) {{ return h.bytes; }})));
        const chartBars = data.vault.hourly_pattern.map(function(h) {{
            const px = Math.max(Math.round((h.bytes / maxHr) * CHART_H), h.bytes > 0 ? 2 : 0);
            const isActive = h.bytes > 0;
            const barStyle = 'width:100%;border-radius:3px 3px 0 0;height:' + px + 'px;min-height:' + (isActive?'2':'0') + 'px;background:linear-gradient(180deg,#818cf8,#4338ca);';
            return '<div class="bar-col"><div style="' + barStyle + '"></div><div class="bar-lbl">' + h.hour + '</div></div>';
        }}).join('');

        // Device cards
        const devCards = data.devices.length === 0
            ? '<p style="color:var(--muted); font-size:13px;">No devices registered.</p>'
            : data.devices.map(function(d) {{
                const dot = '<div class="dev-dot ' + (d.is_online ? 'online' : 'offline') + '"></div>';
                return '<div class="device-item">' + dot +
                    '<div class="dev-info"><div class="dev-name">' + d.name + '</div>' +
                    '<div class="dev-meta"><code style="font-size:11px;">' + d.mac + '</code> &bull; ' + d.ip + ' &bull; Last seen: ' + timeSince(d.last_seen) + '</div></div>' +
                    '<div class="dev-usage"><div class="today">' + fmtBytes(d.today_bytes) + '</div>' +
                    '<div style="color:var(--muted);font-size:11px;">today</div>' +
                    '<div style="font-size:11px;margin-top:2px;">' + fmtBytes(d.cycle_bytes) + ' cycle</div></div></div>';
            }}).join('');

        // Top domains table rows
        const domainRows = data.vault.top_domains.slice(0, 15).map(function(d, i) {{
            const badge = d.domain !== d.ip ? '<span class="domain-badge">' + d.domain + '</span><span style="font-size:10px;color:var(--muted);display:block;">' + d.ip + '</span>'
                                            : '<code style="font-size:11px;">' + d.ip + '</code>';
            return '<tr><td style="color:var(--muted);">#' + (i+1) + '</td><td>' + badge + '</td><td style="text-align:right;font-weight:600;">' + fmtBytes(d.bytes) + '</td></tr>';
        }}).join('') || '<tr><td colspan="3" style="text-align:center;color:var(--muted);padding:20px;">No vault data yet</td></tr>';

        // Groups dropdown
        const groupOptions = '<option value="">— keep current —</option>' + (data.groups || []).map(function(g) {{
            return '<option value="' + g.id + '"' + (g.id === limits.group_id ? ' selected' : '') + '>' + g.name + ' (' + fmtBytes(g.daily_bytes) + '/d &middot; ' + fmtBytes(g.monthly_bytes) + '/cycle)</option>';
        }}).join('');

        const customDailyGb   = limits.custom_daily_bytes  ? (limits.custom_daily_bytes  / Math.pow(1024,3)).toFixed(2) : '';
        const customMonthlyGb = limits.custom_monthly_bytes ? (limits.custom_monthly_bytes / Math.pow(1024,3)).toFixed(2) : '';

        const addonBanner = addonBytes > 0
            ? '<div style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px;">' +
              '<span style="color:#f59e0b;font-weight:600;">Active bonus quota:</span> ' + fmtBytes(addonBytes) +
              '<button onclick="clearQuota()" style="float:right;background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);color:#fca5a5;font-size:11px;padding:3px 10px;border-radius:6px;cursor:pointer;">Clear All</button></div>'
            : '<p style="font-size:12px;color:var(--muted);margin-bottom:14px;">No bonus quota active.</p>';

        const heroCycleStr = effectiveMonthly ? fmtBytes(effectiveMonthly) + (addonBytes > 0 ? ' (incl. +' + fmtBytes(addonBytes) + ')' : '') : 'Unlimited';
        const heroDailyStr = limits.daily_bytes ? fmtBytes(limits.daily_bytes) : 'Unlimited';
        const onlineColor  = onlineDevices.length > 0 ? '#10b981' : '#6b7280';
        const addonNote    = addonBytes > 0 ? ' &bull; <span style="color:#f59e0b;">+' + fmtBytes(addonBytes) + ' quota</span>' : '';

        document.getElementById('profile-content').innerHTML =
        '<div class="profile-hero">' +
            '<div class="avatar">' + username[0].toUpperCase() + '</div>' +
            '<div class="hero-info">' +
                '<h1>' + username + '</h1>' +
                '<div class="sub">Group: ' + (limits.group || 'None') + ' &bull; ' + data.devices.length + ' device(s) &bull; ' + onlineDevices.length + ' online now' + addonNote + '</div>' +
                '<div style="margin-top:10px;" class="limit-bar">' +
                    '<div class="bar-row"><span>Daily: ' + fmtBytes(totalToday) + ' / ' + heroDailyStr + '</span><span>' + dailyUsedPct.toFixed(1) + '%</span></div>' +
                    '<div class="bar-bg"><div class="bar-fill" style="width:' + dailyUsedPct + '%; background:' + barColor(dailyUsedPct) + ';"></div></div>' +
                    '<div class="bar-row" style="margin-top:8px;"><span>Cycle: ' + fmtBytes(totalCycle) + ' / ' + heroCycleStr + '</span><span>' + cycleUsedPct.toFixed(1) + '%</span></div>' +
                    '<div class="bar-bg"><div class="bar-fill" style="width:' + cycleUsedPct + '%; background:' + barColor(cycleUsedPct) + ';"></div></div>' +
                '</div>' +
            '</div>' +
            '<div class="hero-stats">' +
                '<div class="hstat"><div class="val">' + fmtBytes(totalToday) + '</div><div class="lbl">Today</div></div>' +
                '<div class="hstat"><div class="val">' + fmtBytes(totalCycle) + '</div><div class="lbl">This Cycle</div></div>' +
                '<div class="hstat"><div class="val" style="color:' + onlineColor + ';">' + onlineDevices.length + '</div><div class="lbl">Online</div></div>' +
                '<div class="hstat"><div class="val">' + data.devices.length + '</div><div class="lbl">Devices</div></div>' +
            '</div>' +
        '</div>' +

        '<div class="grid2" style="margin-bottom:20px;">' +
            '<div class="card">' +
                '<h2>&#x2699;&#xFE0F; Set Limits</h2>' +
                '<div class="form-group" style="margin-bottom:12px;">' +
                    '<label class="form-label">Group / Package</label>' +
                    '<select id="inp-group" class="form-input">' + groupOptions + '</select>' +
                '</div>' +
                '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px;">' +
                    '<div class="form-group">' +
                        '<label class="form-label">Custom Daily Limit (GB)</label>' +
                        '<input id="inp-daily" type="number" step="any" min="0" class="form-input" placeholder="Group default" value="' + customDailyGb + '">' +
                    '</div>' +
                    '<div class="form-group">' +
                        '<label class="form-label">Custom Monthly Limit (GB)</label>' +
                        '<input id="inp-monthly" type="number" step="any" min="0" class="form-input" placeholder="Group default" value="' + customMonthlyGb + '">' +
                    '</div>' +
                '</div>' +
                '<p style="font-size:11px;color:var(--muted);margin-bottom:12px;">Leave blank to use group defaults. Takes effect immediately.</p>' +
                '<button onclick="setLimits()" class="btn-action">Save Limits</button>' +
            '</div>' +
            '<div class="card">' +
                '<h2>&#x2795; Add Quota</h2>' +
                addonBanner +
                '<div style="display:flex;gap:10px;align-items:flex-end;">' +
                    '<div class="form-group" style="flex:1;margin:0;">' +
                        '<label class="form-label">Add GB (one-time top-up)</label>' +
                        '<input id="inp-addon" type="number" step="any" min="0.1" class="form-input" placeholder="e.g. 10">' +
                    '</div>' +
                    '<button onclick="addQuota()" class="btn-action" style="white-space:nowrap;flex-shrink:0;">Add Quota</button>' +
                '</div>' +
                '<p style="font-size:11px;color:var(--muted);margin-top:10px;">Addons stack on top of the monthly limit. Clear removes all.</p>' +
            '</div>' +
        '</div>' +

        '<div class="grid2">' +
            '<div class="card"><h2>Devices</h2>' + devCards + '</div>' +
            '<div class="card"><h2>Top Visited Destinations</h2><div style="overflow-x:auto;"><table>' +
                '<thead><tr><th>#</th><th>Domain / IP</th><th style="text-align:right;">Data</th></tr></thead>' +
                '<tbody>' + domainRows + '</tbody>' +
            '</table></div></div>' +
        '</div>' +

        '<div class="card" style="margin-top:20px;">' +
            '<h2>Usage Pattern &mdash; Last 7 Days (by Hour of Day)</h2>' +
            '<div class="chart-wrap">' + (chartBars || '<p style="color:var(--muted);padding:20px;">No data</p>') + '</div>' +
            '<div style="font-size:11px;color:var(--muted);margin-top:8px;text-align:center;">Hour of day (UTC) &mdash; bar height = relative traffic volume</div>' +
        '</div>';
    }}

    fetch('/api/user/' + encodeURIComponent(username))
        .then(function(r) {{ return r.json(); }})
        .then(function(data) {{ renderProfile(data); }})
        .catch(function(e) {{
            document.getElementById('profile-content').innerHTML = '<div class="loading" style="color:#ef4444;">Failed to load profile: ' + e + '</div>';
        }});
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
            conn = sqlite3.connect(get_vault_db_path())
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
                    <td class="utc-time" data-utc="{timestamp}">{timestamp}</td>
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
        
        .table-responsive {{
            width: 100%;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }}
        @media(max-width: 768px) {{
            .header {{
                flex-direction: column;
                align-items: stretch;
                padding: 15px 20px;
                gap: 12px;
            }}
            .header .btn-back {{
                text-align: center;
                display: block;
            }}
            .container {{
                margin: 15px auto;
                padding: 0 10px;
            }}
            .card {{
                padding: 16px;
                margin-bottom: 20px;
            }}
            .card h2 {{
                font-size: 15px;
                margin-bottom: 15px;
            }}
            th, td {{
                padding: 8px 10px;
                font-size: 12px;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Packet Vault</h1>
        <a href="/" class="btn-back">Back to Dashboard</a>
    </div>
    <div class="container">
        <div class="card">
            <h2>Real-time Connection Log (Last 200 Packets) - <span id="client-timezone" style="color: #6366f1; font-size: 13px;">Detecting timezone...</span></h2>
            <div class="table-responsive">
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
    </div>
    <script>
        const tzName = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const tzEl = document.getElementById("client-timezone");
        if (tzEl) tzEl.textContent = "Local Time: " + tzName;

        document.querySelectorAll(".utc-time").forEach(el => {{
            const utcStr = el.getAttribute("data-utc");
            if (utcStr) {{
                const date = new Date(utcStr + " UTC");
                if (!isNaN(date.getTime())) {{
                    el.textContent = date.toLocaleString('en-US', {{
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                        hour: 'numeric',
                        minute: '2-digit',
                        second: '2-digit',
                        hour12: true
                    }});
                }}
            }}
        }});
    </script>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

def _memory_watchdog(limit_mb=400, check_interval=60):
    """Restart the process if RSS grows beyond limit_mb to prevent OOM."""
    import time, os, signal
    limit_bytes = limit_mb * 1024 * 1024
    while True:
        time.sleep(check_interval)
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024  # Linux: KB -> bytes
            if usage > limit_bytes:
                print(f"[web] Memory watchdog: RSS {usage // 1024 // 1024}MB > {limit_mb}MB limit — restarting cleanly", flush=True)
                os.kill(os.getpid(), signal.SIGTERM)
        except Exception:
            pass


def run_web_server(port):
    class ReuseAddrThreadingHTTPServer(ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True  # Threads die when main process exits
        request_queue_size = 64

    server = ReuseAddrThreadingHTTPServer(('0.0.0.0', port), WebServerHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Start memory watchdog in background
    wd = threading.Thread(target=_memory_watchdog, args=(400, 60), daemon=True)
    wd.start()

    print(f"[web] Admin Web Dashboard and Captive Portal listening on http://localhost:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--web", type=int, nargs='?', const=6054, help="Run web server portal dashboard.")
    parser.add_argument("--vault-db", help="Override path to vault SQLite database file.")
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
