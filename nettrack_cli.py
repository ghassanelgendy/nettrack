#!/usr/bin/env python3
import os
import sys
import sqlite3
import datetime
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import urllib.parse

DB_PATH = "/var/lib/nettrack/nettrack.db"

def format_bytes(n):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} PB"

REGISTRATION_PASSWORD = os.environ.get("NETTRACK_PASSWORD", "1234G")

def check_db():
    if not os.path.exists(DB_PATH):
        print(f"Error: Database file not found at {DB_PATH}.", file=sys.stderr)
        print("Please make sure the nettrack daemon is running.", file=sys.stderr)
        sys.exit(1)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if migration is needed
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices';")
        has_devices_table = cursor.fetchone() is not None
        
        cursor.execute("SELECT type FROM sqlite_master WHERE name='registered_devices';")
        res = cursor.fetchone()
        has_old_registered_table = res is not None and res[0] == 'table'
        
        if not has_devices_table and has_old_registered_table:
            print("[migration] Starting database migration automatically...", flush=True)
            # 1. Rename old tables
            cursor.execute("ALTER TABLE registered_devices RENAME TO old_registered_devices;")
            cursor.execute("ALTER TABLE device_labels RENAME TO old_device_labels;")
            cursor.execute("ALTER TABLE user_limits RENAME TO old_user_limits;")
            
            # 2. Create the new tables
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
            CREATE TABLE IF NOT EXISTS lowend_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_name TEXT,
                ip_address TEXT,
                mac_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_devices (
                mac_address TEXT PRIMARY KEY,
                reason      TEXT,
                blocked_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            
            # 3. Migrate Users
            users_to_add = {}
            cursor.execute("SELECT label, daily_limit_mb FROM old_user_limits;")
            for label, limit in cursor.fetchall():
                if label and label.strip():
                    users_to_add[label.strip()] = limit
                    
            cursor.execute("SELECT label FROM old_registered_devices;")
            for (label,) in cursor.fetchall():
                if label and label.strip() and label.strip() not in users_to_add:
                    users_to_add[label.strip()] = 2048
                    
            cursor.execute("SELECT label FROM old_device_labels;")
            for (label,) in cursor.fetchall():
                if label and label.strip() and label.strip() not in users_to_add:
                    users_to_add[label.strip()] = 2048
                    
            for username, limit in users_to_add.items():
                cursor.execute("INSERT OR IGNORE INTO users (username, daily_limit_mb) VALUES (?, ?);", (username, limit))
                
            # 4. Migrate registered devices from old_registered_devices
            cursor.execute("SELECT device_uuid, label, floor, device_type FROM old_registered_devices;")
            registered_devices = cursor.fetchall()
            
            bound_macs = set()
            
            for cookie_uuid, label, floor, device_type in registered_devices:
                cursor.execute("SELECT id FROM users WHERE username = ?;", (label.strip() if label else "",))
                u_row = cursor.fetchone()
                user_id = u_row[0] if u_row else None
                
                cursor.execute("""
                INSERT INTO devices (user_id, device_name, floor, device_type, cookie_uuid, approved)
                VALUES (?, ?, ?, ?, ?, 1);
                """, (user_id, f"{label or 'Unknown'} Device", floor or "", device_type or "", cookie_uuid))
                device_id = cursor.lastrowid
                
                # Bind any matching MACs for this label from old_device_labels
                if label:
                    cursor.execute("SELECT ip_address, mac_address FROM old_device_labels WHERE label = ?;", (label.strip(),))
                    for ip, mac in cursor.fetchall():
                        ip = ip.strip() if ip else ""
                        mac = mac.lower().strip() if mac else ""
                        if mac and mac not in bound_macs:
                            cursor.execute("INSERT OR REPLACE INTO device_macs (mac_address, device_id) VALUES (?, ?);", (mac, device_id))
                            bound_macs.add(mac)
                        if ip:
                            cursor.execute("INSERT OR REPLACE INTO device_ips (ip_address, device_id, mac_address) VALUES (?, ?, ?);", (ip, device_id, mac or None))
            
            # 5. Migrate remaining labeled device_labels as approved devices
            cursor.execute("SELECT ip_address, mac_address, label, floor, device_type FROM old_device_labels;")
            all_labels = cursor.fetchall()
            for ip, mac, label, floor, device_type in all_labels:
                ip = ip.strip() if ip else ""
                mac = mac.lower().strip() if mac else ""
                label = label.strip() if label else ""
                
                if mac and mac in bound_macs:
                    # Already bound to a registered device
                    continue
                    
                if label:
                    # Create a new approved device for this label
                    cursor.execute("SELECT id FROM users WHERE username = ?;", (label,))
                    u_row = cursor.fetchone()
                    user_id = u_row[0] if u_row else None
                    
                    cursor.execute("""
                    INSERT INTO devices (user_id, device_name, floor, device_type, cookie_uuid, approved)
                    VALUES (?, ?, ?, ?, NULL, 1);
                    """, (user_id, f"{label} Device", floor or "", device_type or ""))
                    device_id = cursor.lastrowid
                    
                    if mac:
                        cursor.execute("INSERT OR REPLACE INTO device_macs (mac_address, device_id) VALUES (?, ?);", (mac, device_id))
                        bound_macs.add(mac)
                    if ip:
                        cursor.execute("INSERT OR REPLACE INTO device_ips (ip_address, device_id, mac_address) VALUES (?, ?, ?);", (ip, device_id, mac or None))
                else:
                    # Unlabeled device: create as unapproved (approved = 0)
                    if mac:
                        cursor.execute("""
                        INSERT INTO devices (user_id, device_name, floor, device_type, cookie_uuid, approved)
                        VALUES (NULL, 'Discovered Device', ?, ?, NULL, 0);
                        """, (floor or "", device_type or ""))
                        device_id = cursor.lastrowid
                        cursor.execute("INSERT OR REPLACE INTO device_macs (mac_address, device_id) VALUES (?, ?);", (mac, device_id))
                        bound_macs.add(mac)
                        if ip:
                            cursor.execute("INSERT OR REPLACE INTO device_ips (ip_address, device_id, mac_address) VALUES (?, ?, ?);", (ip, device_id, mac))
            
            # 6. Drop old tables
            cursor.execute("DROP TABLE old_registered_devices;")
            cursor.execute("DROP TABLE old_device_labels;")
            cursor.execute("DROP TABLE old_user_limits;")
            print("[migration] Database migration completed successfully!", flush=True)
            
        else:
            # Create new tables if they don't exist
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
            CREATE TABLE IF NOT EXISTS lowend_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_name TEXT,
                ip_address TEXT,
                mac_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_devices (
                mac_address TEXT PRIMARY KEY,
                reason      TEXT,
                blocked_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

        # Recreate Views
        cursor.execute("DROP VIEW IF EXISTS registered_devices;")
        cursor.execute("""
        CREATE VIEW registered_devices AS
        SELECT 
            COALESCE(d.cookie_uuid, dm.mac_address) AS device_uuid,
            u.username AS label,
            d.floor AS floor,
            d.device_type AS device_type
        FROM devices d
        JOIN users u ON d.user_id = u.id
        LEFT JOIN device_macs dm ON dm.device_id = d.id
        WHERE d.approved = 1;
        """)

        cursor.execute("DROP VIEW IF EXISTS user_limits;")
        cursor.execute("""
        CREATE VIEW user_limits AS
        SELECT 
            username AS label,
            daily_limit_mb
        FROM users;
        """)

        cursor.execute("DROP VIEW IF EXISTS device_labels;")
        cursor.execute("""
        CREATE VIEW device_labels AS
        SELECT 
            di.ip_address AS ip_address,
            di.mac_address AS mac_address,
            COALESCE(u.username, '') AS label,
            COALESCE(d.floor, '') AS floor,
            COALESCE(d.device_type, '') AS device_type
        FROM device_ips di
        LEFT JOIN devices d ON di.device_id = d.id
        LEFT JOIN users u ON d.user_id = u.id
        UNION
        SELECT
            '' AS ip_address,
            dm.mac_address AS mac_address,
            COALESCE(u.username, '') AS label,
            COALESCE(d.floor, '') AS floor,
            COALESCE(d.device_type, '') AS device_type
        FROM device_macs dm
        JOIN devices d ON dm.device_id = d.id
        LEFT JOIN users u ON d.user_id = u.id
        WHERE dm.mac_address NOT IN (SELECT mac_address FROM device_ips WHERE mac_address IS NOT NULL AND mac_address != '');
        """)
        
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"Error checking/creating database tables: {exc}", file=sys.stderr)

def get_stats(since_ts):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Total sent / received
    cursor.execute("""
    SELECT SUM(sent_bytes), SUM(received_bytes) 
    FROM hourly_usage 
    WHERE hour_timestamp >= ?
    """, (since_ts,))
    totals = cursor.fetchone()
    total_sent = totals[0] or 0
    total_recv = totals[1] or 0
    
    # Process breakdown
    cursor.execute("""
    SELECT program, SUM(sent_bytes) as sent, SUM(received_bytes) as recv, SUM(sent_bytes + received_bytes) as total
    FROM hourly_usage
    WHERE hour_timestamp >= ?
    GROUP BY program
    ORDER BY total DESC
    """, (since_ts,))
    programs = cursor.fetchall()
    
    conn.close()
    return total_sent, total_recv, programs

def get_today():
    local_today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start_ts = int(local_today.timestamp())
    
    total_sent, total_recv, programs = get_stats(start_ts)
    
    # Hourly trend
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT hour_timestamp, SUM(sent_bytes + received_bytes)
    FROM hourly_usage
    WHERE hour_timestamp >= ?
    GROUP BY hour_timestamp
    ORDER BY hour_timestamp ASC
    """, (start_ts,))
    trend = cursor.fetchall()
    conn.close()
    
    return total_sent, total_recv, programs, trend, "Today"

def get_week():
    local_start = (datetime.datetime.now() - datetime.timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
    start_ts = int(local_start.timestamp())
    
    total_sent, total_recv, programs = get_stats(start_ts)
    
    # Daily trend in local time
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT strftime('%Y-%m-%d', datetime(hour_timestamp, 'unixepoch', 'localtime')) as day,
           SUM(sent_bytes + received_bytes)
    FROM hourly_usage
    WHERE hour_timestamp >= ?
    GROUP BY day
    ORDER BY day ASC
    """, (start_ts,))
    trend = cursor.fetchall()
    conn.close()
    
    return total_sent, total_recv, programs, trend, "Last 7 Days"

def get_month():
    local_start = (datetime.datetime.now() - datetime.timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)
    start_ts = int(local_start.timestamp())
    
    total_sent, total_recv, programs = get_stats(start_ts)
    
    # Daily trend in local time
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT strftime('%Y-%m-%d', datetime(hour_timestamp, 'unixepoch', 'localtime')) as day,
           SUM(sent_bytes + received_bytes)
    FROM hourly_usage
    WHERE hour_timestamp >= ?
    GROUP BY day
    ORDER BY day ASC
    """, (start_ts,))
    trend = cursor.fetchall()
    conn.close()
    
    return total_sent, total_recv, programs, trend, "Last 30 Days"

def get_term_size():
    import shutil
    try:
        cols, lines = shutil.get_terminal_size()
        return cols, lines
    except Exception:
        return 80, 24

def compute_layout(lines, trend_len, apps_len, is_live):
    if not is_live:
        return min(trend_len, 24), min(apps_len, 20)
        
    if lines < 12:
        return 0, 0
        
    # Standard terminal height adaptive routing
    if lines < 20:
        app_rows = max(0, lines - 13)
        return 0, app_rows
        
    available = lines - 18
    if available < 6:
        app_rows = max(0, lines - 13)
        return 0, app_rows
        
    chart_rows = min(trend_len, 5)
    app_rows = available - chart_rows
    
    if app_rows > 10:
        extra_chart = min(trend_len - chart_rows, 5)
        if extra_chart > 0:
            chart_rows += extra_chart
            app_rows = available - chart_rows
            
    if app_rows < 3:
        needed = 3 - app_rows
        shrinkable = chart_rows - 3
        if shrinkable >= needed:
            chart_rows -= needed
            app_rows += needed
        else:
            app_rows = max(0, lines - 13)
            chart_rows = 0
            
    return chart_rows, max(0, app_rows)

def draw_chart_responsive(trend, period_type, width):
    if not trend:
        return
    labels = []
    values = []
    for row in trend:
        if period_type == "Today":
            dt = datetime.datetime.fromtimestamp(row[0])
            labels.append(dt.strftime("%H:00"))
        else:
            labels.append(row[0])
        values.append(row[1])
        
    max_val = max(values) if values else 0
    if max_val == 0:
        max_val = 1
        
    print("-" * width)
    print("TRAFFIC TREND CHART".center(width))
    print("-" * width)
    
    max_bar_width = max(5, width - 26)
    for label, val in zip(labels, values):
        bar_len = int((val / max_val) * max_bar_width)
        bar = "█" * bar_len + "░" * (max_bar_width - bar_len)
        print(f" {label:<10} [{bar}] {format_bytes(val)}")
    print("-" * width)

def print_dashboard(total_sent, total_recv, programs, trend, period_label, is_live=False):
    cols, lines = get_term_size()
    width = max(40, min(cols - 2, 90))
    
    chart_rows, app_rows = compute_layout(lines, len(trend), len(programs), is_live)
    
    # Header
    print("=" * width)
    title = f"NETTRACK NETWORK MONITOR - {period_label.upper()}"
    if len(title) > width:
        title = f"NETTRACK - {period_label.upper()}"
    if len(title) > width:
        title = "NETTRACK"
    print(title.center(width))
    print("=" * width)
    
    # Stats
    if width >= 60:
        print(f" Downloaded : {format_bytes(total_recv):<18} Uploaded : {format_bytes(total_sent)}")
        print(f" Total      : {format_bytes(total_recv + total_sent)}")
    else:
        print(f" Down: {format_bytes(total_recv):<10} Up: {format_bytes(total_sent)}")
        print(f" Total: {format_bytes(total_recv + total_sent)}")
        
    # Chart
    if chart_rows > 0:
        print("")  # Spacer
        trend_slice = trend[-chart_rows:] if len(trend) > chart_rows else trend
        draw_chart_responsive(trend_slice, period_label, width)
        
    # Apps
    if app_rows > 0:
        print("")  # Spacer
        print(f"TOP APPLICATIONS ({period_label.upper()})".center(width))
        print("-" * width)
        
        if width >= 55:
            app_width = width - 43
            print(f"  {'Rank':<4} {'Application':<{app_width}} {'Uploaded':>10} {'Downloaded':>10} {'Total':>10}")
            print("-" * width)
            for idx, (program, sent, recv, total) in enumerate(programs[:app_rows], 1):
                display_name = program
                if len(display_name) > app_width:
                    if display_name.startswith("/"):
                        display_name = "..." + display_name[-(app_width - 3):]
                    else:
                        display_name = display_name[:(app_width - 3)] + "..."
                print(f"  {idx:<4} {display_name:<{app_width}} {format_bytes(sent):>10} {format_bytes(recv):>10} {format_bytes(total):>10}")
        else:
            app_width = width - 19
            print(f"  {'Rank':<4} {'Application':<{app_width}} {'Total':>10}")
            print("-" * width)
            for idx, (program, sent, recv, total) in enumerate(programs[:app_rows], 1):
                display_name = program
                if len(display_name) > app_width:
                    if display_name.startswith("/"):
                        display_name = "..." + display_name[-(app_width - 3):]
                    else:
                        display_name = display_name[:(app_width - 3)] + "..."
                print(f"  {idx:<4} {display_name:<{app_width}} {format_bytes(total):>10}")
    print("=" * width)

# --- Device Data Helpers ---

def get_device_stats(since_ts):
    """Return per-device stats from device_usage joined with device_labels, consolidated by MAC or Label."""
    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
        SELECT
            d.ip_address,
            COALESCE(d.mac_address, '') AS mac,
            COALESCE(
                (SELECT label FROM device_labels WHERE mac_address = d.mac_address AND d.mac_address != '' AND label != '' LIMIT 1),
                (SELECT label FROM device_labels WHERE ip_address = d.ip_address LIMIT 1),
                ''
            ) AS label,
            COALESCE(
                (SELECT floor FROM device_labels WHERE mac_address = d.mac_address AND d.mac_address != '' AND label != '' LIMIT 1),
                (SELECT floor FROM device_labels WHERE ip_address = d.ip_address LIMIT 1),
                ''
            ) AS floor,
            COALESCE(
                (SELECT device_type FROM device_labels WHERE mac_address = d.mac_address AND d.mac_address != '' AND label != '' LIMIT 1),
                (SELECT device_type FROM device_labels WHERE ip_address = d.ip_address LIMIT 1),
                ''
            ) AS device_type,
            SUM(d.sent_bytes)                                    AS sent,
            SUM(d.received_bytes)                                AS recv,
            SUM(d.sent_bytes + d.received_bytes)                 AS total,
            MAX(d.hour_timestamp)                                AS last_seen,
            COALESCE(
                (SELECT daily_limit_mb FROM user_limits WHERE label = (
                    SELECT label FROM device_labels WHERE mac_address = d.mac_address AND d.mac_address != '' AND label != '' LIMIT 1
                )),
                (SELECT daily_limit_mb FROM user_limits WHERE label = (
                    SELECT label FROM device_labels WHERE ip_address = d.ip_address LIMIT 1
                )),
                2048
            ) AS daily_limit_mb
        FROM device_usage d
        WHERE d.hour_timestamp >= ?
          AND COALESCE(d.mac_address, '') NOT IN (SELECT mac_address FROM blocked_devices)
        GROUP BY d.ip_address, d.mac_address
        ORDER BY total DESC
        """, (since_ts,))
        rows = cursor.fetchall()
        conn.close()
        
        consolidated = {}
        for r in rows:
            ip, mac, label, floor, device_type, sent, recv, total, last_seen, daily_limit_mb = r
            
            # Determine group key: primary group by Label (User name), secondary by MAC, fallback to IP
            key = None
            if label and label.strip():
                key = f"label:{label.strip().lower()}"
            elif mac and mac.strip():
                key = f"mac:{mac.strip().lower()}"
            else:
                key = f"ip:{ip}"
                
            sub_device = {
                "ip": ip,
                "mac": mac,
                "sent": sent or 0,
                "recv": recv or 0,
                "total": total or 0,
                "last_seen": last_seen,
            }
            
            if key not in consolidated:
                consolidated[key] = {
                    "ip": ip,
                    "mac": mac,
                    "label": label,
                    "floor": floor,
                    "device_type": device_type,
                    "sent": sent or 0,
                    "recv": recv or 0,
                    "total": total or 0,
                    "last_seen": last_seen,
                    "daily_limit_mb": daily_limit_mb,
                    "sub_devices": [sub_device]
                }
            else:
                entry = consolidated[key]
                # Avoid duplicate sub-devices if any
                if not any(s["ip"] == ip and s["mac"] == mac for s in entry["sub_devices"]):
                    entry["sub_devices"].append(sub_device)
                entry["sent"] += (sent or 0)
                entry["recv"] += (recv or 0)
                entry["total"] += (total or 0)
                if last_seen and (not entry["last_seen"] or last_seen > entry["last_seen"]):
                    entry["last_seen"] = last_seen
                    entry["ip"] = ip
                    entry["mac"] = mac
                    
        res = []
        for entry in consolidated.values():
            res.append(entry)
            
        res.sort(key=lambda x: x["total"], reverse=True)
        return res
    except Exception as exc:
        print(f"[web] get_device_stats error: {exc}", file=sys.stderr)
        return []


def get_device_hourly_trend(ip, since_ts):
    """Return hourly sent/recv trend for a single device IP."""
    try:
        conn   = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
        SELECT hour_timestamp, sent_bytes, received_bytes
        FROM device_usage
        WHERE ip_address = ? AND hour_timestamp >= ?
        ORDER BY hour_timestamp ASC
        """, (ip, since_ts))
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "label": datetime.datetime.fromtimestamp(r[0]).strftime("%d %b %H:00"),
                "sent":  r[1],
                "recv":  r[2],
            }
            for r in rows
        ]
    except Exception:
        return []
def set_device_label(ip, mac, label, floor, device_type, daily_limit_mb=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        user_id = None
        if label and label.strip():
            username = label.strip()
            # 1. Get or create User
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                user_id = row[0]
                if daily_limit_mb is not None:
                    cursor.execute("UPDATE users SET daily_limit_mb = ? WHERE id = ?", (int(daily_limit_mb), user_id))
            else:
                limit_val = int(daily_limit_mb) if daily_limit_mb is not None and str(daily_limit_mb).strip() != "" else 2048
                cursor.execute("INSERT INTO users (username, daily_limit_mb) VALUES (?, ?)", (username, limit_val))
                user_id = cursor.lastrowid

        # 2. Find device_id if exists
        device_id = None
        if mac:
            cursor.execute("SELECT device_id FROM device_macs WHERE mac_address = ?", (mac.lower().strip(),))
            row = cursor.fetchone()
            if row:
                device_id = row[0]
        if not device_id and ip:
            cursor.execute("SELECT device_id FROM device_ips WHERE ip_address = ?", (ip.strip(),))
            row = cursor.fetchone()
            if row:
                device_id = row[0]

        # 3. Create or update Device
        if device_id:
            cursor.execute("""
            UPDATE devices 
            SET user_id = COALESCE(?, user_id),
                floor = COALESCE(?, floor),
                device_type = COALESCE(?, device_type)
            WHERE id = ?
            """, (user_id, floor or "", device_type or "", device_id))
        else:
            cursor.execute("""
            INSERT INTO devices (user_id, device_name, floor, device_type, approved)
            VALUES (?, ?, ?, ?, 1)
            """, (user_id, f"{label or 'Unknown'} Device", floor or "", device_type or ""))
            device_id = cursor.lastrowid

        # 4. Bind MAC
        if mac:
            cursor.execute("INSERT OR REPLACE INTO device_macs (mac_address, device_id) VALUES (?, ?)", (mac.lower().strip(), device_id))
        
        # 5. Bind IP
        if ip:
            cursor.execute("INSERT OR REPLACE INTO device_ips (ip_address, device_id, mac_address) VALUES (?, ?, ?)", (ip.strip(), device_id, mac.lower().strip() if mac else None))

        conn.commit()
        conn.close()
        return True
    except Exception as exc:
        print(f"[web] set_device_label error: {exc}", file=sys.stderr)
        return False

def is_mac_shared(mac_address):
    if not mac_address or mac_address == "00:00:00:00:00:00":
        return False
    mac_lower = mac_address.lower().strip()
    count = 0
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    if parts[3].lower().strip() == mac_lower:
                        count += 1
                        if count > 1:
                            return True
    except Exception:
        pass
    return False

def update_device_mapping(ip_address, uuid):
    if not uuid:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Find device by MAC (uuid)
        cursor.execute("SELECT device_id FROM device_macs WHERE mac_address = ?", (uuid.lower().strip(),))
        row = cursor.fetchone()
        if row:
            device_id = row[0]
            
            # Find MAC for this IP in /proc/net/arp
            mac = uuid.lower().strip() # Default to the uuid mac since the user is using this device
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == ip_address:
                            found_mac = parts[3].lower().strip()
                            if found_mac and found_mac != "00:00:00:00:00:00":
                                mac = found_mac
                            break
            except Exception:
                pass
                
            # If we found a valid physical MAC and it's not shared, associate it with the approved device in device_macs
            if mac and not is_mac_shared(mac):
                cursor.execute("INSERT OR REPLACE INTO device_macs (mac_address, device_id) VALUES (?, ?)", (mac, device_id))
                
            # Update device_ips mapping
            cursor.execute("""
            INSERT INTO device_ips (ip_address, device_id, mac_address, last_seen)
            VALUES (?, ?, ?, datetime('now', 'localtime'))
            ON CONFLICT(ip_address) DO UPDATE SET
                device_id = excluded.device_id,
                mac_address = COALESCE(excluded.mac_address, mac_address),
                last_seen = excluded.last_seen;
            """, (ip_address, device_id, mac))
            
            if not is_mac_shared(mac):
                cursor.execute("DELETE FROM device_ips WHERE mac_address = ? AND ip_address != ?", (mac, ip_address))
            
            # Clean up orphaned temporary unapproved devices
            cursor.execute("DELETE FROM devices WHERE approved = 0 AND id NOT IN (SELECT DISTINCT device_id FROM device_macs)")
            
            conn.commit()
        conn.close()
    except Exception as exc:
        print(f"[web] update_device_mapping error: {exc}", file=sys.stderr)


# ─── Registration HTML ────────────────────────────────────────────────────────
# ─── Connected HTML ───────────────────────────────────────────────────────────
CONNECTED_HTML = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>تم الاتصال بنجاح</title>
    <!-- Removed external font link to prevent 10s TCP timeout blocking when device has no internet -->
    <style>
        :root {
            --bg:          #080d17;
            --card-bg:     rgba(18, 26, 44, 0.75);
            --text:        #f1f5f9;
            --muted:       #7c8fa8;
            --primary:     #3b82f6;
            --border:      rgba(255,255,255,0.07);
            --radius:      14px;
            --font:        'Cairo', 'Outfit', system-ui, sans-serif;
            --green:       #10b981;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--font);
            background: var(--bg);
            background-image:
                radial-gradient(ellipse 80% 50% at 15% -5%, rgba(59,130,246,0.12), transparent),
                radial-gradient(ellipse 60% 40% at 85% 110%, rgba(16,185,129,0.08), transparent);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
        }
        .container {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 2.5rem 2rem;
            width: 100%;
            max-width: 440px;
            text-align: center;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            backdrop-filter: blur(8px);
        }
        .icon {
            font-size: 3.5rem;
            color: var(--green);
            margin-bottom: 1.5rem;
            animation: pulse 2s infinite;
        }
        h2 {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            background: linear-gradient(to left, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p {
            font-size: 0.95rem;
            color: var(--muted);
            line-height: 1.6;
            margin-bottom: 1.5rem;
        }
        .badge {
            display: inline-block;
            padding: 0.4rem 1rem;
            background: rgba(16, 185, 129, 0.12);
            color: var(--green);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✅</div>
        <h2>أهلاً بك {name}</h2>
        <p>تم تفعيل الإنترنت لجهازك بنجاح في <strong>الطابق {floor}</strong>.</p>
        <p style="font-size:0.8rem;color:var(--muted);margin-top:1rem;">جاري توجيهك إلى Google تلقائياً...</p>
        <span class="badge" style="margin-top:1rem;">متصل بالشبكة</span>
    </div>
    <script>
        setTimeout(() => {
            window.location.href = "https://www.google.com";
        }, 2000);
    </script>
</body>
</html>
"""


# ─── Registration HTML ────────────────────────────────────────────────────────
REGISTRATION_HTML = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>تسجيل الجهاز في الشبكة</title>
    <!-- Removed external font link to prevent 10s TCP timeout blocking when device has no internet -->
    <style>
        :root {
            --bg:          #080d17;
            --card-bg:     rgba(18, 26, 44, 0.75);
            --text:        #f1f5f9;
            --muted:       #7c8fa8;
            --primary:     #3b82f6;
            --primary-gl:  rgba(59,130,246,0.15);
            --border:      rgba(255,255,255,0.07);
            --radius:      14px;
            --font:        'Cairo', 'Outfit', system-ui, sans-serif;
            --red:         #ef4444;
            --green:       #10b981;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--font);
            background: var(--bg);
            background-image:
                radial-gradient(ellipse 80% 50% at 15% -5%, rgba(59,130,246,0.12), transparent),
                radial-gradient(ellipse 60% 40% at 85% 110%, rgba(16,185,129,0.08), transparent);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
        }
        .container {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 2rem;
            width: 100%;
            max-width: 440px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            backdrop-filter: blur(8px);
        }
        .logo-header {
            display: flex;
            align-items: center;
            gap: 0.8rem;
            margin-bottom: 1.5rem;
        }
        .logo-icon {
            width: 38px;
            height: 38px;
            border-radius: 8px;
            background: linear-gradient(135deg, var(--primary), #1d4ed8);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.1rem;
            box-shadow: 0 4px 12px rgba(59,130,246,0.3);
        }
        h2 {
            font-size: 1.4rem;
            font-weight: 700;
            background: linear-gradient(to left, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p {
            font-size: 0.85rem;
            color: var(--muted);
            margin-bottom: 1.5rem;
            line-height: 1.6;
        }
        .field {
            margin-bottom: 1.2rem;
        }
        label {
            display: block;
            font-size: 0.85rem;
            font-weight: 600;
            margin-bottom: 0.4rem;
            color: var(--muted);
        }
        input[type="text"], input[type="password"], select {
            width: 100%;
            padding: 0.65rem 0.8rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: rgba(255, 255, 255, 0.03);
            color: var(--text);
            font-family: var(--font);
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s;
        }
        input[type="text"]:focus, input[type="password"]:focus, select:focus {
            border-color: var(--primary);
            background: rgba(255, 255, 255, 0.05);
        }
        .btn {
            width: 100%;
            padding: 0.7rem;
            border-radius: 8px;
            border: none;
            background: linear-gradient(135deg, var(--primary), #2563eb);
            color: white;
            font-family: var(--font);
            font-weight: 600;
            font-size: 0.95rem;
            cursor: pointer;
            box-shadow: 0 4px 14px rgba(59,130,246,0.3);
            transition: opacity 0.2s;
        }
        .btn:hover {
            opacity: 0.9;
        }
        .toast {
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: var(--card-bg);
            border: 1px solid var(--border);
            padding: 0.8rem 1.5rem;
            border-radius: 30px;
            font-size: 0.85rem;
            font-weight: 600;
            box-shadow: 0 8px 16px rgba(0,0,0,0.3);
            backdrop-filter: blur(8px);
            transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            z-index: 1000;
        }
        .toast.show {
            transform: translateX(-50%) translateY(0);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo-header">
            <div class="logo-icon">📡</div>
            <h2>تسجيل الجهاز لتفعيل الإنترنت</h2>
        </div>
        <p>يرجى تسجيل بياناتك لتفعيل اتصال الإنترنت الخاص بجهازك على الشبكة المحلية.</p>
        
        <div class="field">
            <label for="reg-name">الاسم بالكامل</label>
            <input type="text" id="reg-name" placeholder="مثال: غسان، أحمد...">
        </div>
        <div class="field">
            <label for="reg-floor">الطابق / الدور</label>
            <select id="reg-floor">
                <option value="4">الدور الرابع (4)</option>
                <option value="5">الدور الخامس (5)</option>
                <option value="6">الدور السادس (6)</option>
            </select>
        </div>
        <div class="field">
            <label for="reg-type">نوع الجهاز</label>
            <select id="reg-type">
                <option value="phone">📱 هاتف محمول / تابلت</option>
                <option value="pc">💻 كمبيوتر / لابتوب</option>
                <option value="ap">📡 موزع شبكة / راوتر</option>
                <option value="tv">📺 شاشة ذكية / جهاز بث</option>
                <option value="server">🏢 خادم / Server</option>
                <option value="iot">🔌 أجهزة ذكية أخرى</option>
                <option value="other">⚫ أخرى</option>
            </select>
        </div>
        <div class="field">
            <label for="reg-pass">كلمة مرور الشبكة</label>
            <input type="password" id="reg-pass" placeholder="أدخل رمز المرور لتفعيل الخدمة">
        </div>
        
        <button class="btn" onclick="submitRegistration()">تسجيل وتفعيل الإنترنت</button>
    </div>

    <div class="toast" id="toast"></div>

    <script>
        function showToast(msg, err=false) {
            const t = document.getElementById('toast');
            t.textContent = (err ? '✗ ' : '✓ ') + msg;
            t.style.borderColor = err ? 'var(--red)' : 'var(--green)';
            t.style.color       = err ? 'var(--red)' : 'var(--green)';
            t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 3000);
        }

        // Generate or fetch UUID
        let uuid = localStorage.getItem('nettrack_device_uuid');
        if (!uuid) {
            uuid = 'device_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
            localStorage.setItem('nettrack_device_uuid', uuid);
        }

        async function submitRegistration() {
            const name = document.getElementById('reg-name').value.trim();
            const floor = document.getElementById('reg-floor').value;
            const type = document.getElementById('reg-type').value;
            const pass = document.getElementById('reg-pass').value;

            if (!name) {
                showToast('الرجاء إدخال اسمك.', true);
                return;
            }

            try {
                const response = await fetch('/api/devices/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        uuid: uuid,
                        label: name,
                        floor: floor,
                        device_type: type,
                        password: pass
                    })
                });
                
                const result = await response.json();
                if (response.ok && result.ok) {
                    showToast('تم التسجيل بنجاح! جاري التوصيل...');
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1500);
                } else {
                    showToast(result.error || 'فشل التسجيل. رمز المرور غير صحيح.', true);
                }
            } catch(e) {
                showToast('حدث خطأ في الاتصال بالشبكة.', true);
            }
        }
    </script>
</body>
</html>
"""


# ─── Dashboard HTML ───────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>NetTrack - Network Usage Dashboard</title>
    <meta name="description" content="Real-time per-process and per-device network bandwidth monitoring dashboard for your Ubuntu server.">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg:          #080d17;
            --card-bg:     rgba(18, 26, 44, 0.75);
            --card-hover:  rgba(26, 37, 60, 0.9);
            --text:        #f1f5f9;
            --muted:       #7c8fa8;
            --primary:     #3b82f6;
            --primary-gl:  rgba(59,130,246,0.15);
            --green:       #10b981;
            --green-gl:    rgba(16,185,129,0.15);
            --amber:       #f59e0b;
            --amber-gl:    rgba(245,158,11,0.12);
            --red:         #ef4444;
            --border:      rgba(255,255,255,0.07);
            --radius:      14px;
            --font:        'Outfit', system-ui, sans-serif;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body {
            font-family: var(--font);
            background: var(--bg);
            background-image:
                radial-gradient(ellipse 80% 50% at 15% -5%, rgba(59,130,246,0.12), transparent),
                radial-gradient(ellipse 60% 40% at 85% 110%, rgba(16,185,129,0.08), transparent);
            color: var(--text);
            min-height: 100vh;
            padding: 2rem 2.5rem;
        }
        /* ── Header ── */
        header {
            display: flex; align-items: center; justify-content: space-between;
            flex-wrap: wrap; gap: 1.5rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem; margin-bottom: 2rem;
            animation: fadeUp .55s cubic-bezier(.16,1,.3,1) both;
        }
        .logo { display: flex; align-items: center; gap: .9rem; }
        .logo-icon {
            width: 42px; height: 42px; border-radius: 10px;
            background: linear-gradient(135deg, var(--primary), #1d4ed8);
            display: flex; align-items: center; justify-content: center;
            font-size: 1.3rem; box-shadow: 0 4px 14px rgba(59,130,246,.35);
        }
        h1 {
            font-size: 1.7rem; font-weight: 700; letter-spacing: -.03em;
            background: linear-gradient(to right, #fff, #94a3b8);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .subtitle { font-size: .8rem; color: var(--muted); margin-top: .1rem; }
        /* ── Top tab bar ── */
        .tab-bar {
            display: flex; gap: .4rem;
            background: rgba(255,255,255,.04);
            border: 1px solid var(--border);
            border-radius: 10px; padding: .3rem;
        }
        .tab {
            background: transparent; border: none;
            color: var(--muted); font-family: var(--font);
            font-weight: 600; font-size: .85rem;
            padding: .5rem 1.1rem; border-radius: 7px;
            cursor: pointer; transition: all .2s;
        }
        .tab:hover { color: var(--text); background: rgba(255,255,255,.06); }
        .tab.active {
            background: linear-gradient(135deg, var(--primary), #2563eb);
            color: #fff; box-shadow: 0 3px 12px rgba(59,130,246,.35);
        }
        /* ── View panels ── */
        .view { display: none; animation: fadeUp .4s cubic-bezier(.16,1,.3,1) both; }
        .view.active { display: block; }
        /* ── Stat cards ── */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.25rem; margin-bottom: 2rem;
        }
        .card {
            background: var(--card-bg);
            backdrop-filter: blur(14px);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.4rem 1.6rem;
            box-shadow: 0 8px 28px -8px rgba(0,0,0,.55);
            transition: transform .25s, box-shadow .25s, border-color .25s;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 14px 36px -6px rgba(0,0,0,.6);
            border-color: rgba(59,130,246,.25);
        }
        .card-label {
            font-size: .72rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: .08em; color: var(--muted); margin-bottom: .6rem;
        }
        .card-value {
            font-size: 2rem; font-weight: 700; letter-spacing: -.03em; color: #fff;
        }
        .card-value.accent  { color: var(--primary); }
        .card-value.green   { color: var(--green); }
        .card-value.amber   { color: var(--amber); }
        /* ── 2-col layout ── */
        .two-col { display: grid; grid-template-columns: 3fr 2fr; gap: 1.25rem; }
        @media (max-width: 1050px) { .two-col { grid-template-columns: 1fr; } }
        /* ── Timeframe buttons inside a view ── */
        .tf-row {
            display: flex; gap: .5rem; margin-bottom: 1.5rem; flex-wrap: wrap;
        }
        .tf-btn {
            background: rgba(255,255,255,.05); border: 1px solid var(--border);
            color: var(--muted); font-family: var(--font); font-weight: 600;
            font-size: .8rem; padding: .4rem .95rem; border-radius: 7px;
            cursor: pointer; transition: all .2s;
        }
        .tf-btn:hover { color: var(--text); border-color: rgba(59,130,246,.3); }
        .tf-btn.active {
            background: var(--primary-gl); color: var(--primary);
            border-color: rgba(59,130,246,.4);
        }
        /* ── Chart ── */
        .chart-wrap { position: relative; height: clamp(180px,36vh,340px); }
        /* ── Table ── */
        h3 { font-size: 1.1rem; font-weight: 600; margin-bottom: 1.1rem; }
        .tbl-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 380px; }
        th, td {
            text-align: left; padding: .8rem .9rem;
            border-bottom: 1px solid rgba(255,255,255,.04);
            font-size: .88rem;
        }
        th {
            font-size: .72rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: .06em; color: var(--muted);
            border-bottom: 1px solid var(--border);
        }
        tr { transition: background .18s; }
        tr:hover td { background: rgba(255,255,255,.025); }
        .tr { text-align: right; }
        .name-cell { display: flex; align-items: center; gap: .7rem; }
        .app-name {
            font-weight: 600; color: #f8fafc;
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
            max-width: clamp(100px, 25vw, 340px);
        }
        /* ── Badges ── */
        .badge {
            display: inline-block; padding: .18rem .5rem;
            border-radius: 5px; font-size: .63rem; font-weight: 700;
            letter-spacing: .05em; text-transform: uppercase;
            border: 1px solid transparent; white-space: nowrap;
        }
        .b-app    { background: var(--primary-gl); color: #60a5fa; border-color: rgba(59,130,246,.22); }
        .b-docker { background: rgba(6,182,212,.1);  color: #22d3ee; border-color: rgba(6,182,212,.2); }
        .b-media  { background: rgba(244,63,94,.1);   color: #fb7185; border-color: rgba(244,63,94,.2); }
        .b-sys    { background: rgba(148,163,184,.1); color: #94a3b8; border-color: rgba(148,163,184,.2); }
        .b-phone  { background: rgba(168,85,247,.1);  color: #c084fc; border-color: rgba(168,85,247,.2); }
        .b-pc     { background: var(--green-gl);      color: #34d399; border-color: rgba(16,185,129,.2); }
        .b-ap     { background: var(--amber-gl);      color: #fbbf24; border-color: rgba(245,158,11,.2); }
        .b-tv     { background: rgba(239,68,68,.1);   color: #f87171; border-color: rgba(239,68,68,.2); }
        .b-other  { background: rgba(255,255,255,.06);color: #94a3b8; border-color: rgba(255,255,255,.1); }
        /* ── Device icons ── */
        .dev-icon {
            width: 32px; height: 32px; border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1rem; flex-shrink: 0;
        }
        /* ── Label Modal ── */
        .modal-overlay {
            position: fixed; inset: 0; background: rgba(0,0,0,.65);
            backdrop-filter: blur(6px); z-index: 999;
            display: flex; align-items: center; justify-content: center;
            opacity: 0; pointer-events: none; transition: opacity .25s;
        }
        .modal-overlay.open { opacity: 1; pointer-events: auto; }
        .modal {
            background: #111929; border: 1px solid var(--border);
            border-radius: 18px; padding: 2rem; width: min(480px, 92vw);
            box-shadow: 0 30px 80px rgba(0,0,0,.7);
            transform: translateY(20px); transition: transform .3s cubic-bezier(.16,1,.3,1);
        }
        .modal-overlay.open .modal { transform: translateY(0); }
        .modal h2 { font-size: 1.25rem; margin-bottom: 1.4rem; font-weight: 700; }
        .field { margin-bottom: 1rem; }
        .field label {
            display: block; font-size: .78rem; font-weight: 600;
            color: var(--muted); text-transform: uppercase;
            letter-spacing: .06em; margin-bottom: .4rem;
        }
        .field input, .field select {
            width: 100%; padding: .65rem .9rem;
            background: rgba(255,255,255,.05); border: 1px solid var(--border);
            border-radius: 8px; color: var(--text); font-family: var(--font);
            font-size: .9rem; outline: none; transition: border-color .2s;
        }
        .field input:focus, .field select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(59,130,246,.15);
        }
        .field select option { background: #111929; }
        .modal-actions { display: flex; gap: .75rem; margin-top: 1.5rem; justify-content: flex-end; }
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), #2563eb);
            border: none; color: #fff; font-family: var(--font); font-weight: 700;
            font-size: .9rem; padding: .65rem 1.4rem; border-radius: 8px;
            cursor: pointer; transition: all .2s; box-shadow: 0 4px 14px rgba(59,130,246,.3);
        }
        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(59,130,246,.4); }
        .btn-ghost {
            background: transparent; border: 1px solid var(--border); color: var(--muted);
            font-family: var(--font); font-weight: 600; font-size: .9rem;
            padding: .65rem 1.2rem; border-radius: 8px; cursor: pointer; transition: all .2s;
        }
        .btn-ghost:hover { color: var(--text); border-color: rgba(255,255,255,.2); }
        .label-btn {
            background: transparent; border: 1px solid var(--border); color: var(--muted);
            font-size: .75rem; font-weight: 600; padding: .25rem .65rem;
            border-radius: 6px; cursor: pointer; font-family: var(--font);
            transition: all .18s;
        }
        .label-btn:hover { color: var(--primary); border-color: rgba(59,130,246,.35); }
        /* ── Toast ── */
        .toast {
            position: fixed; bottom: 2rem; right: 2rem;
            background: #1e293b; border: 1px solid var(--green);
            color: var(--green); font-weight: 600; font-size: .88rem;
            padding: .7rem 1.3rem; border-radius: 10px;
            box-shadow: 0 6px 24px rgba(0,0,0,.5);
            transform: translateY(20px); opacity: 0;
            transition: all .3s cubic-bezier(.16,1,.3,1);
            z-index: 1000; pointer-events: none;
        }
        .toast.show { transform: translateY(0); opacity: 1; }
        /* ── Animations ── */
        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(14px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        /* ── Device mini-chart ── */
        .dev-chart-wrap {
            position: relative; height: 220px; margin-top: .6rem;
        }
        /* ── Responsive ── */
        @media (max-width: 640px) {
            body { padding: 1rem; }
            h1 { font-size: 1.35rem; }
            .card-value { font-size: 1.6rem; }
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">
            <div class="logo-icon">&#128225;</div>
            <div>
                <h1>NetTrack</h1>
                <div class="subtitle">Network bandwidth &amp; device monitoring</div>
            </div>
        </div>
        <nav class="tab-bar" role="tablist" aria-label="Dashboard sections">
            <button class="tab active" id="tab-apps"   onclick="showView('apps')"   role="tab">&#128202; Applications</button>
            <button class="tab"        id="tab-devices" onclick="showView('devices')" role="tab">&#128241; Devices</button>
            <button class="tab"        id="tab-lowend"  onclick="showView('lowend')"  role="tab">&#128229; Low-End Requests</button>
            <a href="/register" class="tab" style="text-decoration:none;display:inline-block;">&#128221; Register Device</a>
        </nav>
    </header>

    <!-- ════════ APPLICATIONS VIEW ════════ -->
    <section id="view-apps" class="view active">
        <div class="tf-row">
            <button class="tf-btn active" id="app-tf-today" onclick="switchTF('today',this,'app')">Today</button>
            <button class="tf-btn"        id="app-tf-week"  onclick="switchTF('week', this,'app')">Last 7 Days</button>
            <button class="tf-btn"        id="app-tf-month" onclick="switchTF('month',this,'app')">Last 30 Days</button>
        </div>
        <div class="stats-grid">
            <div class="card"><div class="card-label">Total Download</div><div class="card-value green" id="a-recv">—</div></div>
            <div class="card"><div class="card-label">Total Upload</div><div class="card-value amber" id="a-sent">—</div></div>
            <div class="card"><div class="card-label">Combined Usage</div><div class="card-value accent" id="a-total">—</div></div>
        </div>
        <div class="two-col">
            <div class="card">
                <h3>Traffic Trend</h3>
                <div class="chart-wrap"><canvas id="trendChart"></canvas></div>
            </div>
            <div class="card">
                <h3>Top Apps &amp; Services</h3>
                <div class="tbl-wrap">
                    <table>
                        <thead><tr><th>Application</th><th class="tr">Up</th><th class="tr">Down</th><th class="tr">Total</th></tr></thead>
                        <tbody id="app-tbody"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>

    <!-- ════════ DEVICES VIEW ════════ -->
    <section id="view-devices" class="view">
        <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:1rem; margin-bottom:1.5rem;">
            <div class="tf-row" style="margin:0;">
                <button class="tf-btn active" id="dev-tf-today" onclick="switchTF('today',this,'dev')">Today</button>
                <button class="tf-btn"        id="dev-tf-week"  onclick="switchTF('week', this,'dev')">Last 7 Days</button>
                <button class="tf-btn"        id="dev-tf-month" onclick="switchTF('month',this,'dev')">Last 30 Days</button>
            </div>
            <div style="font-size:.78rem; color:var(--muted);" id="dev-status">Loading devices…</div>
        </div>
        <div class="stats-grid" id="dev-stats-grid">
            <div class="card"><div class="card-label">Devices Seen</div><div class="card-value accent" id="d-count">—</div></div>
            <div class="card"><div class="card-label">Top Consumer</div><div class="card-value" id="d-top" style="font-size:1.2rem;">—</div></div>
            <div class="card"><div class="card-label">Network Total</div><div class="card-value green" id="d-total">—</div></div>
        </div>
        <div class="card" style="margin-bottom:1.5rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem; margin-bottom:1rem;">
                <h3 style="margin:0;">Per-Device Bandwidth</h3>
                <input type="text" id="dev-search" placeholder="Search IP, MAC, name..." style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); border-radius:6px; padding:0.35rem 0.75rem; color:var(--fg); font-size:0.85rem; width:220px; outline:none; transition:border-color 0.2s;" oninput="filterAndRenderDevices()" onfocus="this.style.borderColor='var(--primary)'" onblur="this.style.borderColor='rgba(255,255,255,0.1)'">
            </div>
            <div class="tbl-wrap">
                <table id="dev-table">
                    <thead>
                        <tr>
                            <th>Device</th>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th class="tr">Sent</th>
                            <th class="tr">Received</th>
                            <th class="tr">Total</th>
                            <th>Last Seen</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody id="dev-tbody"></tbody>
                </table>
            </div>
        </div>
        <div class="card" style="margin-bottom:1.5rem;">
            <h3 style="color:var(--red);">🚫 Blocked Devices (Entirely Banned)</h3>
            <div class="tbl-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>MAC Address</th>
                            <th>Reason</th>
                            <th>Blocked At</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody id="blocked-tbody">
                        <tr><td colspan="4" style="text-align:center;color:var(--muted);">No blocked devices.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </section>

    <!-- ════════ LOW-END REQUESTS VIEW ════════ -->
    <section id="view-lowend" class="view">
        <div class="card" style="margin-bottom:1.5rem;">
            <h3>📥 Low-End Device Requests</h3>
            <p style="font-size: 0.85rem; color: var(--muted); margin-bottom: 1rem;">
                Devices that cannot submit the login/captive portal form can be approved here. They must send a request to <code>/api/devices/lowend_request?name=DeviceName</code> to show up here.
            </p>
            <div class="tbl-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Device Name</th>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Request Time</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="lowend-tbody">
                        <tr><td colspan="6" style="text-align:center;color:var(--muted);">No pending requests.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </section>

    <!-- ════════ LABEL MODAL ════════ -->
    <div class="modal-overlay" id="label-modal" role="dialog" aria-modal="true" aria-label="Label device">
        <div class="modal">
            <h2>&#9998; Label Device</h2>
            <input type="hidden" id="modal-ip">
            <input type="hidden" id="modal-mac">
            <div class="field">
                <label for="modal-label">Friendly Name</label>
                <input type="text" id="modal-label" placeholder="e.g. Phone, 5th Floor AP, Server…">
            </div>
            <div class="field">
                <label for="modal-floor">Floor / Location</label>
                <input type="text" id="modal-floor" placeholder="e.g. Ground Floor, 3rd Floor…">
            </div>
            <div class="field">
                <label for="modal-type">Device Type</label>
                <select id="modal-type">
                    <option value="">Unknown</option>
                    <option value="phone">&#128241; Phone / Tablet</option>
                    <option value="pc">&#128187; PC / Laptop</option>
                    <option value="ap">&#128225; Access Point / Router</option>
                    <option value="tv">&#128250; Smart TV / Streamer</option>
                    <option value="server">&#127970; Server / NAS</option>
                    <option value="iot">&#128268; IoT / Smart Device</option>
                    <option value="other">&#9899; Other</option>
                </select>
            </div>
            <div class="field">
                <label for="modal-limit">Daily Data Limit (MB)</label>
                <input type="number" id="modal-limit" placeholder="e.g. 2048 (2GB)" min="1">
            </div>
            <div class="modal-actions" style="display:flex; justify-content:space-between; width:100%;">
                <button class="btn-ghost" onclick="closeModal()">Cancel</button>
                <div>
                    <button class="btn-orange" id="modal-disassociate" onclick="disassociateDevice()" style="background:#f59e0b; border:none; padding: .65rem 1.2rem; border-radius: 8px; font-family: var(--font); font-weight: 600; font-size: .9rem; color: white; cursor: pointer; margin-right: .5rem; transition: opacity .2s;" onmouseover="this.style.opacity=0.9" onmouseout="this.style.opacity=1">De-associate Device</button>
                    <button class="btn-red" id="modal-delete" onclick="unregisterDevice()" style="background:#ef4444; border:none; padding: .65rem 1.2rem; border-radius: 8px; font-family: var(--font); font-weight: 600; font-size: .9rem; color: white; cursor: pointer; margin-right: .5rem; transition: opacity .2s;" onmouseover="this.style.opacity=0.9" onmouseout="this.style.opacity=1">Unregister & Block</button>
                    <button class="btn-primary" id="modal-save" onclick="saveLabel()">Save Label</button>
                </div>
            </div>
        </div>
    </div>

    <!-- ════════ APPROVE LOW-END MODAL ════════ -->
    <div class="modal-overlay" id="approve-lowend-modal" role="dialog" aria-modal="true" aria-label="Approve Low-End Device">
        <div class="modal">
            <h2>&#10004; Approve Low-End Device</h2>
            <input type="hidden" id="lowend-modal-id">
            <div class="field">
                <label for="lowend-modal-label">Friendly Name / User Name</label>
                <input type="text" id="lowend-modal-label" placeholder="e.g. Smart Plug, Ghassan, Living Room TV…">
            </div>
            <div class="field">
                <label for="lowend-modal-floor">Floor / Location</label>
                <input type="text" id="lowend-modal-floor" placeholder="e.g. Ground Floor, Room 102…">
            </div>
            <div class="field">
                <label for="lowend-modal-type">Device Type</label>
                <select id="lowend-modal-type">
                    <option value="iot" selected>&#128268; IoT / Smart Device</option>
                    <option value="tv">&#128250; Smart TV / Streamer</option>
                    <option value="phone">&#128241; Phone / Tablet</option>
                    <option value="pc">&#128187; PC / Laptop</option>
                    <option value="ap">&#128225; Access Point / Router</option>
                    <option value="server">&#127970; Server / NAS</option>
                    <option value="other">&#9899; Other</option>
                </select>
            </div>
            <div class="modal-actions" style="display:flex; justify-content:space-between; width:100%; margin-top: 1rem;">
                <button class="btn-ghost" onclick="closeApproveLowendModal()">Cancel</button>
                <button class="btn-primary" onclick="submitApproveLowend()">Approve & Allow</button>
            </div>
        </div>
    </div>

    <!-- ════════ Toast ════════ -->
    <div class="toast" id="toast">&#10003; Label saved!</div>

    <script>
    // ─── State ────────────────────────────────────────────────────────────────
    let apiData    = null;
    let trendChart = null;
    let devTFState = 'today';
    let appTFState = 'today';
    let currentView = 'apps';

    // ─── Helpers ──────────────────────────────────────────────────────────────
    function fmt(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024, u = ['B','KB','MB','GB','TB'];
        const i = Math.min(Math.floor(Math.log(bytes)/Math.log(k)), u.length-1);
        return (bytes/Math.pow(k,i)).toFixed(2)+' '+u[i];
    }
    function fmtDate(ts) {
        if (!ts) return '—';
        const d = new Date(ts*1000);
        return d.toLocaleDateString('en-US', {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
    }
    function devTypeIcon(t) {
        const m = { phone:'&#128241;', pc:'&#128187;', ap:'&#128225;', tv:'&#128250;', server:'&#127970;', iot:'&#128268;' };
        return m[t] || '&#9899;';
    }
    function devTypeBadge(t) {
        const m = { phone:'b-phone', pc:'b-pc', ap:'b-ap', tv:'b-tv', server:'b-docker', iot:'b-media', other:'b-other' };
        const labels = { phone:'Phone', pc:'PC', ap:'AP', tv:'TV', server:'Server', iot:'IoT', other:'Other' };
        const cls = m[t] || 'b-other';
        const label = labels[t] || (t ? t : 'Unknown');
        return `<span class="badge ${cls}">${label}</span>`;
    }

    // ─── View Switching ───────────────────────────────────────────────────────
    function showView(name) {
        currentView = name;
        localStorage.setItem('nettrack_current_view', name);
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.getElementById('view-' + name).classList.add('active');
        document.getElementById('tab-' + name).classList.add('active');
        if (name === 'devices') fetchDevices();
        else if (name === 'lowend') fetchLowendRequests();
    }

    // ─── Timeframe Switching ──────────────────────────────────────────────────
    function switchTF(tf, btn, ns) {
        const prefix = ns === 'app' ? 'app-tf-' : 'dev-tf-';
        document.querySelectorAll(`[id^="${prefix}"]`).forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        if (ns === 'app') {
            appTFState = tf;
            if (apiData) renderApps();
        } else {
            devTFState = tf;
            fetchDevices();
        }
    }

    // ─── Applications View ────────────────────────────────────────────────────
    async function fetchApps() {
        try {
            const r = await fetch('/api/data');
            apiData = await r.json();
            renderApps();
        } catch(e) { console.error('fetchApps:', e); }
    }

    function renderApps() {
        const data = apiData[appTFState];
        if (!data) return;
        document.getElementById('a-recv').textContent  = fmt(data.recv);
        document.getElementById('a-sent').textContent  = fmt(data.sent);
        document.getElementById('a-total').textContent = fmt(data.total);

        // Table
        const tbody = document.getElementById('app-tbody');
        tbody.innerHTML = '';
        (data.apps || []).forEach(app => {
            let name = app.name, badgeCls = 'b-app', badgeTxt = 'App';
            if (name.startsWith('[Docker] '))     { name = name.slice(9); badgeCls='b-docker'; badgeTxt='Docker'; }
            else if (name === 'YouTube Wrapped')  { badgeCls='b-media';  badgeTxt='Media'; }
            else if (name.includes('Unknown') || name.includes('Loopback')) { badgeCls='b-sys'; badgeTxt='System'; }
            tbody.insertAdjacentHTML('beforeend', `
            <tr>
              <td title="${app.name}"><div class="name-cell">
                <span class="badge ${badgeCls}">${badgeTxt}</span>
                <span class="app-name">${name}</span>
              </div></td>
              <td class="tr" style="color:var(--amber);">${fmt(app.sent)}</td>
              <td class="tr" style="color:var(--green);">${fmt(app.recv)}</td>
              <td class="tr" style="font-weight:600;">${fmt(app.total)}</td>
            </tr>`);
        });

        // Trend chart
        const trend = data.trend || [];
        const labels  = trend.map(t => t.label);
        const recvD   = trend.map(t => t.recv);
        const sentD   = trend.map(t => t.sent);
        const chartCfg = {
            type:'bar', data:{
                labels,
                datasets:[
                    { label:'Download', data:recvD, backgroundColor:'rgba(59,130,246,.75)', borderRadius:4 },
                    { label:'Upload',   data:sentD, backgroundColor:'rgba(16,185,129,.75)', borderRadius:4 }
                ]
            },
            options:{
                responsive:true, maintainAspectRatio:false,
                plugins:{ legend:{ labels:{ color:'#f8fafc', font:{family:'Outfit'} } } },
                scales:{
                    x:{ grid:{color:'rgba(255,255,255,.04)'}, ticks:{color:'#7c8fa8', font:{family:'Outfit'}} },
                    y:{ grid:{color:'rgba(255,255,255,.04)'}, ticks:{color:'#7c8fa8', font:{family:'Outfit'}, callback:v=>fmt(v)} }
                }
            }
        };
        if (trendChart) { trendChart.data.labels=labels; trendChart.data.datasets[0].data=recvD; trendChart.data.datasets[1].data=sentD; trendChart.update('none'); }
        else { trendChart = new Chart(document.getElementById('trendChart').getContext('2d'), chartCfg); }
    }

    // ─── Devices View ─────────────────────────────────────────────────────────
    let allDevices = [];

    async function fetchDevices() {
        document.getElementById('dev-status').textContent = 'Refreshing…';
        try {
            const r = await fetch('/api/devices?period=' + devTFState);
            const data = await r.json();
            allDevices = data.devices || [];
            filterAndRenderDevices();
            renderBlocked(data.blocked || []);
        } catch(e) {
            document.getElementById('dev-status').textContent = 'Error fetching device data.';
            console.error('fetchDevices:', e);
        }
    }

    function filterAndRenderDevices() {
        const query = (document.getElementById('dev-search')?.value || '').trim().toLowerCase();
        if (!query) {
            renderDevices(allDevices);
            return;
        }

        const filtered = allDevices.filter(d => {
            const ipMatches = (d.ip || '').toLowerCase().includes(query);
            const macMatches = (d.mac || '').toLowerCase().includes(query);
            const labelMatches = (d.label || '').toLowerCase().includes(query);
            const floorMatches = (d.floor || '').toLowerCase().includes(query);
            const typeMatches = (d.device_type || '').toLowerCase().includes(query);

            let subMatches = false;
            if (d.sub_devices) {
                subMatches = d.sub_devices.some(s => 
                    (s.ip || '').toLowerCase().includes(query) || 
                    (s.mac || '').toLowerCase().includes(query)
                );
            }

            return ipMatches || macMatches || labelMatches || floorMatches || typeMatches || subMatches;
        });

        renderDevices(filtered);
    }

    function toggleSubDevices(uniqueId) {
        const subRow = document.getElementById('sub-devices-' + uniqueId);
        const arrow = document.getElementById('arrow-' + uniqueId);
        if (!subRow || !arrow) return;
        if (subRow.style.display === 'none') {
            subRow.style.display = 'table-row';
            arrow.innerHTML = '&#9660;'; // Down arrow
        } else {
            subRow.style.display = 'none';
            arrow.innerHTML = '&#9654;'; // Right arrow
        }
    }

    function renderDevices(devices) {
        const count = devices.length;
        const total = devices.reduce((s,d)=>s+d.total, 0);
        const top   = devices.length ? (devices[0].label || devices[0].ip) : '—';

        document.getElementById('d-count').textContent = count;
        document.getElementById('d-top').textContent   = top;
        document.getElementById('d-total').textContent = fmt(total);
        document.getElementById('dev-status').textContent =
            count + ' device' + (count!==1?'s':'') + ' detected  ·  passive sniffer active';

        const tbody = document.getElementById('dev-tbody');
        tbody.innerHTML = '';
        devices.forEach(d => {
            const displayName = d.label || d.ip;
            const badgeHtml   = d.device_type ? devTypeBadge(d.device_type) : '<span class="badge b-other">Unknown</span>';
            const icon        = d.device_type ? devTypeIcon(d.device_type) : '&#9675;';
            const floorHtml   = d.floor ? `<div style="font-size:.73rem;color:var(--muted);margin-top:.15rem;">${d.floor}</div>` : '';
            
            const isRandomizedMac = d.mac && /^[0-9a-fA-F][2367abedefABEDEF]:/.test(d.mac);
            const macHtml = isRandomizedMac 
                ? `<span style="font-family:monospace;font-size:.8rem;">${d.mac}</span> <span class="badge" style="font-size:.65rem;background:rgba(239, 68, 68, 0.12);color:var(--red);border:1px solid rgba(239, 68, 68, 0.35);cursor:help;margin-left:.25rem;vertical-align:middle;" title="This device is using a randomized MAC address (Private Wi-Fi Address).">⚠️ Private MAC</span>`
                : (d.mac ? `<span style="font-family:monospace;font-size:.8rem;">${d.mac}</span>` : '—');

            const hasSubDevices = d.sub_devices && d.sub_devices.length > 1;
            const uniqueId = (d.label || d.ip).replace(/[^a-zA-Z0-9]/g, '_');
            const arrowHtml = hasSubDevices 
                ? `<span id="arrow-${uniqueId}" style="cursor:pointer; margin-right: 0.5rem; color: var(--primary); font-size: 0.8rem;" onclick="toggleSubDevices('${uniqueId}')">&#9654;</span>`
                : '';

            const ipDisplay = hasSubDevices ? `<span style="color:var(--primary); font-weight:600; cursor:pointer;" onclick="toggleSubDevices('${uniqueId}')">Multiple (${d.sub_devices.length} IPs)</span>` : d.ip;
            const macDisplay = hasSubDevices ? `<span style="color:var(--primary); font-weight:600; cursor:pointer;" onclick="toggleSubDevices('${uniqueId}')">Multiple (${d.sub_devices.length} MACs)</span>` : macHtml;

            tbody.insertAdjacentHTML('beforeend', `
            <tr id="dev-row-${uniqueId}">
              <td>
                <div class="name-cell">
                  ${arrowHtml}
                  <div class="dev-icon" style="background:var(--primary-gl)">${icon}</div>
                  <div>
                    <div style="font-weight:600;">${displayName}</div>
                    ${badgeHtml}
                    ${floorHtml}
                  </div>
                </div>
              </td>
              <td style="font-family:monospace;font-size:.85rem;color:var(--muted);">${ipDisplay}</td>
              <td>${macDisplay}</td>
              <td class="tr" style="color:var(--amber);">${fmt(d.sent)}</td>
              <td class="tr" style="color:var(--green);">${fmt(d.recv)}</td>
              <td class="tr" style="font-weight:700;">${fmt(d.total)}</td>
              <td style="font-size:.78rem;color:var(--muted);">${fmtDate(d.last_seen)}</td>
              <td><button class="label-btn" onclick='openModal(${JSON.stringify(d)})'>&#9998; Label</button></td>
            </tr>`);

            if (hasSubDevices) {
                let subRowsHtml = '';
                d.sub_devices.forEach(s => {
                    const isSubRandomizedMac = s.mac && /^[0-9a-fA-F][2367abedefABEDEF]:/.test(s.mac);
                    const subMacHtml = isSubRandomizedMac 
                        ? `<span style="font-family:monospace;">${s.mac}</span> <span class="badge" style="font-size:.6rem;background:rgba(239,68,68,0.1);color:var(--red);border:1px solid rgba(239,68,68,0.25);">Private</span>`
                        : (s.mac ? `<span style="font-family:monospace;">${s.mac}</span>` : '—');
                    
                    subRowsHtml += `
                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.03);">
                      <td style="padding: 0.4rem; font-family:monospace; color:var(--muted); text-align: left;">${s.ip}</td>
                      <td style="padding: 0.4rem; text-align: left;">${subMacHtml}</td>
                      <td style="padding: 0.4rem; text-align: right; color:var(--amber);">${fmt(s.sent)}</td>
                      <td style="padding: 0.4rem; text-align: right; color:var(--green);">${fmt(s.recv)}</td>
                      <td style="padding: 0.4rem; text-align: right; font-weight:600;">${fmt(s.total)}</td>
                      <td style="padding: 0.4rem; text-align: left; color:var(--muted);">${fmtDate(s.last_seen)}</td>
                    </tr>`;
                });

                tbody.insertAdjacentHTML('beforeend', `
                <tr class="sub-devices-row" id="sub-devices-${uniqueId}" style="display:none; background: rgba(0,0,0,0.25);">
                  <td colspan="8" style="padding: 0.6rem 1rem 1rem 3.5rem;">
                    <table style="width: 100%; font-size: 0.8rem; border-collapse: collapse; text-align: left;">
                      <thead>
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.06); color: var(--muted);">
                          <th style="padding: 0.4rem; text-align: left;">IP Address</th>
                          <th style="padding: 0.4rem; text-align: left;">MAC Address</th>
                          <th style="padding: 0.4rem; text-align: right;">Sent</th>
                          <th style="padding: 0.4rem; text-align: right;">Received</th>
                          <th style="padding: 0.4rem; text-align: right;">Total</th>
                          <th style="padding: 0.4rem; text-align: left;">Last Seen</th>
                        </tr>
                      </thead>
                      <tbody>
                        ${subRowsHtml}
                      </tbody>
                    </table>
                  </td>
                </tr>`);
            }
        });

        if (!count) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:2.5rem;color:var(--muted);">No device traffic captured yet.<br><small>Make sure the device daemon is running: <code>sudo systemctl start nettrack-device.service</code></small></td></tr>';
        }
    }

    // ─── Label Modal ──────────────────────────────────────────────────────────
    function openModal(device) {
        document.getElementById('modal-ip').value    = device.ip   || '';
        document.getElementById('modal-mac').value   = device.mac  || '';
        document.getElementById('modal-label').value = device.label || '';
        document.getElementById('modal-floor').value = device.floor || '';
        document.getElementById('modal-type').value  = device.device_type || '';
        document.getElementById('modal-limit').value = device.daily_limit_mb || '2048';
        document.getElementById('label-modal').classList.add('open');
        document.getElementById('modal-label').focus();
    }
    function closeModal() {
        document.getElementById('label-modal').classList.remove('open');
    }
    document.getElementById('label-modal').addEventListener('click', e => {
        if (e.target === e.currentTarget) closeModal();
    });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

    async function saveLabel() {
        const payload = {
            ip:             document.getElementById('modal-ip').value,
            mac:            document.getElementById('modal-mac').value,
            label:          document.getElementById('modal-label').value.trim(),
            floor:          document.getElementById('modal-floor').value.trim(),
            device_type:    document.getElementById('modal-type').value,
            daily_limit_mb: document.getElementById('modal-limit').value || '2048',
        };
        try {
            const r = await fetch('/api/devices/label', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (r.ok) {
                closeModal();
                showToast('Label saved!');
                fetchDevices();
            } else {
                showToast('Error saving label.', true);
            }
        } catch(e) { showToast('Network error.', true); }
    }

    async function disassociateDevice() {
        const mac = document.getElementById('modal-mac').value;
        const ip = document.getElementById('modal-ip').value;
        if (!confirm("Are you sure you want to de-associate this device? It will be removed from the user and redirected back to the captive portal login/registration page.")) return;
        
        const payload = { ip: ip, mac: mac };
        try {
            const r = await fetch('/api/devices/disassociate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (r.ok) {
                closeModal();
                showToast('Device de-associated successfully!');
                fetchDevices();
            } else {
                showToast('Error de-associating device.', true);
            }
        } catch(e) { showToast('Network error.', true); }
    }

    async function unregisterDevice() {
        const mac = document.getElementById('modal-mac').value;
        const ip = document.getElementById('modal-ip').value;
        if (!confirm("Are you sure you want to block this device entirely? It will be banned from accessing the internet and cannot register again until unblocked.")) return;
        
        const reason = prompt("Enter a reason for blocking this device (optional):", "Violated network policy");
        if (reason === null) return;
        
        const payload = { ip: ip, mac: mac, reason: reason };
        try {
            const r = await fetch('/api/devices/block', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (r.ok) {
                closeModal();
                showToast('Device blocked entirely!');
                fetchDevices();
            } else {
                showToast('Error blocking device.', true);
            }
        } catch(e) { showToast('Network error.', true); }
    }

    // ─── Low-End Device Requests ──────────────────────────────────────────────
    async function fetchLowendRequests() {
        try {
            const r = await fetch('/api/devices/lowend_requests');
            const data = await r.json();
            renderLowendRequests(data.requests);
        } catch(e) { console.error('fetchLowendRequests:', e); }
    }

    function renderLowendRequests(requests) {
        const tbody = document.getElementById('lowend-tbody');
        if (!requests || requests.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);">No pending requests.</td></tr>';
            return;
        }
        tbody.innerHTML = requests.map(req => {
            const dateStr = fmtDate(new Date(req.created_at).getTime() / 1000);
            const badgeClass = req.status === 'pending' ? 'badge b-other' : 'badge b-allowed';
            const actionHtml = req.status === 'pending' ? `
                <button class="btn-primary" style="padding: 0.25rem 0.6rem; font-size: 0.8rem; margin-right: 0.5rem;" onclick="openApproveLowendModal(${req.id}, '${req.device_name || ''}')">Approve</button>
                <button class="btn-red" style="padding: 0.25rem 0.6rem; font-size: 0.8rem; background: #ef4444; border: none; color: white; border-radius: 6px; cursor: pointer;" onclick="rejectLowendRequest(${req.id})">Decline</button>
            ` : 'Approved';
            return `
                <tr>
                    <td><strong>${req.device_name || 'Low-end device'}</strong></td>
                    <td><code>${req.ip || '—'}</code></td>
                    <td><code>${req.mac || '—'}</code></td>
                    <td>${dateStr}</td>
                    <td><span class="${badgeClass}">${req.status}</span></td>
                    <td>${actionHtml}</td>
                </tr>
            `;
        }).join('');
    }

    function openApproveLowendModal(id, name) {
        document.getElementById('lowend-modal-id').value = id;
        document.getElementById('lowend-modal-label').value = name;
        document.getElementById('lowend-modal-floor').value = '';
        document.getElementById('lowend-modal-type').value = 'iot';
        document.getElementById('approve-lowend-modal').classList.add('active');
    }

    function closeApproveLowendModal() {
        document.getElementById('approve-lowend-modal').classList.remove('active');
    }

    async function submitApproveLowend() {
        const id = document.getElementById('lowend-modal-id').value;
        const label = document.getElementById('lowend-modal-label').value;
        const floor = document.getElementById('lowend-modal-floor').value;
        const device_type = document.getElementById('lowend-modal-type').value;
        
        try {
            const r = await fetch('/api/devices/approve_lowend', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id, label, floor, device_type })
            });
            const res = await r.json();
            if (res.ok) {
                showToast('Device approved and allowed!');
                closeApproveLowendModal();
                fetchLowendRequests();
            } else {
                alert('Failed: ' + res.error);
            }
        } catch(e) { console.error(e); }
    }

    async function rejectLowendRequest(id) {
        if (!confirm('Are you sure you want to decline this request?')) return;
        try {
            const r = await fetch('/api/devices/reject_lowend', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id })
            });
            const res = await r.json();
            if (res.ok) {
                showToast('Request declined');
                fetchLowendRequests();
            }
        } catch(e) { console.error(e); }
    }

    function renderBlocked(blocked) {
        const tbody = document.getElementById('blocked-tbody');
        tbody.innerHTML = '';
        if (blocked.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:1rem;">No blocked devices.</td></tr>';
            return;
        }
        blocked.forEach(b => {
            tbody.insertAdjacentHTML('beforeend', `
            <tr>
              <td style="font-family:monospace;font-size:.85rem;color:var(--muted);">${b.mac}</td>
              <td style="color:var(--red); font-weight: 500;">${b.reason || 'Banned by admin'}</td>
              <td style="font-size:.8rem;color:var(--muted);">${b.blocked_at}</td>
              <td class="tr">
                <button class="label-btn" style="color:var(--green);border-color:rgba(16,185,129,0.3);" onclick="unblockDevice('${b.mac}')">Unblock Device</button>
              </td>
            </tr>
            `);
        });
    }

    async function unblockDevice(mac) {
        if (!confirm("Are you sure you want to unblock this device?")) return;
        try {
            const r = await fetch('/api/devices/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mac: mac })
            });
            if (r.ok) {
                showToast('Device unblocked successfully!');
                fetchDevices();
            } else {
                showToast('Error unblocking device.', true);
            }
        } catch(e) { showToast('Network error.', true); }
    }

    // ─── Toast ────────────────────────────────────────────────────────────────
    function showToast(msg, err=false) {
        const t = document.getElementById('toast');
        t.textContent = (err ? '✗ ' : '✓ ') + msg;
        t.style.borderColor = err ? 'var(--red)' : 'var(--green)';
        t.style.color       = err ? 'var(--red)' : 'var(--green)';
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 3000);
    }

    // ─── Init ─────────────────────────────────────────────────────────────────
    const savedView = localStorage.getItem('nettrack_current_view');
    if (savedView && (savedView === 'apps' || savedView === 'devices')) {
        showView(savedView);
    } else {
        showView('apps');
    }
    fetchApps();
    setInterval(fetchApps, 15000);
    setInterval(() => { if (currentView === 'devices') fetchDevices(); }, 15000);
    </script>
</body>
</html>"""


# ─── Secure Vault HTML ────────────────────────────────────────────────────────
VAULT_HTML = """<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Secure Vault - NetTrack</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg:          #060b13;
            --card-bg:     rgba(15, 23, 42, 0.75);
            --text:        #f8fafc;
            --muted:       #94a3b8;
            --primary:     #3b82f6;
            --border:      rgba(255,255,255,0.08);
            --radius:      12px;
            --font:        'Outfit', sans-serif;
            --red:         #ef4444;
            --green:       #10b981;
            --purple:      #a855f7;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--font);
            background: var(--bg);
            background-image:
                radial-gradient(ellipse 70% 60% at 80% -10%, rgba(168,85,247,0.15), transparent),
                radial-gradient(ellipse 60% 50% at 10% 110%, rgba(59,130,246,0.12), transparent);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        header {
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            padding: 1.2rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 0.8rem;
        }
        .logo-icon {
            width: 36px;
            height: 36px;
            border-radius: 8px;
            background: linear-gradient(135deg, var(--purple), var(--primary));
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.1rem;
            box-shadow: 0 4px 12px rgba(168,85,247,0.3);
        }
        .logo h1 {
            font-size: 1.25rem;
            font-weight: 700;
            background: linear-gradient(to left, #fff, #cbd5e1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .main-container {
            flex: 1;
            max-width: 1200px;
            width: 100%;
            margin: 2rem auto;
            padding: 0 1.5rem;
        }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
            backdrop-filter: blur(8px);
        }
        /* ── Login Form ── */
        .login-card {
            max-width: 400px;
            margin: 10vh auto;
            text-align: center;
        }
        .login-icon {
            font-size: 3.5rem;
            margin-bottom: 1.5rem;
            color: var(--purple);
            text-shadow: 0 0 20px rgba(168,85,247,0.3);
        }
        .login-card h2 {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }
        .login-card p {
            color: var(--muted);
            font-size: 0.9rem;
            margin-bottom: 1.8rem;
        }
        .input-group {
            margin-bottom: 1.5rem;
            text-align: right;
        }
        label {
            display: block;
            font-size: 0.85rem;
            color: var(--muted);
            margin-bottom: 0.5rem;
            font-weight: 600;
        }
        input[type="password"], input[type="text"] {
            width: 100%;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: rgba(255,255,255,0.03);
            color: var(--text);
            font-family: var(--font);
            outline: none;
            text-align: center;
            font-size: 1.1rem;
            transition: all 0.2s;
        }
        input[type="password"]:focus, input[type="text"]:focus {
            border-color: var(--purple);
            background: rgba(255,255,255,0.06);
            box-shadow: 0 0 10px rgba(168,85,247,0.2);
        }
        .btn {
            width: 100%;
            padding: 0.75rem;
            border-radius: 8px;
            border: none;
            background: linear-gradient(135deg, var(--purple), var(--primary));
            color: white;
            font-family: var(--font);
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            box-shadow: 0 4px 14px rgba(168,85,247,0.3);
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.9; }
        
        /* ── Tabs ── */
        .tabs {
            display: flex;
            gap: 1rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1.5rem;
        }
        .tab-btn {
            padding: 0.75rem 1.5rem;
            background: transparent;
            border: none;
            color: var(--muted);
            font-family: var(--font);
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }
        .tab-btn.active {
            color: var(--purple);
            border-bottom-color: var(--purple);
        }
        
        /* ── Table & Logs ── */
        .logs-section, .blacklist-section {
            display: none;
        }
        .logs-section.active, .blacklist-section.active {
            display: block;
        }
        .table-container {
            overflow-x: auto;
            margin-top: 1rem;
            border: 1px solid var(--border);
            border-radius: 8px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }
        th, td {
            padding: 0.9rem 1.2rem;
            border-bottom: 1px solid var(--border);
        }
        th {
            background: rgba(255,255,255,0.02);
            color: var(--muted);
            font-weight: 600;
        }
        tr:hover td {
            background: rgba(255,255,255,0.01);
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.65rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .badge.b-allowed { background: rgba(16,185,129,0.12); color: var(--green); border: 1px solid rgba(16,185,129,0.3); }
        .badge.b-blocked { background: rgba(239,68,68,0.12); color: var(--red); border: 1px solid rgba(239,68,68,0.3); }
        
        .action-btn {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--muted);
            padding: 0.3rem 0.75rem;
            border-radius: 6px;
            cursor: pointer;
            font-family: var(--font);
            font-size: 0.8rem;
            font-weight: 600;
            transition: all 0.2s;
        }
        .action-btn:hover {
            color: var(--red);
            border-color: rgba(239,68,68,0.4);
            background: rgba(239,68,68,0.05);
        }
        .action-btn.unblock:hover {
            color: var(--green);
            border-color: rgba(16,185,129,0.4);
            background: rgba(16,185,129,0.05);
        }
        
        /* ── Add Blacklist ── */
        .add-blacklist-form {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            max-width: 500px;
        }
        .add-blacklist-form input {
            text-align: left;
            font-size: 0.95rem;
        }
        
        .toast {
            position: fixed;
            bottom: 2rem;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: #1e293b;
            border: 1px solid var(--purple);
            color: var(--purple);
            font-weight: 600;
            font-size: .88rem;
            padding: .8rem 2rem;
            border-radius: 30px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.35);
            transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            z-index: 1000;
        }
        .toast.show {
            transform: translateX(-50%) translateY(0);
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">
            <div class="logo-icon">🔒</div>
            <h1>Secure Administration Vault</h1>
        </div>
        <button class="action-btn" onclick="logoutVault()" style="display:none;" id="logout-btn">Log Out</button>
    </header>

    <div class="main-container">
        <!-- Login Form -->
        <div class="card login-card" id="login-section">
            <div class="login-icon">🔒</div>
            <h2>Access Secure Vault</h2>
            <p>Enter the secret vault password to manage domain blocks and monitor local network DNS queries.</p>
            
            <div class="input-group">
                <label for="vault-pass">Secret Password</label>
                <input type="password" id="vault-pass" placeholder="•••••" onkeydown="if(event.key==='Enter') loginVault()">
            </div>
            <button class="btn" onclick="loginVault()">Unlock Vault</button>
        </div>

        <!-- Authenticated Dashboard -->
        <div class="card" id="dashboard-section" style="display:none;">
            <div class="tabs">
                <button class="tab-btn active" id="tab-logs" onclick="showTab('logs')">DNS Query Logs</button>
                <button class="tab-btn" id="tab-blacklist" onclick="showTab('blacklist')">Blacklisted Domains</button>
            </div>

            <!-- DNS Logs Tab -->
            <div class="logs-section active" id="sec-logs">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                    <p style="color:var(--muted); font-size:0.9rem;">Shows the last 200 resolved internet domains from all devices on your local network.</p>
                    <button class="action-btn" onclick="fetchLogs()">🔄 Refresh Logs</button>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Device Name</th>
                                <th>IP Address</th>
                                <th>Requested Domain</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="logs-tbody">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Blacklist Tab -->
            <div class="blacklist-section" id="sec-blacklist">
                <p style="color:var(--muted); font-size:0.9rem; margin-bottom:1.5rem;">Add domains to block them immediately for all devices on the network.</p>
                
                <div class="add-blacklist-form">
                    <input type="text" id="blacklist-input" placeholder="e.g. tiktok.com, instagram.com..." style="text-align:left;" onkeydown="if(event.key==='Enter') addToBlacklist()">
                    <button class="btn" onclick="addToBlacklist()" style="width:140px;">Block Domain</button>
                </div>

                <div class="table-container" style="max-width: 600px;">
                    <table>
                        <thead>
                            <tr>
                                <th>Blocked Domain</th>
                                <th style="text-align:right;">Action</th>
                            </tr>
                        </thead>
                        <tbody id="blacklist-tbody">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div class="toast" id="toast"></div>

    <script>
        function showToast(msg, err=false) {
            const t = document.getElementById('toast');
            t.textContent = (err ? '✗ ' : '✓ ') + msg;
            t.style.borderColor = err ? 'var(--red)' : 'var(--purple)';
            t.style.color       = err ? 'var(--red)' : 'var(--purple)';
            t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 3000);
        }

        function checkAuth() {
            const cookies = document.cookie.split(';');
            const session = cookies.find(c => c.trim().startsWith('nettrack_vault_session='));
            if (session && session.split('=')[1] === 'authenticated') {
                document.getElementById('login-section').style.display = 'none';
                document.getElementById('dashboard-section').style.display = 'block';
                document.getElementById('logout-btn').style.display = 'block';
                // Load data
                fetchLogs();
                fetchBlacklist();
                // Start auto-refresh for logs
                setInterval(fetchLogs, 10000);
            } else {
                document.getElementById('login-section').style.display = 'block';
                document.getElementById('dashboard-section').style.display = 'none';
                document.getElementById('logout-btn').style.display = 'none';
            }
        }

        async function loginVault() {
            const password = document.getElementById('vault-pass').value;
            try {
                const response = await fetch('/api/vault/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const result = await response.json();
                if (response.ok && result.ok) {
                    showToast('Vault unlocked successfully!');
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                } else {
                    showToast(result.error || 'Incorrect password!', true);
                }
            } catch(e) {
                showToast('Connection error occurred.', true);
            }
        }

        function logoutVault() {
            document.cookie = 'nettrack_vault_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
            window.location.reload();
        }

        function showTab(tab) {
            document.getElementById('tab-logs').classList.toggle('active', tab === 'logs');
            document.getElementById('tab-blacklist').classList.toggle('active', tab === 'blacklist');
            document.getElementById('sec-logs').classList.toggle('active', tab === 'logs');
            document.getElementById('sec-blacklist').classList.toggle('active', tab === 'blacklist');
            if (tab === 'logs') fetchLogs();
            if (tab === 'blacklist') fetchBlacklist();
        }

        async function fetchLogs() {
            try {
                const response = await fetch('/api/vault/logs');
                if (!response.ok) return;
                const data = await response.json();
                const tbody = document.getElementById('logs-tbody');
                tbody.innerHTML = '';
                
                if (!data.logs || data.logs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:2rem;">No DNS logs captured yet.</td></tr>';
                    return;
                }
                
                data.logs.forEach(log => {
                    const dateStr = new Date(log.timestamp * 1000).toLocaleString('en-US', { hour12: true });
                    const badgeClass = log.status === 'Blocked' ? 'badge b-blocked' : 'badge b-allowed';
                    const statusText = log.status === 'Blocked' ? 'Blocked' : 'Allowed';
                    
                    const actionBtn = log.status === 'Blocked'
                        ? `<button class="action-btn unblock" onclick="toggleBlock('${log.domain}', false)">Unblock</button>`
                        : `<button class="action-btn" onclick="toggleBlock('${log.domain}', true)">Block</button>`;
                        
                    tbody.insertAdjacentHTML('beforeend', `
                        <tr>
                            <td>${dateStr}</td>
                            <td style="font-weight:600;">${log.device_name}</td>
                            <td style="font-family:monospace;color:var(--muted);">${log.ip}</td>
                            <td style="font-family:monospace;text-align:left;">${log.domain}</td>
                            <td><span class="${badgeClass}">${statusText}</span></td>
                            <td>${actionBtn}</td>
                        </tr>
                    `);
                });
            } catch(e) {
                console.error(e);
            }
        }

        async function fetchBlacklist() {
            try {
                const response = await fetch('/api/vault/blacklist');
                if (!response.ok) return;
                const data = await response.json();
                const tbody = document.getElementById('blacklist-tbody');
                tbody.innerHTML = '';
                
                if (!data.blacklist || data.blacklist.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;color:var(--muted);padding:2rem;">The blacklist is currently empty.</td></tr>';
                    return;
                }
                
                data.blacklist.forEach(domain => {
                    tbody.insertAdjacentHTML('beforeend', `
                        <tr>
                            <td style="font-family:monospace;text-align:left;font-size:1rem;font-weight:600;">${domain}</td>
                            <td style="text-align:right;">
                                <button class="action-btn unblock" onclick="toggleBlock('${domain}', false)">Unblock</button>
                            </td>
                        </tr>
                    `);
                });
            } catch(e) {
                console.error(e);
            }
        }

        async function addToBlacklist() {
            const input = document.getElementById('blacklist-input');
            const domain = input.value.trim().toLowerCase();
            if (!domain) return;
            
            try {
                const response = await fetch('/api/vault/blacklist/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain })
                });
                if (response.ok) {
                    showToast('Domain added to blacklist!');
                    input.value = '';
                    fetchBlacklist();
                } else {
                    showToast('Failed to block domain.', true);
                }
            } catch(e) {
                showToast('Network error.', true);
            }
        }

        async function toggleBlock(domain, shouldBlock) {
            const url = shouldBlock ? '/api/vault/blacklist/add' : '/api/vault/blacklist/remove';
            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain })
                });
                if (response.ok) {
                    showToast(shouldBlock ? 'Domain blocked successfully!' : 'Domain unblocked successfully!');
                    if (document.getElementById('tab-logs').classList.contains('active')) {
                        fetchLogs();
                    } else {
                        fetchBlacklist();
                    }
                } else {
                    showToast('Failed to complete operation.', true);
                }
            } catch(e) {
                showToast('Network error.', true);
            }
        }

        // Run
        checkAuth();
    </script>
</body>
</html>
"""

LIMIT_EXCEEDED_HTML = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>تجاوز حد الاستهلاك - NetTrack</title>
    <!-- Removed Google Fonts link to prevent timeout blocking without internet -->
    <style>
        body {
            font-family: 'Cairo', sans-serif;
            background-color: #060b13;
            color: #f8fafc;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            background-image: radial-gradient(ellipse 60% 50% at 50% -10%, rgba(239,68,68,0.18), transparent);
        }
        .container {
            max-width: 500px;
            width: 90%;
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(239, 68, 68, 0.2);
            padding: 2.5rem;
            border-radius: 16px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(12px);
        }
        .icon {
            font-size: 4rem;
            color: #ef4444;
            margin-bottom: 1.5rem;
            text-shadow: 0 0 15px rgba(239,68,68,0.4);
        }
        h2 { margin-bottom: 0.5rem; font-size: 1.6rem; font-weight: 700; }
        p { color: #94a3b8; font-size: 0.95rem; line-height: 1.6; margin-bottom: 1.8rem; }
        .details {
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 1rem 1.5rem;
            margin-bottom: 1.8rem;
            text-align: right;
        }
        .details div {
            display: flex;
            justify-content: space-between;
            margin: 0.6rem 0;
            font-size: 0.92rem;
        }
        .label { color: #94a3b8; }
        .value { font-weight: 600; color: #f8fafc; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠️</div>
        <h2>تجاوز حد الاستهلاك اليومي</h2>
        <p>عذراً، لقد استهلك جهازك كامل الرصيد اليومي المخصص له للموقع الحالي. يرجى مراجعة إدارة الشبكة لطلب رصيد إضافي.<br>
        <span style="font-size: 0.85rem; color: #64748b;">You have consumed your daily data limit. Please contact the administrator to adjust your plan.</span></p>
        
        <div class="details">
            <div>
                <span class="label">الاسم (Name):</span>
                <span class="value">{name}</span>
            </div>
            <div>
                <span class="label">الاستهلاك اليومي (Usage Today):</span>
                <span class="value" style="color: #ef4444;">{used}</span>
            </div>
            <div>
                <span class="label">الحد الأقصى (Daily Limit):</span>
                <span class="value">{limit}</span>
            </div>
        </div>
    </div>
</body>
</html>
"""

BLOCKED_HTML = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>الجهاز محظور - NetTrack</title>
    <!-- Removed Google Fonts link to prevent timeout blocking without internet -->
    <style>
        body {
            font-family: 'Cairo', sans-serif;
            background-color: #060b13;
            color: #f8fafc;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            background-image: radial-gradient(ellipse 60% 50% at 50% -10%, rgba(239,68,68,0.22), transparent);
        }
        .container {
            max-width: 500px;
            width: 90%;
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(239, 68, 68, 0.25);
            padding: 2.5rem;
            border-radius: 16px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(12px);
        }
        .icon {
            font-size: 4rem;
            color: #ef4444;
            margin-bottom: 1.5rem;
            text-shadow: 0 0 15px rgba(239,68,68,0.4);
        }
        h2 { margin-bottom: 0.5rem; font-size: 1.6rem; font-weight: 700; }
        p { color: #94a3b8; font-size: 0.95rem; line-height: 1.6; margin-bottom: 1.8rem; }
        .details {
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 1rem 1.5rem;
            margin-bottom: 1.8rem;
            text-align: right;
        }
        .details div {
            display: flex;
            justify-content: space-between;
            margin: 0.6rem 0;
            font-size: 0.92rem;
        }
        .label { color: #94a3b8; }
        .value { font-weight: 600; color: #f8fafc; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🚫</div>
        <h2>تم حظر هذا الجهاز</h2>
        <p>لقد تم حظر جهازك من الوصول إلى الشبكة بواسطة مسؤول النظام.</p>
        <div class="details">
            <div>
                <span class="label">السبب (Reason):</span>
                <span class="value">{reason}</span>
            </div>
        </div>
    </div>
</body>
</html>
"""

UNREGISTERED_BLOCK_HTML = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>تسجيل الدخول مطلوب - NetTrack</title>
    <!-- Removed Google Fonts link to prevent timeout blocking without internet -->
    <style>
        body {
            font-family: 'Cairo', sans-serif;
            background-color: #080d17;
            color: #f1f5f9;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            background-image: radial-gradient(ellipse 60% 50% at 50% -10%, rgba(59,130,246,0.15), transparent);
        }
        .container {
            max-width: 450px;
            width: 90%;
            background: rgba(18, 26, 44, 0.75);
            border: 1px solid rgba(255, 255, 255, 0.07);
            padding: 2.5rem;
            border-radius: 16px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(12px);
        }
        .icon {
            font-size: 3.5rem;
            color: #3b82f6;
            margin-bottom: 1.5rem;
            text-shadow: 0 0 15px rgba(59,130,246,0.4);
        }
        h2 { margin-bottom: 0.8rem; font-size: 1.5rem; font-weight: 700; }
        p { color: #94a3b8; font-size: 0.95rem; line-height: 1.6; margin-bottom: 2rem; }
        .btn-login {
            display: inline-block;
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            border: none;
            color: #ffffff;
            font-family: 'Cairo', sans-serif;
            font-weight: 700;
            font-size: 1rem;
            padding: .8rem 2rem;
            border-radius: 10px;
            cursor: pointer;
            text-decoration: none;
            box-shadow: 0 4px 14px rgba(59,130,246,0.35);
            transition: all .2s;
        }
        .btn-login:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(59,130,246,0.45);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔑</div>
        <h2>تسجيل الدخول مطلوب</h2>
        <p>هذا الجهاز غير مسجل في الشبكة. يجب عليك تسجيل الدخول أو إدخال رمز المرور لتفعيل خدمة الإنترنت.<br>
        <span style="font-size: 0.85rem; color: #64748b;">This device is not registered. Please log in to get internet access.</span></p>
        <a href="http://192.168.1.100:6054/register" class="btn-login">تسجيل الدخول (Log In)</a>
        
        <div style="margin-top: 2rem; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 1.5rem;">
            <p style="font-size: 0.85rem; margin-bottom: 1rem; color: #94a3b8;">
                هل هذا جهاز بسيط (شاشة، طابعة، جهاز ذكي)؟ أرسل طلب اتصال مباشرة للمسؤول:<br>
                <span style="color: #64748b;">Low-end device (Smart TV, Printer)? Send a connection request directly to the admin:</span>
            </p>
            <input type="text" id="dev-name" placeholder="اسم الجهاز (e.g. Smart TV, Printer)" onkeypress="if(event.key === 'Enter') { event.preventDefault(); sendRequest(); }" style="width: 100%; padding: 0.65rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.15); background: rgba(0,0,0,0.25); color: white; text-align: center; margin-bottom: 0.8rem; font-family: 'Cairo', sans-serif;">
            <button onclick="sendRequest()" id="req-btn" style="width: 100%; background: #1e293b; border: 1px solid rgba(255,255,255,0.1); color: white; padding: 0.65rem; border-radius: 8px; font-weight: 700; cursor: pointer; font-family: 'Cairo', sans-serif;">إرسال طلب (Send Request)</button>
            <div id="status-msg" style="margin-top: 0.8rem; font-size: 0.85rem; font-weight: 600; display: none;"></div>
        </div>
        
        <script>
            async function sendRequest() {
                const name = document.getElementById('dev-name').value.trim() || 'Low-End Device';
                const btn = document.getElementById('req-btn');
                const status = document.getElementById('status-msg');
                btn.disabled = true;
                btn.innerText = 'جاري الإرسال... (Sending...)';
                try {
                    const r = await fetch('http://192.168.1.100:6054/api/devices/lowend_request?name=' + encodeURIComponent(name));
                    const res = await r.json();
                    if (res.ok) {
                        status.style.color = '#10b981';
                        status.innerText = '✓ تم إرسال الطلب بنجاح! انتظر موافقة المسؤول. (Request sent successfully! Waiting for admin approval.)';
                        status.style.display = 'block';
                    } else {
                        throw new Error();
                    }
                } catch(e) {
                    status.style.color = '#ef4444';
                    status.innerText = '✗ فشل إرسال الطلب. (Failed to send request.)';
                    status.style.display = 'block';
                    btn.disabled = false;
                    btn.innerText = 'إرسال طلب (Send Request)';
                }
            }
        </script>
    </div>
</body>
</html>
"""

# --- Web Server Component ---
class WebDashboardHandler(BaseHTTPRequestHandler):
    def address_string(self):
        # Prevent slow DNS reverse lookups
        return self.client_address[0]

    def log_message(self, format, *args):
        # Silence default request logging in terminal
        return

    def is_vault_authenticated(self):
        cookie_header = self.headers.get("Cookie", "")
        return "nettrack_vault_session=authenticated" in cookie_header

    def get_api_data(self):
        # Compile stats for today, week, month
        check_db()
        
        # Today
        ts_today = int(datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        sent_t, recv_t, progs_t = get_stats(ts_today)
        
        # Week
        ts_week = int((datetime.datetime.now() - datetime.timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        sent_w, recv_w, progs_w = get_stats(ts_week)
        
        # Month
        ts_month = int((datetime.datetime.now() - datetime.timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
        sent_m, recv_m, progs_m = get_stats(ts_month)
        
        # Trends
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Today hourly trend
        cursor.execute("""
        SELECT hour_timestamp, SUM(sent_bytes), SUM(received_bytes)
        FROM hourly_usage WHERE hour_timestamp >= ? GROUP BY hour_timestamp ORDER BY hour_timestamp ASC
        """, (ts_today,))
        trend_today = [{"label": datetime.datetime.fromtimestamp(r[0]).strftime("%H:00"), "sent": r[1], "recv": r[2]} for r in cursor.fetchall()]
        
        # Week daily trend
        cursor.execute("""
        SELECT strftime('%Y-%m-%d', datetime(hour_timestamp, 'unixepoch', 'localtime')) as day,
               SUM(sent_bytes), SUM(received_bytes)
        FROM hourly_usage WHERE hour_timestamp >= ? GROUP BY day ORDER BY day ASC
        """, (ts_week,))
        trend_week = [{"label": r[0], "sent": r[1], "recv": r[2]} for r in cursor.fetchall()]
        
        conn.close()
        
        def serialize_progs(progs):
            return [{"name": p[0], "sent": p[1], "recv": p[2], "total": p[3]} for p in progs]
            
        return {
            "today": {"sent": sent_t, "recv": recv_t, "total": sent_t + recv_t, "apps": serialize_progs(progs_t[:15]), "trend": trend_today},
            "week": {"sent": sent_w, "recv": recv_w, "total": sent_w + recv_w, "apps": serialize_progs(progs_w[:15]), "trend": trend_week},
            "month": {"sent": sent_m, "recv": recv_m, "total": sent_m + recv_m, "apps": serialize_progs(progs_m[:15])}
        }

    def get_device_uuid_from_cookie(self):
        cookie_header = self.headers.get("Cookie", "")
        if "nettrack_device_uuid=" in cookie_header:
            try:
                cookies = dict(item.split("=") for item in cookie_header.split("; ") if "=" in item)
                return cookies.get("nettrack_device_uuid", "").strip()
            except Exception:
                pass
        return None

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        params     = dict(urllib.parse.parse_qsl(parsed_url.query))

        # Check if the device is blocked entirely
        client_ip = self.client_address[0]
        is_blocked = False
        block_reason = "سلوك غير مصرح به"
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
            SELECT reason FROM blocked_devices 
            WHERE mac_address = (SELECT mac_address FROM device_labels WHERE ip_address = ? LIMIT 1);
            """, (client_ip,))
            row = cursor.fetchone()
            if row:
                is_blocked = True
                block_reason = row[0] or block_reason
            conn.close()
        except Exception:
            pass

        if is_blocked and not parsed_url.path.startswith("/api/"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            html = BLOCKED_HTML.replace("{reason}", block_reason)
            self.wfile.write(html.encode('utf-8'))
            return

        # ─── Bypass Registration check for Secure Vault ───
        if parsed_url.path == "/vault":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(VAULT_HTML.encode('utf-8'))
            return

        if parsed_url.path == "/api/vault/logs":
            if not self.is_vault_authenticated():
                self.send_response(401)
                self.end_headers()
                return
            
            # Fetch last 200 DNS logs
            logs = []
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("""
                SELECT l.timestamp, l.ip_address, COALESCE(d.label, 'جهاز غير معروف'), l.domain, l.status
                FROM dns_logs l
                LEFT JOIN device_labels d ON l.ip_address = d.ip_address
                ORDER BY l.timestamp DESC
                LIMIT 200;
                """)
                logs = [{"timestamp": r[0], "ip": r[1], "device_name": r[2], "domain": r[3], "status": r[4]} for r in cursor.fetchall()]
                conn.close()
            except Exception as exc:
                print(f"[web] GET /api/vault/logs error: {exc}", file=sys.stderr)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"logs": logs}).encode('utf-8'))
            return

        if parsed_url.path == "/api/vault/blacklist":
            if not self.is_vault_authenticated():
                self.send_response(401)
                self.end_headers()
                return
                
            blacklist = []
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT domain FROM dns_blacklist ORDER BY domain ASC;")
                blacklist = [row[0] for row in cursor.fetchall()]
                conn.close()
            except Exception as exc:
                print(f"[web] GET /api/vault/blacklist error: {exc}", file=sys.stderr)
                
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"blacklist": blacklist}).encode('utf-8'))
            return

        # Check if the device has exceeded its daily limit
        has_exceeded = False
        user_name = "مستخدم"
        used_str = "0 B"
        limit_str = "2 GB"
        
        client_ip = self.client_address[0]
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Find device name/label and MAC
            cursor.execute("""
            SELECT label, mac_address FROM device_labels WHERE ip_address = ?
            UNION
            SELECT label, device_uuid FROM registered_devices WHERE device_uuid = (
                SELECT mac_address FROM device_labels WHERE ip_address = ? LIMIT 1
            )
            LIMIT 1;
            """, (client_ip, client_ip))
            row = cursor.fetchone()
            if row:
                label, mac = row
                midnight = int(datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
                
                # Get daily limit
                cursor.execute("SELECT COALESCE(daily_limit_mb, 2048) FROM user_limits WHERE label = ?", (label,))
                lim_row = cursor.fetchone()
                limit_mb = lim_row[0] if lim_row else 2048
                limit_bytes = limit_mb * 1024 * 1024
                
                # Get usage today
                cursor.execute("""
                SELECT SUM(sent_bytes + received_bytes) FROM device_usage
                WHERE (ip_address = ? OR mac_address = ?) AND hour_timestamp >= ?
                """, (client_ip, mac or '', midnight))
                usage_row = cursor.fetchone()
                usage_bytes = usage_row[0] if usage_row and usage_row[0] is not None else 0
                
                if usage_bytes >= limit_bytes:
                    has_exceeded = True
                    user_name = label
                    
                    def fmt_bytes(b):
                        if b >= 1024*1024*1024: return f"{b/(1024*1024*1024):.2f} GB"
                        return f"{b/(1024*1024):.2f} MB"
                        
                    used_str = fmt_bytes(usage_bytes)
                    limit_str = fmt_bytes(limit_bytes)
            conn.close()
        except Exception:
            pass
            
        if has_exceeded:
            # If they are trying to load the dashboard or register, serve the limit page
            if parsed_url.path in ["/register", "/", "/index.html"]:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
                html = LIMIT_EXCEEDED_HTML.replace("{name}", user_name).replace("{used}", used_str).replace("{limit}", limit_str)
                self.wfile.write(html.encode('utf-8'))
                return
            # If they are trying to load an external site or an OS check, redirect to /register so they see the warning
            elif not parsed_url.path.startswith("/api/"):
                self.send_response(302)
                self.send_header("Location", "http://192.168.1.100:6054/register")
                self.end_headers()
                return

        # Check if the device is registered by its IP first (since cookies are not sent on NAT-intercepted external requests)
        is_registered = False
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
            SELECT 1 FROM devices d
            JOIN device_ips di ON di.device_id = d.id
            WHERE di.ip_address = ? AND d.approved = 1
            """, (client_ip,))
            is_registered = cursor.fetchone() is not None
            conn.close()
        except Exception:
            pass

        # Check for device tracking cookie as a fallback
        uuid = self.get_device_uuid_from_cookie()
        if not is_registered and uuid:
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM registered_devices WHERE device_uuid = ?", (uuid,))
                is_registered = cursor.fetchone() is not None
                conn.close()
            except Exception:
                pass

        if is_registered:
            update_device_mapping(self.client_address[0], uuid)
            
            # If it's a redirected external captive check, respond with Success/204 to dismiss OS prompt
            host_header = self.headers.get("Host", "").lower()
            if "192.168.1.100" not in host_header and "localhost" not in host_header and "127.0.0.1" not in host_header:
                if "apple" in host_header or "captive" in host_header or "hotspot" in host_header:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")
                    return
                elif "msftconnecttest" in host_header or "msftncsi" in host_header:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"Microsoft Connect Test")
                    return
                else:
                    self.send_response(204)
                    self.end_headers()
                    return
        else:
            # If not registered, handle captive portal redirects or serve the login block page
            host_header = self.headers.get("Host", "").lower()
            if "192.168.1.100" not in host_header and "localhost" not in host_header and "127.0.0.1" not in host_header:
                if not parsed_url.path.startswith("/api/"):
                    self.send_response(302)
                    self.send_header("Location", "http://192.168.1.100:6054/")
                    self.end_headers()
                    return
            else:
                if parsed_url.path != "/register" and not parsed_url.path.startswith("/api/"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                    self.end_headers()
                    self.wfile.write(UNREGISTERED_BLOCK_HTML.encode('utf-8'))
                    return

        if parsed_url.path == "/api/data":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(self.get_api_data()).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices/lowend_requests":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            requests = []
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT id, device_name, ip_address, mac_address, created_at, status FROM lowend_requests ORDER BY created_at DESC;")
                requests = [{"id": r[0], "device_name": r[1], "ip": r[2], "mac": r[3], "created_at": r[4], "status": r[5]} for r in cursor.fetchall()]
                conn.close()
            except Exception as e:
                print(f"[web] error fetching lowend requests: {e}", file=sys.stderr)
            self.wfile.write(json.dumps({"requests": requests}).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices/lowend_request":
            # Low-end device ping/request registration
            client_ip = self.client_address[0]
            device_name = params.get("name", "Unknown Low-End Device").strip()
            
            # Find MAC address from ARP cache
            mac = ""
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == client_ip:
                            mac = parts[3].lower().strip()
                            break
            except Exception:
                pass

            ok = False
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO lowend_requests (device_name, ip_address, mac_address, status)
                VALUES (?, ?, ?, 'pending')
                """, (device_name, client_ip, mac or None))
                conn.commit()
                conn.close()
                ok = True
            except Exception as e:
                print(f"[web] error inserting lowend request: {e}", file=sys.stderr)

            self.send_response(200 if ok else 500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok, "ip": client_ip, "mac": mac}).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            check_db()
            period = params.get("period", "today")
            now    = datetime.datetime.now()
            if period == "week":
                since_ts = int((now - datetime.timedelta(days=6)).replace(
                    hour=0, minute=0, second=0, microsecond=0).timestamp())
            elif period == "month":
                since_ts = int((now - datetime.timedelta(days=29)).replace(
                    hour=0, minute=0, second=0, microsecond=0).timestamp())
            else:
                since_ts = int(now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
            devices = get_device_stats(since_ts)
            blocked = []
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT mac_address, reason, blocked_at FROM blocked_devices ORDER BY blocked_at DESC;")
                blocked = [{"mac": r[0], "reason": r[1], "blocked_at": r[2]} for r in cursor.fetchall()]
                conn.close()
            except Exception as exc:
                print(f"[web] error fetching blocked devices: {exc}", file=sys.stderr)
            self.wfile.write(json.dumps({"devices": devices, "period": period, "blocked": blocked}).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices/trend":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            ip = params.get("ip", "")
            now = datetime.datetime.now()
            since_ts = int((now - datetime.timedelta(days=6)).replace(
                hour=0, minute=0, second=0, microsecond=0).timestamp())
            trend = get_device_hourly_trend(ip, since_ts) if ip else []
            self.wfile.write(json.dumps({"trend": trend}).encode('utf-8'))
            return

        if parsed_url.path == "/register":
            if is_registered:
                # Already registered! Update mapping and send to success page (/)
                update_device_mapping(self.client_address[0], uuid)
                self.send_response(302)
                self.send_header("Location", "http://192.168.1.100:6054/")
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(REGISTRATION_HTML.encode('utf-8'))
            return

        # HTML Page
        is_admin = False
        user_name = ""
        user_floor = ""
        if is_registered:
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                # 1. Try to find user by IP address
                cursor.execute("""
                SELECT u.username, d.floor FROM devices d
                JOIN users u ON d.user_id = u.id
                JOIN device_ips di ON di.device_id = d.id
                WHERE di.ip_address = ? AND d.approved = 1
                LIMIT 1
                """, (client_ip,))
                row = cursor.fetchone()
                
                # 2. Fallback to cookie uuid if not found by IP
                if not row and uuid:
                    cursor.execute("SELECT label, floor FROM registered_devices WHERE device_uuid = ?", (uuid,))
                    row = cursor.fetchone()
                    
                if row:
                    user_name, user_floor = row
                    if user_name.strip().lower() == "ghassan":
                        is_admin = True
                conn.close()
            except Exception:
                pass

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        
        if is_admin:
            self.wfile.write(DASHBOARD_HTML.encode('utf-8'))
        else:
            connected_html = CONNECTED_HTML.replace("{name}", user_name).replace("{floor}", user_floor)
            self.wfile.write(connected_html.encode('utf-8'))


    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        
        # Check for device tracking cookie to automatically update IP/MAC mapping
        uuid = self.get_device_uuid_from_cookie()
        if uuid:
            update_device_mapping(self.client_address[0], uuid)

        if parsed_url.path == "/api/devices/approve_lowend":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            err = ""
            try:
                payload = json.loads(body)
                req_id = payload.get("id")
                label = payload.get("label", "Low-End Device").strip()
                floor = payload.get("floor", "").strip()
                device_type = payload.get("device_type", "low-end").strip()
                
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                
                # Fetch request info
                cursor.execute("SELECT ip_address, mac_address, device_name FROM lowend_requests WHERE id = ?", (req_id,))
                req = cursor.fetchone()
                if req:
                    ip, mac, orig_name = req
                    mac = mac.lower().strip() if mac else ""
                    
                    # 1. Get or create user
                    cursor.execute("SELECT id FROM users WHERE username = ?", (label,))
                    u_row = cursor.fetchone()
                    if u_row:
                        user_id = u_row[0]
                    else:
                        cursor.execute("INSERT INTO users (username, daily_limit_mb) VALUES (?, 2048)", (label, ))
                        user_id = cursor.lastrowid
                        
                    # 2. Check if MAC already exists in device_macs
                    device_id = None
                    if mac:
                        cursor.execute("SELECT device_id FROM device_macs WHERE mac_address = ?", (mac,))
                        d_row = cursor.fetchone()
                        if d_row:
                            device_id = d_row[0]
                    
                    if device_id:
                        cursor.execute("""
                        UPDATE devices 
                        SET user_id = ?, floor = ?, device_type = ?, is_low_end = 1, approved = 1
                        WHERE id = ?
                        """, (user_id, floor, device_type, device_id))
                    else:
                        cursor.execute("""
                        INSERT INTO devices (user_id, device_name, floor, device_type, is_low_end, approved)
                        VALUES (?, ?, ?, ?, 1, 1)
                        """, (user_id, orig_name or f"{label} Low-End Device", floor, device_type))
                        device_id = cursor.lastrowid
                        
                    # 3. Bind MAC
                    if mac:
                        cursor.execute("INSERT OR REPLACE INTO device_macs (mac_address, device_id) VALUES (?, ?)", (mac, device_id))
                    
                    # 4. Bind IP
                    if ip:
                        cursor.execute("INSERT OR REPLACE INTO device_ips (ip_address, device_id, mac_address) VALUES (?, ?, ?)", (ip, device_id, mac or None))
                        
                    # 5. Update request status
                    cursor.execute("UPDATE lowend_requests SET status = 'approved' WHERE id = ?", (req_id,))
                    conn.commit()
                    ok = True
                else:
                    err = "Request not found"
                conn.close()
            except Exception as exc:
                print(f"[web] POST /api/devices/approve_lowend error: {exc}", file=sys.stderr)
                err = str(exc)
            
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok, "error": err}).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices/reject_lowend":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            try:
                payload = json.loads(body)
                req_id = payload.get("id")
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM lowend_requests WHERE id = ?", (req_id,))
                conn.commit()
                conn.close()
                ok = True
            except Exception as exc:
                print(f"[web] POST /api/devices/reject_lowend error: {exc}", file=sys.stderr)
            
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices/register":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            err_msg = ""
            try:
                payload = json.loads(body)
                password = payload.get("password", "")
                label = payload.get("label", "").strip()
                
                # '12345G' for Ghassan, '123' for everyone else
                expected_password = "12345G" if label.lower() == "ghassan" else "123"
                
                if password != expected_password:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"ok": False, "error": "Invalid network access password"}).encode('utf-8'))
                    return
                
                client_ip = self.client_address[0]
                actual_mac = None
                try:
                    with open("/proc/net/arp", "r") as f:
                        for line in f.readlines()[1:]:
                            parts = line.split()
                            if len(parts) >= 4 and parts[0] == client_ip:
                                found_mac = parts[3].lower().strip()
                                if found_mac and found_mac != "00:00:00:00:00:00":
                                    actual_mac = found_mac
                                break
                except Exception:
                    pass

                device_uuid = payload.get("uuid", "")
                if actual_mac and not is_mac_shared(actual_mac):
                    device_uuid = actual_mac
                
                label = payload.get("label", "")
                floor = payload.get("floor", "")
                device_type = payload.get("device_type", "")
                
                # Check if device is blocked
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM blocked_devices WHERE mac_address = ?;", (device_uuid,))
                is_blocked = cursor.fetchone() is not None
                conn.close()
                
                if is_blocked:
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"ok": False, "error": "هذا الجهاز محظور من الشبكة ولا يمكنه التسجيل."}).encode('utf-8'))
                    return
                
                if device_uuid and label:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    
                    # 1. Get or create user
                    cursor.execute("SELECT id FROM users WHERE username = ?", (label.strip(),))
                    u_row = cursor.fetchone()
                    if u_row:
                        user_id = u_row[0]
                    else:
                        cursor.execute("INSERT INTO users (username, daily_limit_mb) VALUES (?, 2048)", (label.strip(),))
                        user_id = cursor.lastrowid
                        
                    # 2. Check if MAC already exists
                    cursor.execute("SELECT device_id FROM device_macs WHERE mac_address = ?", (device_uuid.lower().strip(),))
                    d_row = cursor.fetchone()
                    if d_row:
                        device_id = d_row[0]
                        cursor.execute("""
                        UPDATE devices 
                        SET user_id = ?, floor = ?, device_type = ?, approved = 1
                        WHERE id = ?
                        """, (user_id, floor or "", device_type or "", device_id))
                    else:
                        cursor.execute("""
                        INSERT INTO devices (user_id, device_name, floor, device_type, approved)
                        VALUES (?, ?, ?, ?, 1)
                        """, (user_id, f"{label} Device", floor or "", device_type or ""))
                        device_id = cursor.lastrowid
                        
                    # 3. Save MAC and IP
                    cursor.execute("INSERT OR REPLACE INTO device_macs (mac_address, device_id) VALUES (?, ?)", (device_uuid.lower().strip(), device_id))
                    cursor.execute("INSERT OR REPLACE INTO device_ips (ip_address, device_id, mac_address) VALUES (?, ?, ?)", (self.client_address[0], device_id, device_uuid.lower().strip()))
                    
                    conn.commit()
                    conn.close()
                    
                    update_device_mapping(self.client_address[0], device_uuid)
                    ok = True
                else:
                    err_msg = "Missing required fields"
            except Exception as exc:
                print(f"[web] POST /api/devices/register error: {exc}", file=sys.stderr)
                err_msg = str(exc)
            
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "application/json")
            if ok:
                # Set long-lived cookie (10 years)
                self.send_header("Set-Cookie", f"nettrack_device_uuid={device_uuid}; Path=/; Max-Age=315360000; SameSite=Lax")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok, "error": err_msg}).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices/block":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            try:
                payload = json.loads(body)
                mac = payload.get("mac", "")
                ip = payload.get("ip", "")
                reason = payload.get("reason", "محظور بواسطة مسؤول النظام")
                
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                if not mac and ip:
                    cursor.execute("SELECT mac_address FROM device_labels WHERE ip_address = ? LIMIT 1;", (ip,))
                    row = cursor.fetchone()
                    if row:
                        mac = row[0]
                
                if mac:
                    # 1. Add to blocked_devices
                    cursor.execute("""
                    INSERT OR REPLACE INTO blocked_devices (mac_address, reason, blocked_at)
                    VALUES (?, ?, datetime('now', 'localtime'));
                    """, (mac, reason))
                    
                    # 2. Get device_id for this MAC
                    cursor.execute("SELECT device_id FROM device_macs WHERE mac_address = ?", (mac,))
                    row = cursor.fetchone()
                    if row:
                        device_id = row[0]
                        cursor.execute("DELETE FROM device_macs WHERE device_id = ?", (device_id,))
                        cursor.execute("DELETE FROM device_ips WHERE device_id = ?", (device_id,))
                        cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
                    
                    if ip:
                        cursor.execute("DELETE FROM device_ips WHERE ip_address = ?", (ip,))
                        
                    conn.commit()
                    ok = True

                conn.close()
                self.send_response(200 if ok else 400)
            except Exception as exc:
                print(f"[web] POST /api/devices/block error: {exc}", file=sys.stderr)
                self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices/unblock":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            try:
                payload = json.loads(body)
                mac = payload.get("mac", "")
                if mac:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM blocked_devices WHERE mac_address = ?;", (mac,))
                    conn.commit()
                    conn.close()
                    ok = True
                self.send_response(200 if ok else 400)
            except Exception as exc:
                print(f"[web] POST /api/devices/unblock error: {exc}", file=sys.stderr)
                self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices/label":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            try:
                payload = json.loads(body)
                ok = set_device_label(
                    ip             = payload.get("ip", ""),
                    mac            = payload.get("mac", ""),
                    label          = payload.get("label", ""),
                    floor          = payload.get("floor", ""),
                    device_type    = payload.get("device_type", ""),
                    daily_limit_mb = payload.get("daily_limit_mb"),
                )
                self.send_response(200 if ok else 500)
            except Exception as exc:
                print(f"[web] POST /api/devices/label error: {exc}", file=sys.stderr)
                self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices/disassociate":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            try:
                payload = json.loads(body)
                mac = payload.get("mac", "")
                ip = payload.get("ip", "")
                
                device_id = None
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                if mac:
                    cursor.execute("SELECT device_id FROM device_macs WHERE mac_address = ?", (mac.lower().strip(),))
                    row = cursor.fetchone()
                    if row:
                        device_id = row[0]
                if not device_id and ip:
                    cursor.execute("SELECT device_id FROM device_ips WHERE ip_address = ?", (ip.strip(),))
                    row = cursor.fetchone()
                    if row:
                        device_id = row[0]
                        
                if device_id:
                    cursor.execute("""
                    UPDATE devices 
                    SET user_id = NULL, approved = 0, device_name = 'Discovered Device'
                    WHERE id = ?
                    """, (device_id,))
                    conn.commit()
                    ok = True
                conn.close()
                self.send_response(200 if ok else 400)
            except Exception as exc:
                print(f"[web] POST /api/devices/disassociate error: {exc}", file=sys.stderr)
                self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode('utf-8'))
            return

        if parsed_url.path == "/api/devices/unregister":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            try:
                payload = json.loads(body)
                mac = payload.get("mac", "")
                ip = payload.get("ip", "")
                if mac or ip:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    
                    # 1. Find the label associated with the MAC/IP
                    label = ""
                    if mac:
                        cursor.execute("SELECT label FROM device_labels WHERE mac_address = ?", (mac,))
                    elif ip:
                        cursor.execute("SELECT label FROM device_labels WHERE ip_address = ?", (ip,))
                    row = cursor.fetchone()
                    if row:
                        label = row[0]
                        
                    # 2. Delete devices/users/IPs
                    if label:
                        cursor.execute("SELECT id FROM users WHERE username = ?", (label,))
                        u_row = cursor.fetchone()
                        if u_row:
                            user_id = u_row[0]
                            cursor.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))
                    if mac:
                        cursor.execute("SELECT device_id FROM device_macs WHERE mac_address = ?", (mac,))
                        d_row = cursor.fetchone()
                        if d_row:
                            cursor.execute("DELETE FROM devices WHERE id = ?", (d_row[0],))
                        cursor.execute("DELETE FROM device_macs WHERE mac_address = ?", (mac,))
                        cursor.execute("DELETE FROM device_ips WHERE mac_address = ?", (mac,))
                    if ip:
                        cursor.execute("DELETE FROM device_ips WHERE ip_address = ?", (ip,))
                        
                    conn.commit()
                    conn.close()
                    ok = True
                self.send_response(200 if ok else 400)
            except Exception as exc:
                print(f"[web] POST /api/devices/unregister error: {exc}", file=sys.stderr)
                self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode('utf-8'))
            return

        if parsed_url.path == "/api/vault/login":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            err_msg = ""
            try:
                payload = json.loads(body)
                password = payload.get("password", "")
                if password == "12345":
                    ok = True
                else:
                    err_msg = "رمز المرور غير صحيح"
            except Exception as exc:
                err_msg = str(exc)
            
            self.send_response(200 if ok else 401)
            self.send_header("Content-Type", "application/json")
            if ok:
                # Set session cookie for 1 hour
                self.send_header("Set-Cookie", "nettrack_vault_session=authenticated; Path=/; Max-Age=3600; SameSite=Lax")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok, "error": err_msg}).encode('utf-8'))
            return

        if parsed_url.path == "/api/vault/blacklist/add":
            if not self.is_vault_authenticated():
                self.send_response(401)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            try:
                payload = json.loads(body)
                domain = payload.get("domain", "").strip().lower()
                if domain:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("INSERT OR IGNORE INTO dns_blacklist (domain) VALUES (?)", (domain,))
                    conn.commit()
                    conn.close()
                    ok = True
                self.send_response(200 if ok else 400)
            except Exception as exc:
                print(f"[web] POST /api/vault/blacklist/add error: {exc}", file=sys.stderr)
                self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode('utf-8'))
            return

        if parsed_url.path == "/api/vault/blacklist/remove":
            if not self.is_vault_authenticated():
                self.send_response(401)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode('utf-8')
            ok = False
            try:
                payload = json.loads(body)
                domain = payload.get("domain", "").strip().lower()
                if domain:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM dns_blacklist WHERE domain = ?", (domain,))
                    conn.commit()
                    conn.close()
                    ok = True
                self.send_response(200 if ok else 400)
            except Exception as exc:
                print(f"[web] POST /api/vault/blacklist/remove error: {exc}", file=sys.stderr)
                self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode('utf-8'))
            return

        self.send_response(404)
        self.end_headers()


def run_web_server(port):
    server_address = ('', port)
    try:
        httpd = ThreadingHTTPServer(server_address, WebDashboardHandler)
        print(f"============================================================")
        print(f"   NetTrack Web Dashboard running at http://localhost:{port}")
        print(f"   Access it from your local network via your server's IP.")
        print(f"   Press Ctrl+C to stop.")
        print(f"============================================================")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb server stopped.")
    except Exception as e:
        print(f"Error starting web server: {e}", file=sys.stderr)

def run_live_dashboard(initial_period):
    check_db()
    
    current_period = initial_period
    
    import select
    import tty
    import termios
    import time
    
    class RawTerminal:
        def __enter__(self):
            self.enabled = False
            try:
                self.old_settings = termios.tcgetattr(sys.stdin)
                tty.setcbreak(sys.stdin.fileno())
                # Switch to alternate screen buffer and hide cursor
                sys.stdout.write("\033[?1049h\033[?25l")
                sys.stdout.flush()
                self.enabled = True
            except termios.error:
                pass
            return self

        def __exit__(self, type, value, traceback):
            if self.enabled:
                # Switch back to normal screen buffer and show cursor
                sys.stdout.write("\033[?1049l\033[?25h")
                sys.stdout.flush()
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)

    try:
        last_cols, last_lines = None, None
        with RawTerminal():
            while True:
                cols, lines = get_term_size()
                if last_cols is None or (cols, lines) != (last_cols, last_lines):
                    sys.stdout.write("\033[2J\033[H")
                    sys.stdout.flush()
                    last_cols, last_lines = cols, lines
                else:
                    sys.stdout.write("\033[H")
                    sys.stdout.flush()
                
                # Fetch stats
                if current_period == "week":
                    sent, recv, programs, trend, label = get_week()
                elif current_period == "month":
                    sent, recv, programs, trend, label = get_month()
                else:
                    sent, recv, programs, trend, label = get_today()
                
                # Print dashboard
                print_dashboard(sent, recv, programs, trend, label, is_live=True)
                
                # Print footer/controls
                now_str = datetime.datetime.now().strftime("%H:%M:%S")
                print(f" Last Updated: {now_str} | Controls: [d/1] Today  [w/2] Week  [m/3] Month  [r] Refresh  [q] Quit")
                
                # Clear remainder of screen to remove any ghost characters
                sys.stdout.write("\033[J")
                sys.stdout.flush()
                
                # Wait for input (2 seconds timeout)
                try:
                    rlist, _, _ = select.select([sys.stdin], [], [], 2.0)
                except (InterruptedError, OSError):
                    # Handle window resize or signal interrupt
                    continue
                
                if rlist:
                    key = sys.stdin.read(1)
                    if not key:
                        # EOF on stdin (e.g. redirected input ended)
                        # Sleep to prevent high CPU usage, then check again
                        time.sleep(2.0)
                        continue
                    if key.lower() == 'q':
                        break
                    elif key in ('1', 'd', 'D'):
                        current_period = "today"
                    elif key in ('2', 'w', 'W'):
                        current_period = "week"
                    elif key in ('3', 'm', 'M'):
                        current_period = "month"
                    elif key in ('r', 'R'):
                        pass # Loop will update immediately
    except KeyboardInterrupt:
        pass

# --- Main CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetTrack - CLI Network History Monitor")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--today", action="store_true", help="Show statistics for today (default)")
    group.add_argument("-w", "--week", action="store_true", help="Show statistics for the last 7 days")
    group.add_argument("-m", "--month", action="store_true", help="Show statistics for the last 30 days")
    group.add_argument("--web", type=int, nargs='?', const=6054, help="Run local web server dashboard. Specify optional port (default: 6054)")
    
    parser.add_argument("-l", "--live", action="store_true", help="Stay active and update stats in real-time (default in interactive terminal)")
    parser.add_argument("-o", "--once", action="store_true", help="Display stats once and exit (default when output is piped/redirected)")
    
    args = parser.parse_args()
    
    if args.web is not None:
        run_web_server(args.web)
        sys.exit(0)
        
    check_db()
    
    if args.week:
        initial_period = "week"
    elif args.month:
        initial_period = "month"
    else:
        initial_period = "today"
        
    # Determine if we should run in live mode
    is_live = False
    if args.live:
        is_live = True
    elif args.once:
        is_live = False
    else:
        # Default to live mode if both stdin and stdout are interactive TTYs
        is_live = sys.stdout.isatty() and sys.stdin.isatty()
        
    if is_live:
        run_live_dashboard(initial_period)
    else:
        if initial_period == "week":
            sent, recv, programs, trend, label = get_week()
        elif initial_period == "month":
            sent, recv, programs, trend, label = get_month()
        else:
            sent, recv, programs, trend, label = get_today()
        print_dashboard(sent, recv, programs, trend, label)

