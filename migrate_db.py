#!/usr/bin/env python3
import os
import sys
import shutil
import sqlite3
import datetime

DB_PATH = "/var/lib/nettrack/nettrack.db"

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"Database {DB_PATH} not found. Nothing to migrate.")
        return

    # Backup the database first
    backup_path = f"{DB_PATH}.backup.{int(datetime.datetime.now().timestamp())}"
    print(f"Backing up database to {backup_path}...")
    try:
        shutil.copy2(DB_PATH, backup_path)
    except Exception as e:
        print(f"Failed to create backup: {e}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Check if already migrated
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if cursor.fetchone():
            print("Database already migrated or 'users' table exists. Skipping migration.")
            conn.close()
            return

        print("Starting database migration...")

        # 1. Create temporary backups of the old tables/views
        # Since they might be tables, let's rename them if they exist
        for table in ["registered_devices", "device_labels", "user_limits"]:
            cursor.execute(f"SELECT type FROM sqlite_master WHERE name='{table}';")
            res = cursor.fetchone()
            if res:
                obj_type = res[0]
                if obj_type == "table":
                    print(f"Renaming old table {table} to old_{table}...")
                    cursor.execute(f"ALTER TABLE {table} RENAME TO old_{table};")
                elif obj_type == "view":
                    print(f"Dropping old view {table}...")
                    cursor.execute(f"DROP VIEW {table};")

        # 2. Create the new normalized tables
        print("Creating new tables...")
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

        # 3. Migrate data from old tables if they exist
        users_to_add = {} # username -> limit

        # Read old_user_limits
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='old_user_limits';")
        if cursor.fetchone():
            cursor.execute("SELECT label, daily_limit_mb FROM old_user_limits;")
            for label, limit in cursor.fetchall():
                if label and label.strip():
                    users_to_add[label.strip()] = limit

        # Read old_registered_devices
        registered_devices_data = []
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='old_registered_devices';")
        if cursor.fetchone():
            cursor.execute("SELECT device_uuid, label, floor, device_type FROM old_registered_devices;")
            registered_devices_data = cursor.fetchall()
            for row in registered_devices_data:
                label = row[1]
                if label and label.strip() and label.strip() not in users_to_add:
                    users_to_add[label.strip()] = 2048

        # Read old_device_labels
        device_labels_data = []
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='old_device_labels';")
        if cursor.fetchone():
            cursor.execute("SELECT ip_address, mac_address, label, floor, device_type FROM old_device_labels;")
            device_labels_data = cursor.fetchall()
            for row in device_labels_data:
                label = row[2]
                if label and label.strip() and label.strip() not in users_to_add:
                    users_to_add[label.strip()] = 2048

        # Insert users
        for username, limit in users_to_add.items():
            cursor.execute("INSERT OR IGNORE INTO users (username, daily_limit_mb) VALUES (?, ?);", (username, limit))

        # Migrate registered devices
        bound_macs = set()
        for cookie_uuid, label, floor, device_type in registered_devices_data:
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

        # Migrate device labels and map IPs
        for ip, mac, label, floor, device_type in device_labels_data:
            ip = ip.strip() if ip else ""
            mac = mac.lower().strip() if mac else ""
            label = label.strip() if label else ""
            if not ip:
                continue

            if mac and mac in bound_macs:
                continue

            device_id = None
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

        # 4. Create the compatible views
        print("Creating backwards-compatible views...")
        
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

        # Clean up old tables
        cursor.execute("DROP TABLE IF EXISTS old_registered_devices;")
        cursor.execute("DROP TABLE IF EXISTS old_device_labels;")
        cursor.execute("DROP TABLE IF EXISTS old_user_limits;")

        conn.commit()
        print("Migration completed successfully!")

    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
        sys.exit(1)
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
