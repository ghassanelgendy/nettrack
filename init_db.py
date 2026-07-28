#!/usr/bin/env python3
import os
import sqlite3

DB_DIR = "/var/lib/nettrack"
DB_PATH = os.path.join(DB_DIR, "nettrack.db")

def normalize_mac(mac):
    return mac.strip().lower().replace('-', ':')

def init_database():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # 1. Groups Table (Defines daily and monthly limits in bytes)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        daily_limit_bytes INTEGER DEFAULT 2147483648, -- Default 2 GB
        monthly_limit_bytes INTEGER DEFAULT 64424509440 -- Default 60 GB
    );
    """)
    
    # 2. Users Table (Stores user credentials and group associations)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        group_id INTEGER,
        FOREIGN KEY (group_id) REFERENCES user_groups(id) ON DELETE SET NULL
    );
    """)
    
    # 3. Registered Devices Table (Binds MAC address to a user)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS registered_devices (
        mac_address TEXT PRIMARY KEY,
        ip_address TEXT NOT NULL,
        username TEXT NOT NULL,
        device_name TEXT,
        last_seen TIMESTAMP,
        registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    );
    """)

    # 3.1. Quota Warning Bypasses (Bypasses the 80% warning limit)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS quota_bypasses (
        mac_address TEXT PRIMARY KEY,
        bypassed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3.2. User Addons (Purchased bandwidth additions)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_addons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        addon_bytes INTEGER NOT NULL,
        purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    );
    """)
    
    # Check and migrate columns dynamically if tables already existed
    try:
        cursor.execute("PRAGMA table_info(users);")
        columns = [row[1] for row in cursor.fetchall()]
        if columns:
            if 'password' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN password TEXT DEFAULT '';")
            if 'group_id' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN group_id INTEGER;")
            if 'daily_limit_bytes' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN daily_limit_bytes INTEGER DEFAULT NULL;")
            if 'monthly_limit_bytes' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN monthly_limit_bytes INTEGER DEFAULT NULL;")
            if 'suggested_daily_limit_bytes' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN suggested_daily_limit_bytes INTEGER DEFAULT NULL;")
            if 'suggested_monthly_limit_bytes' not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN suggested_monthly_limit_bytes INTEGER DEFAULT NULL;")
                
        cursor.execute("PRAGMA table_info(registered_devices);")
        rd_columns = [row[1] for row in cursor.fetchall()]
        if rd_columns and 'last_seen' not in rd_columns:
            cursor.execute("ALTER TABLE registered_devices ADD COLUMN last_seen TIMESTAMP;")
    except Exception as e:
        print(f"[db] Migration check warning: {e}")
    
    # Populate Default Groups
    cursor.execute("INSERT OR IGNORE INTO user_groups (name, daily_limit_bytes, monthly_limit_bytes) VALUES ('Standard', 5368709120, 107374182400);") # 5GB / 100GB
    cursor.execute("INSERT OR IGNORE INTO user_groups (name, daily_limit_bytes, monthly_limit_bytes) VALUES ('Heavy', 21474836480, 536870912000);") # 20GB / 500GB

    # 4. Settings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    """)
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('global_pool_bytes', '1073741824000');")
    
    # 4. Hourly Bandwidth Usage Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS hourly_usage (
        process_name TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        sent_bytes INTEGER DEFAULT 0,
        received_bytes INTEGER DEFAULT 0,
        PRIMARY KEY (process_name, timestamp)
    );
    """)
    
    # 4. Device Bandwidth Usage Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS device_usage (
        mac_address TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        sent_bytes INTEGER DEFAULT 0,
        received_bytes INTEGER DEFAULT 0,
        PRIMARY KEY (mac_address, timestamp)
    );
    """)
    
    # Create index for rapid lookup
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_usage_mac ON device_usage(mac_address);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_usage_ts ON device_usage(timestamp);")
    
    # Auto-register the NetTrack server itself
    try:
        # Detect primary route interface
        import subprocess
        res = subprocess.run("ip -o -4 route show default", shell=True, capture_output=True, text=True)
        parts = res.stdout.split()
        if "dev" in parts:
            iface = parts[parts.index("dev") + 1]
        else:
            iface = "eno1"
        with open(f"/sys/class/net/{iface}/address", "r") as f:
            server_mac = normalize_mac(f.read().strip())
        
        # Ensure default Admin user exists
        cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('Admin', '1234G');")
        # Ensure server device is registered
        cursor.execute("""
        INSERT OR IGNORE INTO registered_devices (mac_address, ip_address, username, device_name)
        VALUES (?, '192.168.1.100', 'Admin', 'NetTrack Server (Self)');
        """, (server_mac,))
    except Exception as e:
        print(f"[db] Server auto-registration warning: {e}")

    conn.commit()
    conn.close()
    
    # Initialize vault database as well
    try:
        vault_conn = sqlite3.connect(os.path.join(DB_DIR, "vault.db"))
        vault_cursor = vault_conn.cursor()
        vault_cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            src_mac TEXT,
            src_ip TEXT,
            dst_mac TEXT,
            dst_ip TEXT,
            bytes INTEGER
        );
        """)
        vault_conn.commit()
        vault_conn.close()
        print("[db] Vault database initialized successfully.")
    except Exception as e:
        print(f"[db] Error initializing vault database: {e}")
        
    print("[db] Database initialized successfully.")

if __name__ == "__main__":
    init_database()
