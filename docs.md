# NetTrack Technical Documentation

This file documents the features, database architecture, and network configurations implemented in NetTrack.

---

## 1. Core Features

### User-Grouped & Usage-Sorted Dashboard
The web dashboard groups all authorized network devices by their owners (users). 
- **Grouping:** Every device mapped to a user is displayed under that user's section.
- **Sorting:** Users are sorted in descending order based on their aggregate monthly usage. Devices within each user's section are also sorted by overall usage (upload + download) in descending order.
- **Total Metrics:** Each user section displays the sum of usage of all their devices.

### Robust Process Traffic Tracking
The bandwidth tracking daemon (`nettrack.service`) uses `nethogs` to capture per-process network traffic. The parser handles complex command-line executions (e.g., Google Chrome utility processes, Stremio flatpaks, and YouTube kiosk apps):
- It reconstructs commands with space-separated arguments.
- It isolates traffic statistics from the end of the data stream.
- It extracts actual process basenames (like `chrome` or `stremio`) even if the execution paths contain slashes or parameters.

### 80% Quota Warning & Bypass Page
- When a device hits 80% of its daily or monthly limit, the captive portal intercepts HTTP requests and displays a warning page.
- The page includes a "Skip Warning & Continue" button. Clicking this records a bypass entry in the database.
- The firewall daemon (`nettrack-portal.service`) syncs this state and unblocks the device's IP, allowing access up to 100% of their limit.
- If a device hits 100% of its limit, it is blocked completely with no bypass option.
- Warning bypasses expire and are auto-pruned after 24 hours.

### Billing Cycle Realignment (Starts on 28th)
Monthly quotas and consolidated group usage calculations do not follow calendar months. Instead, they align to a custom cycle starting on the **28th day** of each month.
- If today's date is $\ge 28$, the cycle starts on the 28th of the current month.
- If today's date is $< 28$, the cycle starts on the 28th of the previous month.

### Global ISP Bucket Pool
A global shared bandwidth pool represents the total ISP package limit:
- **Allocation Share:** The dashboard displays what percentage of the Global Pool is allocated to each user based on their monthly limits and addons.
- **Over-allocation Warning:** Calculates and warns the admin if the sum of distributed user quotas exceeds the Global Pool.
- **Remaining Pool Tracker:** Shows how much of the Global Pool remains for the current cycle based on real-time consumption.
- **Automatic Pool Redistribution:** If the sum of all monthly allocations exceeds the Global ISP Pool, the system dynamically recalculates default group limits. Users with custom limits (specific allocations) and addons keep their limits. The remaining pool space is redistributed relatively to the default group users based on their original group limits. Default users' monthly limits are marked as "(Redistributed)" on the dashboard and enforced at runtime.

### Dynamic Heuristic Suggestions
Instead of manual entries, suggested daily and monthly quotas are dynamically calculated from actual usage logs:
- Average daily usage is computed over the last 7 days of recorded data.
- **Suggested Daily:** Average daily usage * 1.5 (50% buffer).
- **Suggested Monthly:** Average daily usage * 30 * 1.5.
- These suggestions update dynamically on the dashboard to guide the administrator when adjusting quotas.

### Asynchronous AJAX Forms & Collapsible UI
To optimize admin workflows, the dashboard runs entirely asynchronously without full-page reloads:
- **AJAX Forms & Button Actions:** Intercepts form submissions and API button clicks (such as clearing dynamic leases, static reservations, or de-authorizing devices) and submits them via background `fetch` requests. Upon completion, a toast message is displayed and the relevant dashboard cards are dynamically updated using a DOMParser wrapper swap.
- **Collapsible User Sections:** Clicking on any user header row in the "Authorized Local Devices" table expands or collapses the list of devices belonging to that user. The collapsed state is persisted across dashboard updates.

### Dynamic Vault Storage & Probing Backups
To support massive logs (50+ GB) on secondary drives and prevent SSD wear on the root partition:
- **Custom Database Path:** Admin can dynamically configure the file path to `vault.db` from the Web Dashboard. Changing the path automatically restarts the backend daemons to apply the setting. Optionally, the `--vault-db` CLI parameter can be supplied to override settings.
- **Dynamic Drive Space Protection:** Capping (deletion of old log entries) is disabled by default to retain unlimited packet logs. Capping is only triggered as a safety measure (capping to the last 1,000,000 rows) if the drive containing `vault.db` has less than 10% free space remaining.
- **Self-Healing Writable Backup Probes:** A background thread executes every 3 days to back up the active `vault.db` transaction-safely. It probes candidate mount points (`/logs`, `/mnt/sdc1`, `/mnt/sda6`, `/mnt/sda5`) by performing temporary write tests, selecting the first writable location (preventing failures if a partition like `/mnt/sdc1` is locked in read-only mode).
- **Precise Packet Timestamps:** Instead of defaulting to insertion time during bulk database inserts (which caused all packets in a 5-second batch to share the exact same timestamp), the sniffer now captures the precise packet arrival time at reception and saves it directly to the vault.
- **Client-Side Timezone & 12-Hour formatting:** Raw database UTC timestamps are automatically converted to the browser's local timezone (using `Intl` detection) and rendered in a clean 12-hour AM/PM layout.
- **Manual Logs Migration (Move to HDD):** Allows migrating the active `vault.db` logs database from the SSD to a writeable secondary HDD mount dynamically, cleaning up the SSD space automatically and restarting all NetTrack services in place.

---

## 2. Database Schema

The SQLite database is located at `/var/lib/nettrack/nettrack.db`.

### `users`
Tracks registered users and custom limits.
- `username` (TEXT, PK)
- `password` (TEXT)
- `group_id` (INTEGER, FK to `user_groups`)
- `daily_limit_bytes` (INTEGER, Nullable custom limit)
- `monthly_limit_bytes` (INTEGER, Nullable custom limit)

### `user_groups`
Defines default package limits.
- `id` (INTEGER, PK Auto-increment)
- `name` (TEXT)
- `daily_limit_bytes` (INTEGER)
- `monthly_limit_bytes` (INTEGER)

### `registered_devices`
Binds hardware MAC addresses to users.
- `mac_address` (TEXT, PK)
- `ip_address` (TEXT)
- `username` (TEXT)
- `device_name` (TEXT)

### `quota_bypasses`
Records active 80% warning page skips.
- `mac_address` (TEXT, PK)
- `bypassed_at` (TIMESTAMP)

### `user_addons`
Records extra bandwidth additions purchased during the cycle.
- `id` (INTEGER, PK Auto-increment)
- `username` (TEXT)
- `addon_bytes` (INTEGER)
- `purchased_at` (TIMESTAMP)

### `settings`
Stores global configurations.
- `key` (TEXT, PK)
- `value` (TEXT)
