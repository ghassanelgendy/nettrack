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
