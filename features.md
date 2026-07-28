# NetTrack Features and Custom Configuration Settings

## Monthly Billing Cycle Shift
- **Change:** Rollover and aggregate traffic tracking start date shifted from the 1st of the month to the **28th day** of each month, tracking usage from the 28th to the 27th.
- **Benefit:** Direct alignment with ISP billing cycles, eliminating manual data offsets.

## Process Traffic Tracking for Commands with Spaces
- **Change:** Overhauled traffic parser logic to correctly map programs with spaces or multiple flags (e.g. Google Chrome, Stremio, YouTube app).
- **Benefit:** Allows correct per-application network utilization statistics.

## Warning Captive Page Bypass (80% Limit)
- **Change:** Blocks internet and redirects device to a custom warning page when usage reaches 80%. Users can click a bypass button which authorizes internet access for 24 hours.
- **Benefit:** Notifies users of high usage beforehand without abrupt interruptions.

## Global ISP Bucket Allocation Tracker & Over-Allocation Warnings
- **Change:** Integrated a global shared bandwidth limit tracker. Warns the administrator on the dashboard if user monthly limit configuration totals exceed the pool size.
- **Benefit:** Prevents total network monthly overallocation.

## Dynamic Heuristic Suggested Quotas
- **Change:** Computes average daily usage over the past 7 days and recommends daily (1.5x average) and monthly (30x daily recommendation) limits.
- **Benefit:** Informs administrators of optimized, realistic limits for each user.

## Global Pool Bandwidth Redistribution
- **Change:** If user allocations exceed the Global ISP Pool, the system dynamically recalculates default group limits. Custom user limits are kept, and the remaining pool is relatively distributed to the default users.
- **Benefit:** Automatically satisfies pool limits at runtime during overallocation.

## Asynchronous AJAX Dashboard Updates
- **Change:** Dashboard forms and API button actions execute asynchronously via fetch requests. Toast alerts notify the admin, and cards update via DOMParser swaps without reloading the page.
- **Benefit:** Increases page load speed and improves user experience by preserving UI states.

## Collapsible User Device Table Rows
- **Change:** Clicking user headings in the device list table collapses/expands the associated client device list.
- **Benefit:** Keeps the device overview screen structured and readable on large deployments.

## Customizable Log Storage Settings & Self-Healing Backups
- **Change:** Configurable vault database location via Web Dashboard settings with automatic service restarts. Implemented a 3-day SQLite backup loop that probes candidate folders (`/logs`, `/mnt/sdc1`, `/mnt/sda6`, `/mnt/sda5`) by writing temporary files to choose the first writeable drive. Added drive space monitor that disables capping unless free space drops below 10%.
- **Benefit:** Allows storing massive logs on secondary drives safely without risk of root drive partition exhaustion or write failures on locked drives.

## Manual Logs Migration (Move to HDD)
- **Change:** A dedicated action button on the Web Settings panel allows transferring active `vault.db` to the first writable secondary HDD partition transaction-safely, updating active settings, purging the database from the SSD, and restarting NetTrack.
- **Benefit:** Instantly frees up SSD disk space on demand while preserving connection histories.

## Dashboard Usage Alert Badge
- **Change:** Added visual inline badges next to the username on the dashboard indicating usage against monthly limits (⚠️ amber for ≥75% and 🔴 pulsing red for ≥100%).
- **Benefit:** Gives the administrator immediate visual cues about which users are approaching or exceeding their bandwidth caps.

## Safe Static Lease Generation
- **Change:** DHCP static lease writer now validates MAC addresses, deduplicates hostnames, and pre-tests configurations with `dnsmasq --test` before committing.
- **Benefit:** Prevents `dnsmasq` from crashing due to invalid input or duplicate entries, ensuring network reliability.

## Multi-threaded Web Server & Memory Watchdogs
- **Change:** Upgraded the captive portal and web dashboard to use `ThreadingHTTPServer` and injected memory watchdog threads in both the web and device daemon services (restarts cleanly at 400MB threshold).
- **Benefit:** Prevents single-request blocking and out-of-memory (OOM) fatal crashes during long runtimes.
