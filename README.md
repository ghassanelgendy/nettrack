# NetTrack

NetTrack is a network gateway bandwidth monitoring, process traffic tracking, and captive portal administration system. It runs directly on a local gateway Linux server to monitor process executions, trace packet logs, and manage individual client device internet access and quotas.

---

## Prerequisites & System Requirements

Before running NetTrack, make sure your server meets the following requirements:

### 1. Operating System
* **Ubuntu** (20.04 LTS or newer recommended) or **Debian** (10 or newer)
* Root (`sudo`) privileges are required for setup, capturing network traffic, and altering firewall rule sets.

### 2. System Packages & Dependencies
NetTrack relies on standard Linux networking tools to trace processes, inspect traffic, and manage the portal firewall. Install these on your host server:

```bash
sudo apt-get update
sudo apt-get install -y tcpdump nethogs iptables python3 sqlite3
```

* **`tcpdump`**: Used by the device sniffer (`nettrack-device.service`) to passively capture IP traffic and log bandwidth statistics per device MAC/IP.
* **`nethogs`**: Used by the process monitor daemon (`nettrack.service`) to parse active bandwidth usage per Linux process.
* **`iptables`**: Managed by the portal firewall daemon (`nettrack-portal.service`) to redirect unauthorized clients to the captive portal and dynamically enforce user daily/monthly bandwidth limits.
* **`dnsmasq`**: Automatically installed and configured by the setup script to act as the network's central DHCP server.

### 3. Network Configuration
* NetTrack must be installed directly on your **network gateway server** (acting as the router/NAT gateway between the local LAN and the WAN/Internet).
* The gateway server's IP address must be set to `192.168.1.100` (or configured inside `nettrack_portal.py` and `setup_gateway.sh` to match your layout).
* Client devices on the local LAN should obtain their IP addresses automatically from the DHCP server (IP range: `192.168.1.101` to `192.168.1.250`).

---

## Features

- **User-Centric Grouping:** Groups authorized network devices by owner. The dashboard dynamically sorts users and devices by aggregate network usage.
- **Process Bandwidth Monitoring:** Tracks traffic metrics for active processes. Accurately handles complex commands and paths (such as Chrome helper processes and flatpaks).
- **80% Quota Warnings:** Displays a captive warning page once a device consumes 80% of its quota. Users can acknowledge and bypass the warning to continue surfing until they reach 100%.
- **Custom Billing Cycles:** Monthly quotas and usage statistics roll over on the 28th of each month (billing cycle runs from the 28th to the 27th).
- **Global ISP Pool Allocations:** Monitors global shared bandwidth distribution. Tracks remaining pool bytes and alerts the administrator of over-allocated user configurations.
- **Usage Heuristics:** Recommends optimal daily and monthly quotas calculated directly from past usage patterns.
- **Mobile Responsive Dashboard:** The admin dashboard and client portal pages are fully responsive on mobile devices and screen widths.

---

## Getting Started & Installation

### Step 1: Run the Gateway Setup Installer
Configure your primary network interface name (the script auto-detects this, defaulting to `eno1` if not found) and execute the installer with root privileges:

```bash
sudo ./setup_gateway.sh
```

This installer script does the following:
1. Installs and configures `dnsmasq` as a central DHCP server on your network interface.
2. Configures packet forwarding (`net.ipv4.ip_forward=1`) and IP masquerading (NAT translation via `iptables`) to turn the server into a router.
3. Deploys and starts **five systemd service daemons**:
   - `nettrack-gateway.service`: Applies NAT masquerading and gateway rules at boot.
   - `nettrack-portal.service`: Regulates captive portal redirections and updates allowed client list based on database quota updates.
   - `nettrack-web.service`: Serves the admin portal and client portal website on port `6054`.
   - `nettrack-device.service`: Runs the background device packet sniffer (`tcpdump`) to track MAC address traffic.
   - `nettrack.service`: Parses active host process bandwidth statistics (`nethogs`).
4. Initializes the local SQLite database.

### Step 2: Access the Admin Dashboard
Once setup is complete, open your web browser and navigate to:
```
http://192.168.1.100:6054/
```
*(If accessing locally from the gateway server, you can use `http://localhost:6054/`)*

* **Default Admin Credentials:**
  - **Username:** `Admin`
  - **Password:** `1234G`

### Step 3: Register and Manage Devices
* **Administrators:** Use the dashboard to define package groups (Standard, Heavy, Custom), configure global ISP bucket pools, allocate limits to users, add billing addons, rename/de-authorize devices, and inspect real-time connection packet logs.
* **Client Devices:** When connecting to the network for the first time, clients will be redirected to the Portal Authentication page when attempting to access the internet. Once they authenticate with their username and password, their device MAC address is associated with their user profile, and internet access is dynamically granted.

---

## Services Reference

The system operates as five unified systemd daemons:
* `nettrack-gateway.service`: Sets up IP forwarding and POSTROUTING NAT rules.
* `nettrack-portal.service`: Syncs allowed IPs and manages iptables warning skips.
* `nettrack-web.service`: Serves the admin panel and client/limited warning portal.
* `nettrack-device.service`: Captures real-time packets using `tcpdump` and updates `device_usage` tables.
* `nettrack.service`: Monitors process traffic on the host using `nethogs`.

Detailed system architecture and database schema information can be found in the [Technical Documentation](docs.md).

