# NetTrack

NetTrack is a network gateway bandwidth monitoring, process traffic tracking, and captive portal administration system. It runs directly on the local gateway server to monitor process executions and manage individual client device internet access.

## Features

- **User-Centric Grouping:** Groups authorized network devices by owner. The dashboard dynamically sorts users and devices by aggregate network usage.
- **Process Bandwidth Monitoring:** Tracks traffic metrics for active processes. Accurately handles complex commands and paths (such as Chrome helper processes and flatpaks).
- **80% Quota Warnings:** Displays a captive warning page once a device consumes 80% of its quota. Users can acknowledge and bypass the warning to continue surfing until they reach 100%.
- **Custom Billing Cycles:** Monthly quotas and usage statistics roll over on the 28th of each month.
- **Global ISP Pool Allocations:** Monitors global shared bandwidth distribution. Tracks remaining pool bytes and alerts the administrator of over-allocated user configurations.
- **Usage Heuristics:** Recommends optimal daily and monthly quotas calculated directly from past usage patterns.

## Getting Started

### Installation
Configure the gateway interface settings and execute the installer:
```bash
sudo ./setup_gateway.sh
```

### Database
NetTrack uses SQLite to store configurations and metrics:
```bash
python3 init_db.py
```

### Services
The system operates as three systemd daemons:
- `nettrack.service`: Collects process bandwidth data.
- `nettrack-portal.service`: Manages captive portal iptables rules and limits.
- `nettrack-web.service`: Serves the admin panel and portal page on port 6054.

Detailed system architecture and database schema information can be found in the [Technical Documentation](docs.md).
