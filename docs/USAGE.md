# Speedpot Usage Guide

## Starting the Application

\`\`\`bash
python main.py
\`\`\`

On first run, select your network interface:
- **0.0.0.0** - Accepts connections from any IP (production)
- **127.0.0.1** - Localhost only (testing)

## Dashboard Tab

### Start/Stop Controls
- **Start Honeypot** - Activates all emulated services
- **Stop Honeypot** - Gracefully shuts down services

### Service Status
Shows real-time connection counts for each port:
- FTP (21)
- SSH (22)
- Telnet (23)
- SMTP (25)
- HTTP (80)
- HTTPS (443)
- RDP (3389)
- HTTP Alt (8080)

### IP Management
- **View Blocked IPs** - See currently blocked IP addresses
- **Auto-Block Settings** - Configure auto-blocking severity level

## Recent Attacks Tab

View detected attacks with:
- Source IP address
- Target port
- Attack type and severity
- Timestamp
- Payload captured

Color coding:
- 🔴 Critical
- 🟠 High
- 🟡 Medium
- 🟢 Low

## Analytics Tab

### Attack Distribution
- Chart of attack types detected
- Breakdown by severity level
- Timeline of attacks over time

### Service Statistics
- Connections per service
- Attack patterns by port
- Top attack sources

## Logs Tab

Real-time logging with:
- Auto-scroll capability
- Search functionality
- Log level filtering

## Options Menu

### Log Settings
- **Log Retention Days** - Auto-archive logs older than X days
- **Log File Size (MB)** - Max log file size before rotation

### Scan Schedule
- Set automatic honeypot startup time
- Useful for scheduled security testing

### Debug Mode
- Enable detailed logging
- Shows [INFO] level messages

## Testing Attacks

### Test 1: Port Scan
```powershell
nmap -p 1-1000 127.0.0.1
