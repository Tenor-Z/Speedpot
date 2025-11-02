# Speedpot - Intelligent Honeypot for Network Security

<div align="center">

![Speedpot Logo](speedpot.ico)

**A comprehensive, intelligent honeypot designed to detect, analyze, and block cyber attacks in real-time.**

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing) • [License](#license)

</div>

## Overview

Speedpot is a full-stack honeypot application that emulates vulnerable services and intelligently detects advanced cyber attacks including port scans, SQL injection, cross-site scripting (XSS), command injection, path traversal, and more. Built with Python and Tkinter, Speedpot provides real-time monitoring, threat intelligence, and automated blocking capabilities.

Whether you're a security researcher, network administrator, or cybersecurity enthusiast, Speedpot helps you understand attack patterns and strengthen your network defenses.

## Features

### Attack Detection
- **Port Scan Detection** - Identifies common port scanning patterns with threat classification
- **SQL Injection Detection** - Detects SQL injection attempts with context-aware analysis
- **XSS Attack Detection** - Identifies cross-site scripting payloads
- **Command Injection Detection** - Catches OS command injection attempts
- **Path Traversal Detection** - Detects directory traversal attacks
- **RCE Detection** - Identifies remote code execution attempts
- **Malicious Scanner Detection** - Recognizes vulnerability scanners (sqlmap, nikto, nmap, etc.)

### Intelligent Protection
- **Auto-Blocking System** - Automatically blocks critical threats
- **Severity Classification** - Categorizes attacks by threat level (Critical, High, Medium, Low)
- **IP Reputation Tracking** - Maintains blocklist with duration and reason
- **Context-Aware Analysis** - Reduces false positives from legitimate security scanning

### Comprehensive Monitoring
- **Real-Time Dashboard** - Live threat monitoring with service status
- **Attack Analytics** - Detailed statistics on attack types, severity, and patterns
- **Connection Tracking** - Per-service connection counting and statistics
- **Network Intelligence** - Geographic and threat-level-based insights
- **Web Dashboard** - Optional Streamlit-based web interface for remote monitoring

### Service Emulation
- **FTP (Port 21)** - File Transfer Protocol emulation
- **SSH (Port 22)** - Secure Shell emulation
- **Telnet (Port 23)** - Telnet protocol emulation
- **SMTP (Port 25)** - Email service emulation
- **HTTP (Port 80)** - Web server emulation
- **HTTPS (Port 443)** - Secure web server emulation
- **RDP (Port 3389)** - Remote Desktop Protocol emulation
- **HTTP Alternate (Port 8080)** - Alternative web server emulation

### Advanced Options
- **Log Retention** - Automatic log archiving and cleanup
- **Log File Size Limits** - Automatic honeypot stopping when logs exceed size limits
- **Scheduled Scans** - Automatic honeypot startup at specified times
- **Debug Mode** - Detailed logging for troubleshooting
- **Configuration Management** - Easy configuration through GUI

### Database & Reporting
- **SQLite Database** - Persistent storage of all attacks and connections
- **Detailed Attack Records** - Full payload capture and analysis
- **Export Capabilities** - Export data for external analysis
- **Statistics & Trends** - Visualize attack patterns over time

## System Requirements

- **OS**: Windows 7 or later (may work on Linux/macOS with modifications)
- **Python**: 3.8 or higher
- **RAM**: 30 MB minimum
- **Disk Space**: 100 MB for installation + space for logs/database

## Installation

### Option 1: Direct Download & Run

1. **Download Speedpot**
```bash
git clone https://github.com/Tenor-Z/speedpot.git
cd speedpot
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Run Speedpot**
```bash
python main.py
```

### Option 2: Windows Executable (Coming Soon)

Pre-compiled `.exe` will be available for download without requiring Python installation.

### Option 3: Docker (Experimental)

```bash
docker build -t speedpot .
docker run -p 21:21 -p 22:22 -p 23:23 -p 25:25 -p 80:80 -p 443:443 -p 3389:3389 -p 8080:8080 speedpot
```

## Quick Start

### Basic Usage

1. **Launch Speedpot**
```bash
python main.py
```

2. **Select Network Interface**
   - Choose to bind to all interfaces (0.0.0.0) or localhost (127.0.0.1)
   - Localhost is recommended for testing on the same machine

3. **Start the Honeypot**
   - Click "Start Honeypot" button on the Dashboard tab
   - Monitor incoming attacks on the Recent Attacks tab

4. **Analyze Threats**
   - View detected attacks in the "View Detected Attacks" window
   - Check attack statistics on the Analytics tab
   - Review blocked IPs in the IP Management section

### Testing the Honeypot

#### Simulate SQL Injection Attack
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:80/?id=1' OR '1'='1" -ErrorAction SilentlyContinue

