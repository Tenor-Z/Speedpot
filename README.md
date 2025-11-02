# 🛡️ Speedpot - Intelligent Honeypot for Network Security

<div align="center">

![Speedpot Logo](speedpot.ico)

**A comprehensive, intelligent honeypot designed to detect, analyze, and block cyber attacks in real-time.**

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing) • [License](#license)

</div>

## Overview

Speedpot is an open-source, full-stack honeypot application that emulates vulnerable services and intelligently detects advanced cyber attacks including port scans, SQL injection, cross-site scripting (XSS), command injection, path traversal, and more. Built with Python and Tkinter, Speedpot provides real-time monitoring, threat intelligence, and automated blocking capabilities.

Whether you're a security researcher, network administrator, or cybersecurity enthusiast, Speedpot helps you understand attack patterns and strengthen your network defenses.

## ✨ Features

### 🎯 Attack Detection
- **Port Scan Detection** - Identifies common port scanning patterns with threat classification
- **SQL Injection Detection** - Detects SQL injection attempts with context-aware analysis
- **XSS Attack Detection** - Identifies cross-site scripting payloads
- **Command Injection Detection** - Catches OS command injection attempts
- **Path Traversal Detection** - Detects directory traversal attacks
- **RCE Detection** - Identifies remote code execution attempts
- **Malicious Scanner Detection** - Recognizes vulnerability scanners (sqlmap, nikto, nmap, etc.)

### 🔒 Intelligent Protection
- **Auto-Blocking System** - Automatically blocks critical threats
- **Severity Classification** - Categorizes attacks by threat level (Critical, High, Medium, Low)
- **IP Reputation Tracking** - Maintains blocklist with duration and reason
- **Context-Aware Analysis** - Reduces false positives from legitimate security scanning

### 📊 Comprehensive Monitoring
- **Real-Time Dashboard** - Live threat monitoring with service status
- **Attack Analytics** - Detailed statistics on attack types, severity, and patterns
- **Connection Tracking** - Per-service connection counting and statistics
- **Network Intelligence** - Geographic and threat-level-based insights
- **Web Dashboard** - Optional Streamlit-based web interface for remote monitoring

### 🔧 Service Emulation
- **FTP (Port 21)** - File Transfer Protocol emulation
- **SSH (Port 22)** - Secure Shell emulation
- **Telnet (Port 23)** - Telnet protocol emulation
- **SMTP (Port 25)** - Email service emulation
- **HTTP (Port 80)** - Web server emulation
- **HTTPS (Port 443)** - Secure web server emulation
- **RDP (Port 3389)** - Remote Desktop Protocol emulation
- **HTTP Alternate (Port 8080)** - Alternative web server emulation

### ⚙️ Advanced Options
- **Log Retention** - Automatic log archiving and cleanup
- **Log File Size Limits** - Automatic honeypot stopping when logs exceed size limits
- **Scheduled Scans** - Automatic honeypot startup at specified times
- **Debug Mode** - Detailed logging for troubleshooting
- **Configuration Management** - Easy configuration through GUI

### 💾 Database & Reporting
- **SQLite Database** - Persistent storage of all attacks and connections
- **Detailed Attack Records** - Full payload capture and analysis
- **Export Capabilities** - Export data for external analysis
- **Statistics & Trends** - Visualize attack patterns over time

## 📋 System Requirements

- **OS**: Windows 7 or later (may work on Linux/macOS with modifications)
- **Python**: 3.8 or higher
- **RAM**: 512 MB minimum
- **Disk Space**: 100 MB for installation + space for logs/database

## 📦 Installation

### Option 1: Direct Download & Run

1. **Download Speedpot**
```bash
git clone https://github.com/yourusername/speedpot.git
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

## 🚀 Quick Start

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
```

#### Simulate XSS Attack
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:80/?search=<script>alert('xss')</script>" -ErrorAction SilentlyContinue
```

#### Simulate Port Scan
```powershell
nmap -p 1-1000 127.0.0.1
```

#### Simulate Command Injection
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:80/exec?cmd=;+ls+-la" -ErrorAction SilentlyContinue
```

### Advanced: Web Dashboard

Run the optional Streamlit-based web interface:
```bash
streamlit run dashboard.py
```

Access at `http://localhost:8501` for real-time monitoring and IP management.

## ⚙️ Configuration

Edit `config.json` to customize Speedpot:

```json
{
  "HOST": "127.0.0.1",
  "PORT": 8080,
  "DEBUG_MODE": false,
  "LOG_RETENTION_DAYS": 30,
  "LOG_SIZE_MB": 100,
  "SCAN_SCHEDULE": "00:00"
}
```

## 🖥️ GUI Navigation

### Dashboard Tab
- Real-time service status and connection counts
- Start/Stop honeypot controls
- Blocked IP management
- Attack detection summaries

### Recent Attacks Tab
- Live stream of detected attacks
- Color-coded severity indicators
- Detailed attack information (source IP, port, type, payload)
- Attack classification and reasoning

### Analytics Tab
- Attack type distribution charts
- Severity distribution breakdown
- Top attacker statistics
- Connection timeline visualization
- Service-specific statistics

### Logs Tab
- Real-time log streaming
- Filter by log level (INFO, WARNING, ERROR)
- Search functionality
- Auto-scroll option

### Options Menu
- Log retention settings
- Log file size limits
- Scheduled scan times
- Debug mode toggle
- Auto-block configuration

## 🗄️ Database Structure

Speedpot uses SQLite with the following main tables:

- **connections** - All incoming connections
- **attacks** - Detected attacks with payload information
- **blocked_ips** - Blocked IP addresses and reasons
- **port_scans** - Detected port scanning attempts

## 🎯 Attack Patterns

Speedpot detects the following attack patterns:

| Attack Type | Pattern | Severity | Action |
|-------------|---------|----------|--------|
| SQL Injection | SQL keywords, quotes, operators | High/Critical | Auto-block on critical |
| XSS | Script tags, event handlers, protocols | High | Alert and log |
| Command Injection | Shell operators, commands | Critical | Auto-block |
| Path Traversal | Directory traversal sequences | High | Alert and log |
| Port Scan | Rapid multi-port connections | Medium | Classify and track |
| Scanner Detection | Known scanner user-agents | Medium/High | Classify and track |

## 🔧 Common Troubleshooting

### Honeypot Won't Start
- Ensure no other services are using the target ports
- Try binding to 127.0.0.1 instead of 0.0.0.0 if port binding fails
- Check firewall settings

### No Attacks Detected
- Ensure honeypot is running (check Dashboard tab status)
- Test with provided attack simulation commands
- Verify services are actually listening on expected ports

### High CPU Usage
- Reduce log verbosity (disable debug mode)
- Increase log retention to clean up old data
- Check if honeypot is handling legitimate traffic from network devices

### Database Errors
- Delete `honeypot.db` to reset (backup first if needed)
- Check disk space availability
- Ensure write permissions in the application directory

## ⚡ Performance

- **Connections per second**: ~1000+ (hardware dependent)
- **Memory footprint**: ~50-100 MB at startup, grows with active connections
- **Database size**: ~1 GB per ~100k attack records
- **CPU**: Minimal usage at idle, spikes during port scans

## ⚠️ Security Considerations

**Important**: Speedpot is designed to be attacked. However:

1. **Isolation Recommended** - Run on isolated networks or VMs
2. **Firewall Rules** - Use firewall to restrict legitimate access
3. **No Real Data** - Never store real credentials or sensitive data
4. **Log Cleanup** - Regularly archive and clean logs to prevent disk space issues
5. **Network Monitoring** - Monitor bandwidth usage during port scans

## 🤝 Contributing

I will always welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
git clone https://github.com/yourusername/speedpot.git
cd speedpot
pip install -r requirements-dev.txt
```

### Areas for Contribution
- Additional attack pattern detection
- Performance optimizations
- Protocol emulation improvements
- UI/UX enhancements
- Documentation improvements
- Bug fixes and testing

## 🗺️ Roadmap

- [ ] Docker containerization
- [ ] Multi-threaded improvements
- [ ] Machine learning-based attack classification
- [ ] Integration with SIEM platforms
- [ ] REST API for remote management
- [ ] Multi-language support
- [ ] Linux/macOS native support
- [ ] Advanced threat intelligence integration

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## ⚖️ Disclaimer

Speedpot is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization to operate honeypots on their networks. Unauthorized access to computer systems is illegal.

## 📞 Support

- 📖 **Documentation**: Check the docs/ folder
- 🐛 **Bug Reports**: Open an issue on GitHub
- 💬 **Discussions**: Use GitHub Discussions for questions

## 🙏 Acknowledgments

- Built with Python and Tkinter
- Database management with SQLite
- Web dashboard with Streamlit
- Attack pattern research from OWASP and security community
- Advanced Threeat Intelligence capabilities by VirusTotal and AbuseIPDB

---

**Made with ❤️ by Tenor-Z**

⭐ Star me on GitHub if you find this project useful!
