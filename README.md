# SentinelAI

<div align="center">

![SentinelAI Logo](https://img.shields.io/badge/SentinelAI-Autonomous%20Threat%20Detection-blue?style=for-the-badge&logo=shield)

**Autonomous AI-Powered Threat Detection & Prevention System**

[![License](https://img.shields.io/badge/License-Dual%20(Personal%20Free%20%7C%20Commercial%20Paid)-green?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=flat-square&logo=docker)](https://docker.com)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)]()

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [API](#-api-reference) • [License](#-license)

</div>

---

## 🛡️ Overview

SentinelAI is an intelligent cybersecurity system that provides **real-time threat detection, AI-powered analysis, and autonomous response** across Windows, Linux, and macOS. It combines a Docker-based dashboard with native agents for complete endpoint protection.

### Why SentinelAI?

- **AI-Powered Analysis**: GPT-4 integration for intelligent threat classification
- **Cross-Platform**: Native agents for Windows, Linux, and macOS
- **Real-Time Protection**: Continuous monitoring with instant threat response
- **Beautiful Dashboard**: Modern web UI with live threat visualization
- **Easy Deployment**: Docker-based dashboard with simple agent setup

---

## ✨ Features

### Core Protection
| Feature | Description |
|---------|-------------|
| **Native Agents** | Windows, Linux, and macOS agents for real endpoint protection |
| **AI Analysis** | GPT-4 powered threat classification and recommendations |
| **Auto-Response** | Automatically block IPs and terminate malicious processes |
| **Real-Time Dashboard** | Beautiful web UI with live threat maps and charts |

### Monitoring Capabilities
| Monitor | Capabilities |
|---------|-------------|
| **Process Monitor** | Detects mimikatz, encoded PowerShell, reverse shells, crypto miners |
| **Network Monitor** | Identifies port scans, brute force, DDoS, suspicious connections |
| **File Scanner** | YARA rules, hash checking, VirusTotal integration, quarantine |
| **Log Aggregation** | Windows Event Logs, auth.log, syslog, custom sources |
| **Firewall Control** | Windows Firewall (netsh), iptables (Linux), pf (macOS) |
| **Registry Monitor** | Watches Run keys, Services, Winlogon for persistence |
| **Startup Monitor** | Tracks startup folder and registry Run entries |
| **Task Monitor** | Detects new scheduled tasks (persistence mechanism) |
| **USB Monitor** | Detects USB device connections and removals |
| **Hosts File Monitor** | Detects DNS hijacking via hosts file changes |
| **Browser Extensions** | Monitors Chrome/Edge for new extensions |
| **Clipboard Monitor** | Detects sensitive data (passwords, API keys, crypto wallets) |
| **DNS Query Monitor** | Detects DNS tunneling and suspicious domain queries |
| **PowerShell Logging** | Captures all PowerShell script block execution |
| **WMI Monitor** | Detects WMI persistence and event subscriptions |
| **DLL Injection** | Monitors for injected DLLs in processes |
| **Named Pipe Monitor** | Detects C2 communication channels |
| **Service Monitor** | Detects new service creation (persistence) |
| **Driver Monitor** | Detects rootkit driver loading |
| **Firewall Rules** | Monitors for unauthorized firewall rule changes |
| **Certificate Monitor** | Detects rogue certificates in Windows store |

### Integrations
| Integration | Description |
|-------------|-------------|
| **OpenAI GPT-4** | Intelligent threat analysis and remediation suggestions |
| **AVG Antivirus** | Parse AVG/Avast logs for threat detections |
| **Windows Defender** | Integration with Windows Security Center |
| **Snort IDS** | Ingest alerts from Snort intrusion detection system |
| **Docker Projects** | Connect any Docker container for centralized monitoring |
| **REST API** | Full API for custom integrations and automation |

### Desktop Application
| Feature | Description |
|---------|-------------|
| **Tauri Desktop App** | Native Windows application with embedded agent |
| **System Tray** | Background protection with tray icon |
| **Real-time Status** | Live agent status and threat count |
| **Activity Logs** | View all security events in-app |
| **One-Click Deploy** | Single exe distribution for endpoints |

---

## 🚀 Quick Start

### Step 1: Start the Dashboard (Docker)

```bash
git clone https://github.com/VibrationRobotics/SentinelAI.git
cd SentinelAI
docker-compose up -d
```

Dashboard available at: **http://localhost:8015**

### Step 2: Run an Agent

<details>
<summary><b>🪟 Windows Agent</b></summary>

```powershell
# Open PowerShell as Administrator
cd SentinelAI\windows_agent
.\run_agent.bat
```

Or manually:
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python agent.py --dashboard http://localhost:8015
```
</details>

<details>
<summary><b>🐧 Linux Agent</b></summary>

```bash
cd SentinelAI/linux_agent
chmod +x run_agent.sh
sudo ./run_agent.sh
```

Or manually:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo python3 agent.py --dashboard http://localhost:8015
```
</details>

<details>
<summary><b>🍎 macOS Agent</b></summary>

```bash
cd SentinelAI/linux_agent
chmod +x run_agent.sh
sudo ./run_agent.sh
```

Or manually:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo python3 agent.py --dashboard http://localhost:8015
```
</details>

<details>
<summary><b>🖥️ Desktop App (Tauri)</b></summary>

Download the pre-built executable or build from source:

```powershell
# Pre-built (recommended)
# Download SentinelAI-Desktop.exe and agent.py to the same folder
# Run SentinelAI-Desktop.exe

# Build from source
cd SentinelAI\sentinel-desktop
npm install
npm run tauri build
```

The desktop app includes:
- Embedded Python agent (auto-starts)
- Real-time protection status
- Activity log viewer
- One-click dashboard access

</details>

---

## 📦 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SentinelAI Dashboard                         │
│                    (Docker - port 8015)                          │
│  ┌─────────────┬─────────────┬─────────────┬──────────────────┐ │
│  │  FastAPI    │  PostgreSQL │    Redis    │     Web UI       │ │
│  │  Backend    │  Database   │    Cache    │   Dashboard      │ │
│  └─────────────┴─────────────┴─────────────┴──────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
┌───────────────────┐ ┌───────────────┐ ┌───────────────────┐
│   Windows Agent   │ │  Linux Agent  │ │   macOS Agent     │
│   (run_agent.bat) │ │ (run_agent.sh)│ │  (run_agent.sh)   │
├───────────────────┤ ├───────────────┤ ├───────────────────┤
│ • Process Monitor │ │ • Process Mon │ │ • Process Monitor │
│ • Network Monitor │ │ • Network Mon │ │ • Network Monitor │
│ • Event Log Parse │ │ • Auth Log    │ │ • System Log      │
│ • Windows Firewal │ │ • iptables    │ │ • pf firewall     │
│ • AI Analysis     │ │ • AI Analysis │ │ • AI Analysis     │
└───────────────────┘ └───────────────┘ └───────────────────┘
```

---

## 🔗 Connecting Other Docker Projects

SentinelAI can receive threat data from ANY Docker container:

```python
import requests

requests.post("http://host.docker.internal:8015/api/v1/threats/analyze", json={
    "source_ip": "192.168.1.100",
    "threat_type": "suspicious_activity",
    "severity": "HIGH",
    "description": "Unusual database query pattern detected"
})
```

Or add to your docker-compose.yml:

```yaml
services:
  your-app:
    environment:
      - SENTINEL_API=http://host.docker.internal:8015/api/v1
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

---

## 📋 Documentation

### Prerequisites
- **Python 3.10+**
- **Docker Desktop** (for dashboard)
- **Administrator/root rights** (for agent firewall control)

### Environment Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Key variables:
| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key for GPT-4 analysis | Required |
| `DATABASE_URL` | PostgreSQL connection string | Auto-configured |
| `REDIS_URL` | Redis connection string | Auto-configured |
| `DASHBOARD_PORT` | Dashboard port | `8015` |

### Docker Commands

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f web

# Rebuild after changes
docker-compose up -d --build web

# Stop all services
docker-compose down
```

### Agent Command Line Options

```bash
# Windows
python agent.py --dashboard URL --verbose --no-ai

# Linux/macOS
python3 agent.py --dashboard URL --verbose --no-ai

Options:
  -d, --dashboard URL    Dashboard URL (default: http://localhost:8015)
  -v, --verbose          Enable verbose logging
  --no-ai                Disable AI analysis (heuristics only)
```

---

## 📡 API Reference

Base URL: `http://localhost:8015`

### Health Check
```http
GET /api/v1/health
```

### Threat Analysis
```http
POST /api/v1/threats/analyze
Content-Type: application/json

{
    "source_ip": "192.168.1.100",
    "threat_type": "malware",
    "severity": "HIGH",
    "description": "Suspicious process detected"
}
```

### Get Recent Threats
```http
GET /api/v1/threats/recent
```

### Agent Registration
```http
POST /api/v1/windows/agent/register
Content-Type: application/json

{
    "hostname": "DESKTOP-ABC123",
    "platform": "Windows",
    "platform_version": "10.0.19041",
    "capabilities": ["process", "network", "eventlog", "firewall"]
}
```

### List Connected Agents
```http
GET /api/v1/windows/agent/list
```

Full API documentation available at:
- **Swagger UI**: http://localhost:8015/docs
- **ReDoc**: http://localhost:8015/redoc

---

## 📁 Project Structure

```
SentinelAI/
├── app/
│   ├── api/endpoints/          # API endpoints
│   │   ├── threats.py          # Threat analysis
│   │   ├── windows.py          # Windows/Agent APIs
│   │   ├── monitoring.py       # Monitoring status
│   │   ├── auto_response.py    # Auto-response config
│   │   └── logs.py             # Log collection
│   ├── services/               # Core services
│   │   ├── openai_service.py   # GPT-4 integration
│   │   ├── network_monitor.py  # Network monitoring
│   │   ├── process_monitor.py  # Process monitoring
│   │   ├── file_scanner.py     # File scanning
│   │   ├── log_collector.py    # Log aggregation
│   │   └── auto_response_service.py
│   ├── static/                 # Frontend assets
│   │   ├── index.html          # Dashboard UI
│   │   ├── js/                 # JavaScript
│   │   └── css/                # Stylesheets
│   └── main.py                 # Application entry
├── windows_agent/              # Windows agent
│   ├── agent.py                # Agent script
│   ├── run_agent.bat           # Windows startup
│   └── requirements.txt
├── linux_agent/                # Linux/macOS agent
│   ├── agent.py                # Agent script
│   ├── run_agent.sh            # Unix startup
│   └── requirements.txt
├── docker-compose.yml          # Docker configuration
├── Dockerfile                  # Docker build
├── .env.example                # Environment template
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

---

## 📜 Version History

### v1.4.0 (November 2025) - Complete Security Suite
- ✨ **Hybrid ML/Rule Detection** - 95%+ cost savings vs pure AI
  - Rule-based detection (instant, free) for known patterns
  - Local ML model for uncertain cases
  - OpenAI only for truly ambiguous HIGH threats
- ✨ **AI Analysis for ALL Monitors** - HIGH/CRITICAL events analyzed by GPT-4
- ✨ **AMSI Integration** - Windows Antimalware Scan Interface monitoring
- ✨ **ETW Monitoring** - Event Tracing for Windows (Security-Auditing, PowerShell, TaskScheduler)
- ✨ **Sysmon Integration** - Full Sysmon event parsing (Process, Network, DLL, Registry)
- ✨ **DLL Injection Detection** - Monitor suspicious DLLs loaded into processes
- ✨ **PostgreSQL Persistent Storage** - All agents, events, and audit logs in database
- ✨ **Multi-Agent SaaS** - Multiple agents connect to central dashboard
- ✨ **Frontend AI Display** - Shows AI badges, MITRE techniques, confidence scores
- 🔧 25 active security monitors with hybrid ML/AI analysis
- 🔧 Full API for security events (/api/v1/windows/events)

### v1.3.0 (November 2025) - Advanced Monitoring & Desktop App
- ✨ **Tauri Desktop App** - Native Windows application with embedded agent
- ✨ **Clipboard Monitor** - Detect sensitive data exposure
- ✨ **DNS Query Monitor** - Detect DNS tunneling and suspicious domains
- ✨ **PowerShell Logging** - Capture all script block execution
- ✨ **WMI Monitor** - Detect WMI-based persistence
- ✨ **Named Pipe Monitor** - Detect C2 communication channels
- ✨ **Service Monitor** - Detect new service creation
- ✨ **Driver Monitor** - Detect rootkit driver loading
- ✨ **Firewall Rule Monitor** - Detect unauthorized changes
- ✨ **Certificate Monitor** - Detect rogue certificates
- ✨ **Windows Defender Integration** - Native Windows Security
- ✨ **AVG/Avast Integration** - Parse AV logs for detections
- ✨ **Audit Log System** - Comprehensive activity logging

### v1.0.0 (November 2025) - Native Agents Release
- ✨ Native Windows Agent with AI-powered detection
- ✨ Native Linux/macOS Agent with auth log monitoring
- ✨ Connected Agents dashboard section
- ✨ Agent heartbeat and auto-reconnection
- ✨ Two-stage detection (heuristics + AI)
- ✨ Process whitelist configuration
- 🔧 GPT-4 integration for threat analysis
- 🔧 Real-time threat map with geolocation
- 🔧 Auto-response system with IP blocking

### v0.2.0 (October 2025) - Dashboard Enhancement
- ✨ Real-time monitoring dashboard
- ✨ Network monitor with DDoS detection
- ✨ File scanner with YARA rules
- ✨ Process monitor with behavior analysis
- ✨ Log aggregation from multiple sources
- 🔧 Snort IDS integration
- 🔧 Docker-based deployment

### v0.1.0 (September 2025) - Initial Release
- ✨ Core threat analysis API
- ✨ AI-powered threat classification
- ✨ Docker containerization
- ✨ Basic web dashboard

---

## 📄 License

### Dual License

**Personal/Non-Commercial Use**: FREE
- Use SentinelAI for personal projects, learning, and non-commercial purposes at no cost.

**Commercial Use**: Paid License Required
- For commercial use, enterprise deployment, or integration into commercial products, please contact us for licensing options.

Contact: [Create an issue](https://github.com/VibrationRobotics/SentinelAI/issues) for licensing inquiries.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## ⭐ Support

If you find SentinelAI useful, please consider giving it a star on GitHub!

<div align="center">

**Made with ❤️ by [VibrationRobotics](https://github.com/VibrationRobotics)**

</div>
