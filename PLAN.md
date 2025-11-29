# SentinelAI - Full Autonomous Threat Detection System

## Vision
A fully autonomous AI-powered threat detection and response system that protects machines from network attacks, malware, and suspicious activity in real-time. Supports Windows, Linux, and macOS with native agents.

---

## Current State ✅

| Feature | Status | Description |
|---------|--------|-------------|
| Threat Analysis API | ✅ Complete | Receives and processes threat data |
| OpenAI Integration | ✅ Complete | GPT-4o-mini for intelligent analysis |
| IP Geolocation | ✅ Complete | Maps attackers on world map |
| Dashboard | ✅ Complete | Real-time visualization with Bootstrap 5 |
| IP Blocking (iptables) | ✅ Complete | Blocks IPs in container firewall |
| Remediation Logging | ✅ Complete | All actions logged with rollback |
| Manual Fix Application | ✅ Complete | Click to execute fixes |
| Snort Connector | ✅ Complete | Ingests Snort IDS alerts |
| Windows Agent | ✅ Complete | Native Windows protection (26 monitors) + Autonomous Response |
| Linux/macOS Agent | ✅ Complete | Native Unix protection |
| Agent Dashboard | ✅ Complete | Shows connected agents |
| User Authentication | ✅ Complete | JWT login/register with roles |
| Admin Panel | ✅ Complete | User/tier/role management |
| API Key Auth | ✅ Complete | Agents require API key |
| VirusTotal | ✅ Complete | Hash/URL/IP/domain lookups |
| Tauri Desktop | ✅ Complete | Native Windows app with GUI |

---

## Development Phases

### Phase 1: Auto-Response Mode ✅
**Status: COMPLETE**
**Effort: 1-2 hours**

Automatically respond to threats based on severity without manual intervention.

- [x] Add auto-response toggle in settings
- [x] Configure severity threshold (HIGH = auto-block)
- [x] Add cooldown to prevent blocking same IP repeatedly
- [x] IP whitelist support
- [x] Dashboard indicator showing auto-response status
- [x] Notification when auto-action taken

**Files created:**
- `app/services/auto_response_service.py` - Auto-response logic
- `app/api/endpoints/auto_response.py` - Settings API
- `app/static/js/monitoring.js` - Frontend controls

---

### Phase 2: Real Network Monitoring ✅
**Status: COMPLETE**
**Effort: 4-6 hours**

Capture and analyze live network traffic to detect attacks in real-time.

- [x] Packet capture with scapy
- [x] Port scan detection
- [x] Brute force detection (multiple failed connections)
- [x] DDoS detection (traffic volume anomalies)
- [x] SYN flood detection
- [x] Suspicious port monitoring (SSH, RDP, FTP)
- [x] Suspicious payload detection (SQL injection, XSS)

**Files created:**
- `app/services/network_monitor.py` - Packet capture, analysis, and pattern detection
- `app/api/endpoints/monitoring.py` - Monitoring API endpoints

**Dependencies:**
- scapy
- psutil

---

### Phase 3: File System & Virus Scanner ✅
**Status: COMPLETE**
**Effort: 6-8 hours**

Monitor file system for malware and suspicious files.

- [x] Real-time file system monitoring with watchdog
- [x] Hash checking against known malware (MD5/SHA256)
- [x] YARA rules for pattern matching
- [x] VirusTotal API integration (optional)
- [x] Quarantine suspicious files
- [x] Scan on-demand and directory scans
- [x] Monitor Downloads, Temp folders
- [x] Suspicious content pattern detection

**Files created:**
- `app/services/file_scanner.py` - File scanning, hash checking, quarantine, and pattern detection
- `app/api/endpoints/monitoring.py` - Scanning API endpoints

**Dependencies:**
- watchdog
- requests (VirusTotal API)

---

### Phase 4: System Process Monitor ✅
**Status: COMPLETE**
**Effort: 4-6 hours**

Monitor running processes for suspicious behavior.

- [x] Track all running processes
- [x] Detect suspicious process spawning
- [x] Monitor for reverse shells (cmd.exe/powershell spawned by web server)
- [x] Detect suspicious command lines
- [x] Monitor for crypto miners
- [x] Auto-kill malicious processes
- [x] High CPU/memory usage detection

**Files created:**
- `app/services/process_monitor.py` - Process tracking and behavior analysis
- `app/api/endpoints/monitoring.py` - Process API endpoints

**Dependencies:**
- psutil

---

### Phase 5: Log Aggregation ✅
**Status: COMPLETE**
**Effort: 3-4 hours**

Collect and analyze logs from multiple sources.

- [x] Windows Event Log reader (Security, System, Application)
- [x] SSH auth log parser (/var/log/auth.log)
- [x] Web server log parser (Apache/Nginx)
- [x] Syslog parser
- [x] Custom log source support
- [x] Threat detection in logs
- [x] Log search functionality

**Files created:**
- `app/services/log_collector.py` - Log collection with built-in parsers for Windows Events, SSH, syslog
- `app/api/endpoints/logs.py` - Log API endpoints

**Dependencies:**
- (parsers built into log_collector.py)

---

### Phase 6: Native Agent System ✅
**Status: COMPLETE**
**Effort: 8-10 hours**

Native agents for Windows, Linux, and macOS with full system access.

#### Windows Agent ✅
- [x] Process monitoring with AI analysis
- [x] Network connection monitoring
- [x] Windows Event Log parsing
- [x] Windows Firewall control (netsh/PowerShell)
- [x] Heartbeat/auto-reconnect
- [x] Whitelist for legitimate apps
- [x] Two-stage detection (heuristics + AI)

#### Linux/macOS Agent ✅
- [x] Process monitoring
- [x] Network connection monitoring
- [x] Auth log monitoring (/var/log/auth.log)
- [x] iptables/pf firewall control
- [x] Reverse shell detection
- [x] Crypto miner detection

**Files created:**
- `windows_agent/agent.py` - Windows agent
- `windows_agent/run_agent.bat` - Windows startup script
- `linux_agent/agent.py` - Linux/macOS agent
- `linux_agent/run_agent.sh` - Unix startup script

**Dependencies:**
- psutil
- requests
- pywin32 (Windows only)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     SentinelAI Dashboard                        │
│         (Real-time visualization, alerts, controls)             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Core API Server                            │
│              (FastAPI + WebSocket for real-time)                │
└─────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  AI Analysis  │     │  Auto-Response  │     │   Remediation   │
│   (OpenAI)    │     │    Service      │     │    Service      │
└───────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Network     │     │     File        │     │    Process      │
│   Monitor     │     │    Scanner      │     │    Monitor      │
└───────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Log          │     │   Windows       │     │   Threat        │
│  Collector    │     │   Integration   │     │   Database      │
└───────────────┘     └─────────────────┘     └─────────────────┘
```

---

## Priority Order

1. **Phase 1: Auto-Response** - Quick win, immediate value
2. **Phase 2: Network Monitor** - Core protection capability
3. **Phase 4: Process Monitor** - Catch malware execution
4. **Phase 3: File Scanner** - Prevent malware persistence
5. **Phase 5: Log Aggregation** - Better visibility
6. **Phase 6: Windows Integration** - Full host protection

---

## Progress Tracking

### Phase 1: Auto-Response Mode ✅
- [x] Create plan
- [x] Create auto_response_service.py
- [x] Add settings API endpoint (auto_response.py)
- [x] Test auto-blocking (working!)
- [x] Add frontend toggle
- [x] Add dashboard integration

### Phase 2: Network Monitor ✅
- [x] Install scapy
- [x] Create network_monitor.py
- [x] Implement port scan detection
- [x] Implement brute force detection
- [x] Add API endpoints
- [x] Add to dashboard

### Phase 3: File Scanner ✅
- [x] Install watchdog
- [x] Create file_scanner.py
- [x] Add YARA rules (sample)
- [x] Implement quarantine
- [x] Add VirusTotal integration (optional)
- [x] Add API endpoints
- [x] Add to dashboard

### Phase 4: Process Monitor ✅
- [x] Create process_monitor.py
- [x] Implement behavior analysis
- [x] Add process kill capability
- [x] Add API endpoints
- [x] Add to dashboard

### Phase 5: Log Aggregation ✅
- [x] Create log_collector.py
- [x] Add Windows Event parser
- [x] Add SSH auth parser
- [x] Add syslog parser
- [x] Add threat detection
- [x] Add API endpoints
- [x] Add to dashboard

### Phase 6: Native Agents ✅
- [x] Create windows_firewall.py
- [x] Add API endpoints
- [x] Add system info API
- [x] Create Windows Agent (windows_agent/)
- [x] Create Linux/macOS Agent (linux_agent/)
- [x] Agent registration API
- [x] Agent heartbeat system
- [x] Connected agents dashboard section

---

## Getting Started

### Quick Start - Windows

```powershell
# 1. Start Dashboard (Docker)
docker-compose up -d

# 2. Run Windows Agent (new terminal, as Admin)
cd windows_agent
.\run_agent.bat
```

### Quick Start - Linux/macOS

```bash
# 1. Start Dashboard (Docker)
docker-compose up -d

# 2. Run Linux/macOS Agent (new terminal)
cd linux_agent
chmod +x run_agent.sh
sudo ./run_agent.sh
```

Dashboard URL: **http://localhost:8015**

### Connecting Other Docker Projects

From any Docker container, send threats to SentinelAI:
```python
import requests
requests.post("http://host.docker.internal:8015/api/v1/threats/analyze", json={
    "source_ip": "192.168.1.100",
    "threat_type": "suspicious_activity",
    "severity": "HIGH",
    "description": "Your threat description"
})
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SentinelAI Dashboard                      │
│                  (Docker - port 8015)                        │
│  ┌─────────────┬─────────────┬─────────────┬──────────────┐ │
│  │  FastAPI    │  PostgreSQL │    Redis    │    Web UI    │ │
│  │  Backend    │  Database   │    Cache    │  Dashboard   │ │
│  └─────────────┴─────────────┴─────────────┴──────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
┌───────────────────┐ ┌───────────────┐ ┌───────────────────┐
│   Windows Agent   │ │  Linux Agent  │ │   macOS Agent     │
│   (native .bat)   │ │  (native .sh) │ │   (native .sh)    │
├───────────────────┤ ├───────────────┤ ├───────────────────┤
│ • Process Monitor │ │ • Process Mon │ │ • Process Monitor │
│ • Network Monitor │ │ • Network Mon │ │ • Network Monitor │
│ • Event Log Parse │ │ • Auth Log    │ │ • System Log      │
│ • Windows Firewal │ │ • iptables    │ │ • pf firewall     │
│ • AI Analysis     │ │ • AI Analysis │ │ • AI Analysis     │
└───────────────────┘ └───────────────┘ └───────────────────┘
```

---

## Windows Agent Features

### Current Capabilities
| Feature | Status | Description |
|---------|--------|-------------|
| Process Monitoring | ✅ | Tracks all processes, detects suspicious ones |
| Network Monitoring | ✅ | Monitors connections, detects suspicious ports |
| Event Log Parsing | ✅ | Reads Windows Security/System/Application logs |
| Windows Firewall | ✅ | Block IPs via netsh/PowerShell |
| AI Analysis | ✅ | Two-stage: heuristics + GPT-4 |
| Heartbeat | ✅ | Auto-reconnects every 30 seconds |
| Whitelist | ✅ | Configurable safe process list |

### Detected Threats
- Reverse shells (PowerShell encoded commands)
- Credential theft tools (mimikatz, lazagne)
- Crypto miners (xmrig, minerd)
- Suspicious network connections
- Privilege escalation attempts
- Malicious scheduled tasks

---

## Recent Updates (v1.5.0)

### Autonomous Agent Response System ✅
- [x] Agent command queue in database (AgentCommand model)
- [x] Agent polls dashboard for pending commands every 30 seconds
- [x] Command execution: block_ip, kill_process, quarantine_file, unblock_ip, scan_path
- [x] Command result reporting back to dashboard
- [x] Auto-response service queues commands for agents on threat detection

### Inbound Network Monitoring ✅
- [x] Monitor all incoming connections to server
- [x] Port scan detection (10+ ports from same IP)
- [x] Connection flood detection (>5 conn/sec)
- [x] Dangerous port alerts (SMB 445, RDP 3389, WinRM, etc.)
- [x] New listening port detection (backdoor detection)
- [x] Auto-block external attackers (port scanners, flooders, brute force)
- [x] Cloud provider whitelist (Google, Cloudflare, AWS, Azure, DigitalOcean)

### Brute Force Detection ✅
- [x] Track failed login attempts by IP/user
- [x] Alert on 5+ failures in 10 minutes
- [x] Auto-block brute force attackers
- [x] Parse Windows Event ID 4625 for source IP

### Agent System Info & Dashboard ✅
- [x] Comprehensive system info collection (CPU, RAM, disk, network)
- [x] Public IP detection and display
- [x] Listening ports with process names
- [x] Security software detection (Defender, AVG, etc.)
- [x] Clickable agent rows in dashboard
- [x] Agent details modal with full system info
- [x] Recent events and blocked IPs per agent
- [x] Real-time connection stats

### Administrator Privileges ✅
- [x] Admin check on startup with clear warning
- [x] Auto-blocking requires Administrator
- [x] Batch file auto-changes to script directory (Run as Admin fix)

---

## Recent Updates (v1.3.0)

### AI Intelligence Improvements ✅
- [x] Enhanced AI context for Windows system events
- [x] AI now recognizes normal Windows activity (Event 4672, SYSTEM account, etc.)
- [x] False positive detection for common system events
- [x] Re-analyze with AI button in threat details
- [x] Add to Whitelist functionality
- [x] Mark as False Positive option

### Dashboard Improvements ✅
- [x] Functional navbar (Dashboard, Threats, Agents, Settings)
- [x] Real Settings modal (Auto-Response, Whitelist, Monitoring toggles)
- [x] Removed Azure-specific settings
- [x] AI Actions section in threat details

---

## Future Enhancements

### Phase 7: Advanced Agent Monitoring ✅ COMPLETE

#### Windows Agent - Implemented ✅
- [x] Registry monitoring - *Watches Run keys, Services, Winlogon*
- [x] Startup item monitoring - *Registry + Startup folders*
- [x] Scheduled task monitoring - *Detects new tasks (195 tracked)*
- [x] USB device monitoring - *Detects connections/removals*
- [x] Hosts file monitoring - *Detects DNS hijacking*
- [x] Browser extension monitoring - *Chrome/Edge extensions (12 tracked)*
- [x] AVG Antivirus integration - *Parses AVG logs, sends to AI*
- [x] Clipboard monitor - *Detects passwords, API keys, crypto wallets, private keys*
- [x] DNS query monitor - *Detects DNS tunneling, suspicious TLDs, malicious domains*
- [x] PowerShell script block logging - *Captures Event ID 4104, detects encoded commands*
- [x] WMI event subscription monitor - *Detects persistence via WMI consumers/filters*
- [x] Named pipe monitor - *Detects C2 communication channels, suspicious pipes*
- [x] Certificate store monitor - *Monitors Root/CA stores (18 tracked)*
- [x] Firewall rule monitor - *Detects unauthorized rule changes (376 tracked)*
- [x] Service creation monitor - *Detects new services (299 tracked)*
- [x] Driver load monitor - *Detects rootkit drivers (439 tracked)*
- [x] Windows Defender integration - *Event IDs 1116-1119 for malware detection*

#### Windows Agent - Implemented (Phase 9) ✅
- [x] AMSI integration - *Monitors Windows Defender AMSI events (Event ID 1116)*
- [x] ETW (Event Tracing) - *Security-Auditing, Sysmon, PowerShell, TaskScheduler*
- [x] Sysmon integration - *Process, Network, DLL, Registry, DNS events*
- [x] DLL injection detection - *Monitors suspicious DLLs loaded into processes*

#### Windows Agent - Implemented (Phase 10) ✅
- [x] Inbound connection monitoring - *Detects incoming attacks on server*
- [x] Port scan detection - *Alerts on 10+ ports probed*
- [x] Connection flood detection - *DDoS/flood attack detection*
- [x] Brute force detection - *5+ failed logins = auto-block*
- [x] Autonomous command execution - *Receives and executes dashboard commands*
- [x] Auto-block attackers - *Firewall rules added automatically*
- [x] System info reporting - *CPU, RAM, disk, network to dashboard*
- [x] Clickable agent details - *Full system info in dashboard modal*

#### Windows Agent - Planned
- [ ] Avast/Norton/McAfee integration - *Other AV vendors*
- [ ] Multi-agent fleet management - *Manage 100+ agents from dashboard*
- [ ] Agent auto-update - *Push updates from dashboard*
- [ ] Remote shell - *Execute commands on agent from dashboard*
- [ ] File transfer - *Upload/download files to/from agents*

#### Linux Agent - Implemented ✅
- [x] Cron job monitor - *Detects new/modified cron jobs in /etc/cron.d, /var/spool/cron*
- [x] SSH key monitor - *Watches authorized_keys changes for all users*
- [x] Sudo log monitor - *Tracks privilege escalation via auth.log*
- [x] Kernel module monitor - *Detects rootkit modules (diamorphine, reptile, etc.)*
- [x] LD_PRELOAD monitor - *Detects library injection via env and /etc/ld.so.preload*
- [x] Setuid binary monitor - *Tracks new setuid/setgid binaries*
- [x] Container escape detection - *Monitors docker.sock, cgroup escapes*
- [x] Auditd integration - *Parses /var/log/audit/audit.log for suspicious syscalls*
- [x] SELinux/AppArmor alerts - *Monitors policy violations (AVC denials)*
- [x] Package manager monitor - *Detects unauthorized installs (dpkg/rpm/pacman)*
- [x] Systemd service monitor - *Detects new/modified services*
- [x] File integrity monitoring - *Hashes /etc/passwd, /etc/shadow, /etc/sudoers, etc.*
- [x] Process monitor - *Detects reverse shells, crypto miners, malicious tools*
- [x] Network monitor - *Detects suspicious connections and ports*

#### Linux Agent - Planned
- [ ] eBPF integration - Advanced kernel-level monitoring

#### macOS Agent - Implemented ✅
- [x] Process monitor - *Detects suspicious processes*
- [x] Network monitor - *Detects suspicious connections*
- [x] System log monitor - */var/log/system.log parsing*
- [x] pf firewall integration - *IP blocking via pfctl*
- [x] Launch Daemon monitor - *Watches /Library/LaunchDaemons and LaunchAgents*
- [x] Keychain monitor - *Monitors keychain access via unified log*
- [x] Gatekeeper monitor - *Detects unsigned app blocks and bypass attempts*
- [x] TCC database monitor - *Monitors privacy permission changes*
- [x] Unified Log monitor - *Parses macOS unified log for security events*
- [x] XProtect integration - *Monitors Apple's built-in malware detection*

#### macOS Agent - Planned
- [ ] FileVault monitor - *Disk encryption status changes*
- [ ] SIP (System Integrity Protection) monitor - *SIP bypass attempts*

#### Cross-Platform - Planned
- [ ] Threat intelligence feeds - Check IPs/hashes against known bad
- [ ] YARA rule scanning - Custom malware signatures
- [ ] Memory scanning - Detect in-memory malware
- [ ] Behavioral analysis - ML-based anomaly detection
- [ ] Honeypot files - Canary files to detect ransomware
- [ ] Data exfiltration detection - Large outbound transfers
- [ ] Lateral movement detection - Internal network scanning

### Phase 8: Tauri Desktop App ✅ COMPLETE
- [x] Native Windows .exe with GUI - *sentinel-desktop/ created*
- [x] System tray icon - *Configured in tauri.conf.json*
- [x] Real-time notifications - *Using tauri-plugin-notification*
- [x] One-click threat response - *Quick Scan, Block IP buttons*
- [x] Embed Python agent in .exe - *Auto-starts agent on launch*
- [x] Build .exe successfully - *5.2MB standalone executable*
- [x] Window controls (minimize, maximize, close) - *Custom titlebar with Tauri commands*
- [x] Activity Logs page - *View all security events in-app*
- [x] Agent status indicator - *Shows Protected/Not Connected*
- [x] Start/Stop Agent button - *Dynamic state based on agent status*
- [x] Multi-machine deployment - *External IP support for SaaS*
- [x] Auto-start on boot - *tauri-plugin-autostart integrated*
- [x] Settings page - *Autostart toggle, dashboard URL, detection options*
- [x] Package as .msi installer - *Configured in tauri.conf.json (msi + nsis)*
- [ ] Code signing for distribution

### Phase 9: SaaS Deployment ✅ (Complete)
- [x] Public dashboard URL - *http://148.170.66.162:8015*
- [x] Agent connects to central server - *Multiple agents tested*
- [x] Audit logging system - */api/v1/audit endpoint*
- [x] AI Analysis for all monitors - *HIGH/CRITICAL events sent to GPT-4*
- [x] Frontend displays AI results - *Badges, MITRE techniques, confidence scores*
- [x] User authentication & API keys - */api/v1/agents/api-keys endpoint*
- [x] Per-agent licensing - */api/v1/agents/licenses endpoint*
- [x] Usage analytics - */api/v1/agents/stats endpoint*
- [ ] White-label support - *Custom branding for resellers*
- [ ] HTTPS with domain - *Need SSL cert + reverse proxy*

### Phase 10: Enterprise Features ✅ (Partially Complete)
- [x] Multi-agent management - */api/v1/agents/ endpoint with full CRUD*
- [x] Autonomous self-healing - *Auto-restart unhealthy Docker containers*
- [x] System health monitoring - */api/v1/agents/health-status endpoint*
- [x] User authentication - *JWT-based login/register with bcrypt password hashing*
- [x] User settings persistence - *Settings saved to PostgreSQL, not localStorage*
- [x] API key management - *Generate, view, revoke API keys for agent auth*
- [x] API key enforcement - *Agents require valid API key to register*
- [x] Subscription/License UI - *View tier, limits, usage stats*
- [x] Dynamic navbar - *Shows real user name and alert count from DB*
- [x] Role-based access control - *Admin, User, Viewer roles with UI restrictions*
- [x] VirusTotal integration - *Hash, URL, IP, domain reputation lookups*
- [ ] Centralized policy management - *Requires more design work*
- [ ] Agent auto-update - *Requires code signing infrastructure*
- [ ] SIEM integration (Splunk, ELK) - *Webhook/syslog export needed*
- [ ] Compliance reporting (SOC2, HIPAA) - *Report templates needed*
- [ ] Active Directory integration - *LDAP/OAuth2 integration needed*

**Files created/modified:**
- `app/api/endpoints/settings.py` - User settings, API keys, subscription, admin endpoints
- `app/api/deps.py` - API key validation dependency
- `app/static/js/settingsManager.js` - Frontend settings management
- `app/static/js/auth.js` - Frontend authentication with admin panel
- `app/db/models.py` - UserSettings, APIKey, AgentLicense models with max_agents
- `windows_agent/agent.py` - API key support added
- `app/static/index.html` - Profile modal, Admin Panel modal, navbar with roles

**Admin Panel Features:**
- User management (list, edit role, edit tier, enable/disable)
- Agent monitoring (view all connected agents)
- Audit log viewer (recent system activity)
- Tier management (Free → Pro → Enterprise upgrades)

**VirusTotal Integration:**
- `app/services/virustotal_service.py` - VT API client with caching and rate limiting
- `app/api/endpoints/virustotal.py` - REST endpoints for hash/URL/IP/domain lookups
- Endpoints: `/api/v1/virustotal/check/hash`, `/check/url`, `/check/ip`, `/check/domain`
- Rate limited to 4 requests/minute (free tier)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    CENTRAL SERVER (Docker)                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  SentinelAI Dashboard (port 8015)                           ││
│  │  - Receives events from ALL agents                          ││
│  │  - AI Analysis engine (OpenAI/Local LLM)                    ││
│  │  - Central threat database                                  ││
│  │  - Web UI for monitoring                                    ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ HTTPS (your public IP or domain)
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Your PC     │    │  Dev #2 PC   │    │  Customer X  │
│  Agent .exe  │    │  Agent .exe  │    │  Agent .exe  │
│  (Bygheart)  │    │  (Remote)    │    │  (SaaS User) │
└──────────────┘    └──────────────┘    └──────────────┘
```

## Notes

- **Dashboard (Docker)**: Visualization, AI analysis, threat storage
- **Windows Agent (Native)**: Real Windows protection, runs outside Docker
- **Linux/macOS Agent (Native)**: Unix protection with auth log monitoring
- **Tauri Desktop App**: GUI wrapper that embeds and manages the agent
- All phases run concurrently for layered protection
- Run agents as Administrator/root for full firewall control
- Agents auto-create venv on first run
- Agents auto-reconnect if dashboard restarts
- For SaaS: Agents need YOUR server IP/domain, not the other way around

---

## Suggested Future Features

### High Priority (Easy to Implement)
- [x] **Agent Command Queue** - Dashboard can send commands to agents ✅
- [x] **Auto-Block Attackers** - Port scanners, brute force auto-blocked ✅
- [x] **Agent System Info** - Full hardware/software info in dashboard ✅
- [ ] **Email Alerts** - SMTP notifications for HIGH/CRITICAL threats
- [ ] **Webhook Notifications** - Discord/Slack/Teams integration
- [ ] **Threat Export** - CSV/JSON export of threat history
- [ ] **Dashboard Dark/Light Mode** - Theme toggle
- [ ] **Agent Groups** - Organize agents by location/department
- [ ] **Scheduled Scans** - Cron-like file scanning

### Medium Priority (Moderate Effort)
- [x] **Agent Remote Commands** - Execute commands on agents from dashboard ✅
- [ ] **2FA/MFA** - TOTP authentication for dashboard
- [ ] **IP Reputation Database** - Local cache of known bad IPs
- [ ] **Threat Intelligence Feeds** - AbuseIPDB, AlienVault OTX
- [ ] **Custom YARA Rules UI** - Upload/manage YARA rules from dashboard
- [ ] **Backup/Restore** - Database backup functionality
- [ ] **Agent Fleet Dashboard** - Overview of all agents with health status
- [ ] **Bulk Agent Actions** - Apply commands to multiple agents at once

### Low Priority (Complex)
- [ ] **Machine Learning Model** - Train on your own threat data
- [ ] **Network Traffic Analysis** - Deep packet inspection
- [ ] **Honeypot Integration** - Canary tokens/files
- [ ] **Mobile App** - iOS/Android monitoring app
- [ ] **Multi-Tenant SaaS** - Isolated customer environments

---

## API Endpoints Summary

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/auth/login` | POST | No | Get JWT token |
| `/api/v1/auth/register` | POST | No | Create account |
| `/api/v1/auth/me` | GET | JWT | Get current user |
| `/api/v1/threats/analyze` | POST | API Key | Submit threat |
| `/api/v1/threats/recent` | GET | No | Get recent threats |
| `/api/v1/agents/` | GET | JWT | List all agents |
| `/api/v1/agents/register` | POST | API Key | Register agent |
| `/api/v1/settings/api-keys` | GET/POST | JWT | Manage API keys |
| `/api/v1/settings/admin/users` | GET | Admin | List users |
| `/api/v1/settings/admin/users/{id}/tier` | PUT | Admin | Change tier |
| `/api/v1/virustotal/check/hash` | POST | JWT | Check file hash |
| `/api/v1/virustotal/status` | GET | No | VT service status |

---

*Last Updated: November 29, 2025*
