# SentinelAI Windows Agent

Native Windows agent for **real-time threat detection and autonomous protection** of your Windows PC.

## 🛡️ What It Protects

- **Process Monitoring**: Detects mimikatz, encoded PowerShell, attack tools, suspicious executables
- **Network Monitoring**: Identifies reverse shells, C2 traffic, port scans, brute force
- **Windows Event Logs**: Failed logins, privilege escalation, new services, audit log tampering
- **Windows Firewall**: Automatically blocks malicious IPs
- **Reports to Dashboard**: All events appear in the Docker dashboard in real-time

## 🚀 Quick Start

### 1. Start the Dashboard (Docker)

```powershell
# In the main SentinelAI directory
cd F:\DESKTOP\sentinel\SentinelAI
docker-compose up -d
```

### 2. Set Up Virtual Environment (Recommended)

```powershell
# Open PowerShell as Administrator
cd F:\DESKTOP\sentinel\SentinelAI\windows_agent

# Create virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Agent

```powershell
# Make sure venv is activated
.\venv\Scripts\activate

# Run the agent
python agent.py
```

Or use the batch file (after venv setup):
```powershell
run_agent.bat
```

### 4. Verify It's Working

You should see:
```
╔═══════════════════════════════════════════════════════════╗
║           SentinelAI Windows Agent v1.0                   ║
║     Native Windows Protection & Threat Detection          ║
╚═══════════════════════════════════════════════════════════╝

2024-XX-XX - SentinelAgent - INFO - Windows Agent initialized - Dashboard: http://localhost:8015
2024-XX-XX - SentinelAgent - INFO - Process monitor started
2024-XX-XX - SentinelAgent - INFO - Network monitor started
2024-XX-XX - SentinelAgent - INFO - Event log monitor started
2024-XX-XX - SentinelAgent - INFO - Successfully registered with dashboard
```

## Command Line Options

```
python agent.py [OPTIONS]

Options:
  -d, --dashboard URL    Dashboard URL (default: http://localhost:8015)
  -v, --verbose          Enable verbose logging
  --no-ai                Disable AI analysis (use heuristics only)
```

## 🤖 AI-Powered Analysis

The agent uses a **two-stage detection system**:

### Stage 1: Fast Heuristics (Local)
- Whitelist check (known safe apps)
- Blacklist check (known malware names)
- Command line pattern matching

### Stage 2: AI Analysis (Dashboard)
For uncertain processes, the agent sends data to the dashboard AI:
- Processes running from unusual locations (Temp, Downloads)
- PowerShell/CMD with complex arguments
- Script hosts (wscript, cscript, mshta)
- Executables from user directories

The AI returns:
- **Threat classification** (malware type)
- **Confidence score** (0-1)
- **Recommended action** (block, monitor, allow)

### Example Output
```
2025-11-27 - SentinelAgent - INFO - AI-powered analysis: Enabled
2025-11-27 - SentinelAgent - DEBUG - Requesting AI analysis for: suspicious.exe
2025-11-27 - SentinelAgent - WARNING - SUSPICIOUS PROCESS [AI]: suspicious.exe (PID: 1234) - AI detected threat: Potential credential stealer
```

## What It Monitors

### Suspicious Processes
- Known attack tools (mimikatz, pwdump, lazagne, etc.)
- Encoded PowerShell commands
- Processes running from temp directories
- Download cradles (certutil, bitsadmin)

### Network Connections
- Connections to suspicious ports (4444, 5555, 1337, etc.)
- Potential reverse shells
- Unusual outbound connections

### Windows Event Logs
- Failed login attempts (Event 4625)
- Privilege escalation (Event 4672)
- New services installed (Event 4697)
- Scheduled tasks created (Event 4698)
- User account changes
- Audit log cleared (Event 1102)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows Host                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           SentinelAI Windows Agent                   │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
│  │  │ Process  │ │ Network  │ │ EventLog │            │   │
│  │  │ Monitor  │ │ Monitor  │ │ Monitor  │            │   │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘            │   │
│  │       └────────────┼────────────┘                   │   │
│  │                    ▼                                 │   │
│  │            Event Queue                               │   │
│  │                    │                                 │   │
│  │                    ▼                                 │   │
│  │         HTTP POST to Dashboard ──────────────────────┼───┼──┐
│  └─────────────────────────────────────────────────────┘   │  │
└─────────────────────────────────────────────────────────────┘  │
                                                                  │
┌─────────────────────────────────────────────────────────────┐  │
│                    Docker Container                          │  │
│  ┌─────────────────────────────────────────────────────┐   │  │
│  │           SentinelAI Dashboard                       │◄──┼──┘
│  │  - Receives agent events                             │   │
│  │  - AI threat analysis                                │   │
│  │  - Visualization & alerts                            │   │
│  │  - Auto-response actions                             │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Running as Administrator

For full capabilities (firewall control, event log access), run as Administrator:

1. Right-click Command Prompt or PowerShell
2. Select "Run as administrator"
3. Navigate to the windows_agent directory
4. Run `python agent.py`

## Logs

The agent creates a log file `sentinel_agent.log` in the current directory.

## Troubleshooting

### "Dashboard not reachable"
- Ensure Docker is running: `docker-compose up -d`
- Check the dashboard URL is correct
- Verify firewall allows connections to port 8015

### "Access Denied" errors
- Run as Administrator
- Some processes may be protected by Windows

### No events appearing
- Check the agent is running (look for log output)
- Verify the dashboard is receiving events at `/api/v1/threats/recent`
