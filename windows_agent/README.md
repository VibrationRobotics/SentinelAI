# SentinelAI Windows Agent

Native Windows agent for **real-time threat detection and autonomous protection** of your Windows PC.

## 🛡️ What It Protects

- **Process Monitoring**: Detects mimikatz, encoded PowerShell, attack tools, suspicious executables
- **Network Monitoring**: Identifies reverse shells, C2 traffic, port scans, brute force
- **Windows Event Logs**: Failed logins, privilege escalation, new services, audit log tampering
- **Windows Firewall**: Automatically blocks malicious IPs
- **Advanced ML v2.0**: 150+ feature extraction, ensemble models, behavioral analysis
- **MITRE ATT&CK**: Maps detections to 45+ techniques
- **Autonomous Learning**: Model improves over time from real-world data
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

## 🤖 AI & ML-Powered Analysis

The agent uses a **three-stage detection system**:

### Stage 1: Advanced ML v2.0 (Local - FREE)
The primary detection engine with 150+ features:
- **Feature Extraction**: Process, network, file, registry, behavioral, context, anomaly
- **Ensemble Models**: LightGBM + XGBoost + Random Forest weighted voting
- **Behavioral Analysis**: Detects attack chains (reconnaissance, lateral movement, exfiltration)
- **Anomaly Detection**: Baseline learning with Isolation Forest
- **MITRE ATT&CK**: Maps to 45+ techniques with confidence scores

### Stage 2: Legacy Heuristics (Fallback)
- Whitelist check (known safe apps)
- Blacklist check (known malware names)
- Command line pattern matching

### Stage 3: OpenAI GPT-4 (Dashboard - Optional)
For uncertain cases (40-70% confidence), escalates to AI:
- Deep threat classification
- Remediation recommendations
- False positive detection

### Autonomous Learning
The ML model **improves over time**:
- Learns from high-confidence (>80%) predictions
- Accepts user feedback to correct mistakes
- Auto-retrains every 24 hours with 500+ samples
- Persists learning between agent restarts

### Example Output
```
2025-11-29 - SentinelAgent - INFO - Advanced ML v2.0: Enabled
2025-11-29 - SentinelAgent - INFO - Autonomous ML learning enabled - model will improve over time
2025-11-29 - SentinelAgent - WARNING - THREAT DETECTED [ML]: mimikatz.exe - CRITICAL (conf: 0.92)
2025-11-29 - SentinelAgent - INFO - MITRE: T1003.001 (LSASS Memory), T1003.002 (SAM Database)
```

## 🧠 Training the ML Model

The agent comes with a pre-trained model, but you can retrain:

```powershell
# Activate virtual environment
.\venv\Scripts\activate

# Train with synthetic data (5000 samples)
python train_ml.py

# Run tests
python test_ml.py
```

### Model Files
```
windows_agent/ml/models/
├── ensemble_model.pkl      # Trained ML models
├── baseline.pkl            # Anomaly detection baseline
└── online_training_data.pkl # Collected training samples
```

### Benchmark Results
Run `python benchmark_ml.py` to test the model:

| Metric | Score |
|--------|-------|
| **Accuracy** | 96.5% |
| **Precision** | 99.7% (when we say threat, we're right) |
| **Recall** | 89.9% (catches 90% of threats) |
| **F1 Score** | 94.5% |
| **False Positive Rate** | 0.2% (almost no false alarms) |

Trained on 5,000 synthetic samples (67% benign, 33% malicious).

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
