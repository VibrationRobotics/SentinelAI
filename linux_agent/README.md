# SentinelAI Linux/macOS Agent

Native agent for Linux and macOS systems that monitors and reports to the SentinelAI dashboard.

## 🚀 Quick Start

### Linux
```bash
cd linux_agent
chmod +x run_agent.sh
./run_agent.sh

# For full functionality (firewall control, auth logs):
sudo ./run_agent.sh
```

### macOS
```bash
cd linux_agent
chmod +x run_agent.sh
./run_agent.sh

# For full functionality:
sudo ./run_agent.sh
```

## 📋 Features

### Process Monitoring
- Tracks all running processes
- Detects suspicious process names (mimikatz, netcat, miners)
- Monitors for reverse shell patterns
- Detects executables running from /tmp
- Suspicious command-line detection

### Network Monitoring
- Monitors active network connections
- Detects connections to suspicious ports (4444, 5555, 1337, etc.)
- Tracks connection statistics

### Authentication Log Monitoring
- Monitors `/var/log/auth.log` (Linux) or `/var/log/system.log` (macOS)
- Detects failed login attempts
- Tracks sudo command usage

### Firewall Control
- **Linux**: Uses iptables to block malicious IPs
- **macOS**: Uses pf (packet filter) to block IPs

## 🔧 Command Line Options

```bash
python3 agent.py [OPTIONS]

Options:
  -d, --dashboard URL    Dashboard URL (default: http://localhost:8015)
  -v, --verbose          Enable verbose logging
  --no-ai                Disable AI analysis
```

## 🛡️ Detected Threats

### Suspicious Executables
- mimikatz, pwdump, lazagne (credential theft)
- nc, ncat, netcat, socat (network tools)
- meterpreter, cobaltstrike (attack frameworks)
- xmrig, minerd, cpuminer (crypto miners)

### Suspicious Command Patterns
- Reverse shells (`bash -i`, `/dev/tcp/`)
- Download and execute (`curl | bash`)
- Base64 encoded commands
- Credential file access (`/etc/passwd`, `/etc/shadow`)
- Firewall tampering (`iptables -F`)

## 📁 Files

```
linux_agent/
├── agent.py           # Main agent script
├── requirements.txt   # Python dependencies
├── run_agent.sh       # Startup script
└── README.md          # This file
```

## 🔐 Permissions

For full functionality, run as root:
- Reading `/var/log/auth.log`
- Blocking IPs with iptables/pf
- Monitoring all processes

Without root, the agent still monitors:
- User processes
- Network connections
- Basic threat detection

## 🌐 Dashboard Integration

The agent registers with the SentinelAI dashboard and appears in the "Connected Agents" section. All detected threats are sent to the dashboard for AI analysis and visualization.
