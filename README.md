# SentinelAI: Autonomous AI-Powered Threat Detection & Prevention

An intelligent cybersecurity system that provides **real-time threat detection, analysis, and autonomous response** for Windows systems. Combines a Docker-based dashboard with a native Windows agent for complete protection.

## 🛡️ Key Features

### Core Protection
- **Windows Agent**: Native Windows monitoring for processes, network, and event logs
- **Auto-Response System**: Automatically blocks malicious IPs and terminates suspicious processes
- **Real-Time Dashboard**: Beautiful web UI showing all threats and system status
- **AI-Driven Analysis**: Machine learning threat classification and response generation

### Monitoring Capabilities
- **Process Monitor**: Detects mimikatz, encoded PowerShell, attack tools
- **Network Monitor**: Identifies port scans, brute force, reverse shells
- **File Scanner**: YARA rules, hash checking, quarantine capabilities
- **Log Aggregation**: Windows Event Logs, SSH logs, syslog parsing
- **Windows Firewall**: Native firewall control via netsh

### Integrations
- **Azure AI Services**: OpenAI, Anomaly Detector, Content Safety, AI Search
- **Snort IDS**: Ingest alerts from Snort intrusion detection
- **Docker Projects**: Connect any Docker container for monitoring
- **REST API**: Full API for custom integrations

## 🚀 Quick Start (Recommended)

### Step 1: Start the Dashboard (Docker)

```powershell
# Clone and start
cd SentinelAI
docker-compose up -d
```

Dashboard available at: **http://localhost:8015**

### Step 2: Run the Windows Agent (Native)

```powershell
# Open PowerShell as Administrator
cd SentinelAI\windows_agent

# Create virtual environment (first time only)
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the agent
python agent.py
```

The agent will:
- ✅ Monitor all Windows processes for threats
- ✅ Watch network connections for suspicious activity
- ✅ Parse Windows Security Event Logs
- ✅ Report everything to the Docker dashboard
- ✅ Block malicious IPs via Windows Firewall

---

## 📦 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR WINDOWS PC                          │
│                                                                  │
│  ┌──────────────────────┐      ┌──────────────────────────────┐ │
│  │   Windows Agent      │      │      Docker Desktop          │ │
│  │   (Native Python)    │      │  ┌────────────────────────┐  │ │
│  │                      │ HTTP │  │   SentinelAI Dashboard │  │ │
│  │ • Process Monitor    │─────►│  │   (FastAPI + Web UI)   │  │ │
│  │ • Network Monitor    │      │  │                        │  │ │
│  │ • Event Log Parser   │      │  │ • AI Threat Analysis   │  │ │
│  │ • Firewall Control   │      │  │ • Auto-Response        │  │ │
│  │                      │      │  │ • Visualization        │  │ │
│  └──────────────────────┘      │  └────────────────────────┘  │ │
│           ▲                    │             ▲                 │ │
│           │                    │             │                 │ │
│    Monitors YOUR PC            │    Can connect to OTHER       │ │
│    (processes, network,        │    Docker projects too!       │ │
│     files, event logs)         │                               │ │
│                                └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔗 Connecting Other Docker Projects

SentinelAI can receive threat data from ANY Docker container. Add this to your other project's code:

```python
import requests

# Send threat to SentinelAI
requests.post("http://host.docker.internal:8015/api/v1/threats/analyze", json={
    "source_ip": "192.168.1.100",
    "threat_type": "suspicious_activity",
    "severity": "HIGH",
    "description": "Unusual database query pattern detected",
    "payload": '{"query": "SELECT * FROM users"}'
})
```

Or from docker-compose, add SentinelAI to your network:

```yaml
# In your other project's docker-compose.yml
services:
  your-app:
    # ... your config ...
    environment:
      - SENTINEL_API=http://host.docker.internal:8015/api/v1
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

---

## 🖥️ Full Setup Options

### Option A: Docker Dashboard + Windows Agent (Recommended)

Best for: **Full Windows PC protection**

```powershell
# 1. Start Dashboard
docker-compose up -d

# 2. Run Windows Agent (as Admin)
cd windows_agent
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python agent.py
```

### Option B: Docker Only (Testing/Development)

Best for: **Testing the dashboard, no Windows protection**

```powershell
docker-compose up -d
# Dashboard at http://localhost:8015
# Only monitors Docker container, NOT your Windows PC
```

### Option C: Fully Native (No Docker)

Best for: **Maximum Windows integration**

```powershell
# Create venv in main directory
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt

# Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8015

# In another terminal, run the agent
cd windows_agent
python agent.py --dashboard http://localhost:8015
```

---

## 📋 Setup Details

### Prerequisites
- **Python 3.10+**
- **Docker Desktop** (for dashboard)
- **Administrator rights** (for Windows Agent firewall control)

### Docker Deployment

```powershell
# Build and start
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f web

# Stop
docker-compose down
```

### Using Snort Connector with Docker

The Snort connector is included as a separate service in the Docker Compose configuration. It automatically monitors the `/app/snort_logs/alert` file inside the container, which is mapped to the `./snort_logs/alert` file in your project directory.

1. Start the Snort connector service:
```bash
docker-compose up -d snort-connector
```

2. View Snort connector logs:
```bash
docker-compose logs -f snort-connector
```

3. Test with sample alerts:
Add Snort-formatted alerts to the `./snort_logs/alert` file to trigger the connector. The connector will automatically detect changes and send the alerts to the CyberCare API.

4. Configure the connector:
You can customize the connector behavior by editing the environment variables in the `docker-compose.yml` file:
```yaml
environment:
  - SNORT_LOG_PATH=/app/snort_logs/alert
  - API_URL=http://web:8000/api/v1/threats/analyze
  - POLL_INTERVAL=5
  # Uncomment to enable batch mode
  # - BATCH_MODE=--batch --batch-size 10
  # Database configuration
  # - DB_PATH=/app/data/snort_threats.db
  # - RETRY_UNSENT=true
  # - RETRY_INTERVAL=60
  # - RETRY_LIMIT=3
```

## API Documentation

Once the application is running, you can access the interactive API documentation at:
- Swagger UI: `http://localhost:8005/docs`
- ReDoc: `http://localhost:8005/redoc`

### Key Endpoints

#### Health Check
```
GET /api/v1/health
```
Returns the health status of the application.

#### Authentication
```
POST /api/v1/auth/login
```
Authenticate and get an access token.

```
POST /api/v1/auth/register
```
Register a new user.

```
GET /api/v1/auth/me
```
Get current user information.

#### Threat Analysis
```
POST /api/v1/threats/analyze
```
Analyze a single security threat.

```
POST /api/v1/threats/batch-analyze
```
Analyze multiple security threats in background.

```
GET /api/v1/threats/status/{job_id}
```
Check the status of a batch analysis job.

```
GET /api/v1/threats/recent
```
Get recent analyzed threats.

## Monitoring & Simulation Tools

CyberCare comes with built-in tools for threat monitoring and simulation, perfect for testing and demonstrations.

### Threat Simulator

The threat simulator generates synthetic security events to test the system's detection and response capabilities.

```bash
# Generate a single threat
python tools/threat_simulator.py --url http://localhost:8005/api/v1/threats/analyze

# Generate a batch of threats
python tools/threat_simulator.py --batch --batch-url http://localhost:8005/api/v1/threats/batch-analyze --batch-size 5

# Run continuous simulation
python tools/threat_simulator.py --continuous --min-interval 5 --max-interval 15 --duration 60
```

### Snort IDS Connector

The Snort connector monitors Snort IDS alert logs and forwards detected threats to the CyberCare API.

```bash
# Monitor a Snort alert log file using polling
python tools/snort_connector.py --log-path /path/to/snort/alert --api-url http://localhost:8005/api/v1/threats/analyze --poll-interval 5

# Use file system monitoring (more efficient)
python tools/snort_connector.py --log-path /path/to/snort/alert --api-url http://localhost:8005/api/v1/threats/analyze --watch

# Process alerts in batch mode
python tools/snort_connector.py --log-path /path/to/snort/alert --api-url http://localhost:8005/api/v1/threats/analyze --batch-mode --batch-size 10

# Enable Azure AI integration for enhanced threat analysis
python tools/snort_connector.py --log-path /path/to/snort/alert --api-url http://localhost:8005/api/v1/threats/analyze --use-ai

# Specify custom database path for persistent storage
python tools/snort_connector.py --log-path /path/to/snort/alert --db-path /path/to/custom/database.db

# Configure retry for unsent alerts
python tools/snort_connector.py --log-path /path/to/snort/alert --retry-unsent --retry-interval 60 --retry-limit 3
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://postgres:postgres@db:5432/cybercare` |
| `REDIS_URL` | Redis connection string | `redis://redis:6379/0` |
| `SECRET_KEY` | JWT secret key | `changeme` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration time | `30` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `LOG_FILE` | Log file path | `app.log` |
| `USE_AZURE_AI` | Enable Azure AI services | `False` |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI service endpoint | - |
| `AZURE_OPENAI_KEY` | Azure OpenAI API key | - |
| `AZURE_OPENAI_DEPLOYMENT_ID` | Azure OpenAI deployment ID | - |
| `AZURE_ANOMALY_DETECTOR_ENDPOINT` | Azure Anomaly Detector endpoint | - |
| `AZURE_ANOMALY_DETECTOR_KEY` | Azure Anomaly Detector API key | - |
| `AZURE_CONTENT_SAFETY_ENDPOINT` | Azure Content Safety endpoint | - |
| `AZURE_CONTENT_SAFETY_KEY` | Azure Content Safety API key | - |
| `AZURE_SEARCH_ENDPOINT` | Azure AI Search endpoint | - |
| `AZURE_SEARCH_KEY` | Azure AI Search API key | - |
| `AZURE_SEARCH_INDEX_NAME` | Azure AI Search index name | - |
| `AZURE_METRICS_ADVISOR_ENDPOINT` | Azure Metrics Advisor endpoint | - |
| `AZURE_METRICS_ADVISOR_SUBSCRIPTION_KEY` | Azure Metrics Advisor subscription key | - |
| `AZURE_METRICS_ADVISOR_API_KEY` | Azure Metrics Advisor API key | - |

## Project Structure

```
cybercare/
├── app/
│   ├── api/
│   │   ├── deps.py             # Dependency injection
│   │   └── endpoints/
│   │       ├── auth.py         # Authentication endpoints
│   │       ├── threats.py      # Threat analysis endpoints
│   │       ├── incidents.py    # Incident management
│   │       └── analysis.py     # Analytics and reporting
│   ├── core/
│   │   ├── config.py           # Application configuration
│   │   └── security.py         # Security utilities
│   ├── db/
│   │   ├── base.py             # Database connection
│   │   └── models.py           # SQLAlchemy models
│   ├── models/
│   │   ├── ai/
│   │   │   ├── threat_classifier.py  # AI threat classification
│   │   │   └── azure/          # Azure AI services integration
│   │   │       ├── openai_service.py        # Azure OpenAI integration
│   │   │       ├── anomaly_detector.py      # Azure Anomaly Detector
│   │   │       ├── content_safety.py        # Azure Content Safety
│   │   │       ├── search_service.py        # Azure AI Search
│   │   │       ├── metrics_advisor.py       # Azure Metrics Advisor
│   │   │       └── ai_service_manager.py    # Unified AI service manager
│   │   └── domain/
│   │       ├── user.py         # User domain models
│   │       └── threat.py       # Threat domain models
│   ├── services/
│   │   ├── threat_detection.py # Threat detection service
│   │   └── response_automation.py  # Automated response
│   └── main.py                 # Application entry point
├── tests/
│   ├── conftest.py             # Test fixtures
│   ├── test_auth.py            # Authentication tests
│   └── test_threats.py         # Threat analysis tests
├── alembic/                    # Database migrations
├── docker-compose.yml          # Docker configuration
├── Dockerfile                  # Docker build instructions
├── .env.example                # Environment variables template
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation
```

## Version History

- **0.2.0** - Azure AI Integration
  - Added Azure OpenAI, Anomaly Detector, Content Safety, AI Search, and Metrics Advisor
  - Enhanced Snort connector with AI capabilities
  - Expanded database schema for AI analysis
  - Improved logging and error handling
- **0.1.0** - Initial release with core functionality
  - AI-powered threat detection
  - Basic authentication
  - Threat analysis API
  - Docker containerization

## License

This project is licensed under the MIT License - see the LICENSE file for details.
