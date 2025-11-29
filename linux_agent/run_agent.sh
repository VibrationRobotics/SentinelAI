#!/bin/bash
echo "============================================"
echo "  SentinelAI Linux/macOS Agent v2.0"
echo "============================================"
echo ""

# API Key Configuration (optional - get from dashboard Settings > API Keys)
# Uncomment and set your API key for authenticated mode:
# export SENTINEL_API_KEY="sk_live_your_api_key_here"

# Dashboard URL (change for remote dashboard)
DASHBOARD_URL="${SENTINEL_DASHBOARD_URL:-http://localhost:8015}"

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "Installing dependencies..."
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

echo ""
echo "Dashboard: $DASHBOARD_URL"
if [ -n "$SENTINEL_API_KEY" ]; then
    echo "API Key: Configured"
else
    echo "API Key: Not set (set SENTINEL_API_KEY environment variable)"
fi
echo ""
echo "Starting agent... Press Ctrl+C to stop"
echo ""

# Check if running as root for full functionality
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Warning: Not running as root. Some features may be limited."
    echo "   Run with: sudo -E ./run_agent.sh (use -E to preserve environment)"
    echo ""
fi

# Build command with optional API key
CMD="python3 agent.py --dashboard $DASHBOARD_URL"
if [ -n "$SENTINEL_API_KEY" ]; then
    CMD="$CMD --api-key $SENTINEL_API_KEY"
fi

$CMD "$@"
