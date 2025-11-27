#!/bin/bash
echo "============================================"
echo "  SentinelAI Linux/macOS Agent"
echo "============================================"
echo ""

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
echo "Starting agent... Press Ctrl+C to stop"
echo ""

# Check if running as root for full functionality
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Warning: Not running as root. Some features may be limited."
    echo "   Run with: sudo ./run_agent.sh"
    echo ""
fi

python3 agent.py --dashboard http://localhost:8015 "$@"
