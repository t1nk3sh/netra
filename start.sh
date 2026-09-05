#!/usr/bin/env bash

# NETra ML Network Threat Detection Startup Script
# Automatically starts backend, frontend, and opens browser.

set -e

# Parse arguments first before starting any services
LIVE_MODE=""
INTERFACE="any"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --live)
            LIVE_MODE="--live"
            shift
            ;;
        --interface|-i)
            INTERFACE="$2"
            shift 2
            ;;
        --interface=*)
            INTERFACE="${1#*=}"
            shift
            ;;
        -i=*)
            INTERFACE="${1#*=}"
            shift
            ;;
        -h|--help)
            echo "NETra ML Network Threat Detection Ingest Agent Launcher."
            echo ""
            echo "Usage: ./start.sh [options]"
            echo ""
            echo "Options:"
            echo "  --live            Enable live capture mode"
            echo "  -i, --interface   Network interface to sniff (e.g. eth0, wlo1) (default: any)"
            echo "  -h, --help        Show help options"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for instructions."
            exit 1
            ;;
    esac
done

# Check and grant raw packet capture capabilities to Python upfront
REAL_PY=$(readlink -f .venv/bin/python 2>/dev/null || which python3)
if command -v setcap &>/dev/null && [ -f "$REAL_PY" ]; then
    if ! getcap "$REAL_PY" 2>/dev/null | grep -q "cap_net_raw"; then
        echo "🔒 Configuring raw packet capture permissions for Python (one-time setup)..."
        sudo setcap cap_net_raw,cap_net_admin+eip "$REAL_PY" 2>/dev/null || {
            echo "⚠️ Note: Could not set packet capture capability automatically. If you switch to live capture, run:"
            echo "   sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python)"
        }
    fi
fi

# Check docker socket permissions
if command -v docker &>/dev/null && ! docker info &>/dev/null; then
    echo "⚠️  Warning: Cannot connect to Docker API. Attempting socket permission adjustment..."
    sudo chmod 666 /var/run/docker.sock || {
        echo "❌ Error: Failed to secure Docker connection. Please run:"
        echo "   sudo chmod 666 /var/run/docker.sock"
    }
fi

# Setup clean termination of background tasks on exit/Ctrl+C
cleanup() {
    echo -e "\nStopping all services..."
    if [ -n "$BACKEND_PID" ]; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi
    if [ -n "$FRONTEND_PID" ]; then
        kill "$FRONTEND_PID" 2>/dev/null || true
    fi
    if [ -n "$SENSOR_PID" ]; then
        kill "$SENSOR_PID" 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# 1. Activate Python virtual environment and check requirements
if [ ! -d ".venv" ]; then
    echo "Python virtual environment .venv not found. Creating..."
    python3 -m venv .venv
fi

source .venv/bin/activate
echo "Ensuring python dependencies are up to date..."
pip install -r requirements.txt --quiet

# 2. Set environment and start FastAPI & WebSocket Backend Server
export PYTHONPATH=.
echo "Starting FastAPI Backend on http://localhost:8000..."
uvicorn backend.main:app --port 8000 --log-level info &
BACKEND_PID=$!

# Wait briefly for backend to initialize
sleep 2

# 3. Start Lightweight NiceGUI Frontend Dashboard
echo "Starting Lightweight NiceGUI Dashboard on http://localhost:8501..."
.venv/bin/python dashboard/nicegui_app.py &
FRONTEND_PID=$!

# 4. Start Threat Detection Sensor
if [ -n "$LIVE_MODE" ]; then
    echo "Starting LIVE Capture Sensor on interface: $INTERFACE..."
    .venv/bin/python scripts/live_detector.py --live --interface "$INTERFACE" &
else
    echo "Starting Sensor (dynamic UI controllable mode)..."
    .venv/bin/python scripts/live_detector.py &
fi
SENSOR_PID=$!

# Wait briefly for Dashboard and Sensor to initialize
sleep 2

# 5. Open Default Browser
echo "Opening dashboard in your browser..."
python3 -m webbrowser http://localhost:8501 || true

# Keep script running to maintain logs and wait for Ctrl+C
wait
