#!/usr/bin/env bash

# NETra ML Network Threat Detection Startup Script
# Automatically starts backend, frontend, and opens browser.

set -e

# ── ASCII Splash ──────────────────────────────────────────────────────
splash() {
    echo ""
    if command -v figlet &>/dev/null; then
        figlet -w 120 "NETra"
    else
        echo -e "\033[1;34m"
        cat <<'EOF'
  _   _      _     _______             _    
 | \ | |    | |   |__   __|           | |   
 |  \| | ___| |_     | |_ __ __ _  ___| | __
 | . ` |/ _ \ __|    | | '__/ _` |/ __| |/ /
 | |\  |  __/ |_     | | | | (_| | (__|   < 
 |_| \_|\___|\__|    |_|_|  \__,_|\___|_|\_\
                                            
                                            
EOF
        echo -e "\033[0m"
    fi
    echo -e "\033[1;36m   ML-Based Network Threat Detection\033[0m"
    echo -e "\033[0;90m   Passive ingress monitoring • Real-time threat analysis\033[0m"
    echo ""
}
splash
# ──────────────────────────────────────────────────────────────────────

# Parse arguments first before starting any services
LIVE_MODE=""
INTERFACE="any"
ROTATION="5"

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
        --rotation|-r)
            ROTATION="$2"
            shift 2
            ;;
        --rotation=*)
            ROTATION="${1#*=}"
            shift
            ;;
        -r=*)
            ROTATION="${1#*=}"
            shift
            ;;
        -h|--help)
            echo "NETra ML Network Threat Detection Ingest Agent Launcher."
            echo ""
            echo "Usage: ./start.sh [options]"
            echo ""
            echo "Options:"
            echo "  --live               Enable live capture mode"
            echo "  -i, --interface      Network interface to sniff (e.g. eth0, wlo1) (default: any)"
            echo "  -r, --rotation       PCAP rotation interval in seconds (default: 5)"
            echo "  -h, --help           Show help options"
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
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/service.log"

# Empty the shared service log at each startup for a clean slate
: > "$LOG_FILE"

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
export NETRA_LOG_DIR="$LOG_DIR"
echo "Starting FastAPI Backend on http://localhost:8000 (logs -> $LOG_FILE)..."
uvicorn backend.main:app --port 8000 --log-level info >>"$LOG_FILE" 2>&1 &
BACKEND_PID=$!

# Wait briefly for backend to initialize
sleep 2

# 3. Start Lightweight NiceGUI Frontend Dashboard
echo "Starting Lightweight NiceGUI Dashboard on http://localhost:8501..."
.venv/bin/python dashboard/nicegui_app.py >>"$LOG_FILE" 2>&1 &
FRONTEND_PID=$!

# 4. Start Threat Detection Sensor
if [ -n "$LIVE_MODE" ]; then
    echo "Starting LIVE Capture Sensor on interface: $INTERFACE (rotation: ${ROTATION}s)..."
    .venv/bin/python scripts/live_detector.py --live --interface "$INTERFACE" --rotation "$ROTATION" >>"$LOG_FILE" 2>&1 &
else
    echo "Starting Sensor (dynamic UI controllable mode, rotation: ${ROTATION}s)..."
    .venv/bin/python scripts/live_detector.py --rotation "$ROTATION" >>"$LOG_FILE" 2>&1 &
fi
SENSOR_PID=$!

# Wait briefly for Dashboard and Sensor to initialize
sleep 2

# 5. Open Default Browser & print clickable log/view links
echo "Opening dashboard in your browser..."
python3 -m webbrowser http://localhost:8501 || true

echo ""
echo -e "\033[1;36m──────────────────────────────────────────────────────────\033[0m"
echo -e "\033[1;32m NETra is running\033[0m"
echo -e "\033[0;32m Dashboard : http://localhost:8501       \033[0m"
echo -e "\033[0;32m Backend   : http://localhost:8000/logs  \033[0m \033[0;90m(View live service logs in browser)\033[0m"
echo -e "\033[0;90m Log file  : $LOG_FILE\033[0m"
echo -e "\033[1;36m──────────────────────────────────────────────────────────\033[0m"
echo ""
echo "Ctrl+C to stop all services."

# Keep script running to maintain logs and wait for Ctrl+C
wait
