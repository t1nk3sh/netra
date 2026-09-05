#!/usr/bin/env bash

# NETra ML Network Threat Detection Project Setup Script
# Configures directories, virtualenv, dependencies, docker image, and seeds models.

set -e

echo "=== Starting NETra ML Threat Detection Node Setup ==="

# 1. Verify standard system packages
for pkg in python3 pip3 docker; do
    if ! command -v "$pkg" &>/dev/null; then
        echo "⚠️  WARNING: '$pkg' is not installed or not in your PATH. Please install it."
    fi
done

# 2. Configure project directory structure
echo "Configuring operational telemetry directories..."
mkdir -p data/samples
mkdir -p data/zeek
mkdir -p data/live_captures
mkdir -p data/live_zeek
mkdir -p models/artifacts

# 3. Establish Python virtual environment & install requirements
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment in .venv..."
    python3 -m venv .venv
fi

source .venv/bin/activate
echo "Installing package dependencies from requirements.txt..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# 4. Pull Zeek container from registry
if command -v docker &>/dev/null; then
    echo "Pulling official Zeek Docker image..."
    if docker info &>/dev/null; then
        docker pull zeek/zeek:latest || echo "⚠️ Docker pull failed. Check internet access."
    elif groups | grep -qw docker; then
        echo "Docker requires group reloading. Pulling under group wrapper..."
        sg docker -c "docker pull zeek/zeek:latest" || echo "⚠️ Docker pull failed."
    else
        echo "⚠️  Docker daemon is not running or socket is permission denied. Skip pulling image."
    fi
else
    echo "⚠️  Docker is not installed. Zeek will require native 'zeek' binary or local Docker daemon setup."
fi

# 5. Train Seed Random Forest Classifier
echo "Training seed Random Forest model using generated samples..."
export PYTHONPATH=.
.venv/bin/python scripts/train_default_model.py

# 6. Configure raw packet capture capabilities for Python (enables non-root sniffing)
echo "Configuring raw socket capture capabilities for Python..."
REAL_PY=$(readlink -f .venv/bin/python 2>/dev/null || which python3)
if command -v setcap &>/dev/null && [ -f "$REAL_PY" ]; then
    sudo setcap cap_net_raw,cap_net_admin+eip "$REAL_PY" 2>/dev/null || echo "⚠️ Could not setcap automatically. You can run: sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python)"
fi

# 7. Make startup files executable
chmod +x start.sh

echo "=========================================================="
echo "🎯 Setup complete! Your system is ready."
echo "Launch the system with: ./start.sh"
echo "=========================================================="
