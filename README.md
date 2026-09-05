# NETra — ML-Based Network Threat Detection System

NETra is a passive, unidirectional network threat detection and forensic analysis system. It captures raw IP traffic, extracts high-dimensional flow statistics and metadata via Zeek and Scapy, evaluates flows against machine learning models (Random Forest, XGBoost, Isolation Forest), and delivers real-time threat intelligence through a high-performance NiceGUI dashboard.

---

## Key Features

- **Unidirectional Passive Monitoring**: Strictly read-only traffic capture with zero return-path communication, network injection, or active probing.
- **Multi-Model ML Detection Engine**: Pre-trained on CIC-IDS2017 benchmarks (Random Forest 98.3% F1, XGBoost 98.8% F1, Isolation Forest anomaly detector) across 37 statistical and connection-state features.
- **Reactive NiceGUI SOC Dashboard**: Clean, modern interface (Port 8501) featuring 7 operational views:
  - **Overview**: Threat status, active alert counters, telemetry gauges, and threat distribution charts.
  - **Alerts**: Searchable security events table with confidence scores, severity levels, and evidence payloads.
  - **Traffic**: Live ingress rate dynamics, connection state health, targeted port analysis, protocol breakdown, and flow stream.
  - **PCAP Analysis**: Deep forensic packet inspection, automated flow reconstruction, progress tracking, and intrusion summaries.
  - **Threat Analysis**: Behavioral threat cards, automated signature discovery, and MITRE-aligned classification.
  - **Models**: Live model registry, in-app benchmark evaluator against sample datasets, and one-click production model activation.
  - **System**: Service health telemetry, sensor status, pipeline latency metrics, and API diagnostics.
- **Dynamic Model Switching**: Hot-swap active inference models in real time without dropping active packet captures.
- **PCAP Forensic Pipeline**: Upload or select stored PCAPs to reconstruct bidirectional sessions and score threat vectors asynchronously.
- **Dual Theme Support**: Dark and light modes with persistent styling and responsive ECharts telemetry.

---

## Passive Operational Constraints

NETra is architected strictly as a non-intrusive network observer:
1. **No Network Injection**: Zero SYN scans, ping sweeps, DNS lookups, or return-path traffic are emitted to monitored networks.
2. **Metadata & Flow Analysis**: Inspection relies on packet headers, entropy, connection durations, byte ratios, and inter-arrival intervals without decrypting TLS payloads.
3. **Telemetry-Only Action**: Generates passive security alerts and structured audit logs without executing disruptive firewall triggers or RST packet injection.

---

## Architecture Overview

```
                          [ Monitored Network TAP / SPAN / Interface ]
                                              │ (Passive Sniffing)
                                              ▼
                                   ┌──────────────────────┐
                                   │  Scapy Live Sniffer  │
                                   │  & PCAP Ingestion    │
                                   └──────────┬───────────┘
                                              │ (PCAPs / Raw Packets)
                                              ▼
                                   ┌──────────────────────┐
                                   │ Zeek Log Parser /    │
                                   │ Scapy Flow Extractor │
                                   └──────────┬───────────┘
                                              │ (Normalized Flows)
                                              ▼
                                   ┌──────────────────────┐
                                   │ ML Feature Pipeline  │
                                   │ (37 Flow Features)   │
                                   └──────────┬───────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
           ┌──────────────────────┐                       ┌──────────────────────┐
           │ ML Inference Engine  │                       │ Rule-based Threat    │
           │ (RF / XGB / IsoForest│                       │ Detectors (DDoS, etc)│
           └──────────┬───────────┘                       └──────────┬───────────┘
                      │                                               │
                      └───────────────────────┬───────────────────────┘
                                              │ (Alerts & Flow Telemetry)
                                              ▼
                                   ┌──────────────────────┐
                                   │ FastAPI Backend      │ (Port 8000)
                                   │ REST & WebSockets    │
                                   └──────────┬───────────┘
                                              │
                                              ▼
                                   ┌──────────────────────┐
                                   │ NiceGUI SOC App      │ (Port 8501)
                                   │ (Reactive Dashboard) │
                                   └──────────────────────┘
```

---

## Prerequisites

- **Linux** (Kernel 5.x / 6.x recommended)
- **Python 3.12+**
- **Docker** (optional, for Zeek containerized log parsing)
- **libpcap / tcpdump** (for raw packet capture capabilities)

---

## Quick Start

### 1. One-Click Setup
Create the virtual environment, install dependencies, fetch the Zeek Docker image, and train the baseline model:
```bash
./setup.sh
```

### 2. Live Capture Permissions (Optional)
To capture on live network interfaces without running as root:
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python)
```

### 3. Launch Services
Start the FastAPI backend (port 8000), the NiceGUI dashboard (port 8501), and the live detection sensor:
```bash
# Replay mode (uses sample traffic)
./start.sh

# Live interface capture mode
./start.sh --live --interface=wlo1
```

---

## Machine Learning & Model Registry

The inference engine transforms raw connection flows into 37 standardized features covering byte rates, packet ratios, TCP state sequences, and duration entropy.

### Pre-Trained Models (`models/artifacts/`)
- `default_rf.joblib`: Active production Random Forest model.
- `cic_rf.joblib`: Random Forest trained on 200k CIC-IDS2017 flows (98.3% F1 score).
- `cic_xgboost.joblib`: XGBoost classifier for ultra-low latency inference (<0.001 ms/flow, 98.8% F1 score).
- `cic_isolation_forest.joblib`: Unsupervised anomaly detector for zero-day threat detection.
- `sample_rf.joblib`: Synthetic baseline classifier.

### Training Custom Models
```bash
# Train Random Forest on custom CSV/Parquet dataset
PYTHONPATH=. .venv/bin/python scripts/train_default_model.py \
    --data data/samples/your_dataset.parquet \
    --model-type random_forest \
    --output models/artifacts/custom_rf.joblib

# Train XGBoost
PYTHONPATH=. .venv/bin/python scripts/train_default_model.py \
    --data data/samples/cic_combined.parquet \
    --model-type xgboost \
    --output models/artifacts/cic_xgboost.joblib
```

---

## Project Structure

```
├── backend/               # FastAPI backend endpoints (/alerts, /flows, /analyze_pcap)
├── capture/               # Scapy live capture sniffer & forensic PCAP analyzer
├── config/                # Threshold and classification configurations
├── dashboard/             # NiceGUI dashboard application
│   ├── nicegui_app.py     # Main reactive dashboard UI (7 pages, theme engine)
│   ├── services/          # Backend API client integration
│   └── utils/             # Formatting and timezone utilities
├── detection/             # Rule-based threat detectors (DDoS, Port Scans)
├── features/              # Statistical and flow feature extractors
├── inference/             # ML predictor runtime and threat classifier
├── models/                # Model training, preprocessing pipeline, and artifacts
├── scripts/               # Launcher, dataset combiners, and live sensor daemon
├── streaming/             # Tumbling window manager and streaming pipeline
├── tests/                 # Unit, backend, and integration test suite
├── zeek/                  # Zeek container runner and log parser
├── setup.sh               # One-click environment bootstrap script
└── start.sh               # Unified service launcher script
```

---

## Testing

Run the full test suite (214 tests):
```bash
.venv/bin/pytest --tb=short -q
```

Run specific test modules:
```bash
# Test ML predictor and threat classifier
.venv/bin/pytest tests/unit/test_predictor.py --tb=short

# Test PCAP forensic analyzer
.venv/bin/pytest tests/unit/test_pcap_analyzer.py --tb=short

# Test backend REST endpoints
.venv/bin/pytest tests/unit/test_backend.py --tb=short
```
