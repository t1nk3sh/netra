# NETra - ML-Based Network Threat Detection Enclave (Passive Monitor)

A passive, strictly read-only unidirectional network threat monitoring prototype. It captures raw network traffic, parses it into connection logs via Zeek, extracts time-series features, runs ML inference, and displays security alerts in real-time on a modern SaaS-style NiceGUI dashboard.

---

## 🛡️ Passive Operational Constraints
This dashboard works strictly as a passive monitor:
* **No network injection**: Zero probes, active scans, or return-path communications are sent back into the monitored networks.
* **No decryption**: Traffic analysis is strictly metadata-based (resolving protocol ratios, packet gaps, and connection entropy headers in TLS/DNS) with zero payload decryption.
* **No disruption**: Implements strictly telemetry alerts without trigger mitigation commands.

---

## ⚙️ Prerequisites & Tool Checklist
To configure this project, ensure the following are present on the host:
* **Python 3.12+**
* **Docker / Docker Compose** (for running the containerized Zeek instance)
* **tcpdump / Scapy** (for raw socket sniffing)

---

## 🚀 Setup & Launch

### 1. One-Click Setup
Initialize environment directories, python virtualenvs, install dependencies, fetch the required Zeek image, and train the baseline model:
```bash
./setup.sh
```

### 2. Live Monitoring permissions (Optional)
To run live interface captures without standard root privileges, grant raw packet capabilities to the Python binary in the virtualenv:
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python)
```

### 3. Launching Services
Run the unified launcher command to start the backend uvicorn service, NiceGUI frontend, and the ingestion sensor:
```bash
./start.sh
```
* **Options:**
  * Launch help options: `./start.sh --help`
  * Launch live monitoring: `./start.sh --live --interface=wlo1`

---

## 🧠 Machine Learning Model Training

The ML classifiers map flow states to anomaly likelihood metrics using the preprocessor pipeline.

### Option A: Train on Default Predefined Dataset
Train on the predefined CSV logs that automatically ship with the code:
```bash
PYTHONPATH=. .venv/bin/python scripts/train_default_model.py
```

### Option B: Train on Custom Datasets (e.g. CIC-IDS2017)
To import external files:
1. Place the dataset CSV in a folder (e.g., `data/samples/`).
2. Run training with custom paths and models (`random_forest`, `xgboost`, `isolation_forest`):
   ```bash
   PYTHONPATH=. .venv/bin/python scripts/train_default_model.py \
       --data data/samples/your_custom_dataset.csv \
       --model-type xgboost \
       --output models/artifacts/default_rf.joblib
   ```
* **Schema standardizing**: The pipeline automatically aligns arbitrary csv parameters, renames classification labels to standardize them, and converts text class tags (e.g. `'BENIGN'`) to standard integers.

---

## 🐳 Dockerizing the Application

To wrap the threat engine and dashboard services inside containers:

### 1. Launch with Docker Compose
Run the entire platform (FastAPI, Redis, NiceGUI, and Sensor) using Docker Compose:
```bash
docker-compose up --build
```

### 2. Native Registry Build
Alternatively, build single components natively:
```bash
# Build Backend
docker build -t threat-backend -f docker/Dockerfile.backend .

# Build Dashboard UI
docker build -t threat-dashboard -f docker/Dockerfile.dashboard .
```

---

## 🧪 Testing
To verify code logic and integration components, execute:
```bash
.venv/bin/pytest --tb=short
```
*Processes all unit and e2e integration runs (207 passed).*
