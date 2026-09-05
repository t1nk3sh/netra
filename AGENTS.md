# AGENTS.md

## Project Overview
NETra — ML-based network threat detection system with a NiceGUI dashboard for passive, unidirectional IP traffic monitoring and real-time threat analysis.

## Quick Start
```bash
# One-time setup (creates venv, installs deps, pulls Zeek image, trains model)
./setup.sh

# Launch all services (backend:8000, dashboard:8501, sensor)
./start.sh

# Launch with live capture on specific interface
./start.sh --live --interface=wlo1
```

## Testing
```bash
# Run all tests (207 tests, ~10s)
.venv/bin/pytest --tb=short -q

# Run single test file
.venv/bin/pytest tests/unit/test_predictor.py --tb=short

# Run specific test
.venv/bin/pytest tests/unit/test_predictor.py::test_predict -v
```

## Architecture
- **Backend**: FastAPI REST API on port 8000 (`backend/main.py`)
- **Dashboard**: NiceGUI app on port 8501 (`dashboard/nicegui_app.py`)
- **Sensor**: Live/replay threat detection (`scripts/live_detector.py`)
- **Zeek**: Docker-based (`zeek/zeek:latest`) for log parsing
- **ML Pipeline**: Scikit-learn/XGBoost classifiers in `models/`

## Critical Conventions

### Python Path
Always set `PYTHONPATH=.` when running scripts manually:
```bash
export PYTHONPATH=.
```

### Live Capture Permissions
The sensor needs raw packet capabilities. Run once:
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python)
```

### Docker Socket
If Docker commands fail:
```bash
sudo chmod 666 /var/run/docker.sock
```

### NiceGUI Dark Mode
The dashboard uses Quasar's dark mode (`.body--dark` class). Do NOT use Tailwind `dark:` prefixed classes — NiceGUI doesn't compile Tailwind. Use CSS variables from `:root` and `body.body--dark` in the `<style>` block.

### Sensor Config Files
- Config: `data/sensor_config.json` (mode: "live"/"replay", interface, model_path)
- Status: `data/sensor_status.json` (runtime state, errors, active model)

### Model Registry & Dynamic Switching
- Artifacts stored in `models/artifacts/*.joblib`:
  - `default_rf.joblib`: Active production model loaded by live sensor
  - `sample_rf.joblib`: Synthetic 200-flow baseline model (100% test accuracy on sample)
  - `cic_rf.joblib`: CIC-IDS2017 Random Forest (98.3% F1 on 200k flows)
  - `cic_xgboost.joblib`: CIC-IDS2017 XGBoost (98.8% F1 on 200k flows, <0.001ms latency)
  - `cic_isolation_forest.joblib`: Unsupervised anomaly detection model
- UI on **Models** page allows real-time switching, benchmark evaluation against any dataset in `data/samples/`, and one-click activation.
- `scripts/live_detector.py` watches `data/sensor_config.json` and hot-reloads the active model without dropping capture.

### Alert Schema
Alerts follow this structure:
```python
{
    "id": str,
    "timestamp": float,  # Unix epoch
    "flow_id": str,
    "threat_class": str,
    "confidence": float,
    "severity": str,  # critical/high/medium/low
    "source": str,
    "destination": str,
    "evidence": dict
}
```

### Timestamp Handling
Backend sends epoch floats. Use `format_timestamp()` or `format_time_only()` from `dashboard/utils/formatting.py` — they handle floats, ISO strings, and datetime objects.

## Key Files
- `dashboard/nicegui_app.py` — Main NiceGUI dashboard (reactive in-place updates, no DOM rebuilds)
- `dashboard/utils/formatting.py` — Timestamp formatting (epoch/ISO/datetime)
- `capture/pcap_analyzer.py` — Deep PCAP forensic analysis, Scapy flow reconstruction, & ML threat classification
- `scripts/live_detector.py` — Sensor with config monitoring
- `scripts/train_default_model.py` — Model training CLI
- `backend/main.py` — FastAPI endpoints (`/alerts`, `/flows`, `/analyze_pcap`, `/samples/pcaps`)
- `capture/live_capture.py` — Scapy passive sniffer
- `start.sh` — Unified launcher with argument parsing
- `setup.sh` — One-click environment setup

## Common Pitfalls
1. **NiceGUI doesn't compile Tailwind** — `dark:` prefixed classes don't work. Use CSS variables.
2. **Epoch timestamps** — Backend sends floats, not ISO strings. Always use the formatting helpers.
3. **NaN/Inf values** — Flow objects may contain these; they're scrubbed to `None` before HTTP transport.
4. **Missing `PYTHONPATH`** — Scripts fail silently without it. Always set `PYTHONPATH=.`
5. **Docker tests** — Zeek tests require Docker. They skip gracefully if Docker unavailable.
6. **Sensor errors** — Check `data/sensor_status.json` for `last_error` field when debugging capture issues.
