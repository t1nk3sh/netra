"""FastAPI Backend implementation for Cyber Threat Detection.

Provides REST endpoints and WebSockets for real-time threat alert streaming.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from alerts.alert_schema import Alert
from alerts.alert_manager import AlertManager
from capture.pcap_analyzer import analyze_pcap_file

logger = logging.getLogger(__name__)

# Resolve every path relative to the project root so the project works when
# cloned anywhere and launched from any working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = Path(os.getenv("NETRA_LOG_DIR", str(PROJECT_ROOT / "logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "service.log"
SAMPLES_DIR = PROJECT_ROOT / "data" / "samples"
UPLOADS_DIR = PROJECT_ROOT / "data" / "uploads"

# Route HTTP/access noise away from the console into the shared service log so
# the launcher terminal stays clean while logs remain reviewable via /logs.
if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", "") == str(LOG_FILE) for h in logger.handlers):
    try:
        fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(fh)
    except Exception:
        pass

app = FastAPI(
    title="NETra - ML-Based Unidirectional Network Threat Detection API",
    description="REST & WebSocket API for observing cyber threat alerts",
    version="0.1.0",
)

# Enable CORS for frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Connection Manager for WebSockets
class WebSocketManager:
    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        self.loop = asyncio.get_running_loop()
        logger.info("New WebSocket connection accepted. Total: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket disconnected. Remaining: %d", len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]) -> None:
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error("Failed to send socket broadcast message: %s", e)


ws_manager = WebSocketManager()


# Alert callback to broadcast new alerts
def on_new_alert(alert: Alert) -> None:
    message = {
        "event": "alert",
        "data": alert.model_dump(),
    }
    
    # If we have a registered websocket loop running, dispatch thread-safely
    if hasattr(ws_manager, "loop") and ws_manager.loop.is_running():
        asyncio.run_coroutine_threadsafe(ws_manager.broadcast(message), ws_manager.loop)
        return
        
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(ws_manager.broadcast(message))
    except RuntimeError:
        try:
            new_loop = asyncio.new_event_loop()
            new_loop.run_until_complete(ws_manager.broadcast(message))
            new_loop.close()
        except Exception as e:
            logger.error("Failed to run broadcast in fallback loop: %s", e)


# Initialize global AlertManager with WebSocket callback
alert_manager = AlertManager(
    dedup_window_sec=30.0,
    dispatch_callback=on_new_alert,
)


@app.get("/health")
def get_health() -> Dict[str, str]:
    """Check backend system health."""
    return {"status": "ok", "service": "threat-detection-backend"}


def _tail_log(max_chars: int = 50_000) -> str:
    try:
        if not LOG_FILE.exists():
            return "(No log output yet.)"
        size = LOG_FILE.stat().st_size
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            if size > max_chars:
                f.seek(size - max_chars)
                f.readline()  # skip partial first line
            return f.read()
    except Exception as e:
        return f"(Could not read log: {e})"


@app.get("/logs", response_class=HTMLResponse)
def get_logs() -> str:
    """Serve a lightweight self-refreshing page tailing the shared service log."""
    body = _tail_log()
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NETra Service Logs</title>
<meta http-equiv="refresh" content="3">
<style>
  body {{ background:#0d1117; color:#c9d1d9; font-family:ui-monospace,Menlo,Consolas,monospace; margin:0; padding:16px; }}
  h1 {{ color:#58a6ff; font-size:16px; border-bottom:1px solid #30363d; padding-bottom:8px; }}
  pre {{ white-space:pre-wrap; word-break:break-word; font-size:12px; line-height:1.5; }}
  .bar {{ margin:10px 0; }}
  a {{ color:#58a6ff; }}
</style>
</head>
<body>
<h1>NETra Service Logs <span style="color:#8b949e;font-weight:normal">(auto-refresh 3s)</span></h1>
<div class="bar"><a href="/logs">Reload</a> &middot; <span id="n"></span> lines</div>
<pre>{body}</pre>
</body>
</html>"""



# In-memory store of raw flows/packets currently being analyzed
recent_flows: List[Dict[str, Any]] = []

# In-memory store of live pipeline/sensor telemetry statistics
live_pipeline_stats: Dict[str, Any] = {
    "mode": "idle",
    "interface": "any",
    "packets_per_sec": 0.0,
    "latency_ms": 0.0,
    "total_flows_analyzed": 0,
    "total_packets_sniffed": 0,
    "last_zeek_run": None,
    "active": False,
}

@app.post("/pipeline_stats", response_model=Dict[str, Any])
def update_pipeline_stats(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Receive live telemetry performance stats from the running sensor."""
    global live_pipeline_stats
    live_pipeline_stats.update(stats)
    return {"success": True}

@app.get("/pipeline_stats", response_model=Dict[str, Any])
def get_pipeline_stats() -> Dict[str, Any]:
    """Retrieve live telemetry performance stats from the running sensor."""
    return live_pipeline_stats

@app.get("/alerts", response_model=List[Alert])
def get_alerts(
    threat_class: Optional[str] = None,
    severity: Optional[str] = None,
) -> List[Alert]:
    """Retrieve security alert history, with optional filtering."""
    return alert_manager.get_alerts(threat_class=threat_class, severity=severity)


@app.post("/flows", response_model=Dict[str, Any])
def create_flows(flows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Ingest raw processed flow metadata (representing actively analyzed packets)."""
    global recent_flows
    # Append onto head of list and limit to 50 items
    recent_flows = (flows + recent_flows)[:50]
    return {"success": True, "count_ingested": len(flows)}


@app.get("/flows", response_model=List[Dict[str, Any]])
def get_flows() -> List[Dict[str, Any]]:
    """Retrieve the recent analyzed packet/flow metadata stream."""
    return recent_flows


@app.post("/alerts", response_model=Dict[str, Any])
def create_alert(alert: Alert) -> Dict[str, Any]:
    """Ingest a new alert into the manager (triggers WebSocket broadcast)."""
    dispatched = alert_manager.process_alert(alert)
    return {"success": True, "dispatched": dispatched, "alert_id": alert.id}


@app.get("/alerts/{alert_id}", response_model=Alert)
def get_alert_by_id(alert_id: str) -> Alert:
    """Retrieve details of a specific alert by ID."""
    for alert in alert_manager.alert_history:
        if alert.id == alert_id:
            return alert
    raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found")


@app.get("/statistics")
def get_statistics() -> Dict[str, Any]:
    """Summary of historical alert quantities and distributions."""
    total = len(alert_manager.alert_history)
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    class_counts: Dict[str, int] = {}

    for alert in alert_manager.alert_history:
        sev = alert.severity.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts[sev] = 1

        tc = alert.threat_class
        class_counts[tc] = class_counts.get(tc, 0) + 1

    return {
        "total_alerts": total,
        "severity_counts": severity_counts,
        "threat_class_counts": class_counts,
    }


@app.get("/threats")
def get_threats() -> List[Dict[str, Any]]:
    """Get active threats aggregated by attacking/offending IP addresses."""
    threat_ips: Dict[str, Dict[str, Any]] = {}
    
    for alert in alert_manager.alert_history:
        src = alert.source
        if src not in threat_ips:
            threat_ips[src] = {
                "source": src,
                "alert_count": 0,
                "max_confidence": 0.0,
                "highest_severity": "low",
                "threat_classes": set(),
                "last_seen": alert.timestamp,
            }
        
        entry = threat_ips[src]
        entry["alert_count"] += 1
        entry["max_confidence"] = max(entry["max_confidence"], alert.confidence)
        entry["threat_classes"].add(alert.threat_class)
        
        # Keep track of last timestamp
        if alert.timestamp > entry["last_seen"]:
            entry["last_seen"] = alert.timestamp

        # Severity comparative order
        sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        current_highest = entry["highest_severity"]
        if sev_order.get(alert.severity.lower(), 0) > sev_order.get(current_highest, 0):
            entry["highest_severity"] = alert.severity

    # Formatting set for JSON response
    results = []
    for entry in threat_ips.values():
        entry["threat_classes"] = list(entry["threat_classes"])
        results.append(entry)

    # Sort by alert count descending
    return sorted(results, key=lambda x: x["alert_count"], reverse=True)


@app.get("/samples/pcaps")
def list_available_pcaps() -> List[Dict[str, Any]]:
    """List available sample and uploaded PCAP files for analysis."""
    pcap_files = []
    
    # Check sample pcaps
    samples_dir = SAMPLES_DIR
    if samples_dir.exists():
        for p in sorted(samples_dir.glob("*.pcap")):
            pcap_files.append({
                "name": p.name,
                "path": str(p),
                "size_bytes": p.stat().st_size,
                "type": "sample",
            })
            
    # Check uploads
    uploads_dir = UPLOADS_DIR
    if uploads_dir.exists():
        for p in sorted(uploads_dir.glob("*.pcap*")):
            pcap_files.append({
                "name": p.name,
                "path": str(p),
                "size_bytes": p.stat().st_size,
                "type": "upload",
            })
            
    return pcap_files


MAX_UPLOAD_SIZE_BYTES = 200 * 1024 * 1024  # 200 MB
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@app.post("/analyze_pcap")
async def analyze_uploaded_pcap(
    file: Optional[UploadFile] = None,
    file_path: Optional[str] = None,
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """Analyze a user-provided or uploaded PCAP file for threats and connection flows."""
    target_path: Path
    
    if file is not None and file.filename:
        # Sanitize filename to prevent path traversal
        safe_filename = Path(file.filename).name
        if not safe_filename or safe_filename.startswith("."):
            raise HTTPException(status_code=400, detail="Invalid filename provided")

        suffix = Path(safe_filename).suffix.lower()
        if suffix not in ALLOWED_PCAP_EXTENSIONS and not safe_filename.endswith((".pcap.gz", ".pcapng.gz")):
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported file type '{suffix}'. Allowed: {', '.join(sorted(ALLOWED_PCAP_EXTENSIONS))}"
            )

        uploads_dir = UPLOADS_DIR
        uploads_dir.mkdir(parents=True, exist_ok=True)
        target_path = uploads_dir / safe_filename

        # Stream write in chunks with size limit enforcement
        total_bytes = 0
        chunk_size = 64 * 1024
        try:
            with open(target_path, "wb") as out_file:
                while chunk := await file.read(chunk_size):
                    total_bytes += len(chunk)
                    if total_bytes > MAX_UPLOAD_SIZE_BYTES:
                        target_path.unlink(missing_ok=True)
                        raise HTTPException(
                            status_code=413, 
                            detail=f"File exceeds maximum upload limit of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB"
                        )
                    out_file.write(chunk)
        except HTTPException:
            raise
        except Exception as e:
            target_path.unlink(missing_ok=True)
            raise HTTPException(status_code=500, detail=f"Failed to save upload: {e}")
    elif file_path:
        target_path = Path(file_path).resolve()
        # Security validation on file path
        if not target_path.exists():
            raise HTTPException(status_code=404, detail=f"PCAP file not found: {file_path}")
        if not target_path.is_file():
            raise HTTPException(status_code=400, detail=f"Path is not a regular file: {file_path}")
        if target_path.suffix.lower() not in ALLOWED_PCAP_EXTENSIONS:
            raise HTTPException(
                status_code=400, 
                detail=f"Target file does not have a supported PCAP extension ({', '.join(sorted(ALLOWED_PCAP_EXTENSIONS))})"
            )
    else:
        raise HTTPException(status_code=400, detail="Either file upload or file_path must be provided")

    if not target_path.exists():
        raise HTTPException(status_code=404, detail=f"PCAP file not found: {target_path}")

    try:
        results = analyze_pcap_file(target_path, threshold=threshold)
        return results
    except Exception as e:
        logger.error("PCAP analysis failed: %s", e)
        raise HTTPException(status_code=500, detail=f"PCAP analysis error: {e}")


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    """Delivers real-time threat alerts to WebSocket connections."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Low CPU idle polling interval for active WebSocket keepalive
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error("Websocket connection exception: %s", e)
        ws_manager.disconnect(websocket)
