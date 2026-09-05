"""Live threat detector sensor.

Supports two modes:
  --live       Sniff packets from a real network interface, write rotating PCAPs,
               run Zeek on each rotation, and feed parsed flows into the ML pipeline.
  (default)    Replay pre-existing Zeek logs for demo/testing.

The full live pipeline is:
  NIC -> Scapy sniff -> PCAP file -> Zeek (Docker/native) -> conn.log -> 
  Feature Engineering -> ML/Rules -> Alerts -> FastAPI -> Dashboard
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import signal
import sys
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import Any

import httpx
import numpy as np
import pandas as pd

from alerts.alert_schema import Alert
from capture.live_capture import LiveCapture, CaptureConfig
from capture.pcap_analyzer import _extract_scapy_flows
from inference.predictor import DEFAULT_MODEL_PATH
from streaming.pipeline import StreamingPipeline
from zeek.log_parser import parse_conn_log
from zeek.runner import ZeekRunner, ZeekConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

CONN_LOG = Path("data/samples/zeek_logs/conn.log")
SAMPLE_PCAP = Path("data/samples/test_traffic.pcap")
LIVE_CAPTURE_DIR = Path("data/live_captures")
LIVE_ZEEK_DIR = Path("data/live_zeek")
API_URL = "http://localhost:8000/alerts"
FLOWS_URL = "http://localhost:8000/flows"
SPEED_MULTIPLIER = 1.0


class LiveDetectorSensor:
    """Passive network sensor supporting live capture and replay modes."""

    def __init__(self) -> None:
        self.running = True
        self.client = httpx.Client(timeout=3.0)
        self.pipeline: StreamingPipeline | None = None
        self.zeek_runner: ZeekRunner | None = None
        self.current_thread: threading.Thread | None = None
        self.active_mode: str | None = None
        self.active_interface: str | None = None
        self.active_model_path: str | None = str(DEFAULT_MODEL_PATH)
        self.sub_running = False

    def stop(self) -> None:
        self.running = False
        self.stop_sub_systems()

    def stop_sub_systems(self) -> None:
        self.sub_running = False
        if hasattr(self, "capture") and self.capture:
            try:
                self.capture.stop()
            except Exception:
                pass

    def _ensure_model(self) -> None:
        m_path = Path(self.active_model_path) if self.active_model_path else DEFAULT_MODEL_PATH
        if not m_path.exists():
            logger.info("Model not found at %s. Training default model first...", m_path)
            from scripts.train_default_model import train_default
            train_default()

    def _init_pipeline(self) -> StreamingPipeline:
        m_path = Path(self.active_model_path) if self.active_model_path else DEFAULT_MODEL_PATH
        return StreamingPipeline(
            window_size_sec=5.0,
            model_path=m_path,
            alert_callback=self.post_alert,
        )

    def _init_zeek(self, output_dir: Path) -> ZeekRunner | None:
        runner = ZeekRunner(ZeekConfig(output_dir=output_dir))
        if runner.is_available():
            logger.info("Zeek backend: %s", runner.backend)
            return runner
        logger.error("No Zeek backend available (install Zeek or start Docker)")
        return None

    def post_alert(self, alert: Alert) -> None:
        try:
            logger.info("Posting alert: %s (%s)", alert.id, alert.threat_class)
            payload = json.loads(alert.model_dump_json())
            res = self.client.post(API_URL, json=payload)
            if res.status_code != 200:
                logger.error("Backend returned status %d", res.status_code)
        except Exception as e:
            logger.error("Failed to post alert: %s", e)

    def post_flows(self, flows: list[dict[str, Any]]) -> None:
        try:
            cleaned = []
            for f in flows:
                fc = f.copy()
                for k, v in fc.items():
                    if isinstance(v, (datetime, pd.Timestamp)):
                        fc[k] = v.isoformat()
                    elif pd.isna(v) or (isinstance(v, float) and not np.isfinite(v)):
                        fc[k] = None
                if "ts" in fc:
                    fc["ts"] = float(fc["ts"])
                cleaned.append(fc)
            self.client.post(FLOWS_URL, json=cleaned)
        except Exception as e:
            logger.error("Failed to post flows: %s", e)

    def push_pipeline_stats(self) -> None:
        """Calculate and publish real pipeline performance metrics to FastAPI."""
        if not self.pipeline:
            return
        try:
            perf = self.pipeline.get_performance_stats()
            sniffed = getattr(self.capture, "total_packets_sniffed", 0) if hasattr(self, "capture") and self.capture else 0
            stats = {
                "mode": self.active_mode or "replay",
                "interface": self.active_interface or "any",
                "active": self.running and self.sub_running,
                "packets_per_sec": round(perf.get("flows_per_second", 0.0), 2),
                "latency_ms": round(perf.get("avg_latency_per_flow_ms", 0.0), 3),
                "total_flows_analyzed": perf.get("processed_flows", 0),
                "total_packets_sniffed": sniffed,
            }
            self.client.post("http://localhost:8000/pipeline_stats", json=stats)
        except Exception:
            pass

    def _update_zeek_run_status(self, success: bool, count: int, error: str = "") -> None:
        """Update last Zeek execution stats in the sensor status tracker file."""
        p_status = Path("data/sensor_status.json")
        status = {}
        if p_status.exists():
            try:
                with open(p_status, "r") as f:
                    status = json.load(f)
            except Exception:
                pass
        
        status["last_zeek_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status["last_zeek_success"] = success
        status["last_zeek_count"] = count
        if error:
            status["last_zeek_error"] = error
            
        try:
            with open(p_status, "w") as f:
                json.dump(status, f)
        except Exception:
            pass

    # ── Live capture mode ────────────────────────────────────────────

    def _on_pcap_ready(self, pcap_path: Path) -> None:
        """Called by LiveCapture when a rotation PCAP is ready."""
        if not self.running or not self.sub_running:
            return

        logger.info("Processing live PCAP: %s", pcap_path)
        records: list[dict[str, Any]] = []
        zeek_success = False

        if self.zeek_runner and self.zeek_runner.is_available():
            zeek_out = LIVE_ZEEK_DIR / pcap_path.stem
            zeek_out.mkdir(parents=True, exist_ok=True)
            self.zeek_runner._config.output_dir = str(zeek_out)

            try:
                result = self.zeek_runner.process_pcap(pcap_path)
                conn_log = zeek_out / "conn.log"
                if result.success and conn_log.exists():
                    df = parse_conn_log(conn_log)
                    if not df.empty:
                        records = df.to_dict(orient="records")
                        zeek_success = True
                        logger.info("Zeek extracted %d flows from %s", len(records), pcap_path)
                        self._update_zeek_run_status(True, len(records))
            except Exception as e:
                logger.debug("Zeek live extraction error: %s", e)
            finally:
                shutil.rmtree(zeek_out, ignore_errors=True)

        # Fallback to Scapy packet flow reconstruction if Zeek produced no flows
        if not records:
            try:
                records = _extract_scapy_flows(pcap_path)
                if records:
                    logger.info("Scapy extracted %d connection flows from %s", len(records), pcap_path)
                    self._update_zeek_run_status(True, len(records))
            except Exception as ex:
                logger.error("Scapy flow extraction error on %s: %s", pcap_path, ex)

        if records and self.pipeline:
            # Feed flows into streaming pipeline and backend
            for rec in records:
                if not self.running or not self.sub_running:
                    break
                self.pipeline.process_record(rec)
                self.post_flows([rec])

            self.pipeline.flush()
            self.push_pipeline_stats()

        # Clean up processed PCAP
        try:
            pcap_path.unlink()
        except Exception:
            pass

    def start_live(self, interface: str = "any", rotation_sec: int = 5) -> None:
        """Start live passive capture from a network interface."""
        self._ensure_model()
        self.pipeline = self._init_pipeline()

        LIVE_ZEEK_DIR.mkdir(parents=True, exist_ok=True)
        self.zeek_runner = self._init_zeek(LIVE_ZEEK_DIR)

        logger.info("=== LIVE CAPTURE MODE on interface '%s' (rotation=%ds) ===", interface, rotation_sec)

        config = CaptureConfig(
            interface=interface,
            output_dir=LIVE_CAPTURE_DIR,
            rotation_seconds=rotation_sec,
            rotation_packets=50,
            bpf_filter="",
        )
        self.capture = LiveCapture(config=config, on_pcap_ready=self._on_pcap_ready)
        self.capture.start()
        self.capture = LiveCapture(config=config, on_pcap_ready=self._on_pcap_ready)
        self.capture.start()

    # ── Replay mode (fallback/demo) ──────────────────────────────────

    def start_replay(self) -> None:
        """Replay pre-existing Zeek logs for demo/testing."""
        self._ensure_model()

        # Run Zeek on sample PCAP if conn.log is missing
        if not CONN_LOG.exists():
            logger.info("conn.log not found. Running Zeek on %s...", SAMPLE_PCAP)
            if SAMPLE_PCAP.exists():
                runner = self._init_zeek(CONN_LOG.parent)
                if runner:
                    try:
                        result = runner.process_pcap(SAMPLE_PCAP)
                        self._update_zeek_run_status(result.success, 10 if result.success else 0)
                        if result.success:
                            logger.info("Zeek produced logs: %s", result.logs_produced)
                        else:
                            logger.error("Zeek failed: %s", result.stderr[:300])
                    except Exception as e:
                        logger.error("Zeek error: %s", e)

        if not CONN_LOG.exists():
            logger.error("No conn.log at %s. Cannot start replay.", CONN_LOG)
            return

        df = parse_conn_log(CONN_LOG)
        if df.empty:
            logger.error("No flows found in %s", CONN_LOG)
            return

        df_sorted = df.sort_values(by="ts").reset_index(drop=True)
        records = df_sorted.to_dict(orient="records")

        pipeline = self._init_pipeline()
        logger.info("=== REPLAY MODE (%d flows) ===", len(records))

        gaps = [0.0] + [
            max(0.0, float(records[i]["ts"]) - float(records[i - 1]["ts"]))
            for i in range(1, len(records))
        ]

        loop_count = 0
        while self.running and self.sub_running:
            loop_count += 1
            logger.info("--- Replay loop #%d ---", loop_count)
            base_time = time.time()

            for idx, rec in enumerate(records):
                if not self.running or not self.sub_running:
                    break
                if gaps[idx] > 0:
                    time.sleep(gaps[idx] / SPEED_MULTIPLIER)

                curr_ts = base_time + (float(rec["ts"]) - float(records[0]["ts"]))
                rec_copy = rec.copy()
                rec_copy["ts"] = curr_ts
                if "timestamp" in rec_copy:
                    rec_copy["timestamp"] = curr_ts

                pipeline.process_record(rec_copy)
                self.post_flows([rec_copy])

            pipeline.flush()
            self.push_pipeline_stats()
            logger.info("Replay loop #%d complete. Sleeping 10s.", loop_count)
            for _ in range(5):
                if not self.running or not self.sub_running:
                    break
                time.sleep(2)

    # ── Configuration Monitor ────────────────────────────────────────

    def monitor_config(self) -> None:
        """Dynamic filesystem-based control loop to allow live switching from the UI."""
        config_path = Path("data/sensor_config.json")
        default_config = {
            "mode": "replay",
            "interface": "any",
            "rotation": 30,
            "model_path": str(DEFAULT_MODEL_PATH),
        }
        
        while self.running:
            # Read config settings
            config = default_config.copy()
            if config_path.exists():
                try:
                    with open(config_path, "r") as f:
                        config = json.load(f)
                except Exception:
                    pass
            
            target_mode = config.get("mode", "replay")
            target_interface = config.get("interface", "any")
            target_rotation = config.get("rotation", 30)
            target_model_path = config.get("model_path", str(DEFAULT_MODEL_PATH))

            # Trigger shift if settings differ from current running thread
            if (self.active_mode != target_mode or 
                self.active_interface != target_interface or 
                self.active_model_path != target_model_path or
                self.current_thread is None or 
                not self.current_thread.is_alive()):
                
                logger.info(
                    "Configuration shift: Switching to mode=%s, iface=%s, model=%s", 
                    target_mode, target_interface, target_model_path
                )
                
                # Stop existing thread
                self.stop_sub_systems()
                if self.current_thread and self.current_thread.is_alive():
                    self.current_thread.join(timeout=3.0)
                
                self.active_mode = target_mode
                self.active_interface = target_interface
                self.active_model_path = target_model_path
                
                # Write dynamic sensor status database
                status_info = {
                    "mode": target_mode,
                    "interface": target_interface,
                    "model_path": target_model_path,
                    "active": True,
                    "timestamp": time.time()
                }
                try:
                    p_status = Path("data/sensor_status.json")
                    with open(p_status, "w") as f:
                        json.dump(status_info, f)
                except Exception:
                    pass

                self.sub_running = True
                if target_mode == "live":
                    self.current_thread = threading.Thread(
                        target=self.start_live,
                        args=(target_interface, target_rotation),
                        daemon=True
                    )
                else:
                    self.current_thread = threading.Thread(
                        target=self.start_replay,
                        daemon=True
                    )
                self.current_thread.start()
            
            # Periodically sync capture error state if any
            if hasattr(self, "capture") and getattr(self.capture, "last_error", None):
                try:
                    p_status = Path("data/sensor_status.json")
                    if p_status.exists():
                        with open(p_status, "r") as f:
                            cur_status = json.load(f)
                        cur_status["last_error"] = self.capture.last_error
                        with open(p_status, "w") as f:
                            json.dump(cur_status, f)
                except Exception:
                    pass

            # Sleep brief intervals
            time.sleep(2)


def main():
    parser = argparse.ArgumentParser(description="NETra ML Network Threat Detection Sensor")
    parser.add_argument(
        "--live", action="store_true",
        help="Enable live packet capture from a network interface"
    )
    parser.add_argument(
        "--interface", "-i", default="any",
        help="Network interface to capture on (default: any)"
    )
    parser.add_argument(
        "--rotation", "-r", type=int, default=5,
        help="PCAP rotation interval in seconds (default: 5)"
    )
    args = parser.parse_args()

    sensor = LiveDetectorSensor()

    def handle_exit(signum, frame):
        try:
            sensor.stop()
            p_status = Path("data/sensor_status.json")
            if p_status.exists():
                p_status.unlink()
        except Exception:
            pass
        os._exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # Initialize sensor config based on command line arguments, allowing restart compatibility
    config_path = Path("data/sensor_config.json")
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        init_config = {
            "mode": "live" if args.live else "replay",
            "interface": args.interface,
            "rotation": args.rotation
        }
        with open(config_path, "w") as f:
            json.dump(init_config, f)
    except Exception as e:
        logger.error("Failed to seed initial sensor config: %s", e)

    # Start main configuration listener loop
    sensor.monitor_config()


if __name__ == "__main__":
    main()
