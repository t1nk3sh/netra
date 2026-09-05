"""Streaming detection pipeline.

Ingests flow records incrementally, groups them into time windows, calculates
statistical features, runs ML inference, and generates standardized security alerts.

Measures and logs processing latency.
"""

from __future__ import annotations

import logging
import time
from datetime import timezone
from pathlib import Path
from typing import Any, Callable, Dict, List

import pandas as pd

from alerts.alert_schema import Alert
from detection.ddos import DDoSDetector
from detection.scanning import ReconnaissanceDetector
from features.flow_features import extract_per_flow_features
from inference.predictor import ThreatPredictor
from streaming.window_manager import WindowManager

logger = logging.getLogger(__name__)


class StreamingPipeline:
    """Manages e-2-e streaming threat detection on flow records."""

    def __init__(
        self,
        window_size_sec: float = 5.0,
        model_path: str | Path | None = None,
        recon_thresholds: Dict[str, Any] | None = None,
        ddos_thresholds: Dict[str, Any] | None = None,
        alert_callback: Callable[[Alert], None] | None = None,
    ) -> None:
        self.window_manager = WindowManager(window_size_sec)
        
        # Load detectors
        self.recon_detector = ReconnaissanceDetector(recon_thresholds)
        self.ddos_detector = DDoSDetector(ddos_thresholds)
        
        # Initalize ML predictor
        try:
            self.predictor = ThreatPredictor(model_path)
            logger.info("ML predictor loaded successfully in streaming pipeline.")
        except Exception as e:
            logger.warning("ML predictor could not be loaded: %s. ML inference will be skipped.", e)
            self.predictor = None

        self.alert_callback = alert_callback
        
        # Performance logging
        self.metrics = {
            "processed_windows": 0,
            "processed_flows": 0,
            "total_latency_sec": 0.0,
            "alerts_generated": 0,
        }

    def process_record(self, record: Dict[str, Any]) -> List[Alert]:
        """Incremental ingestion of a single flow record.

        Args:
            record: Dict of flow fields.

        Returns:
            List of Alert objects if a time window was closed and triggered alerts.
        """
        alerts: List[Alert] = []
        for window_records in self.window_manager.add_record(record):
            alerts.extend(self._process_window(window_records))
        return alerts

    def flush(self) -> List[Alert]:
        """Flush the pipeline, processing the final unfinished window.

        Returns:
            List of generated Alert objects.
        """
        remaining = self.window_manager.flush()
        if remaining:
            return self._process_window(remaining)
        return []

    def _process_window(self, records: List[Dict[str, Any]]) -> List[Alert]:
        """Process a batch of flow records belonging to a single time window."""
        start_time = time.perf_counter()
        df = pd.DataFrame(records)
        flows_count = len(df)
        window_alerts: List[Alert] = []

        logger.info("Processing window with %d flows", flows_count)

        # 1. Run Reconnaissance (Port/Host scan) Detector
        try:
            recon_alerts = self.recon_detector.detect(df)
            window_alerts.extend(recon_alerts)
        except Exception as e:
            logger.exception("Error during scanning detection: %s", e)

        # 2. Run DDoS Detector
        try:
            ddos_alerts = self.ddos_detector.detect(df)
            window_alerts.extend(ddos_alerts)
        except Exception as e:
            logger.exception("Error during DDoS detection: %s", e)

        # 3. Run ML Inference (anomaly/malicious classification on features)
        if self.predictor is not None and not df.empty:
            try:
                # Extract features for ML
                ml_features_df = extract_per_flow_features(df)
                
                # Predict
                ml_predictions = self.predictor.predict(ml_features_df)
                
                for idx, pred in enumerate(ml_predictions):
                    if pred["threat_predicted"]:
                        flow = df.iloc[idx]
                        alert = Alert(
                            timestamp=df["timestamp"].iloc[idx] if "timestamp" in df.columns else pd.Timestamp.now(tz=timezone.utc),
                            flow_id=str(flow.get("uid", "")),
                            threat_class=f"ml_{pred['model_type']}_threat",
                            confidence=pred["confidence"],
                            severity="high" if pred["confidence"] >= 0.8 else "medium",
                            source=str(flow.get("src_ip", "unknown")),
                            destination=str(flow.get("dst_ip", "unknown")),
                            evidence={
                                "proto": flow.get("proto"),
                                "dst_port": int(flow.get("dst_port", 0)) if flow.get("dst_port") is not None else 0,
                                "duration": float(flow.get("duration", 0.0)) if flow.get("duration") is not None else 0.0,
                            }
                        )
                        window_alerts.append(alert)
            except Exception as e:
                logger.exception("Error during ML inference: %s", e)

        # Emit alerts via callback if configured
        if self.alert_callback is not None:
            for alert in window_alerts:
                try:
                    self.alert_callback(alert)
                except Exception as e:
                    logger.error("Callback execution error: %s", e)

        # Update metrics
        latency = time.perf_counter() - start_time
        self.metrics["processed_windows"] += 1
        self.metrics["processed_flows"] += flows_count
        self.metrics["total_latency_sec"] += latency
        self.metrics["alerts_generated"] += len(window_alerts)

        logger.info(
            "Window processed in %.4f seconds (avg latency/flow: %.6f ms)",
            latency,
            (latency / flows_count * 1000.0) if flows_count > 0 else 0.0,
        )

        return window_alerts

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get aggregate throughput and latency statistics.

        Returns:
            Dict containing metric summaries.
        """
        total_lat = self.metrics["total_latency_sec"]
        flows = self.metrics["processed_flows"]
        
        return {
            "processed_windows": self.metrics["processed_windows"],
            "processed_flows": flows,
            "alerts_generated": self.metrics["alerts_generated"],
            "total_latency_sec": total_lat,
            "avg_latency_per_window_ms": (total_lat / self.metrics["processed_windows"] * 1000.0) if self.metrics["processed_windows"] > 0 else 0.0,
            "avg_latency_per_flow_ms": (total_lat / flows * 1000.0) if flows > 0 else 0.0,
            "flows_per_second": (flows / total_lat) if total_lat > 0 else 0.0,
        }
