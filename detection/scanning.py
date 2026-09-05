"""Reconnaissance and scanning detector.

Detects port scanning, host scanning (net sweeps), and fan-out behavior
from passive unidirectional IP traffic.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd
import yaml

from alerts.alert_schema import Alert
from features.statistical_features import calculate_entropy

logger = logging.getLogger(__name__)

DEFAULT_THRESHOLDS = {
    "port_scan": {
        "min_unique_ports": 10,
        "min_conn_rate": 2.0,
        "min_failed_ratio": 0.5,
        "min_confidence": 0.5,
    },
    "host_scan": {
        "min_unique_hosts": 5,
        "min_conn_rate": 2.0,
        "min_failed_ratio": 0.5,
        "min_confidence": 0.5,
    },
}


def load_thresholds(config_path: str | Path | None = None) -> Dict[str, Any]:
    """Load thresholds from a YAML configuration file or return defaults.

    Args:
        config_path: Path to the YAML thresholds file.

    Returns:
        Dict of configurations.
    """
    if config_path is None:
        config_path = Path("config/thresholds.yaml")

    p = Path(config_path)
    if not p.exists():
        logger.warning("Thresholds config file %s not found, using defaults", p)
        return DEFAULT_THRESHOLDS

    try:
        with open(p, "r") as f:
            cfg = yaml.safe_load(f)
            return cfg.get("reconnaissance", DEFAULT_THRESHOLDS)
    except Exception as e:
        logger.exception("Error loading thresholds from %s: %s", p, e)
        return DEFAULT_THRESHOLDS


class ReconnaissanceDetector:
    """Passively detects port and host scanning activity."""

    def __init__(self, thresholds: Dict[str, Any] | None = None) -> None:
        self.thresholds = thresholds or load_thresholds()

    def detect(self, df: pd.DataFrame) -> List[Alert]:
        """Perform reconnaissance detection on a DataFrame of flows.

        Args:
            df: DataFrame parsed from a conn.log.

        Returns:
            List of generated Alert objects.
        """
        alerts: List[Alert] = []
        if df.empty:
            return alerts

        # Required columns: src_ip, dst_ip, dst_port, conn_state, ts
        required_cols = {"src_ip", "dst_ip", "dst_port", "conn_state", "ts"}
        missing = required_cols - set(df.columns)
        if missing:
            logger.error("Missing required columns for scan detection: %s", missing)
            return alerts

        grouped = df.groupby("src_ip")

        for src_ip, group in grouped:
            # We don't analyze traffic originating from multicast/broadcast or empty addresses
            if not src_ip or src_ip in ("-", "0.0.0.0", "255.255.255.255"):
                continue

            flows_count = len(group)
            unique_ports = group["dst_port"].nunique()
            unique_hosts = group["dst_ip"].nunique()

            min_ts = group["ts"].min()
            max_ts = group["ts"].max()
            duration = max_ts - min_ts
            conn_rate = flows_count / duration if duration > 0.0 else flows_count

            # Calculate failed ratio
            # Failed connection states: S0 (SYN sent, no response), REJ (connection rejected)
            failed_mask = group["conn_state"].isin(["S0", "REJ"])
            failed_count = failed_mask.sum()
            failed_ratio = failed_count / flows_count if flows_count > 0 else 0.0

            # Calculate entropies
            port_entropy = calculate_entropy(group["dst_port"].tolist())
            host_entropy = calculate_entropy(group["dst_ip"].tolist())

            # Check for Port Scanning
            ps_cfg = self.thresholds.get("port_scan", DEFAULT_THRESHOLDS["port_scan"])
            if (
                unique_ports >= ps_cfg["min_unique_ports"]
                and conn_rate >= ps_cfg["min_conn_rate"]
                and failed_ratio >= ps_cfg["min_failed_ratio"]
            ):
                confidence = self._calculate_port_scan_confidence(
                    unique_ports, conn_rate, failed_ratio, port_entropy, ps_cfg
                )
                if confidence >= ps_cfg["min_confidence"]:
                    severity = self._determine_severity(confidence, unique_ports)
                    evidence = {
                        "unique_dst_ports": int(unique_ports),
                        "unique_dst_hosts": int(unique_hosts),
                        "conn_rate": float(conn_rate),
                        "failed_ratio": float(failed_ratio),
                        "port_entropy": float(port_entropy),
                        "flow_count": int(flows_count),
                    }
                    alerts.append(
                        Alert(
                            timestamp=datetime.fromtimestamp(max_ts, tz=timezone.utc),
                            threat_class="port_scan",
                            confidence=confidence,
                            severity=severity,
                            source=str(src_ip),
                            destination=None,  # Multiple targets
                            evidence=evidence,
                        )
                    )

            # Check for Host Scanning (Net Sweep)
            hs_cfg = self.thresholds.get("host_scan", DEFAULT_THRESHOLDS["host_scan"])
            if (
                unique_hosts >= hs_cfg["min_unique_hosts"]
                and conn_rate >= hs_cfg["min_conn_rate"]
                and failed_ratio >= hs_cfg["min_failed_ratio"]
            ):
                confidence = self._calculate_host_scan_confidence(
                    unique_hosts, conn_rate, failed_ratio, host_entropy, hs_cfg
                )
                if confidence >= hs_cfg["min_confidence"]:
                    severity = self._determine_severity(confidence, unique_hosts)
                    evidence = {
                        "unique_dst_ports": int(unique_ports),
                        "unique_dst_hosts": int(unique_hosts),
                        "conn_rate": float(conn_rate),
                        "failed_ratio": float(failed_ratio),
                        "host_entropy": float(host_entropy),
                        "flow_count": int(flows_count),
                    }
                    alerts.append(
                        Alert(
                            timestamp=datetime.fromtimestamp(max_ts, tz=timezone.utc),
                            threat_class="host_scan",
                            confidence=confidence,
                            severity=severity,
                            source=str(src_ip),
                            destination=None,  # Multiple targets
                            evidence=evidence,
                        )
                    )

        return alerts

    def _calculate_port_scan_confidence(
        self,
        unique_ports: int,
        conn_rate: float,
        failed_ratio: float,
        port_entropy: float,
        cfg: Dict[str, Any],
    ) -> float:
        # Logistic/sigmoid scaling for components
        # More ports scanned -> higher confidence
        port_factor = 1.0 - np.exp(-(unique_ports - cfg["min_unique_ports"]) / 20.0)
        # Higher rate -> higher confidence
        rate_factor = 1.0 - np.exp(-conn_rate / 10.0)
        # Port entropy: scanning many different ports results in higher entropy.
        # Max entropy for N ports is log2(N). If port entropy is higher, it's a stronger scanner.
        entropy_factor = min(port_entropy / 4.0, 1.0)

        # Weighted combination
        confidence = (
            0.4 * port_factor
            + 0.3 * failed_ratio
            + 0.2 * rate_factor
            + 0.1 * entropy_factor
        )
        return float(np.clip(confidence, 0.0, 1.0))

    def _calculate_host_scan_confidence(
        self,
        unique_hosts: int,
        conn_rate: float,
        failed_ratio: float,
        host_entropy: float,
        cfg: Dict[str, Any],
    ) -> float:
        # More hosts scanned -> higher confidence
        host_factor = 1.0 - np.exp(-(unique_hosts - cfg["min_unique_hosts"]) / 10.0)
        # Higher rate -> higher confidence
        rate_factor = 1.0 - np.exp(-conn_rate / 10.0)
        # Host entropy: scanning many different hosts results in higher entropy.
        entropy_factor = min(host_entropy / 3.0, 1.0)

        # Weighted combination
        confidence = (
            0.4 * host_factor
            + 0.3 * failed_ratio
            + 0.2 * rate_factor
            + 0.1 * entropy_factor
        )
        return float(np.clip(confidence, 0.0, 1.0))

    def _determine_severity(self, confidence: float, count: int) -> str:
        if confidence >= 0.85 and count >= 50:
            return "critical"
        elif confidence >= 0.70 or count >= 20:
            return "high"
        elif confidence >= 0.50:
            return "medium"
        return "low"
