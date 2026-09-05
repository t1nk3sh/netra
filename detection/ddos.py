"""DDoS and volumetric protocol flood detector.

Detects SYN floods, UDP floods, reflection/amplification patterns, and
potential IP spoofing behaviors from passive unidirectional IP traffic.
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

DEFAULT_DDOS_THRESHOLDS = {
    "syn_flood": {
        "min_syn_rate": 10.0,
        "min_flows_count": 30,
        "min_failed_ratio": 0.8,
    },
    "udp_flood": {
        "min_udp_rate": 20.0,
        "min_flows_count": 50,
    },
    "reflection": {
        "min_rate": 15.0,
        "min_flows_count": 30,
        "reflection_ports": [53, 123, 161, 1900],
    },
}


def load_ddos_thresholds(config_path: str | Path | None = None) -> Dict[str, Any]:
    """Load DDoS thresholds from a YAML configuration file or return defaults.

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
        return DEFAULT_DDOS_THRESHOLDS

    try:
        with open(p, "r") as f:
            cfg = yaml.safe_load(f)
            return cfg.get("ddos", DEFAULT_DDOS_THRESHOLDS)
    except Exception as e:
        logger.exception("Error loading DDoS thresholds from %s: %s", p, e)
        return DEFAULT_DDOS_THRESHOLDS


class DDoSDetector:
    """Passively detects DDoS attacks targeting observed hosts."""

    def __init__(self, thresholds: Dict[str, Any] | None = None) -> None:
        self.thresholds = thresholds or load_ddos_thresholds()

    def detect(self, df: pd.DataFrame) -> List[Alert]:
        """Perform DDoS detection on a DataFrame of flows.

        Args:
            df: DataFrame parsed from a conn.log.

        Returns:
            List of generated Alert objects.
        """
        alerts: List[Alert] = []
        if df.empty:
            return alerts

        # Required columns
        required_cols = {"src_ip", "dst_ip", "src_port", "dst_port", "proto", "conn_state", "ts"}
        missing = required_cols - set(df.columns)
        if missing:
            logger.error("Missing required columns for DDoS detection: %s", missing)
            return alerts

        # Ensure correct numeric types
        df_clean = df.copy()
        df_clean["orig_pkts"] = pd.to_numeric(df_clean.get("orig_pkts", 0), errors="coerce").fillna(0)
        df_clean["resp_pkts"] = pd.to_numeric(df_clean.get("resp_pkts", 0), errors="coerce").fillna(0)
        df_clean["orig_bytes"] = pd.to_numeric(df_clean.get("orig_bytes", 0), errors="coerce").fillna(0)
        df_clean["resp_bytes"] = pd.to_numeric(df_clean.get("resp_bytes", 0), errors="coerce").fillna(0)

        # DDoS attacks target the destination host. Group by target IP.
        grouped = df_clean.groupby("dst_ip")

        for dst_ip, group in grouped:
            if not dst_ip or dst_ip in ("-", "255.255.255.255"):
                continue

            flows_count = len(group)
            min_ts = group["ts"].min()
            max_ts = group["ts"].max()
            duration = max_ts - min_ts
            time_denom = duration if duration > 0.0 else 1.0

            # Calculate packet sizes and rates
            total_orig_pkts = group["orig_pkts"].sum()
            total_resp_pkts = group["resp_pkts"].sum()
            total_pkts = total_orig_pkts + total_resp_pkts
            pkts_per_sec = total_pkts / time_denom

            total_orig_bytes = group["orig_bytes"].sum()
            total_resp_bytes = group["resp_bytes"].sum()
            total_bytes = total_orig_bytes + total_resp_bytes
            bytes_per_sec = total_bytes / time_denom

            # Source concentration indicators
            unique_srcs = group["src_ip"].nunique()
            src_entropy = calculate_entropy(group["src_ip"].tolist())

            # Detect SYN Flood
            tcp_group = group[group["proto"] == "tcp"]
            syn_cfg = self.thresholds.get("syn_flood", DEFAULT_DDOS_THRESHOLDS["syn_flood"])
            if not tcp_group.empty:
                # Connection attempts that are S0 (SYN sent, no response)
                syn_only_mask = tcp_group["conn_state"] == "S0"
                # Or check if history has only "S" flags
                if "history" in tcp_group.columns:
                    syn_only_mask = syn_only_mask | (tcp_group["history"].fillna("") == "S")

                syn_flows_count = syn_only_mask.sum()
                syn_rate = syn_flows_count / time_denom
                tcp_failed_ratio = syn_flows_count / len(tcp_group)

                if (
                    syn_flows_count >= syn_cfg["min_flows_count"]
                    and syn_rate >= syn_cfg["min_syn_rate"]
                    and tcp_failed_ratio >= syn_cfg["min_failed_ratio"]
                ):
                    confidence = self._calculate_confidence(
                        syn_flows_count, syn_rate, tcp_failed_ratio, unique_srcs, src_entropy, "syn_flood"
                    )
                    evidence = {
                        "syn_flows_count": int(syn_flows_count),
                        "syn_rate_per_sec": float(syn_rate),
                        "failed_ratio": float(tcp_failed_ratio),
                        "unique_src_count": int(unique_srcs),
                        "src_entropy": float(src_entropy),
                        "pkts_per_sec": float(pkts_per_sec),
                        "possible_spoofing": bool(unique_srcs > 20 and tcp_failed_ratio > 0.95),
                    }
                    alerts.append(
                        Alert(
                            timestamp=datetime.fromtimestamp(max_ts, tz=timezone.utc),
                            threat_class="ddos_syn_flood",
                            confidence=confidence,
                            severity=self._determine_severity(confidence, syn_flows_count),
                            source="multiple" if unique_srcs > 1 else str(group["src_ip"].iloc[0]),
                            destination=str(dst_ip),
                            evidence=evidence,
                        )
                    )

            # Detect UDP Flood
            udp_group = group[group["proto"] == "udp"]
            udp_cfg = self.thresholds.get("udp_flood", DEFAULT_DDOS_THRESHOLDS["udp_flood"])
            if not udp_group.empty:
                udp_flows_count = len(udp_group)
                udp_rate = udp_flows_count / time_denom

                if (
                    udp_flows_count >= udp_cfg["min_flows_count"]
                    and udp_rate >= udp_cfg["min_udp_rate"]
                ):
                    confidence = self._calculate_confidence(
                        udp_flows_count, udp_rate, 1.0, unique_srcs, src_entropy, "udp_flood"
                    )
                    evidence = {
                        "udp_flows_count": int(udp_flows_count),
                        "udp_rate_per_sec": float(udp_rate),
                        "unique_src_count": int(unique_srcs),
                        "src_entropy": float(src_entropy),
                        "pkts_per_sec": float(pkts_per_sec),
                        "bytes_per_sec": float(bytes_per_sec),
                    }
                    alerts.append(
                        Alert(
                            timestamp=datetime.fromtimestamp(max_ts, tz=timezone.utc),
                            threat_class="ddos_udp_flood",
                            confidence=confidence,
                            severity=self._determine_severity(confidence, udp_flows_count),
                            source="multiple" if unique_srcs > 1 else str(group["src_ip"].iloc[0]),
                            destination=str(dst_ip),
                            evidence=evidence,
                        )
                    )

            # Detect Reflection / Amplification Flood (e.g. DNS, NTP, SNMP, SSDP reflection)
            reflection_cfg = self.thresholds.get("reflection", DEFAULT_DDOS_THRESHOLDS["reflection"])
            reflection_ports = reflection_cfg["reflection_ports"]
            # Reflection traffic originates from a service port on a remote server to our target
            reflection_mask = group["src_port"].isin(reflection_ports)
            reflection_group = group[reflection_mask]
            
            if not reflection_group.empty:
                ref_flows_count = len(reflection_group)
                ref_rate = ref_flows_count / time_denom

                if (
                    ref_flows_count >= reflection_cfg["min_flows_count"]
                    and ref_rate >= reflection_cfg["min_rate"]
                ):
                    # Compute mean packet size
                    ref_pkts = reflection_group["orig_pkts"].sum() + reflection_group["resp_pkts"].sum()
                    ref_bytes = reflection_group["orig_bytes"].sum() + reflection_group["resp_bytes"].sum()
                    avg_packet_size = ref_bytes / ref_pkts if ref_pkts > 0 else 0.0

                    confidence = self._calculate_confidence(
                        ref_flows_count, ref_rate, 1.0, unique_srcs, src_entropy, "reflection"
                    )
                    # Reflection usually features a high ratio of responder bytes to originator bytes
                    # but depending on flow direction: if we are passive, we see incoming (resp or orig depending on orientation).
                    evidence = {
                        "reflection_flows_count": int(ref_flows_count),
                        "reflection_rate_per_sec": float(ref_rate),
                        "avg_packet_size": float(avg_packet_size),
                        "unique_src_count": int(unique_srcs),
                        "src_entropy": float(src_entropy),
                        "ports_involved": [int(p) for p in reflection_group["src_port"].unique()],
                    }
                    alerts.append(
                        Alert(
                            timestamp=datetime.fromtimestamp(max_ts, tz=timezone.utc),
                            threat_class="ddos_reflection",
                            confidence=confidence,
                            severity=self._determine_severity(confidence, ref_flows_count),
                            source="multiple" if unique_srcs > 1 else str(group["src_ip"].iloc[0]),
                            destination=str(dst_ip),
                            evidence=evidence,
                        )
                    )

        return alerts

    def _calculate_confidence(
        self,
        count: int,
        rate: float,
        failed_ratio: float,
        unique_srcs: int,
        src_entropy: float,
        attack_type: str,
    ) -> float:
        # Scale with quantity of attack flows
        count_factor = 1.0 - np.exp(-count / 50.0)
        # Scale with rate
        rate_factor = 1.0 - np.exp(-rate / 50.0)
        # Failed ratio is critical for TCP SYN flood
        if attack_type == "syn_flood":
            cf = 0.3 * count_factor + 0.3 * rate_factor + 0.4 * failed_ratio
        else:
            # For UDP or Reflection, volume & rate dictate confidence
            cf = 0.5 * count_factor + 0.5 * rate_factor

        # Adjust score according to source profile
        # Highly distributed DDoS (entropy > 2) bumps confidence up slightly
        if unique_srcs > 10 and src_entropy > 2.0:
            cf = min(cf + 0.1, 1.0)

        # Clamping
        return float(np.clip(cf, 0.0, 1.0))

    def _determine_severity(self, confidence: float, count: int) -> str:
        if confidence >= 0.85 and count >= 200:
            return "critical"
        elif confidence >= 0.70 or count >= 100:
            return "high"
        elif confidence >= 0.40:
            return "medium"
        return "low"
