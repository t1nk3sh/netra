"""PCAP File Threat & Traffic Analyzer.

Provides end-to-end passive analysis of user-uploaded or local PCAP files:
1. Packet-level metrics & protocol distribution (via Scapy)
2. Connection flow extraction (via Zeek or fallback flow reconstruction)
3. ML Threat Inference & Anomaly Scoring (via ThreatPredictor)
4. Heuristic & rule-based scan/flood detection
5. Formats structured forensic summaries and flow lists for dashboard presentation.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import numpy as np
import pandas as pd
from scapy.all import PcapReader as ScapyPcapReader
from scapy.packet import Packet

from capture.pcap_reader import get_pcap_statistics
from dashboard.utils.formatting import format_timestamp, format_time_only
from inference.predictor import DEFAULT_MODEL_PATH, ThreatPredictor
from models.preprocessing import FEATURE_COLUMNS, FlowFeaturePreprocessor
from zeek.log_parser import parse_conn_log
from zeek.runner import ZeekConfig, ZeekRunner

logger = logging.getLogger(__name__)


def _safe_int(val: Any, default: int = 0) -> int:
    """Safely cast value to integer, handling NaN/Inf/None."""
    try:
        if val is None or pd.isna(val) or not np.isfinite(float(val)):
            return default
        return int(float(val))
    except Exception:
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely cast value to float, handling NaN/Inf/None."""
    try:
        if val is None or pd.isna(val) or not np.isfinite(float(val)):
            return default
        return float(val)
    except Exception:
        return default


def _extract_scapy_flows(pcap_path: Path) -> List[Dict[str, Any]]:
    """Fallback flow extractor using Scapy when Zeek is unavailable or produces no logs."""
    # 5-tuple -> list of packets
    flow_map: Dict[tuple, list] = defaultdict(list)
    
    with ScapyPcapReader(str(pcap_path)) as reader:
        for idx, pkt in enumerate(reader):
            if not pkt.haslayer("IP") and not pkt.haslayer("IPv6"):
                continue
            
            ip_layer = pkt["IP"] if pkt.haslayer("IP") else pkt["IPv6"]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto_num = ip_layer.proto if pkt.haslayer("IP") else ip_layer.nh
            
            sport = None
            dport = None
            tcp_flags = ""
            proto_str = "OTHER"
            
            if pkt.haslayer("TCP"):
                proto_str = "TCP"
                sport = int(pkt["TCP"].sport)
                dport = int(pkt["TCP"].dport)
                tcp_flags = str(pkt["TCP"].flags)
            elif pkt.haslayer("UDP"):
                proto_str = "UDP"
                sport = int(pkt["UDP"].sport)
                dport = int(pkt["UDP"].dport)
            elif pkt.haslayer("ICMP"):
                proto_str = "ICMP"
            
            # Canonical flow key (bidirectional grouping)
            key = (src_ip, dst_ip, sport, dport, proto_str)
            rev_key = (dst_ip, src_ip, dport, sport, proto_str)
            
            target_key = key if key in flow_map or rev_key not in flow_map else rev_key
            flow_map[target_key].append({
                "ts": float(pkt.time),
                "len": len(pkt),
                "is_orig": (target_key == key),
                "tcp_flags": tcp_flags,
            })

    records = []
    for (src_ip, dst_ip, sport, dport, proto_str), pkts in flow_map.items():
        if not pkts:
            continue
        
        pkts_sorted = sorted(pkts, key=lambda x: x["ts"])
        start_ts = pkts_sorted[0]["ts"]
        end_ts = pkts_sorted[-1]["ts"]
        duration = max(0.0001, end_ts - start_ts)
        
        orig_pkts = [p for p in pkts_sorted if p["is_orig"]]
        resp_pkts = [p for p in pkts_sorted if not p["is_orig"]]
        
        orig_bytes = sum(p["len"] for p in orig_pkts)
        resp_bytes = sum(p["len"] for p in resp_pkts)
        total_bytes = orig_bytes + resp_bytes
        total_pkts = len(pkts_sorted)
        
        # History flags summary
        syn_count = sum(1 for p in pkts_sorted if "S" in p.get("tcp_flags", ""))
        ack_count = sum(1 for p in pkts_sorted if "A" in p.get("tcp_flags", ""))
        fin_count = sum(1 for p in pkts_sorted if "F" in p.get("tcp_flags", ""))
        rst_count = sum(1 for p in pkts_sorted if "R" in p.get("tcp_flags", ""))
        
        # Determine conn_state approximation
        conn_state = "SF"
        if rst_count > 0:
            conn_state = "REJ" if syn_count > 0 and ack_count == 0 else "RSTO"
        elif syn_count > 0 and ack_count == 0:
            conn_state = "S0"
            
        rec = {
            "ts": start_ts,
            "uid": f"F_{abs(hash((src_ip, dst_ip, sport, dport, start_ts))) % 10000000}",
            "src_ip": src_ip,
            "src_port": sport or 0,
            "dst_ip": dst_ip,
            "dst_port": dport or 0,
            "proto": proto_str.lower(),
            "conn_state": conn_state,
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "total_bytes": total_bytes,
            "orig_pkts": len(orig_pkts),
            "resp_pkts": len(resp_pkts),
            "total_pkts": total_pkts,
            "packets_per_sec": total_pkts / duration,
            "bytes_per_sec": total_bytes / duration,
            "orig_packets_per_sec": len(orig_pkts) / duration,
            "resp_packets_per_sec": len(resp_pkts) / duration,
            "avg_pkt_size": total_bytes / max(1, total_pkts),
            "avg_pkt_size_orig": orig_bytes / max(1, len(orig_pkts)),
            "avg_pkt_size_resp": resp_bytes / max(1, len(resp_pkts)),
            "byte_ratio": orig_bytes / max(1, resp_bytes),
            "pkt_ratio": len(orig_pkts) / max(1, len(resp_pkts)),
            "is_tcp": 1 if proto_str == "TCP" else 0,
            "is_udp": 1 if proto_str == "UDP" else 0,
            "hist_syn_count": syn_count,
            "hist_syn_ack_count": 1 if syn_count > 0 and ack_count > 0 else 0,
            "hist_ack_count": ack_count,
            "hist_data_count": max(0, total_pkts - syn_count - fin_count - rst_count),
            "hist_fin_count": fin_count,
            "hist_rst_count": rst_count,
            "hist_length": len(pkts_sorted),
            f"conn_state_{conn_state}": 1,
        }
        records.append(rec)
        
    return records


def analyze_pcap_file(
    pcap_path: str | Path,
    model_path: str | Path | None = None,
    threshold: float = 0.5,
    on_progress: Optional[Callable[[int, str, float], None]] = None,
) -> Dict[str, Any]:
    """Perform end-to-end passive threat and flow analysis on a PCAP file.

    Args:
        pcap_path: Path to the .pcap / .pcapng file.
        model_path: Optional path to .joblib model weights. Defaults to active model.
        threshold: Anomaly confidence threshold for flagging threats (default: 0.5).
        on_progress: Optional callback invoked as on_progress(step_number, status_message, progress_ratio).

    Returns:
        Structured dictionary containing summary stats, detected threats, and flow records.
    """
    p = Path(pcap_path)
    if not p.exists():
        raise FileNotFoundError(f"PCAP file not found: {p}")
    if not p.is_file():
        raise ValueError(f"Target is not a valid file: {p}")

    start_time = time.perf_counter()
    
    # ── Step 1: Packet level statistics via Scapy ──────────────────────
    if on_progress:
        on_progress(1, f"Inspecting packet headers & protocol distribution in {p.name}...", 0.20)
    pcap_stats = get_pcap_statistics(p)
    file_size_bytes = p.stat().st_size
    duration = max(0.001, pcap_stats.duration)
    pps = round(pcap_stats.packet_count / duration, 2)
    mbps = round((pcap_stats.total_bytes * 8) / (duration * 1_000_000), 3)

    proto_name_map = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 58: "ICMPv6"}
    protocol_distribution = {
        proto_name_map.get(proto_num, f"Proto-{proto_num}"): count
        for proto_num, count in pcap_stats.protocols.items()
        if count > 0
    }

    # ── Step 2: Extract connection flows ──────────────────────────────
    if on_progress:
        on_progress(2, f"Reconstructing flow sessions from {pcap_stats.packet_count:,} packets...", 0.40)
    flow_records: List[Dict[str, Any]] = []
    zeek_used = False
    
    try:
        temp_zeek_out = Path("data/zeek_analysis") / f"temp_{int(time.time()*1000)}"
        temp_zeek_out.mkdir(parents=True, exist_ok=True)
        runner = ZeekRunner(ZeekConfig(output_dir=temp_zeek_out))
        
        if runner.is_available():
            z_res = runner.process_pcap(p)
            conn_log = temp_zeek_out / "conn.log"
            if z_res.success and conn_log.exists():
                df_conn = parse_conn_log(conn_log)
                if not df_conn.empty:
                    flow_records = df_conn.to_dict(orient="records")
                    zeek_used = True
    except Exception as e:
        logger.debug("Zeek processing failed, falling back to Scapy: %s", e)

    # Fallback to Scapy packet reconstruction if Zeek didn't yield flows
    if not flow_records:
        flow_records = _extract_scapy_flows(p)

    if not protocol_distribution and flow_records:
        flow_proto_counts: Dict[str, int] = defaultdict(int)
        for rec in flow_records:
            pr = str(rec.get("proto", "TCP")).upper()
            flow_proto_counts[pr] += 1
        protocol_distribution = dict(flow_proto_counts)

    # ── Step 3: Model Inference & Feature Alignment ───────────────────
    if on_progress:
        on_progress(3, f"Synthesizing 37-dimensional feature vectors across {len(flow_records):,} flows...", 0.60)
    predictor = ThreatPredictor(model_path=model_path or DEFAULT_MODEL_PATH)
    
    analyzed_flows = []
    detected_threats = []
    
    if flow_records:
        df_flows = pd.DataFrame(flow_records)
        
        # Ensure all required feature columns exist
        for col in FEATURE_COLUMNS:
            if col not in df_flows.columns:
                df_flows[col] = 0.0
                
        # ── Step 4: Run Machine Learning Inference ────────────────────
        if on_progress:
            on_progress(4, f"Evaluating anomaly classifications using {Path(predictor.model_path).name}...", 0.80)
        predictions = predictor.predict(df_flows, threshold=threshold)
        
        for idx, (rec, pred) in enumerate(zip(flow_records, predictions)):
            is_threat = bool(pred.get("threat_predicted", False))
            confidence = float(pred.get("confidence", 0.0))
            
            src_ip = str(rec.get("src_ip", "-"))
            dst_ip = str(rec.get("dst_ip", "-"))
            src_port = _safe_int(rec.get("src_port", 0))
            dst_port = _safe_int(rec.get("dst_port", 0))
            proto = str(rec.get("proto", "TCP")).upper()
            ts_val = _safe_float(rec.get("ts"), time.time())
            
            # Rule based refinement / threat classification
            threat_type = "benign"
            severity = "low"
            
            if is_threat or confidence >= threshold:
                threat_type = predictor.classify_threat_type(rec)
                if threat_type == "benign":
                    threat_type = "anomalous_intrusion"
                    
                if confidence >= 0.90:
                    severity = "critical"
                elif confidence >= 0.75:
                    severity = "high"
                elif confidence >= 0.50 or confidence >= threshold:
                    severity = "medium"
                else:
                    severity = "low"
                    
                threat_alert = {
                    "id": f"ALT-PCAP-{idx+1:04d}",
                    "timestamp": ts_val,
                    "time_str": format_time_only(ts_val),
                    "threat_class": threat_type.replace("_", " ").title(),
                    "severity": severity.upper(),
                    "confidence": f"{int(confidence * 100)}%",
                    "confidence_raw": confidence,
                    "source": f"{src_ip}:{src_port}",
                    "destination": f"{dst_ip}:{dst_port}",
                    "protocol": proto,
                    "evidence": {
                        "orig_bytes": _safe_int(rec.get("orig_bytes")),
                        "resp_bytes": _safe_int(rec.get("resp_bytes")),
                        "packets_tx": _safe_int(rec.get("orig_pkts")),
                        "packets_rx": _safe_int(rec.get("resp_pkts")),
                        "duration_sec": round(_safe_float(rec.get("duration")), 3),
                        "conn_state": str(rec.get("conn_state", "SF")),
                        "packets_per_sec": round(_safe_float(rec.get("packets_per_sec")), 1),
                        "bytes_per_sec": round(_safe_float(rec.get("bytes_per_sec")), 1),
                    },
                }
                detected_threats.append(threat_alert)

            flow_entry = {
                "id": rec.get("uid", f"F-{idx+1}"),
                "time": format_time_only(ts_val),
                "timestamp": ts_val,
                "proto": proto,
                "source": f"{src_ip}:{src_port}",
                "destination": f"{dst_ip}:{dst_port}",
                "state": str(rec.get("conn_state", "-")),
                "packets": f"{_safe_int(rec.get('orig_pkts'))} / {_safe_int(rec.get('resp_pkts'))}",
                "bytes": f"{_safe_int(rec.get('total_bytes')):,}",
                "duration": f"{_safe_float(rec.get('duration')):.2f}s",
                "status": "THREAT" if is_threat else "SAFE",
                "threat_class": threat_type.replace("_", " ").title() if is_threat else "Benign",
                "confidence": f"{int(confidence * 100)}%",
                "raw_confidence": confidence,
                "is_threat": is_threat,
            }
            analyzed_flows.append(flow_entry)

    analysis_latency = round((time.perf_counter() - start_time) * 1000.0, 2)
    
    # ── Step 5: Aggregate Forensic Summary ────────────────────────────
    if on_progress:
        on_progress(5, f"Aggregating forensic report & connection telemetry for {p.name}...", 1.00)
    threat_count = len(detected_threats)
    total_flows_count = len(analyzed_flows)
    safe_count = max(0, total_flows_count - threat_count)
    threat_pct = round((threat_count / max(1, total_flows_count)) * 100, 1)

    # Top targeted destination ports
    dst_ports_counter: Dict[int, int] = defaultdict(int)
    src_ips_counter: Dict[str, int] = defaultdict(int)
    for rec in flow_records:
        dp = int(rec.get("dst_port", 0) or 0)
        if dp > 0:
            dst_ports_counter[dp] += 1
        s_ip = str(rec.get("src_ip", "-"))
        if s_ip != "-":
            src_ips_counter[s_ip] += 1

    top_ports = sorted(dst_ports_counter.items(), key=lambda x: x[1], reverse=True)[:5]
    top_sources = sorted(src_ips_counter.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "filename": p.name,
        "file_size_formatted": f"{round(file_size_bytes/1024, 1)} KB" if file_size_bytes < 1024*1024 else f"{round(file_size_bytes/(1024*1024), 2)} MB",
        "file_size_bytes": file_size_bytes,
        "packet_count": pcap_stats.packet_count,
        "duration_sec": round(duration, 2),
        "total_bytes": pcap_stats.total_bytes,
        "packets_per_sec": pps,
        "bandwidth_mbps": mbps,
        "protocol_distribution": protocol_distribution,
        "zeek_engine_used": zeek_used,
        "active_model_name": Path(predictor.model_path).name,
        "analysis_latency_ms": analysis_latency,
        "summary": {
            "total_flows": total_flows_count,
            "threat_flows": threat_count,
            "safe_flows": safe_count,
            "threat_percentage": threat_pct,
            "top_ports": top_ports,
            "top_sources": top_sources,
        },
        "threats": detected_threats,
        "flows": analyzed_flows,
    }
