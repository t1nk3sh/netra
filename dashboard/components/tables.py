"""Threat summary tables component for Streamlit."""

from __future__ import annotations

from typing import Any, List, Dict
import pandas as pd
import streamlit as st

from dashboard.utils.formatting import format_timestamp


def render_threat_actors_table(threats: List[Dict[str, Any]]) -> None:
    """Render the highest risk offending IPs.

    Args:
        threats: List from get_threats() API.
    """
    if not threats:
        st.write("No recurring threat actors identified yet.")
        return

    records = []
    for t in threats:
        records.append({
            "IP Address": t["source"],
            "Alert Count": t["alert_count"],
            "Max Confidence": f"{int(t['max_confidence'] * 100)}%",
            "Highest Severity": t["highest_severity"].upper(),
            "Threat Vectors": ", ".join(t["threat_classes"]),
        })

    df = pd.DataFrame(records)
    st.table(df)


def render_analyzed_packets_table(flows: List[Dict[str, Any]]) -> None:
    """Render the metadata list of actively analyzed packets/flows.

    Args:
        flows: List of raw flows from get_flows().
    """
    if not flows:
        st.write("Waiting for network capture logs stream...")
        return

    records = []
    for f in flows:
        records.append({
            "Time": format_timestamp(f.get("timestamp") or f.get("ts", "")),
            "Protocol": f.get("proto", "unknown").upper(),
            "Source": f"{f.get('src_ip', '-')}:{f.get('src_port', '')}" if f.get('src_port') else f.get('src_ip', '-'),
            "Destination": f"{f.get('dst_ip', '-')}:{f.get('dst_port', '')}" if f.get('dst_port') else f.get('dst_ip', '-'),
            "State": f.get("conn_state", f.get("service", "-")),
            "Packets (Sent/Rcvd)": f"{int(f.get('orig_pkts', 0) or 0)} / {int(f.get('resp_pkts', 0) or 0)}",
            "Bytes": f"{int(f.get('total_bytes', 0) or 0):,}",
            "Duration": f"{float(f.get('duration', 0.0) or 0.0):.2f}s" if f.get('duration') else "< 0.01s",
        })

    df = pd.DataFrame(records)
    st.dataframe(df, use_container_width=True, hide_index=True)
