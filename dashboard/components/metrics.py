"""Metrics summary widget component for Streamlit."""

from __future__ import annotations

from typing import Any, Dict, List
import numpy as np
import streamlit as st


def render_metrics(statistics: Dict[str, Any], alerts: List[Dict[str, Any]], flows: List[Dict[str, Any]]) -> None:
    """Render the dashboard top overview metrics banner using st.columns.

    Args:
        statistics: Dict from get_statistics() endpoint output.
        alerts: List of alerts.
        flows: List of raw flows.
    """
    total = statistics.get("total_alerts", 0)
    sevs = statistics.get("severity_counts", {})
    
    # Calculate Active Threats
    # Defined as unique source IPs involved in active alerts
    active_threats = len({a.get("source") for a in alerts if a.get("severity", "").lower() in ["critical", "high"]})
    
    # Calculate Average Confidence
    confidences = [a.get("confidence", 0.0) for a in alerts if "confidence" in a]
    avg_confidence_val = np.mean(confidences) if confidences else 0.0
    avg_confidence = f"{avg_confidence_val * 100:.1f}%"
    
    # Calculate Traffic/Flow Rate
    # If flows are available, estimate flows per second or total flows
    if flows:
        # Sum bytes or flows
        flow_count = len(flows)
        traffic_rate_str = f"{flow_count} active"
    else:
        traffic_rate_str = "0 flows/s"

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric(
            label="Total Alerts",
            value=total,
            help="Total number of passive threat alerts processed"
        )
    with col2:
        st.metric(
            label="Critical Threats",
            value=sevs.get("critical", 0),
            help="Highest priority security breaches requiring immediate forensics"
        )
    with col3:
        st.metric(
            label="Active Threats",
            value=active_threats,
            help="Unique source IPs showing warning or critical patterns"
        )
    with col4:
        st.metric(
            label="Avg Confidence",
            value=avg_confidence,
            help="Mean threat classification confidence score"
        )
    with col5:
        st.metric(
            label="Traffic Volume",
            value=traffic_rate_str,
            help="Total recent network connection flows recorded"
        )
