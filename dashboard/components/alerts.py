"""Alerts log table and detail inspector components."""

from __future__ import annotations

import json
from typing import Any, Dict, List
import pandas as pd
import streamlit as st
from dashboard.utils.formatting import format_timestamp, get_severity_details


def render_alerts_table(alerts: List[Dict[str, Any]]) -> str | None:
    """Render the chronological security alert stream.

    Provides a clean pandas-based table representation in Streamlit.
    Allows user to select an alert to query forensic details.

    Args:
        alerts: List of Alert dicts.

    Returns:
        The selected alert ID, or None if none selected.
    """
    if not alerts:
        with st.container(border=True):
            st.markdown("### No threats detected")
            st.markdown("Monitoring is active. No suspicious activity has been detected during the selected period.")
        return None

    # Load into DataFrame for pretty formatting
    display_records = []
    for alert in alerts:
        display_records.append({
            "Time": format_timestamp(alert["timestamp"]),
            "Threat": str(alert["threat_class"]).replace("_", " ").title(),
            "Severity": alert["severity"].upper(),
            "Confidence": f"{int(alert['confidence'] * 100)}%",
            "Source IP": alert["source"],
            "Destination IP": alert.get("destination") or "Multiple / Subnet",
        })

    df = pd.DataFrame(display_records)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Let user select alert for detailed forensics inspection
    alert_options = {
        alert["id"]: f"[{alert['severity'].upper()}] {str(alert['threat_class']).replace('_', ' ').title()} from {alert['source']}"
        for alert in alerts
    }
    
    selected_id = st.selectbox(
        "🔍 Select Alert to Inspect Forensic Details:",
        options=list(alert_options.keys()),
        format_func=lambda x: alert_options[x],
        index=0 if alerts else None,
        key="selected_alert_dropdown"
    )

    return selected_id


def render_alert_details(alert: Dict[str, Any]) -> None:
    """Render forensic details panel for a selected Alert.

    Args:
        alert: Dict containing alert details.
    """
    if not alert:
        return

    sev_info = get_severity_details(alert["severity"])
    threat_fmt = str(alert["threat_class"]).replace("_", " ").title()

    with st.container(border=True):
        st.markdown(f"### 🛡️ Forensics Inspector / Alert Details: `{alert['id']}`")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"**Threat Category:** `{threat_fmt}`")
            st.markdown(f"**Severity:** {sev_info['emoji']}")
        with col2:
            st.markdown(f"**Timestamp (UTC):** {format_timestamp(alert['timestamp'])}")
            st.markdown(f"**Confidence:** `{int(alert['confidence'] * 100)}%`")
        with col3:
            st.markdown(f"**Source IP:** `{alert['source']}`")
            st.markdown(f"**Destination:** `{alert.get('destination') or 'Multiple / Subnet'}`")

        evidence = alert.get("evidence", {})
        if evidence:
            st.markdown("**Evidence Artifacts (Feature State):**")
            st.code(json.dumps(evidence, indent=2), language="json")
        else:
            st.info("No supporting dynamic evidence dictionary was provided with this alert.")
