"""Alerts page for filtering and searching threat alerts historical log."""

import streamlit as st
import pandas as pd
from dashboard.components.alerts import render_alert_details
from dashboard.utils.formatting import format_timestamp


from dashboard.services.api_client import APIClient

def render_alerts_page(alerts: list, api_client: APIClient | None = None, backend_connected: bool = False) -> None:
    """Render the threat history page with search filters."""
    st.markdown("## 🔎 Threat Alert Registry")
    st.markdown("Search and inspect chronological passive security detections.")

    if not alerts:
        st.markdown(
            """
            <div style='background-color: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 8px; padding: 30px; text-align: center;'>
                <p style='color: #475569; font-weight: 600; margin: 0;'>No alerts registered</p>
                <p style='color: #64748b; font-size: 0.85rem; margin: 6px 0 0 0;'>The detection engine has not emitted any threat flags for the current capture session.</p>
            </div>
            """,
            unsafe_allow_html=True
        )
        return

    # Filter widget section
    col_f1, col_f2, col_f3 = st.columns(3)
    
    with col_f1:
        classes = sorted(list({a["threat_class"] for a in alerts}))
        selected_class = st.selectbox("Category Filter", ["All Categories"] + classes)
        
    with col_f2:
        severities = sorted(list({a["severity"] for a in alerts}))
        selected_sev = st.selectbox("Severity Filter", ["All Severities"] + severities)
        
    with col_f3:
        search_ip = st.text_input("Source IP Search").strip()

    # Apply filters
    filtered = alerts
    if selected_class != "All Categories":
        filtered = [a for a in filtered if a["threat_class"] == selected_class]
    if selected_sev != "All Severities":
        filtered = [a for a in filtered if a["severity"] == selected_sev]
    if search_ip:
        filtered = [a for a in filtered if search_ip in a["source"]]

    st.markdown(f"**Showing {len(filtered)} alerts matching criteria**")

    # Render display table or list
    if not filtered:
        st.info("No logs match the selected filters.")
        return

    records = []
    for item in filtered:
        records.append({
            "ID": item["id"],
            "Timestamp": format_timestamp(item["timestamp"]),
            "Category": item["threat_class"].replace("_", " ").title(),
            "Severity": item["severity"].upper(),
            "Source IP": item["source"],
            "Destination IP": item.get("destination") or "Multiple / None",
            "Confidence": f"{int(item['confidence'] * 100)}%"
        })

    df = pd.DataFrame(records)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Forensic select
    alert_choices = {item["ID"]: f"[{item['Severity']}] {item['Category']} - Source: {item['Source IP']}" for item in records}
    inspect_id = st.selectbox(
        "Inspect Details",
        options=list(alert_choices.keys()),
        format_func=lambda x: alert_choices[x],
        key="history_inspect_id"
    )

    if inspect_id:
        selected_alert = None
        if backend_connected and api_client:
            selected_alert = api_client.get_alert_by_id(inspect_id)
        else:
            selected_alert = next((a for a in alerts if a["id"] == inspect_id), None)
            
        if selected_alert:
            render_alert_details(selected_alert)
