"""Overview page layout of the threat dashboard."""

import streamlit as st
from dashboard.components.metrics import render_metrics
from dashboard.components.charts import (
    render_severity_distribution_chart,
    render_threat_distribution_chart,
    render_threat_activity_chart,
)
from dashboard.components.alerts import render_alerts_table, render_alert_details
from dashboard.components.tables import render_threat_actors_table


from dashboard.services.api_client import APIClient

def render_overview_page(statistics: dict, alerts: list, flows: list, threat_ips: list, api_client: APIClient | None = None, backend_connected: bool = False) -> None:
    """Render the dashboard overview layout."""
    
    # 1. Metric summary cards
    render_metrics(statistics, alerts, flows)
    
    # Standard grid layout split
    col_left, col_right = st.columns([2, 1])
    
    with col_left:
        st.markdown("### 📈 Network Threat Activity")
        
        # Timeframe selector
        timeframe = st.segmented_control(
            "Timeframe Filter",
            options=["1H", "6H", "24H", "7D"],
            default="24H",
            label_visibility="collapsed"
        )
        
        # Activity chart
        render_threat_activity_chart(alerts, timeframe=timeframe)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Severity Distribution Chart
        render_severity_distribution_chart(statistics)
        
    with col_right:
        st.markdown("### 📊 Threat Classification Vectors")
        # Threat Type Pie Chart
        render_threat_distribution_chart(statistics)
        
        st.markdown("---")
        st.markdown("### 🕸️ Highest Risk IP Threat Actors")
        # List of offending IPs
        render_threat_actors_table(threat_ips)

    st.markdown("<br><hr style='border-color: #e2e8f0;'><br>", unsafe_allow_html=True)
    
    # Recent Alerts List
    st.markdown("### 📋 Recent Security Alerts")
    selected_id = render_alerts_table(alerts)
    
    # Forensic Inspector for selected alert
    if selected_id:
        selected_alert = None
        if backend_connected and api_client:
            selected_alert = api_client.get_alert_by_id(selected_id)
        else:
            selected_alert = next((a for a in alerts if a["id"] == selected_id), None)
            
        if selected_alert:
            render_alert_details(selected_alert)
