"""Main Streamlit Application for Unidirectional IP Traffic Cyber Threat Detection."""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import time
import random
from datetime import datetime, timezone
import streamlit as st

from dashboard.services.api_client import APIClient
from dashboard.utils.theme import apply_theme
from dashboard.components.sidebar import render_sidebar
from dashboard.components.header import render_header

from dashboard.views.overview import render_overview_page
from dashboard.views.alerts import render_alerts_page
from dashboard.views.traffic import render_traffic_page
from dashboard.views.threats import render_threats_page
from dashboard.views.models import render_models_page
from dashboard.views.system import render_system_page

# Set page configuration standard
st.set_page_config(
    page_title="NETra - Network Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply global SaaS theme
apply_theme()

# Initialize API client
@st.cache_resource
def get_api_client() -> APIClient:
    return APIClient()


api_client = get_api_client()

# Initialize session state for mock simulation data if the backend is offline
if "simulated_alerts" not in st.session_state:
    st.session_state.simulated_alerts = []
if "simulated_flows" not in st.session_state:
    st.session_state.simulated_flows = []
if "simulated_stats" not in st.session_state:
    st.session_state.simulated_stats = {
        "total_alerts": 0,
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "threat_class_counts": {},
    }
if "simulated_threats" not in st.session_state:
    st.session_state.simulated_threats = []


def run_mock_simulation_step():
    """Inject a new simulated security event into the session state."""
    classes = ["port_scan", "host_scan", "ddos_syn_flood", "ddos_udp_flood", "ml_rf_threat"]
    severities = ["low", "medium", "high", "critical"]
    
    tc = random.choice(classes)
    sev = random.choice(severities)
    source = f"19.2.16.{random.randint(10, 50)}"

    simulated = {
        "id": f"sim_{random.randint(1000, 9999)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_class": tc,
        "confidence": round(random.random() * 0.4 + 0.6, 2),
        "severity": sev,
        "source": source,
        "destination": "10.0.0.1",
        "evidence": {
            "flow_count": random.randint(10, 150),
            "rate_per_sec": random.randint(10, 100),
            "details": "Simulated forensic alert generated locally because the backend is offline."
        }
    }

    # Prepend list
    st.session_state.simulated_alerts.insert(0, simulated)
    
    # Update Stats
    st.session_state.simulated_stats["total_alerts"] += 1
    st.session_state.simulated_stats["severity_counts"][sev] += 1
    st.session_state.simulated_stats["threat_class_counts"][tc] = (
        st.session_state.simulated_stats["threat_class_counts"].get(tc, 0) + 1
    )
    
    # Update Threats group
    threats = st.session_state.simulated_threats
    existing = next((t for t in threats if t["source"] == source), None)
    if existing:
        existing["alert_count"] += 1
        existing["max_confidence"] = max(existing["max_confidence"], simulated["confidence"])
        existing["highest_severity"] = simulated["severity"]
        existing["last_seen"] = simulated["timestamp"]
    else:
        st.session_state.simulated_threats.append({
            "source": source,
            "alert_count": 1,
            "max_confidence": simulated["confidence"],
            "highest_severity": simulated["severity"],
            "threat_classes": [simulated["threat_class"]],
            "last_seen": simulated["timestamp"]
        })
        
    st.session_state.simulated_threats = sorted(
        st.session_state.simulated_threats,
        key=lambda x: x["alert_count"],
        reverse=True
    )

    # Generate mock analyzed flow
    simulated_flow = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "proto": random.choice(["tcp", "udp", "icmp"]),
        "src_ip": source,
        "src_port": random.randint(1024, 65535),
        "dst_ip": "10.0.0.1",
        "dst_port": random.choice([80, 443, 53, 22]),
        "orig_pkts": random.randint(1, 10),
        "resp_pkts": random.randint(0, 10),
        "total_bytes": random.randint(40, 2000),
    }
    st.session_state.simulated_flows.insert(0, simulated_flow)
    st.session_state.simulated_flows = st.session_state.simulated_flows[:50]


# Render Sidebar
selected_page, auto_refresh = render_sidebar(api_client)

# Health Connection check
backend_connected = api_client.get_health()

# Simulated mode choice check if offline
is_simulated = False
if not backend_connected:
    # If backend is offline, enable simulated sandbox mode by default unless disabled
    is_simulated = st.sidebar.checkbox("🎮 Local Sandbox Simulation", value=True)
    if is_simulated:
        run_mock_simulation_step()

# Render Header with correct status
render_header(backend_connected=backend_connected, is_simulated=is_simulated)

# Backend Offline without simulation page check
if not backend_connected and not is_simulated:
    st.markdown(
        """
        <div style='background-color: #fef2f2; border: 1px solid #fca5a5; border-radius: 12px; padding: 30px; text-align: center; margin-top: 40px;'>
            <h2 style='color: #dc2626; margin: 0 0 10px 0;'>Backend offline</h2>
            <p style='color: #991b1b; font-size: 1rem; margin: 0 0 20px 0;'>The monitoring API could not be reached. Check that the FastAPI server is running.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    if st.button("Retry Connection"):
        st.rerun()
else:
    # Pull data from backend or fallback to session simulation
    pipeline_stats = {}
    if backend_connected:
        statistics = api_client.get_statistics()
        alerts = api_client.get_alerts()
        threat_ips = api_client.get_threats()
        flows = api_client.get_flows()
        pipeline_stats = api_client.get_pipeline_stats()
    else:
        statistics = st.session_state.simulated_stats
        alerts = st.session_state.simulated_alerts
        threat_ips = st.session_state.simulated_threats
        flows = st.session_state.simulated_flows

    # Route selected page views
    if selected_page == "Overview":
        render_overview_page(
            statistics=statistics,
            alerts=alerts,
            flows=flows,
            threat_ips=threat_ips,
            api_client=api_client,
            backend_connected=backend_connected
        )
    elif selected_page == "Alerts":
        render_alerts_page(
            alerts=alerts,
            api_client=api_client,
            backend_connected=backend_connected
        )
    elif selected_page == "Traffic":
        render_traffic_page(flows=flows, pipeline_stats=pipeline_stats)
    elif selected_page == "Threat Analysis":
        render_threats_page(alerts=alerts)
    elif selected_page == "Models":
        render_models_page()
    elif selected_page == "System":
        render_system_page(
            backend_connected=backend_connected,
            is_simulated=is_simulated,
            alerts=alerts,
            pipeline_stats=pipeline_stats
        )

# Main timer loop auto rerun
if auto_refresh:
    time.sleep(5)
    st.rerun()
