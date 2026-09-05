"""System health page rendering component checks."""

import streamlit as st
from dashboard.components.status import render_system_status


def render_system_page(backend_connected: bool, is_simulated: bool = False, alerts: list | None = None, pipeline_stats: dict | None = None) -> None:
    """Render the System Health page."""
    st.markdown("## 🖥️ Node Status & System Health")
    st.markdown("Observe processing pipeline latency, system performance, and host health indicators.")

    # Health status check rendering
    render_system_status(backend_connected=backend_connected, is_simulated=is_simulated, pipeline_stats=pipeline_stats)

    st.markdown("---")
    st.markdown("### Operational Telemetry State")

    # Clearly distinguish "No threats detected" from "Detection system offline"
    if not backend_connected and not is_simulated:
        st.error("🚨 DETECTING SYSTEM OFFLINE: The monitoring API backend server could not be reached. Deep packet analysis networks and rule engines are currently halted.")
        st.info("CRITICAL ERROR: Connection Refused")
    else:
        # Check alerts
        has_serious = alerts and any(a.get("severity", "").lower() in ["critical", "high"] for a in alerts)
        
        if has_serious:
            st.warning("⚠️ PATTERNS OF CONCERN FLAG ACTIVE: Active threat warnings matching known attack vector profiles have been logged on the tap link.")
        else:
            st.success("🛡️ NO THREATS DETECTED: Ingress traffic matches clean network signatures. Monitoring link ingestion flow profiles are normal.")
