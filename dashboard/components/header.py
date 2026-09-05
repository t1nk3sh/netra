"""Header component rendering containing service status state indicators."""

import json
import logging
from pathlib import Path
from datetime import datetime
import streamlit as st

logger = logging.getLogger(__name__)

def render_header(backend_connected: bool, is_simulated: bool = False) -> None:
    """Render the standard header with system status indicators."""
    now_str = datetime.now().strftime("%H:%M:%S")
    
    col_title, col_status = st.columns([2, 1])
    
    with col_title:
        st.title("NETra Threat Detection")
        st.caption("Passive Security Operations & Threat Classification Enclave")
        
    # Read sensor status JSON if present
    sensor_mode = None
    sensor_iface = None
    p_status = Path("data/sensor_status.json")
    if p_status.exists():
        try:
            with open(p_status, "r") as f:
                data = json.load(f)
                sensor_mode = data.get("mode")
                sensor_iface = data.get("interface")
        except Exception as e:
            logger.warning("Failed to parse sensor status payload: %s", e)

    with col_status:
        # Determine status state
        if backend_connected:
            if sensor_mode == "live":
                st.success(f"● LIVE CAPTURE ACTIVE ({sensor_iface})")
            elif sensor_mode == "replay":
                st.info("● REPLAY SIMULATION ACTIVE")
            else:
                st.success("● MONITORING ACTIVE")
        elif is_simulated:
            st.warning("● WEB CLIENT SIMULATION ACTIVE")
        else:
            st.error("● SYSTEM OFFLINE")
        st.caption(f"Last updated: {now_str}")
        
    st.markdown("---")
