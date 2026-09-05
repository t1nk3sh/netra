"""Sidebar component for Streamlit dashboard navigation."""

import json
import time
import socket
from pathlib import Path
import streamlit as st
from dashboard.services.api_client import APIClient


def render_sidebar(api_client: APIClient) -> tuple[str, bool]:
    """Render the sidebar with modern navigation pills and ingestion controls."""
    
    # 1. Header Branding
    st.sidebar.markdown(
        """
        <div style='padding: 6px 0 16px 0;'>
            <div style='display: flex; align-items: center; gap: 8px;'>
                <span style='font-size: 1.6rem;'>🛡️</span>
                <div>
                    <h3 style='margin: 0; font-size: 1.25rem; font-weight: 800; color: #0f172a; line-height: 1.1;'>NETra</h3>
                    <span style='font-size: 0.75rem; color: #64748b; font-weight: 500;'>ENCLAVE THREAT MONITOR</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    st.sidebar.markdown("### Navigation")
    
    # Modern Navigation Options with Icons
    page_options = [
        "📊 Overview",
        "🚨 Alerts",
        "🌐 Traffic",
        "🛡️ Threat Analysis",
        "🧠 Models",
        "⚙️ System"
    ]
    
    selected_page = st.sidebar.radio(
        label="Navigation Menu",
        options=page_options,
        label_visibility="collapsed"
    )
    
    # Extract clean page name (strip leading icon)
    clean_page_name = selected_page.split(" ", 1)[-1] if " " in selected_page else selected_page

    # Read interface list dynamically from OS
    try:
        interfaces = ["any"] + [name for index, name in socket.if_nameindex()]
    except Exception:
        interfaces = ["any", "wlo1", "lo", "docker0", "eth0"]

    # Load current sensor configuration
    config_path = Path("data/sensor_config.json")
    config = {"mode": "replay", "interface": "any"}
    if config_path.exists():
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
        except Exception:
            pass

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Ingestion Mode")
    
    mode_options = ["▶ Replay Simulation", "⚡ Live Packet Ingestion"]
    current_mode_idx = 1 if config.get("mode") == "live" else 0
    
    mode_choice = st.sidebar.radio(
        label="Mode Selector",
        options=mode_options,
        index=current_mode_idx,
        label_visibility="collapsed"
    )
    
    target_mode = "live" if "Live" in mode_choice else "replay"
    
    target_iface = config.get("interface", "any")
    if target_mode == "live":
        try:
            iface_idx = interfaces.index(target_iface)
        except ValueError:
            iface_idx = 0
            
        target_iface = st.sidebar.selectbox(
            "Target Interface",
            options=interfaces,
            index=iface_idx,
            help="Select the local network card to sniff packets from"
        )
        
    # Save settings action
    if st.sidebar.button("💾 Apply Settings", use_container_width=True):
        new_config = {
            "mode": target_mode,
            "interface": target_iface,
            "rotation": 30
        }
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, "w") as f:
                json.dump(new_config, f)
            st.sidebar.success("Ingestion settings applied!")
            time.sleep(0.5)
            st.rerun()
        except Exception as e:
            st.sidebar.error(f"Failed to apply: {e}")

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Controls")
    
    # Auto-refresh check toggle
    auto_refresh = st.sidebar.checkbox("🔄 Auto-Refresh (5s)", value=True)
    
    # Force reload button
    if st.sidebar.button("🔄 Sync Live Data", use_container_width=True):
        st.rerun()
        
    st.sidebar.markdown(
        """
        <div style='margin-top: 20px; font-size: 0.75rem; color: #94a3b8; text-align: center;'>
            NETra SOC Enclave • v1.0.0
        </div>
        """,
        unsafe_allow_html=True
    )
    
    return clean_page_name, auto_refresh
