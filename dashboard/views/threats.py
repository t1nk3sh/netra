"""Threat analysis page explaining rules and threat metrics details."""

import streamlit as st
import numpy as np
from dashboard.utils.formatting import format_timestamp


def render_threats_page(alerts: list) -> None:
    """Render the Threat Analysis page."""
    st.markdown("## 🔍 Passive Attack Analytics & Rule Engines")
    st.markdown("Forensic indicators and active detection status for target threat vectors.")

    categories = {
        "DDoS": {
            "patterns": ["ddos", "ddos_syn_flood", "ddos_udp_flood", "flood"],
            "desc": "Volumetric SYN/UDP flood attacks aimed at exhaust target nodes.",
            "evidence": "Indicators checked: SYN packets ratio, packet/sec flow rates, volumetric traffic thresholds."
        },
        "Reconnaissance": {
            "patterns": ["port_scan", "host_scan", "scanning", "scan", "reconnaissance"],
            "desc": "Sequential destination scanning sweeping across ports/subnets.",
            "evidence": "Indicators checked: Unique destination ports swept, connection success/failure ratios, scan thresholds."
        },
        "C2 Beaconing": {
            "patterns": ["c2_beaconing", "beaconing", "c2", "beacon"],
            "desc": "Regular heartbeat calls to remote Command & Control platforms.",
            "evidence": "Indicators checked: Interval regularity, frequency entropy, ML flow profile match."
        },
        "DGA": {
            "patterns": ["dga"],
            "desc": "Dynamic algorithm-generated query domains bypassing reputation filters.",
            "evidence": "Indicators checked: Character entropy, consonant-to-vowel ratio, domain length distributions."
        },
        "DNS Tunneling": {
            "patterns": ["dns_tunneling", "tunneling", "dns_tunnel"],
            "desc": "Data tunneling stealthily encapsulated within standard DNS TXT Queries.",
            "evidence": "Indicators checked: DNS TXT query volume, domain length average, byte-to-char encoding density."
        },
        "Encrypted Traffic": {
            "patterns": ["encrypted_traffic", "encrypted", "ssl", "tls", "ja3", "ja4"],
            "desc": "Malicious sessions masking payloads inside encrypted SSL/TLS layers.",
            "evidence": "Indicators checked: JA3/JA4 cryptographic fingerprints, cipher-suite negotiations, packet length variance."
        },
        "Exfiltration": {
            "patterns": ["exfiltration", "data_exfil", "leak"],
            "desc": "Passive outbound data leakage bypassing monitoring rules.",
            "evidence": "Indicators checked: Inhomogeneous origin-to-response byte ratios, bulk sequence durations, flow-level payload sizes."
        }
    }

    # Group alerts
    for name, info in categories.items():
        # Match alerts by threat class
        matched = []
        for alert in alerts:
            tc = alert.get("threat_class", "").lower()
            if any(p in tc for p in info["patterns"]):
                matched.append(alert)
                
        info["count"] = len(matched)
        if matched:
            info["status"] = "🔴 THREAT WARNING ACTIVE"
            info["confidence"] = f"{int(np.mean([a['confidence'] for a in matched]) * 100)}%"
            # Get latest
            latest_time = max(a["timestamp"] for a in matched)
            info["recent"] = format_timestamp(latest_time)
        else:
            info["status"] = "🟢 ACTIVE MONITORING (NO DETECTIONS)"
            info["confidence"] = "N/A"
            info["recent"] = "None"

    # Render category grid natively via containers and columns
    for name, info in categories.items():
        with st.container(border=True):
            col_t, col_s = st.columns([2, 1])
            with col_t:
                st.markdown(f"### {name} Engine")
            with col_s:
                st.markdown(f"**Status:** {info['status']}")
            
            st.write(info["desc"])
            
            col_d1, col_d2, col_d3 = st.columns(3)
            with col_d1:
                st.metric("Detections Count", info["count"])
            with col_d2:
                st.metric("Mean Confidence", info["confidence"])
            with col_d3:
                st.metric("Last Alert Logged", info["recent"])
                
            st.code(info["evidence"])
            st.markdown("<br>", unsafe_allow_html=True)
