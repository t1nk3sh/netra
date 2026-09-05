"""Traffic page displaying network volume metrics and protocol distribution."""

from datetime import timezone
import pandas as pd
import plotly.express as px
import streamlit as st
from dashboard.components.charts import render_protocol_pie_chart
from dashboard.components.tables import render_analyzed_packets_table


def render_traffic_page(flows: list, pipeline_stats: dict | None = None) -> None:
    """Render the dedicated passive packet & flow analysis traffic dashboard."""
    st.markdown("## 📊 Passive Traffic & Flow Telemetry")
    st.markdown("Explore traffic volume metrics and protocol characteristics collected from the unidirectional TAP monitor link.")

    p_stats = pipeline_stats or {}
    iface = p_stats.get("interface", "any")
    mode = p_stats.get("mode", "replay")
    sniffed = p_stats.get("total_packets_sniffed", 0)
    
    col_info1, col_info2, col_info3 = st.columns(3)
    with col_info1:
        st.info(f"🌐 Monitored Adapter: **{iface}**")
    with col_info2:
        st.info(f"⚡ Ingestion State: **{'Live Packet Sniffing' if mode == 'live' else 'Replay Simulation'}**")
    with col_info3:
        if mode == "live" and sniffed > 0:
            st.info(f"📦 Total Packets Sniffed: **{sniffed:,}**")
        else:
            st.info(f"📦 Analyzed Flows Buffer: **{len(flows)} active**")

    if not flows:
        st.warning("No traffic data available. The network capture monitoring link has not recorded any packets in the active buffer.")
        return

    df = pd.DataFrame(flows)
    
    # Ensure standard schema fields exist in the DataFrame to prevent KeyError
    required_cols = {
        "orig_pkts": 0,
        "resp_pkts": 0,
        "total_bytes": 0,
        "timestamp": pd.Timestamp.now(tz=timezone.utc).isoformat() if hasattr(timezone, "utc") else pd.Timestamp.now().isoformat(),
        "src_ip": "-",
        "dst_ip": "-",
        "proto": "unknown"
    }
    for col, default_val in required_cols.items():
        if col not in df.columns:
            df[col] = default_val
    
    # 1. Main Volume Indicators
    total_flows = len(df)
    total_packets = int(df["orig_pkts"].fillna(0).sum() + df["resp_pkts"].fillna(0).sum())
    total_bytes = int(df["total_bytes"].fillna(0).sum())
    
    # Format bytes readable
    if total_bytes >= 1_048_576:
        bytes_label = f"{total_bytes / 1_048_576:.2f} MB"
    elif total_bytes >= 1024:
        bytes_label = f"{total_bytes / 1024:.2f} KB"
    else:
        bytes_label = f"{total_bytes} Bytes"

    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(label="Recent Flows Count", value=total_flows)
    with col2:
        st.metric(label="Processed Ingress Packets", value=f"{total_packets:,}")
    with col3:
        st.metric(label="Total Volumetric Ingress", value=bytes_label)

    st.markdown("---")
    
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.markdown("### Protocol Composition")
        render_protocol_pie_chart(flows)
        
    with col_right:
        # Traffic volume over time
        st.markdown("### Throughput Time Series")
        df["dt"] = pd.to_datetime(df["timestamp"])
        df_time = df.set_index("dt").resample("1min")["total_bytes"].sum().reset_index(name="Volume (Bytes)")
        
        if not df_time.empty:
            fig_time = px.line(
                df_time,
                x="dt",
                y="Volume (Bytes)",
                title="Bps Throughput Profile (1-Min Aggregation)",
            )
            fig_time.update_traces(line_color="#2563eb")
            fig_time.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#475569",
                margin=dict(t=40, b=20, l=40, r=20),
                height=220,
                xaxis=dict(showgrid=True, gridcolor="#e2e8f0"),
                yaxis=dict(showgrid=True, gridcolor="#e2e8f0")
            )
            st.plotly_chart(fig_time, use_container_width=True)
            
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Top IPs bar charts
    col_ips_left, col_ips_right = st.columns(2)
    
    with col_ips_left:
        st.markdown("### Top Sources (IP Address)")
        top_src = df["src_ip"].value_counts().reset_index()
        top_src.columns = ["Source IP", "Flow Counts"]
        fig_src = px.bar(
            top_src.head(5),
            x="Flow Counts",
            y="Source IP",
            orientation="h",
            labels={"Flow Counts": "Connection Flows", "Source IP": "Origin IP"},
            color_discrete_sequence=["#3b82f6"]
        )
        fig_src.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#475569",
            margin=dict(t=10, b=10, l=10, r=10),
            height=200
        )
        st.plotly_chart(fig_src, use_container_width=True)
        
    with col_ips_right:
        st.markdown("### Top Destinations (IP Address)")
        top_dst = df["dst_ip"].value_counts().reset_index()
        top_dst.columns = ["Dest IP", "Flow Counts"]
        fig_dst = px.bar(
            top_dst.head(5),
            x="Flow Counts",
            y="Dest IP",
            orientation="h",
            labels={"Flow Counts": "Connection Flows", "Dest IP": "Target IP"},
            color_discrete_sequence=["#1e3a8a"]
        )
        fig_dst.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#475569",
            margin=dict(t=10, b=10, l=10, r=10),
            height=200
        )
        st.plotly_chart(fig_dst, use_container_width=True)

    st.markdown("---")
    st.markdown("### 🔍 Actively Analyzed Ingress Flow Streams Grid")
    render_analyzed_packets_table(flows)
