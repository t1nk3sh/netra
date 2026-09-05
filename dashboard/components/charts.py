"""Interactive charts using Plotly for Streamlit."""

from __future__ import annotations

from typing import Any, Dict, List
import pandas as pd
import plotly.express as px
import streamlit as st


def render_severity_distribution_chart(statistics: Dict[str, Any]) -> None:
    """Render Plotly Donut Chart for severity distribution.

    Args:
        statistics: Dict from get_statistics() API.
    """
    sevs = statistics.get("severity_counts", {})
    if not any(sevs.values()):
        st.write("No severity data available.")
        return

    # Clean display labels
    df = pd.DataFrame([
        {"Severity": k.upper(), "Count": v}
        for k, v in sevs.items() if v > 0
    ])

    # SaaS palette for severities
    color_map = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#3b82f6"
    }

    fig = px.pie(
        df,
        values="Count",
        names="Severity",
        color="Severity",
        color_discrete_map=color_map,
        title="Severity Distribution",
        hole=0.5,
    )
    fig.update_traces(textinfo='percent+value')
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#475569",
        margin=dict(t=40, b=0, l=0, r=0),
        height=250,
        showlegend=True
    )
    st.plotly_chart(fig, use_container_width=True)


def render_threat_distribution_chart(statistics: Dict[str, Any]) -> None:
    """Render vertical or donut Plotly Donut Chart representing threat classes.

    Args:
        statistics: Dict from get_statistics() API.
    """
    classes = statistics.get("threat_class_counts", {})
    if not classes:
        st.write("No threat vectors identified yet.")
        return

    # Format classes beautifully
    formatted_classes = {
        k.replace("_", " ").title(): v
        for k, v in classes.items() if v > 0
    }

    df = pd.DataFrame(list(formatted_classes.items()), columns=["Threat Vector", "Count"])

    # SaaS cohesive cool colors
    fig = px.pie(
        df,
        values="Count",
        names="Threat Vector",
        color_discrete_sequence=px.colors.qualitative.Safe,
        title="Threat Distribution",
        hole=0.5,
    )
    fig.update_traces(textinfo='percent')
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#475569",
        margin=dict(t=40, b=0, l=0, r=0),
        height=250
    )
    st.plotly_chart(fig, use_container_width=True)


def render_threat_activity_chart(alerts: List[Dict[str, Any]], timeframe: str = "24H") -> None:
    """Render Plotly Area chart representing threat logs count over time.

    Args:
        alerts: List of alerts.
        timeframe: Hour or Day limit string ("1H", "6H", "24H", "7D").
    """
    if not alerts:
        st.write("No activity data available to chart.")
        return

    df = pd.DataFrame(alerts)
    df["dt"] = pd.to_datetime(df["timestamp"])
    
    # Try parsing datetimes safely
    now = pd.Timestamp.now(tz=df["dt"].dt.tz)
    
    if timeframe == "1H":
        df_filtered = df[df["dt"] >= now - pd.Timedelta(hours=1)]
        resample_rule = "1min"
    elif timeframe == "6H":
        df_filtered = df[df["dt"] >= now - pd.Timedelta(hours=6)]
        resample_rule = "5min"
    elif timeframe == "7D":
        df_filtered = df[df["dt"] >= now - pd.Timedelta(days=7)]
        resample_rule = "12h"
    else:  # 24H
        df_filtered = df[df["dt"] >= now - pd.Timedelta(hours=24)]
        resample_rule = "1h"

    if df_filtered.empty:
        st.info("No threat alerts detected during this period.")
        return

    df_grouped = df_filtered.set_index("dt").resample(resample_rule).size().reset_index(name="Alerts Count")

    fig = px.area(
        df_grouped,
        x="dt",
        y="Alerts Count",
        labels={"dt": "Timestamp", "Alerts Count": "Alerts Count"},
        title=f"Threat Activity ({timeframe} Log Window)",
    )
    
    fig.update_traces(
        line_color="#2563eb",
        fillcolor="rgba(37, 99, 235, 0.1)"
    )
    
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#475569",
        margin=dict(t=40, b=20, l=40, r=20),
        height=280,
        xaxis=dict(showgrid=True, gridcolor="#e2e8f0"),
        yaxis=dict(showgrid=True, gridcolor="#e2e8f0")
    )
    st.plotly_chart(fig, use_container_width=True)


def render_project_flowchart() -> None:
    """Render a Graphviz flowchart explaining the project's passive unidirectional pipeline."""
    dot_code = """
    digraph G {
        bgcolor="rgba(0,0,0,0)"
        node [shape=box, style="filled,rounded", color="#e2e8f0", fillcolor="#ffffff", fontcolor="#0f172a", fontname="Helvetica", penwidth=1]
        edge [color="#2563eb", fontname="Helvetica", fontcolor="#475569", fontsize=9, penwidth=1.5]
        
        A [label="Network Traffic\\n(TAP/SPAN/PCAP Mirror)", fillcolor="#eff6ff", color="#bfdbfe"]
        B [label="Read-Only Ingestion\\n(No Return Path Enclave)", fillcolor="#f0fdf4", color="#bbf7d0"]
        C [label="Features Ingestion\\n(Sliding Time Windows)", fillcolor="#faf5ff", color="#e9d5ff"]
        D [label="Detection Engines\\n(ML Classifiers & Rules)", fillcolor="#fff7ed", color="#fed7aa"]
        E [label="API Backend\\n(FastAPI alerts dispatcher)", fillcolor="#f8fafc", color="#e2e8f0"]
        F [label="Live UI Display\\n(Real-Time Stats)", fillcolor="#f0f9ff", color="#bae6fd"]
        
        A -> B [label="Passive Tap"]
        B -> C [label="Logs Feeds"]
        C -> D [label="Vector Extractor"]
        D -> E [label="POST Alert"]
        E -> F [label="Sync Engine"]
    }
    """
    st.graphviz_chart(dot_code)


def render_protocol_pie_chart(flows: List[Dict[str, Any]]) -> None:
    """Render a Plotly Pie Chart of the protocol ratio of actively analyzed flows.

    Args:
        flows: List of raw flows from get_flows().
    """
    if not flows:
        st.write("No active connection stream packets detected yet.")
        return

    protos = [f.get("proto", "unknown").upper() for f in flows]
    df = pd.DataFrame(protos, columns=["Protocol"])
    counts = df["Protocol"].value_counts().reset_index()
    counts.columns = ["Protocol", "Count"]

    color_map = {
        "TCP": "#2563eb",
        "UDP": "#3b82f6",
        "ICMP": "#64748b",
        "UNKNOWN": "#94a3b8"
    }

    fig = px.pie(
        counts,
        values="Count",
        names="Protocol",
        color="Protocol",
        color_discrete_map=color_map,
        title="Protocol Distribution (Analyzed Packets)",
        hole=0.4
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#475569",
        margin=dict(t=40, b=0, l=0, r=0),
        height=220
    )
    st.plotly_chart(fig, use_container_width=True)
