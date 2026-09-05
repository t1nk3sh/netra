"""Flow feature engineering from Zeek conn.log data.

Extracts ML-ready features from parsed connection metadata.
All features are derived from passive observation only.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


HISTORY_FLAGS = {
    "S": "syn",
    "H": "syn_ack",
    "A": "ack",
    "D": "data",
    "F": "fin",
    "R": "rst",
}


def extract_per_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract per-flow features from a parsed conn.log DataFrame.

    Args:
        df: DataFrame from parse_conn_log() with normalized column names.

    Returns:
        DataFrame with one row per flow and ML-ready feature columns.
    """
    features = pd.DataFrame(index=df.index)

    if "uid" in df.columns:
        features["uid"] = df["uid"]
    if "src_ip" in df.columns:
        features["src_ip"] = df["src_ip"]
    if "dst_ip" in df.columns:
        features["dst_ip"] = df["dst_ip"]
    if "src_port" in df.columns:
        features["src_port"] = df["src_port"]
    if "dst_port" in df.columns:
        features["dst_port"] = df["dst_port"]
    if "proto" in df.columns:
        features["proto"] = df["proto"]
    if "service" in df.columns:
        features["service"] = df["service"]
    if "conn_state" in df.columns:
        features["conn_state"] = df["conn_state"]
    if "ts" in df.columns:
        features["ts"] = df["ts"]

    features["duration"] = pd.to_numeric(df.get("duration"), errors="coerce").fillna(0.0)
    features["orig_bytes"] = pd.to_numeric(df.get("orig_bytes"), errors="coerce").fillna(0.0)
    features["resp_bytes"] = pd.to_numeric(df.get("resp_bytes"), errors="coerce").fillna(0.0)
    features["orig_pkts"] = pd.to_numeric(df.get("orig_pkts"), errors="coerce").fillna(0.0)
    features["resp_pkts"] = pd.to_numeric(df.get("resp_pkts"), errors="coerce").fillna(0.0)
    features["orig_ip_bytes"] = pd.to_numeric(df.get("orig_ip_bytes"), errors="coerce").fillna(0.0)
    features["resp_ip_bytes"] = pd.to_numeric(df.get("resp_ip_bytes"), errors="coerce").fillna(0.0)
    features["missed_bytes"] = pd.to_numeric(df.get("missed_bytes"), errors="coerce").fillna(0.0)

    features["total_bytes"] = features["orig_bytes"] + features["resp_bytes"]
    features["total_pkts"] = features["orig_pkts"] + features["resp_pkts"]
    features["total_ip_bytes"] = features["orig_ip_bytes"] + features["resp_ip_bytes"]

    safe_duration = features["duration"].replace(0.0, np.nan)
    features["packets_per_sec"] = features["total_pkts"] / safe_duration
    features["bytes_per_sec"] = features["total_bytes"] / safe_duration
    features["orig_packets_per_sec"] = features["orig_pkts"] / safe_duration
    features["resp_packets_per_sec"] = features["resp_pkts"] / safe_duration

    features["avg_pkt_size_orig"] = _safe_divide(features["orig_bytes"], features["orig_pkts"])
    features["avg_pkt_size_resp"] = _safe_divide(features["resp_bytes"], features["resp_pkts"])
    features["avg_pkt_size"] = _safe_divide(features["total_bytes"], features["total_pkts"])

    features["byte_ratio"] = _safe_ratio(features["orig_bytes"], features["resp_bytes"])
    features["pkt_ratio"] = _safe_ratio(features["orig_pkts"], features["resp_pkts"])
    features["ip_byte_ratio"] = _safe_ratio(features["orig_ip_bytes"], features["resp_ip_bytes"])

    features["is_tcp"] = (df.get("proto") == "tcp").astype(int) if "proto" in df.columns else 0
    features["is_udp"] = (df.get("proto") == "udp").astype(int) if "proto" in df.columns else 0

    if "history" in df.columns:
        history_features = _extract_history_features(df["history"])
        features = pd.concat([features, history_features], axis=1)

    if "conn_state" in df.columns:
        state_features = _extract_conn_state_features(df["conn_state"])
        features = pd.concat([features, state_features], axis=1)

    features = features.fillna(0.0)

    return features


def extract_aggregate_features(df: pd.DataFrame, group_by: str = "src_ip") -> pd.DataFrame:
    """Extract aggregate features grouped by a key (e.g., source IP).

    Args:
        df: DataFrame from extract_per_flow_features().
        group_by: Column to group by. Default is "src_ip".

    Returns:
        DataFrame with one row per group and aggregate feature columns.
    """
    if group_by not in df.columns:
        raise ValueError(f"Column '{group_by}' not found in DataFrame")

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if group_by in numeric_cols:
        numeric_cols.remove(group_by)

    grouped = df.groupby(group_by)

    agg = pd.DataFrame(index=grouped.groups.keys())
    agg.index.name = group_by

    agg["flow_count"] = grouped.size()

    if "dst_ip" in df.columns:
        agg["unique_dst_ips"] = grouped["dst_ip"].nunique()
    if "dst_port" in df.columns:
        agg["unique_dst_ports"] = grouped["dst_port"].nunique()

    for col in ["duration", "total_bytes", "total_pkts", "orig_bytes", "resp_bytes"]:
        if col in numeric_cols:
            agg[f"{col}_sum"] = grouped[col].sum()
            agg[f"{col}_mean"] = grouped[col].mean()
            agg[f"{col}_std"] = grouped[col].std().fillna(0.0)
            agg[f"{col}_max"] = grouped[col].max()
            agg[f"{col}_min"] = grouped[col].min()

    if "byte_ratio" in numeric_cols:
        agg["byte_ratio_mean"] = grouped["byte_ratio"].mean()
    if "pkt_ratio" in numeric_cols:
        agg["pkt_ratio_mean"] = grouped["pkt_ratio"].mean()

    if "ts" in df.columns:
        ts_sorted = grouped["ts"].apply(lambda x: x.sort_values())
        agg["ts_range"] = grouped["ts"].max() - grouped["ts"].min()

    if "is_tcp" in numeric_cols:
        agg["tcp_fraction"] = grouped["is_tcp"].mean()
    if "is_udp" in numeric_cols:
        agg["udp_fraction"] = grouped["is_udp"].mean()

    if "conn_state_S0" in df.columns:
        agg["failed_conn_ratio"] = grouped["conn_state_S0"].mean()

    agg = agg.fillna(0.0)
    return agg.reset_index()


def _safe_divide(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    with np.errstate(divide="ignore", invalid="ignore"):
        result = numerator / denominator.replace(0, np.nan)
    return result.fillna(0.0)


def _safe_ratio(a: pd.Series, b: pd.Series) -> pd.Series:
    total = a + b
    with np.errstate(divide="ignore", invalid="ignore"):
        result = a / total.replace(0, np.nan)
    return result.fillna(0.5)


def _extract_history_features(history: pd.Series) -> pd.DataFrame:
    result = pd.DataFrame(index=history.index)
    for char, name in HISTORY_FLAGS.items():
        result[f"hist_{name}_count"] = history.fillna("").apply(
            lambda h, c=char: h.count(c)
        )
    result["hist_length"] = history.fillna("").apply(len)
    return result


def _extract_conn_state_features(conn_state: pd.Series) -> pd.DataFrame:
    states = ["S0", "S1", "SF", "REJ", "RSTO", "RSTR", "OTH"]
    result = pd.DataFrame(index=conn_state.index)
    for state in states:
        result[f"conn_state_{state}"] = (conn_state == state).astype(int)
    return result
