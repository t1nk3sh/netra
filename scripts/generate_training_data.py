"""Generate a synthetic labeled flow feature dataset for training tests."""

from pathlib import Path
import numpy as np
import pandas as pd

from models.preprocessing import FEATURE_COLUMNS

OUTPUT_PATH = "data/samples/labeled_flows.csv"


def generate(num_benign: int = 150, num_malicious: int = 50) -> str:
    """Generate and save synthetic flow feature dataset.

    Args:
        num_benign: Number of benign samples.
        num_malicious: Number of malicious samples.

    Returns:
        Path to the saved CSV.
    """
    np.random.seed(42)

    # Core columns
    all_cols = ["ts", "uid", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "conn_state", "label"] + FEATURE_COLUMNS
    all_cols = list(dict.fromkeys(all_cols)) # Deduplicate

    records = []
    base_ts = 1700000000.0

    # 1. Benign records
    for i in range(num_benign):
        rec = {
            "ts": base_ts + i * 5.0,
            "uid": f"benign_{i}",
            "src_ip": f"10.0.0.{np.random.randint(10, 200)}",
            "dst_ip": "192.168.1.100",
            "src_port": int(np.random.randint(1024, 65535)),
            "dst_port": int(np.random.choice([80, 443, 53])),
            "proto": str(np.random.choice(["tcp", "udp"])),
            "conn_state": "SF",
            "label": 0,
        }

        # Features
        rec["duration"] = float(np.random.exponential(scale=1.5))
        rec["orig_pkts"] = int(np.random.randint(2, 20))
        rec["resp_pkts"] = int(np.random.randint(2, 20))
        rec["orig_bytes"] = int(rec["orig_pkts"] * np.random.randint(60, 500))
        rec["resp_bytes"] = int(rec["resp_pkts"] * np.random.randint(60, 1000))
        rec["orig_ip_bytes"] = int(rec["orig_bytes"] + 40 * rec["orig_pkts"])
        rec["resp_ip_bytes"] = int(rec["resp_bytes"] + 40 * rec["resp_pkts"])
        rec["missed_bytes"] = 0
        rec["total_pkts"] = rec["orig_pkts"] + rec["resp_pkts"]
        rec["total_bytes"] = rec["orig_bytes"] + rec["resp_bytes"]
        rec["total_ip_bytes"] = rec["orig_ip_bytes"] + rec["resp_ip_bytes"]

        denom = rec["duration"] if rec["duration"] > 0 else 0.1
        rec["packets_per_sec"] = float(rec["total_pkts"] / denom)
        rec["bytes_per_sec"] = float(rec["total_bytes"] / denom)
        rec["orig_packets_per_sec"] = float(rec["orig_pkts"] / denom)
        rec["resp_packets_per_sec"] = float(rec["resp_pkts"] / denom)

        rec["avg_pkt_size_orig"] = float(rec["orig_bytes"] / rec["orig_pkts"])
        rec["avg_pkt_size_resp"] = float(rec["resp_bytes"] / rec["resp_pkts"])
        rec["avg_pkt_size"] = float(rec["total_bytes"] / rec["total_pkts"])

        rec["byte_ratio"] = float(rec["orig_bytes"] / (rec["total_bytes"] or 1.0))
        rec["pkt_ratio"] = float(rec["orig_pkts"] / (rec["total_pkts"] or 1.0))
        rec["ip_byte_ratio"] = float(rec["orig_ip_bytes"] / (rec["total_ip_bytes"] or 1.0))

        rec["is_tcp"] = 1 if rec["proto"] == "tcp" else 0
        rec["is_udp"] = 1 if rec["proto"] == "udp" else 0

        # history features
        rec["hist_syn_count"] = 1 if rec["proto"] == "tcp" else 0
        rec["hist_syn_ack_count"] = 1 if rec["proto"] == "tcp" else 0
        rec["hist_ack_count"] = int(np.random.randint(1, 5)) if rec["proto"] == "tcp" else 0
        rec["hist_data_count"] = int(np.random.randint(1, 5))
        rec["hist_fin_count"] = 1 if rec["proto"] == "tcp" else 0
        rec["hist_rst_count"] = 0
        rec["hist_length"] = int(rec["hist_syn_count"] + rec["hist_syn_ack_count"] + rec["hist_ack_count"] + rec["hist_fin_count"])

        # States
        rec["conn_state_S0"] = 0
        rec["conn_state_S1"] = 0
        rec["conn_state_SF"] = 1
        rec["conn_state_REJ"] = 0
        rec["conn_state_RSTO"] = 0
        rec["conn_state_RSTR"] = 0
        rec["conn_state_OTH"] = 0

        records.append(rec)

    # 2. Malicious records (DDoS SYN flood)
    for i in range(num_malicious):
        rec = {
            "ts": base_ts + num_benign * 5.0 + i * 0.1,
            "uid": f"malicious_{i}",
            "src_ip": f"192.168.10.{np.random.randint(2, 254)}",
            "dst_ip": "10.0.0.1",
            "src_port": int(np.random.randint(1024, 65535)),
            "dst_port": 80,
            "proto": "tcp",
            "conn_state": "S0",
            "label": 1,
        }

        # Features
        rec["duration"] = 0.0
        rec["orig_pkts"] = 1
        rec["resp_pkts"] = 0
        rec["orig_bytes"] = 40
        rec["resp_bytes"] = 0
        rec["orig_ip_bytes"] = 80
        rec["resp_ip_bytes"] = 0
        rec["missed_bytes"] = 0
        rec["total_pkts"] = 1
        rec["total_bytes"] = 40
        rec["total_ip_bytes"] = 80

        rec["packets_per_sec"] = 100.0  # high rate representation
        rec["bytes_per_sec"] = 4000.0
        rec["orig_packets_per_sec"] = 100.0
        rec["resp_packets_per_sec"] = 0.0

        rec["avg_pkt_size_orig"] = 40.0
        rec["avg_pkt_size_resp"] = 0.0
        rec["avg_pkt_size"] = 40.0

        rec["byte_ratio"] = 1.0
        rec["pkt_ratio"] = 1.0
        rec["ip_byte_ratio"] = 1.0

        rec["is_tcp"] = 1
        rec["is_udp"] = 0

        # history features
        rec["hist_syn_count"] = 1
        rec["hist_syn_ack_count"] = 0
        rec["hist_ack_count"] = 0
        rec["hist_data_count"] = 0
        rec["hist_fin_count"] = 0
        rec["hist_rst_count"] = 0
        rec["hist_length"] = 1

        rec["conn_state_S0"] = 1
        rec["conn_state_S1"] = 0
        rec["conn_state_SF"] = 0
        rec["conn_state_REJ"] = 0
        rec["conn_state_RSTO"] = 0
        rec["conn_state_RSTR"] = 0
        rec["conn_state_OTH"] = 0

        records.append(rec)

    df = pd.DataFrame(records)
    
    # Fill remaining columns to be safe
    for col in all_cols:
        if col not in df.columns:
            df[col] = 0.0

    df = df[all_cols]
    
    Path(OUTPUT_PATH).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)
    return OUTPUT_PATH


if __name__ == "__main__":
    p = generate()
    print(f"Generated synthetic training data at {p}")
