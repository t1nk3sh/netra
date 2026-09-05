"""Combine CIC-IDS2017 daily files (CSV or Parquet) into a labeled training set
whose columns match the project's model feature schema (`FEATURE_COLUMNS`).

Why: the runtime preprocessor (`models.preprocessing.FlowFeaturePreprocessor`)
expects Zeek-style column names. CIC-IDS2017 uses its own naming, so we map the
well-known CIC columns onto our feature names and zero-fill the rest. Training
without this mapping silently produces all-zero features and a useless model.
"""

import argparse
from pathlib import Path

import pandas as pd


# ── CIC-IDS2017 column name -> our feature column name ──────────────
CIC_TO_FEATURE = {
    "Flow Duration": "duration",  # microseconds -> converted to seconds below
    "Fwd Packets Length Total": "orig_bytes",
    "Bwd Packets Length Total": "resp_bytes",
    "Total Fwd Packets": "orig_pkts",
    "Total Backward Packets": "resp_pkts",
    "Fwd Packet Length Mean": "avg_pkt_size_orig",
    "Bwd Packet Length Mean": "avg_pkt_size_resp",
    "Flow Bytes/s": "bytes_per_sec",
    "Flow Packets/s": "packets_per_sec",
    "Label": "label",
}


def _strip_more_options(line: str) -> str:
    """CIC files sometimes end with a trailing 'More options...' row."""
    return line.split("More options...")[0]


def load_cic_csv(path: Path) -> pd.DataFrame:
    """Load a single CIC-IDS2017 daily CSV, fixing header quirks."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    header_idx = 0
    if len(lines) > 1 and lines[1][0].isdigit():
        header_idx = 0 if "Flow" in lines[0] else 1

    header = [c.strip().strip('"') for c in lines[header_idx].split(",")]
    data_rows = [ln for ln in lines[header_idx + 1:]]
    rows = []
    for ln in data_rows:
        ln = _strip_more_options(ln)
        cells = [c.strip().strip('"') for c in ln.split(",")]
        if len(cells) < len(header):
            cells = cells + [""] * (len(header) - len(cells))
        else:
            cells = cells[:len(header)]
        rows.append(cells)

    df = pd.DataFrame(rows, columns=header)
    df = df.replace(["Infinity", "-Infinity", "N/A", "NaN"], pd.NA)
    for col in df.columns:
        if col != "Label":
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def load_cic_parquet(path: Path) -> pd.DataFrame:
    """Load a single CIC-IDS2017 daily Parquet file."""
    df = pd.read_parquet(path)
    df.columns = [str(c).strip() for c in df.columns]
    return df


def load_cic_file(path: Path) -> pd.DataFrame:
    return load_cic_parquet(path) if path.suffix.lower() == ".parquet" else load_cic_csv(path)


def map_to_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Map raw CIC columns onto our feature schema and derive derived metrics."""
    mapped = {}
    for cic_col, feat_col in CIC_TO_FEATURE.items():
        if cic_col in df.columns:
            if feat_col == "label":
                # Keep the raw label string for downstream classification.
                mapped[feat_col] = df[cic_col].astype(str)
            else:
                mapped[feat_col] = pd.to_numeric(df[cic_col], errors="coerce")
        elif feat_col == "label":
            mapped["label"] = df["label"] if "label" in df.columns else df["Label"]

    out = pd.DataFrame(mapped)

    # Duration: CIC is in microseconds -> convert to seconds
    if "duration" in out.columns:
        out["duration"] = out["duration"] / 1e6

    # CIC Protocol is an IANA protocol number: TCP=6, UDP=17.
    proto = pd.to_numeric(df["Protocol"], errors="coerce") if "Protocol" in df.columns else None
    if proto is not None:
        out["is_tcp"] = (proto == 6).astype(int)
        out["is_udp"] = (proto == 17).astype(int)
    else:
        out["is_tcp"] = 0
        out["is_udp"] = 0

    # Derived aggregate fields
    out["total_bytes"] = out["orig_bytes"].fillna(0) + out["resp_bytes"].fillna(0)
    out["total_pkts"] = out["orig_pkts"].fillna(0) + out["resp_pkts"].fillna(0)
    out["avg_pkt_size"] = (out["avg_pkt_size_orig"].fillna(0) + out["avg_pkt_size_resp"].fillna(0)) / 2.0

    def ratio(a, b):
        out_col = out[a] / out[b].where(out[b] != 0, pd.NA)
        return out_col.fillna(0.0).astype(float)

    out["byte_ratio"] = ratio("orig_bytes", "resp_bytes")
    out["pkt_ratio"] = ratio("orig_pkts", "resp_pkts")
    out["orig_packets_per_sec"] = out["orig_pkts"] / out["duration"].where(out["duration"] > 0, pd.NA)
    out["resp_packets_per_sec"] = out["resp_pkts"] / out["duration"].where(out["duration"] > 0, pd.NA)
    out["orig_packets_per_sec"] = out["orig_packets_per_sec"].fillna(0.0)
    out["resp_packets_per_sec"] = out["resp_packets_per_sec"].fillna(0.0)

    # Columns CIC cannot provide -> zero fill (kept at 0, model treats them as absent)
    return out


def add_zero_fill(df: pd.DataFrame) -> pd.DataFrame:
    """Guarantee every feature column from the runtime schema exists."""
    from models.preprocessing import FEATURE_COLUMNS
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Combine CIC-IDS2017 daily files")
    parser.add_argument(
        "--data", "-d", default="data/samples",
        help="Folder containing the daily files (CSV or Parquet, default: data/samples)",
    )
    parser.add_argument(
        "--output", "-o", default="data/samples/cic_combined.parquet",
        help="Output combined file path (.parquet or .csv)",
    )
    parser.add_argument(
        "--max-rows", type=int, default=0,
        help="Limit total rows (0 = no limit) for quick experimentation",
    )
    args = parser.parse_args()

    folder = Path(args.data)
    files = sorted(list(folder.glob("*.csv")) + list(folder.glob("*.parquet")))
    files = [f for f in files if "combined" not in f.name.lower()]

    if not files:
        raise SystemExit(f"No CSV/Parquet files found in {folder}")

    frames = [map_to_schema(load_cic_file(f)) for f in files]
    combined = pd.concat(frames, ignore_index=True)

    if "label" not in combined.columns:
        raise SystemExit("No Label/Class column found in the dataset files")

    # Standardize: 'Benign' -> 0, everything else -> 1
    def label_to_int(x):
        return 0 if str(x).strip().lower() == "benign" else 1
    combined["label"] = combined["label"].apply(label_to_int)

    combined = add_zero_fill(combined)

    if args.max_rows and len(combined) > args.max_rows:
        combined = combined.sample(n=args.max_rows, random_state=42)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix.lower() == ".csv":
        combined.to_csv(out, index=False)
    else:
        combined.to_parquet(out, index=False)

    benign = int((combined["label"] == 0).sum())
    threat = int((combined["label"] == 1).sum())
    print(f"Combined {len(files)} files -> {out}")
    print(f"  Total rows : {len(combined)}")
    print(f"  Benign     : {benign}")
    print(f"  Threats    : {threat}")


if __name__ == "__main__":
    main()