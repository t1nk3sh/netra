"""Shared path constants for the test suite.

Import from here so test paths resolve relative to the project root,
not the current working directory.
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SAMPLES_DIR = DATA_DIR / "samples"
MODEL_ARTIFACTS_DIR = PROJECT_ROOT / "models" / "artifacts"
DEFAULT_MODEL_PATH = MODEL_ARTIFACTS_DIR / "default_rf.joblib"
CONN_LOG = SAMPLES_DIR / "zeek_logs" / "conn.log"
SAMPLE_PCAP = SAMPLES_DIR / "test_traffic.pcap"
ZEEK_PCAP = SAMPLES_DIR / "zeek_test_traffic.pcap"
LABELED_FLOWS = SAMPLES_DIR / "labeled_flows.csv"
ZEEK_LOGS_DIR = SAMPLES_DIR / "zeek_logs"
