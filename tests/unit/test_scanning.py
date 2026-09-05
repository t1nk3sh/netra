"""Unit tests for detection/scanning.py"""

import pytest
import pandas as pd
from alerts.alert_schema import Alert
from detection.scanning import ReconnaissanceDetector, load_thresholds


@pytest.fixture
def normal_traffic_df() -> pd.DataFrame:
    # 5 normal successful connections to a web server and a DNS server
    data = [
        {"ts": 1700000000.0, "src_ip": "10.0.0.10", "dst_ip": "192.168.1.1", "dst_port": 80, "conn_state": "SF"},
        {"ts": 1700000001.0, "src_ip": "10.0.0.10", "dst_ip": "192.168.1.1", "dst_port": 80, "conn_state": "SF"},
        {"ts": 1700000002.0, "src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "dst_port": 53, "conn_state": "SF"},
        {"ts": 1700000003.0, "src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "dst_port": 53, "conn_state": "SF"},
        {"ts": 1700000004.0, "src_ip": "10.0.0.10", "dst_ip": "192.168.1.1", "dst_port": 443, "conn_state": "SF"},
    ]
    return pd.DataFrame(data)


@pytest.fixture
def port_scan_df() -> pd.DataFrame:
    # Port scan: Source 10.0.0.2 to target 192.168.1.1 across 15 different ports in 1 second, all failing (S0)
    data = []
    base_ts = 1700000000.0
    for port in range(1, 16):
        data.append({
            "ts": base_ts + port * 0.05,
            "src_ip": "10.0.0.2",
            "dst_ip": "192.168.1.1",
            "dst_port": 80 + port,
            "conn_state": "S0"
        })
    return pd.DataFrame(data)


@pytest.fixture
def host_scan_df() -> pd.DataFrame:
    # Host scan: Source 10.0.0.3 to 10 different target IPs on port 22 in 1 second, all failing (REJ)
    data = []
    base_ts = 1700000000.0
    for host_id in range(1, 11):
        data.append({
            "ts": base_ts + host_id * 0.05,
            "src_ip": "10.0.0.3",
            "dst_ip": f"192.168.1.{host_id}",
            "dst_port": 22,
            "conn_state": "REJ"
        })
    return pd.DataFrame(data)


class TestLoadThresholds:
    def test_load_default_fallback(self):
        # Passing None or non-existent file path loads defaults
        thresholds = load_thresholds("/nonexistent/file.yaml")
        assert "port_scan" in thresholds
        assert thresholds["port_scan"]["min_unique_ports"] == 10

    def test_load_from_valid_yaml(self):
        thresholds = load_thresholds("config/thresholds.yaml")
        assert "port_scan" in thresholds
        assert "host_scan" in thresholds
        assert thresholds["port_scan"]["min_unique_ports"] == 10
        assert thresholds["host_scan"]["min_unique_hosts"] == 5


class TestReconnaissanceDetector:
    def test_detector_empty_df(self):
        detector = ReconnaissanceDetector()
        alerts = detector.detect(pd.DataFrame())
        assert alerts == []

    def test_detector_missing_columns(self):
        detector = ReconnaissanceDetector()
        df = pd.DataFrame({"src_ip": ["10.0.0.1"], "dst_ip": ["10.0.0.2"]})
        alerts = detector.detect(df)
        assert alerts == []

    def test_detector_normal_traffic(self, normal_traffic_df: pd.DataFrame):
        detector = ReconnaissanceDetector()
        alerts = detector.detect(normal_traffic_df)
        assert alerts == []

    def test_detector_port_scan(self, port_scan_df: pd.DataFrame):
        detector = ReconnaissanceDetector()
        alerts = detector.detect(port_scan_df)
        assert len(alerts) == 1
        alert = alerts[0]
        assert isinstance(alert, Alert)
        assert alert.threat_class == "port_scan"
        assert alert.source == "10.0.0.2"
        assert alert.confidence >= 0.5
        assert alert.severity in ("low", "medium", "high", "critical")
        assert alert.evidence["unique_dst_ports"] == 15
        assert alert.evidence["failed_ratio"] == 1.0

    def test_detector_host_scan(self, host_scan_df: pd.DataFrame):
        detector = ReconnaissanceDetector()
        alerts = detector.detect(host_scan_df)
        assert len(alerts) == 1
        alert = alerts[0]
        assert isinstance(alert, Alert)
        assert alert.threat_class == "host_scan"
        assert alert.source == "10.0.0.3"
        assert alert.confidence >= 0.5
        assert alert.evidence["unique_dst_hosts"] == 10
        assert alert.evidence["failed_ratio"] == 1.0

    def test_no_alert_for_multicast_or_invalid_src(self):
        detector = ReconnaissanceDetector()
        # Source is "-" or Broadcast/Multicast
        df = pd.DataFrame([
            {"ts": 1700000000.0 + i * 0.1, "src_ip": "-", "dst_ip": "1.2.3.4", "dst_port": i, "conn_state": "S0"}
            for i in range(20)
        ])
        alerts = detector.detect(df)
        assert alerts == []

    def test_detector_custom_thresholds(self, port_scan_df: pd.DataFrame):
        # Configure thresholds to require 25 unique ports (our scan scan_df only has 15)
        custom_thresholds = {
            "port_scan": {
                "min_unique_ports": 25,
                "min_conn_rate": 2.0,
                "min_failed_ratio": 0.5,
                "min_confidence": 0.5,
            }
        }
        detector = ReconnaissanceDetector(thresholds=custom_thresholds)
        alerts = detector.detect(port_scan_df)
        # Should not alert because unique ports (15) < min_unique_ports (25)
        assert alerts == []
