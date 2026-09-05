"""Unit tests for detection/ddos.py"""

import pytest
import pandas as pd
from alerts.alert_schema import Alert
from detection.ddos import DDoSDetector, load_ddos_thresholds


@pytest.fixture
def normal_traffic_df() -> pd.DataFrame:
    data = [
        {
            "ts": 1700000000.0 + i,
            "src_ip": f"10.0.0.{i}",
            "dst_ip": "192.168.1.100",
            "src_port": 1024 + i,
            "dst_port": 80,
            "proto": "tcp",
            "conn_state": "SF",
            "orig_pkts": 5,
            "resp_pkts": 4,
            "orig_bytes": 300,
            "resp_bytes": 400,
        }
        for i in range(10)
    ]
    return pd.DataFrame(data)


@pytest.fixture
def syn_flood_df() -> pd.DataFrame:
    # 50 connection requests (S0) to a single server on port 80 in 1 second from various source IPs
    data = []
    base_ts = 1700000000.0
    for i in range(50):
        data.append({
            "ts": base_ts + i * 0.02,
            "src_ip": f"192.168.2.{i}",
            "dst_ip": "10.0.0.99",
            "src_port": 20000 + i,
            "dst_port": 80,
            "proto": "tcp",
            "conn_state": "S0",
            "history": "S",
            "orig_pkts": 1,
            "resp_pkts": 0,
            "orig_bytes": 40,
            "resp_bytes": 0,
        })
    return pd.DataFrame(data)


@pytest.fixture
def udp_flood_df() -> pd.DataFrame:
    # 100 connection records (UDP) to a single target on random ports in 1 second
    data = []
    base_ts = 1700000000.0
    for i in range(100):
        data.append({
            "ts": base_ts + i * 0.01,
            "src_ip": f"192.168.3.{i % 5}", # 5 distinct source IPs
            "dst_ip": "10.0.0.99",
            "src_port": 30000 + i,
            "dst_port": 5000 + i,
            "proto": "udp",
            "conn_state": "SF",
            "orig_pkts": 1,
            "resp_pkts": 0,
            "orig_bytes": 500,
            "resp_bytes": 0,
        })
    return pd.DataFrame(data)


@pytest.fixture
def dns_reflection_df() -> pd.DataFrame:
    # 40 UDP packets originating from port 53 (DNS reflection) to a victim on random port
    data = []
    base_ts = 1700000000.0
    for i in range(40):
        data.append({
            "ts": base_ts + i * 0.02,
            "src_ip": f"8.8.8.{i % 2}",  # DNS servers
            "dst_ip": "10.0.0.99",
            "src_port": 53,
            "dst_port": 12345 + i,
            "proto": "udp",
            "conn_state": "SF",
            "orig_pkts": 1,
            "resp_pkts": 0,
            "orig_bytes": 1000, # Large packet size, typical of reflection response
            "resp_bytes": 0,
        })
    return pd.DataFrame(data)


class TestLoadDdosThresholds:
    def test_load_default_fallback(self):
        thresholds = load_ddos_thresholds("/nonexistent/file.yaml")
        assert "syn_flood" in thresholds
        assert "udp_flood" in thresholds
        assert thresholds["syn_flood"]["min_syn_rate"] == 10.0

    def test_load_from_valid_yaml(self):
        thresholds = load_ddos_thresholds("config/thresholds.yaml")
        assert "syn_flood" in thresholds
        assert "udp_flood" in thresholds
        assert thresholds["syn_flood"]["min_syn_rate"] == 10.0
        assert thresholds["udp_flood"]["min_udp_rate"] == 20.0


class TestDDoSDetector:
    def test_detector_empty_df(self):
        detector = DDoSDetector()
        alerts = detector.detect(pd.DataFrame())
        assert alerts == []

    def test_detector_missing_columns(self):
        detector = DDoSDetector()
        df = pd.DataFrame({"src_ip": ["10.0.0.1"], "dst_ip": ["10.0.0.2"]})
        alerts = detector.detect(df)
        assert alerts == []

    def test_detector_normal_traffic(self, normal_traffic_df: pd.DataFrame):
        detector = DDoSDetector()
        alerts = detector.detect(normal_traffic_df)
        assert alerts == []

    def test_detector_syn_flood(self, syn_flood_df: pd.DataFrame):
        detector = DDoSDetector()
        alerts = detector.detect(syn_flood_df)
        assert len(alerts) == 1
        alert = alerts[0]
        assert isinstance(alert, Alert)
        assert alert.threat_class == "ddos_syn_flood"
        assert alert.destination == "10.0.0.99"
        assert alert.source == "multiple"
        assert alert.confidence >= 0.5
        assert alert.evidence["syn_flows_count"] == 50
        assert alert.evidence["possible_spoofing"] is True

    def test_detector_udp_flood(self, udp_flood_df: pd.DataFrame):
        detector = DDoSDetector()
        alerts = detector.detect(udp_flood_df)
        assert len(alerts) == 1
        alert = alerts[0]
        assert isinstance(alert, Alert)
        assert alert.threat_class == "ddos_udp_flood"
        assert alert.destination == "10.0.0.99"
        assert alert.confidence >= 0.5
        assert alert.evidence["udp_flows_count"] == 100

    def test_detector_reflection(self, dns_reflection_df: pd.DataFrame):
        detector = DDoSDetector()
        alerts = detector.detect(dns_reflection_df)
        assert len(alerts) == 1
        alert = alerts[0]
        assert isinstance(alert, Alert)
        assert alert.threat_class == "ddos_reflection"
        assert alert.destination == "10.0.0.99"
        assert alert.confidence >= 0.5
        assert alert.evidence["reflection_flows_count"] == 40
        assert 53 in alert.evidence["ports_involved"]

    def test_detector_custom_thresholds(self, syn_flood_df: pd.DataFrame):
        # Configure thresholds high so that we do not trigger alert
        custom_thresholds = {
            "syn_flood": {
                "min_syn_rate": 1000.0,
                "min_flows_count": 500,
                "min_failed_ratio": 0.8,
            }
        }
        detector = DDoSDetector(thresholds=custom_thresholds)
        alerts = detector.detect(syn_flood_df)
        assert alerts == []
