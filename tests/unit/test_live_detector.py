"""Unit tests for scripts/live_detector.py message serialization."""

import numpy as np
import pytest
from unittest.mock import Mock

from scripts.live_detector import LiveDetectorSensor


def _make_detector() -> LiveDetectorSensor:
    det = LiveDetectorSensor.__new__(LiveDetectorSensor)
    det.cumulative_bytes = 0
    det.cumulative_packets = 0
    det.client = Mock()
    return det


class TestPostFlowsNaN:
    def test_nan_bytes_and_packets_fall_back_to_parts(self):
        det = _make_detector()
        flow = {
            "uid": "f1",
            "ts": 1788762654.0,
            "src_ip": "192.168.1.5",
            "dst_ip": "8.8.8.8",
            "src_port": 12345,
            "dst_port": 443,
            "proto": "tcp",
            "conn_state": "SF",
            "total_bytes": np.nan,
            "total_pkts": np.nan,
            "orig_bytes": 100,
            "resp_bytes": 200,
            "orig_pkts": 2,
            "resp_pkts": 3,
            "duration": 1.5,
        }
        det.post_flows([flow])

        assert det.client.post.called is True
        assert det.cumulative_bytes == 300
        assert det.cumulative_packets == 5

    def test_post_succeeds_with_nan_fields(self):
        det = _make_detector()
        flow = {
            "uid": "f2",
            "ts": np.nan,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 80,
            "dst_port": 443,
            "proto": "tcp",
            "conn_state": "S0",
            "total_bytes": np.nan,
            "total_pkts": np.nan,
            "orig_bytes": np.nan,
            "resp_bytes": np.nan,
            "orig_pkts": np.nan,
            "resp_pkts": np.nan,
            "duration": np.nan,
        }
        det.post_flows([flow])

        assert det.client.post.called is True
        assert det.cumulative_bytes == 0
        assert det.cumulative_packets == 1
        payload = det.client.post.call_args.kwargs["json"]
        assert payload[0]["total_bytes"] is None
        assert payload[0]["ts"] is not None

    def test_normal_numeric_values_unchanged(self):
        det = _make_detector()
        flow = {
            "uid": "f3",
            "ts": 1788762654.0,
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 53,
            "dst_port": 53,
            "proto": "udp",
            "conn_state": "SF",
            "total_bytes": 500,
            "total_pkts": 7,
            "orig_bytes": 200,
            "resp_bytes": 300,
            "orig_pkts": 3,
            "resp_pkts": 4,
            "duration": 2.0,
        }
        det.post_flows([flow])

        assert det.client.post.called is True
        assert det.cumulative_bytes == 500
        assert det.cumulative_packets == 7
