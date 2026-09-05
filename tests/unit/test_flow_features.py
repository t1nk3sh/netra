"""Unit tests for features/flow_features.py"""

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from features.flow_features import (
    extract_per_flow_features,
    extract_aggregate_features,
    _safe_divide,
    _safe_ratio,
    _extract_history_features,
    _extract_conn_state_features,
)
from zeek.log_parser import parse_conn_log

CONN_LOG = Path("data/samples/zeek_logs/conn.log")


@pytest.fixture(scope="module")
def conn_df() -> pd.DataFrame:
    return parse_conn_log(CONN_LOG)


@pytest.fixture(scope="module")
def flow_features(conn_df: pd.DataFrame) -> pd.DataFrame:
    return extract_per_flow_features(conn_df)


class TestSafeDivide:
    def test_normal_division(self):
        a = pd.Series([10.0, 20.0, 30.0])
        b = pd.Series([2.0, 4.0, 5.0])
        result = _safe_divide(a, b)
        assert result.tolist() == [5.0, 5.0, 6.0]

    def test_zero_denominator(self):
        a = pd.Series([10.0, 20.0])
        b = pd.Series([0.0, 0.0])
        result = _safe_divide(a, b)
        assert (result == 0.0).all()

    def test_mixed(self):
        a = pd.Series([10.0, 20.0])
        b = pd.Series([2.0, 0.0])
        result = _safe_divide(a, b)
        assert result.iloc[0] == 5.0
        assert result.iloc[1] == 0.0


class TestSafeRatio:
    def test_normal_ratio(self):
        a = pd.Series([75.0])
        b = pd.Series([25.0])
        result = _safe_ratio(a, b)
        assert result.iloc[0] == pytest.approx(0.75)

    def test_zero_total(self):
        a = pd.Series([0.0])
        b = pd.Series([0.0])
        result = _safe_ratio(a, b)
        assert result.iloc[0] == 0.5

    def test_all_originator(self):
        a = pd.Series([100.0])
        b = pd.Series([0.0])
        result = _safe_ratio(a, b)
        assert result.iloc[0] == pytest.approx(1.0)


class TestHistoryFeatures:
    def test_syn_count(self):
        history = pd.Series(["ShADFf", "S", "Dd"])
        result = _extract_history_features(history)
        assert result["hist_syn_count"].iloc[0] == 1
        assert result["hist_syn_count"].iloc[1] == 1
        assert result["hist_syn_count"].iloc[2] == 0

    def test_data_count(self):
        history = pd.Series(["ShADFf", "Dd"])
        result = _extract_history_features(history)
        assert result["hist_data_count"].iloc[0] == 1
        assert result["hist_data_count"].iloc[1] == 1

    def test_length(self):
        history = pd.Series(["ShADFf", "S"])
        result = _extract_history_features(history)
        assert result["hist_length"].iloc[0] == 6
        assert result["hist_length"].iloc[1] == 1

    def test_nan_handling(self):
        history = pd.Series([np.nan, "S"])
        result = _extract_history_features(history)
        assert result["hist_length"].iloc[0] == 0


class TestConnStateFeatures:
    def test_sf_state(self):
        states = pd.Series(["SF", "S0", "SF"])
        result = _extract_conn_state_features(states)
        assert result["conn_state_SF"].tolist() == [1, 0, 1]
        assert result["conn_state_S0"].tolist() == [0, 1, 0]

    def test_all_states_present(self):
        states = pd.Series(["SF"])
        result = _extract_conn_state_features(states)
        expected = ["conn_state_S0", "conn_state_S1", "conn_state_SF",
                     "conn_state_REJ", "conn_state_RSTO", "conn_state_RSTR",
                     "conn_state_OTH"]
        for col in expected:
            assert col in result.columns


class TestPerFlowFeatures:
    def test_returns_dataframe(self, flow_features: pd.DataFrame):
        assert isinstance(flow_features, pd.DataFrame)

    def test_row_count_matches(self, conn_df: pd.DataFrame, flow_features: pd.DataFrame):
        assert len(flow_features) == len(conn_df)

    def test_identity_columns_preserved(self, flow_features: pd.DataFrame):
        assert "src_ip" in flow_features.columns
        assert "dst_ip" in flow_features.columns
        assert "src_port" in flow_features.columns
        assert "dst_port" in flow_features.columns
        assert "proto" in flow_features.columns

    def test_duration(self, flow_features: pd.DataFrame):
        assert "duration" in flow_features.columns
        http_row = flow_features[flow_features["dst_port"] == 80].iloc[0]
        assert http_row["duration"] == pytest.approx(0.1)

    def test_byte_columns(self, flow_features: pd.DataFrame):
        assert "orig_bytes" in flow_features.columns
        assert "resp_bytes" in flow_features.columns
        assert "total_bytes" in flow_features.columns
        http_row = flow_features[flow_features["dst_port"] == 80].iloc[0]
        assert http_row["total_bytes"] == 85.0

    def test_packet_columns(self, flow_features: pd.DataFrame):
        assert "orig_pkts" in flow_features.columns
        assert "resp_pkts" in flow_features.columns
        assert "total_pkts" in flow_features.columns

    def test_rate_columns(self, flow_features: pd.DataFrame):
        assert "packets_per_sec" in flow_features.columns
        assert "bytes_per_sec" in flow_features.columns
        http_row = flow_features[flow_features["dst_port"] == 80].iloc[0]
        assert http_row["packets_per_sec"] == pytest.approx(80.0)
        assert http_row["bytes_per_sec"] == pytest.approx(850.0)

    def test_avg_packet_size(self, flow_features: pd.DataFrame):
        assert "avg_pkt_size" in flow_features.columns
        assert "avg_pkt_size_orig" in flow_features.columns
        assert "avg_pkt_size_resp" in flow_features.columns

    def test_ratios(self, flow_features: pd.DataFrame):
        assert "byte_ratio" in flow_features.columns
        assert "pkt_ratio" in flow_features.columns
        for val in flow_features["byte_ratio"]:
            assert 0.0 <= val <= 1.0

    def test_protocol_flags(self, flow_features: pd.DataFrame):
        assert "is_tcp" in flow_features.columns
        assert "is_udp" in flow_features.columns
        tcp_rows = flow_features[flow_features["is_tcp"] == 1]
        udp_rows = flow_features[flow_features["is_udp"] == 1]
        assert len(tcp_rows) == 3
        assert len(udp_rows) == 3

    def test_history_features(self, flow_features: pd.DataFrame):
        assert "hist_syn_count" in flow_features.columns
        assert "hist_length" in flow_features.columns

    def test_conn_state_features(self, flow_features: pd.DataFrame):
        assert "conn_state_SF" in flow_features.columns
        assert "conn_state_S0" in flow_features.columns

    def test_no_nans(self, flow_features: pd.DataFrame):
        numeric = flow_features.select_dtypes(include=[np.number])
        assert not numeric.isna().any().any()

    def test_zero_duration_safe(self, flow_features: pd.DataFrame):
        s0_rows = flow_features[flow_features["conn_state_S0"] == 1]
        assert not s0_rows["packets_per_sec"].isna().any()
        assert not s0_rows["bytes_per_sec"].isna().any()


class TestAggregateFeatures:
    def test_returns_dataframe(self, flow_features: pd.DataFrame):
        agg = extract_aggregate_features(flow_features)
        assert isinstance(agg, pd.DataFrame)

    def test_grouped_by_src_ip(self, flow_features: pd.DataFrame):
        agg = extract_aggregate_features(flow_features, group_by="src_ip")
        assert "src_ip" in agg.columns
        assert len(agg) == flow_features["src_ip"].nunique()

    def test_flow_count(self, flow_features: pd.DataFrame):
        agg = extract_aggregate_features(flow_features)
        total = agg["flow_count"].sum()
        assert total == len(flow_features)

    def test_unique_dst_ips(self, flow_features: pd.DataFrame):
        agg = extract_aggregate_features(flow_features)
        row = agg[agg["src_ip"] == "10.0.0.1"].iloc[0]
        assert row["unique_dst_ips"] >= 1

    def test_unique_dst_ports(self, flow_features: pd.DataFrame):
        agg = extract_aggregate_features(flow_features)
        row = agg[agg["src_ip"] == "10.0.0.1"].iloc[0]
        assert row["unique_dst_ports"] >= 1

    def test_statistical_columns(self, flow_features: pd.DataFrame):
        agg = extract_aggregate_features(flow_features)
        for prefix in ["total_bytes", "duration"]:
            for suffix in ["sum", "mean", "std", "max", "min"]:
                assert f"{prefix}_{suffix}" in agg.columns

    def test_tcp_fraction(self, flow_features: pd.DataFrame):
        agg = extract_aggregate_features(flow_features)
        for val in agg["tcp_fraction"]:
            assert 0.0 <= val <= 1.0

    def test_invalid_group_by(self, flow_features: pd.DataFrame):
        with pytest.raises(ValueError, match="not found"):
            extract_aggregate_features(flow_features, group_by="nonexistent")

    def test_group_by_dst_ip(self, flow_features: pd.DataFrame):
        agg = extract_aggregate_features(flow_features, group_by="dst_ip")
        assert "dst_ip" in agg.columns
        assert len(agg) == flow_features["dst_ip"].nunique()
