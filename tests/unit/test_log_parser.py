"""Unit tests for zeek/log_parser.py"""

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

from zeek.log_parser import (
    parse_zeek_log,
    parse_conn_log,
    parse_dns_log,
    parse_ssl_log,
    _detect_format,
    _zeek_ts_to_datetime,
)

SAMPLE_DIR = Path("data/samples/zeek_logs")
CONN_LOG = SAMPLE_DIR / "conn.log"
DNS_LOG = SAMPLE_DIR / "dns.log"
SSL_LOG = SAMPLE_DIR / "ssl.log"
CONN_JSON_LOG = SAMPLE_DIR / "conn_json.log"


class TestFormatDetection:
    def test_detects_tsv(self):
        assert _detect_format(CONN_LOG) == "tsv"

    def test_detects_json(self):
        assert _detect_format(CONN_JSON_LOG) == "json"


class TestTimestampConversion:
    def test_valid_timestamp(self):
        dt = _zeek_ts_to_datetime(1700000000.0)
        assert dt is not None
        assert dt.tzinfo == timezone.utc
        assert dt.year == 2023

    def test_none_for_nan(self):
        assert _zeek_ts_to_datetime(float("nan")) is None

    def test_none_for_invalid(self):
        assert _zeek_ts_to_datetime("not_a_number") is None


class TestParseConnLog:
    def test_returns_dataframe(self):
        df = parse_conn_log(CONN_LOG)
        assert isinstance(df, pd.DataFrame)

    def test_row_count(self):
        df = parse_conn_log(CONN_LOG)
        assert len(df) == 6

    def test_column_renaming(self):
        df = parse_conn_log(CONN_LOG)
        assert "src_ip" in df.columns
        assert "dst_ip" in df.columns
        assert "src_port" in df.columns
        assert "dst_port" in df.columns
        assert "id.orig_h" not in df.columns

    def test_source_ip_values(self):
        df = parse_conn_log(CONN_LOG)
        assert (df["src_ip"] == "10.0.0.1").all()

    def test_destination_ip_values(self):
        df = parse_conn_log(CONN_LOG)
        dst_ips = set(df["dst_ip"].unique())
        assert "93.184.216.34" in dst_ips
        assert "8.8.8.8" in dst_ips

    def test_numeric_conversion(self):
        df = parse_conn_log(CONN_LOG)
        http_row = df[df["dst_port"] == 80].iloc[0]
        assert http_row["orig_bytes"] == 40
        assert http_row["resp_bytes"] == 45
        assert http_row["duration"] == pytest.approx(0.1)

    def test_missing_values_as_nan(self):
        df = parse_conn_log(CONN_LOG)
        s0_rows = df[df["conn_state"] == "S0"]
        assert s0_rows["duration"].isna().all()
        assert s0_rows["orig_bytes"].isna().all()

    def test_timestamp_column_created(self):
        df = parse_conn_log(CONN_LOG)
        assert "timestamp" in df.columns
        assert df["timestamp"].iloc[0] is not None
        assert isinstance(df["timestamp"].iloc[0], datetime)

    def test_protocols(self):
        df = parse_conn_log(CONN_LOG)
        protos = set(df["proto"].unique())
        assert "tcp" in protos
        assert "udp" in protos

    def test_port_types(self):
        df = parse_conn_log(CONN_LOG)
        assert df["src_port"].dtype in ("int64", "float64")
        assert df["dst_port"].dtype in ("int64", "float64")


class TestParseDnsLog:
    def test_returns_dataframe(self):
        df = parse_dns_log(DNS_LOG)
        assert isinstance(df, pd.DataFrame)

    def test_row_count(self):
        df = parse_dns_log(DNS_LOG)
        assert len(df) == 3

    def test_query_domains(self):
        df = parse_dns_log(DNS_LOG)
        domains = set(df["query"].values)
        assert "example.com" in domains
        assert "test.org" in domains
        assert "suspicious.xyz" in domains

    def test_column_renaming(self):
        df = parse_dns_log(DNS_LOG)
        assert "src_ip" in df.columns
        assert "dst_ip" in df.columns

    def test_dns_server(self):
        df = parse_dns_log(DNS_LOG)
        assert (df["dst_ip"] == "8.8.8.8").all()

    def test_rcode_name(self):
        df = parse_dns_log(DNS_LOG)
        assert (df["rcode_name"] == "NOERROR").all()

    def test_boolean_flags(self):
        df = parse_dns_log(DNS_LOG)
        assert df["RD"].all()
        assert not df["rejected"].any()


class TestParseSslLog:
    def test_returns_dataframe(self):
        df = parse_ssl_log(SSL_LOG)
        assert isinstance(df, pd.DataFrame)

    def test_row_count(self):
        df = parse_ssl_log(SSL_LOG)
        assert len(df) == 2

    def test_tls_versions(self):
        df = parse_ssl_log(SSL_LOG)
        versions = set(df["version"].values)
        assert "TLSv13" in versions
        assert "TLSv12" in versions

    def test_server_names(self):
        df = parse_ssl_log(SSL_LOG)
        names = set(df["server_name"].values)
        assert "example.com" in names
        assert "github.com" in names

    def test_column_renaming(self):
        df = parse_ssl_log(SSL_LOG)
        assert "src_ip" in df.columns
        assert "dst_ip" in df.columns


class TestParseJsonFormat:
    def test_json_conn_log(self):
        df = parse_zeek_log(CONN_JSON_LOG)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2

    def test_json_column_renaming(self):
        df = parse_zeek_log(CONN_JSON_LOG)
        assert "src_ip" in df.columns
        assert "dst_ip" in df.columns

    def test_json_values(self):
        df = parse_zeek_log(CONN_JSON_LOG)
        assert df["src_ip"].iloc[0] == "10.0.0.1"
        assert df["dst_ip"].iloc[0] == "93.184.216.34"

    def test_json_numeric(self):
        df = parse_zeek_log(CONN_JSON_LOG)
        assert df["ts"].iloc[0] == pytest.approx(1700000000.0)

    def test_json_timestamp_column(self):
        df = parse_zeek_log(CONN_JSON_LOG)
        assert "timestamp" in df.columns


class TestEdgeCases:
    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_zeek_log("/nonexistent/conn.log")

    def test_not_a_file(self, tmp_path: Path):
        with pytest.raises(ValueError, match="not a file"):
            parse_zeek_log(tmp_path)

    def test_empty_tsv_log(self, tmp_path: Path):
        log = tmp_path / "empty.log"
        log.write_text(
            "#separator \\x09\n"
            "#fields\tts\tuid\n"
            "#types\ttime\tstring\n"
        )
        df = parse_zeek_log(log)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0

    def test_empty_json_log(self, tmp_path: Path):
        log = tmp_path / "empty.log"
        log.write_text("")
        df = parse_zeek_log(log)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0
