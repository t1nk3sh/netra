"""Zeek log parser for converting Zeek output into Python records/DataFrames.

Supports both Zeek TSV (tab-separated, with #-prefixed headers) and
JSON log formats. Preserves timestamps, normalizes column names,
handles missing values, and maintains source/destination directionality.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

ZEEK_UNSET = "-"
ZEEK_EMPTY = "(empty)"
ZEEK_SEPARATOR = "\t"

CONN_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents",
]

DNS_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
    "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD",
    "RA", "Z", "answers", "TTLs", "rejected",
]

SSL_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "version", "cipher", "curve", "server_name", "resumed",
    "last_alert", "next_protocol", "established",
    "ssl_history", "cert_chain_fps", "client_cert_chain_fps",
    "sni_matches_cert", "validation_status",
]

HTTP_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "trans_depth", "method", "host", "uri", "referrer", "version",
    "user_agent", "request_body_len", "response_body_len", "status_code",
    "status_msg", "info_code", "info_msg", "tags", "username",
    "password", "proxied", "orig_fuids", "orig_filenames", "orig_mime_types",
    "resp_fuids", "resp_filenames", "resp_mime_types",
]

WEIRD_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "name", "addl", "notice", "peer", "source",
]

NOTICE_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "fuid", "file_mime_type", "file_desc", "proto", "note", "msg",
    "sub", "src", "dst", "p", "n", "peer_descr", "actions",
    "suppress_for", "dropped",
]

DHCP_COLUMNS = [
    "ts", "uids", "client_addr", "server_addr", "mac", "host_name",
    "client_fqdn", "domain", "requested_addr", "assigned_addr",
    "lease_time", "client_message", "server_message", "msg_types",
    "duration",
]

COLUMN_RENAMES = {
    "id.orig_h": "src_ip",
    "id.orig_p": "src_port",
    "id.resp_h": "dst_ip",
    "id.resp_p": "dst_port",
}

NUMERIC_COLUMNS = {
    "ts", "duration", "orig_bytes", "resp_bytes", "missed_bytes",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "src_port", "dst_port", "rtt", "trans_id",
    "request_body_len", "response_body_len", "status_code", "info_code",
    "trans_depth", "lease_time",
}

BOOLEAN_COLUMNS = {
    "local_orig", "local_resp", "AA", "TC", "RD", "RA", "Z",
    "rejected", "resumed", "established", "sni_matches_cert",
    "proxied", "notice", "dropped",
}


def _detect_format(path: Path) -> str:
    with open(path, "r") as f:
        first_line = f.readline().strip()
    if not first_line:
        return "empty"
    if first_line.startswith("#") or first_line.startswith("@"):
        return "tsv"
    try:
        json.loads(first_line)
        return "json"
    except (json.JSONDecodeError, ValueError):
        pass
    return "tsv"


def _parse_zeek_tsv(path: Path) -> pd.DataFrame:
    separator = ZEEK_SEPARATOR
    fields: list[str] = []
    types: list[str] = []
    data_lines: list[str] = []

    with open(path, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#separator"):
                raw_sep = line.split(" ", 1)[1] if " " in line else "\\x09"
                separator = bytes(raw_sep, "utf-8").decode("unicode_escape")
            elif line.startswith("#fields"):
                fields = line.split(separator)[1:]
            elif line.startswith("#types"):
                types = line.split(separator)[1:]
            elif line.startswith("#"):
                continue
            else:
                data_lines.append(line)

    if not fields:
        raise ValueError(f"No #fields header found in Zeek log: {path}")

    if not data_lines:
        return pd.DataFrame(columns=fields)

    csv_text = "\n".join(data_lines)
    df = pd.read_csv(
        StringIO(csv_text),
        sep=separator,
        header=None,
        names=fields,
        na_values=[ZEEK_UNSET, ZEEK_EMPTY],
        dtype=str,
    )

    return df


def _parse_zeek_json(path: Path) -> pd.DataFrame:
    records: list[dict[str, Any]] = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON line in %s", path)
                continue

    if not records:
        return pd.DataFrame()

    return pd.DataFrame(records)


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns=COLUMN_RENAMES)
    return df


def _convert_types(df: pd.DataFrame) -> pd.DataFrame:
    for col in df.columns:
        if col in NUMERIC_COLUMNS:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        elif col in BOOLEAN_COLUMNS:
            df[col] = df[col].map({"T": True, "F": False, True: True, False: False})

    if "ts" in df.columns:
        df["timestamp"] = df["ts"].apply(_zeek_ts_to_datetime)

    return df


def _zeek_ts_to_datetime(ts: Any) -> datetime | None:
    if pd.isna(ts):
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None


def parse_zeek_log(path: str | Path) -> pd.DataFrame:
    """Parse a Zeek log file into a normalized DataFrame.

    Supports both TSV and JSON formats. Normalizes column names,
    converts types, and preserves source/destination directionality.

    Args:
        path: Path to the Zeek log file.

    Returns:
        DataFrame with parsed and normalized Zeek log data.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Zeek log not found: {p}")
    if not p.is_file():
        raise ValueError(f"Path is not a file: {p}")

    fmt = _detect_format(p)
    logger.info("Parsing Zeek log %s (format=%s)", p.name, fmt)

    if fmt == "empty":
        return pd.DataFrame()
    elif fmt == "json":
        df = _parse_zeek_json(p)
    else:
        df = _parse_zeek_tsv(p)

    df = _normalize_columns(df)
    df = _convert_types(df)

    return df


def parse_conn_log(path: str | Path) -> pd.DataFrame:
    """Parse a Zeek conn.log file."""
    return parse_zeek_log(path)


def parse_dns_log(path: str | Path) -> pd.DataFrame:
    """Parse a Zeek dns.log file."""
    return parse_zeek_log(path)


def parse_ssl_log(path: str | Path) -> pd.DataFrame:
    """Parse a Zeek ssl.log file."""
    return parse_zeek_log(path)


def parse_http_log(path: str | Path) -> pd.DataFrame:
    """Parse a Zeek http.log file."""
    return parse_zeek_log(path)


def parse_weird_log(path: str | Path) -> pd.DataFrame:
    """Parse a Zeek weird.log file."""
    return parse_zeek_log(path)


def parse_notice_log(path: str | Path) -> pd.DataFrame:
    """Parse a Zeek notice.log file."""
    return parse_zeek_log(path)


def parse_dhcp_log(path: str | Path) -> pd.DataFrame:
    """Parse a Zeek dhcp.log file."""
    return parse_zeek_log(path)
