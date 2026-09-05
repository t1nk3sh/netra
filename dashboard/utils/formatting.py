"""Formatting and styling utilities for the dashboard components."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def format_timestamp(ts_val: Any, use_local_tz: bool = True) -> str:
    """Format an ISO timestamp string, unix epoch float, or datetime to a readable string.

    Args:
        ts_val: ISO format timestamp string, unix epoch number, or datetime object.
        use_local_tz: If True, formats in the local system timezone (defaults to True).
                      If False, formats in UTC.

    Returns:
        Formatted timezone-aware string representation (YYYY-MM-DD HH:MM:SS [TZ]).
    """
    if ts_val is None or ts_val == "" or ts_val == "-":
        return "-"
    try:
        if isinstance(ts_val, (int, float)):
            if use_local_tz:
                # Convert epoch directly using local system timezone
                dt = datetime.fromtimestamp(float(ts_val))
            else:
                dt = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
        elif isinstance(ts_val, str):
            # Check if it is a numeric epoch string (e.g. "1788250134.306")
            try:
                epoch = float(ts_val)
                if use_local_tz:
                    dt = datetime.fromtimestamp(epoch)
                else:
                    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            except ValueError:
                parsed_dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                if use_local_tz:
                    dt = parsed_dt.astimezone()
                else:
                    dt = parsed_dt
        elif isinstance(ts_val, datetime):
            if use_local_tz:
                dt = ts_val.astimezone() if ts_val.tzinfo is not None else ts_val
            else:
                dt = ts_val if ts_val.tzinfo is not None else ts_val.replace(tzinfo=timezone.utc)
        else:
            return str(ts_val)

        if use_local_tz:
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception as e:
        logger.debug("Failed to format timestamp %s: %s", ts_val, e)
        return str(ts_val)


def format_time_only(ts_val: Any, use_local_tz: bool = True) -> str:
    """Extract only the HH:MM:SS time portion safely in local system time."""
    formatted = format_timestamp(ts_val, use_local_tz=use_local_tz)
    if " " in formatted:
        parts = formatted.split(" ")
        if len(parts) >= 2:
            return parts[1]
    return formatted if formatted != "-" else "--:--:--"


def get_severity_details(severity: str) -> dict[str, str]:
    """Map severity string to UI coloring metrics and decorations.

    Args:
        severity: Severity label (e.g., critical, high, medium, low).

    Returns:
        Dict with color (CSS class/Hex), emoji badge, and display text.
    """
    sev = str(severity).lower().strip()
    if sev == "critical":
        return {
            "hex": "#ef4444",
            "emoji": "🔴 CRITICAL",
            "bg_color": "rgba(239, 68, 68, 0.15)",
        }
    elif sev == "high":
        return {
            "hex": "#f97316",
            "emoji": "🟠 HIGH",
            "bg_color": "rgba(249, 115, 22, 0.15)",
        }
    elif sev == "medium":
        return {
            "hex": "#eab308",
            "emoji": "🟡 MEDIUM",
            "bg_color": "rgba(234, 179, 8, 0.15)",
        }
    else:  # low or other
        return {
            "hex": "#6b7280",
            "emoji": "⚪ LOW",
            "bg_color": "rgba(107, 114, 128, 0.15)",
        }
