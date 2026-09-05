"""Time window manager for streaming flow records.

Accumulates flow records into discrete tumbling time windows based on their
observed network timestamps. When a window boundary is crossed, the window
is closed and emitted for feature extraction and detection.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Generator, List

logger = logging.getLogger(__name__)


class WindowManager:
    """Manages tumbling time windows for streaming data."""

    def __init__(self, window_size_sec: float = 5.0) -> None:
        if window_size_sec <= 0:
            raise ValueError("window_size_sec must be positive")
        self.window_size_sec = window_size_sec
        self.current_window_start: float | None = None
        self.buffer: List[Dict[str, Any]] = []

    def add_record(self, record: Dict[str, Any]) -> Generator[List[Dict[str, Any]], None, None]:
        """Add a flow record to the window manager.

        If the record falls outside the current window, it closes and yields
        the current buffer of records, then opens a new window.

        Args:
            record: Dict containing the parsed flow columns (must contain "ts").

        Yields:
            List of records belonging to the closed window.
        """
        ts = record.get("ts")
        if ts is None:
            logger.warning("Record missing 'ts' column, skipping: %s", record)
            return

        ts = float(ts)

        if self.current_window_start is None:
            self.current_window_start = ts
            self.buffer.append(record)
            return

        # Check if record belongs to current window
        # Tumbling window boundary: [start, start + size)
        if ts < self.current_window_start + self.window_size_sec:
            self.buffer.append(record)
        else:
            # Boundary crossed, yield the accumulated window
            yield self.buffer
            
            # Start new window.
            # Handle possible gap by starting the window at the current record's timestamp
            self.current_window_start = ts
            self.buffer = [record]

    def flush(self) -> List[Dict[str, Any]]:
        """Flush the remaining records in the current active window buffer.

        Returns:
            List of remaining flow records in the buffer.
        """
        buffered = self.buffer.copy()
        self.buffer = []
        self.current_window_start = None
        return buffered
