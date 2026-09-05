"""PCAP replay module for internal packet streaming.

Replays packets from a PCAP file as an incremental stream into the internal
processing pipeline. Does NOT inject packets into any real network interface.

Supports three replay speeds:
  - realtime: preserves original inter-packet timing
  - accelerated: scales timing by a configurable multiplier
  - unlimited: delivers packets as fast as possible (no delay)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Generator

from capture.pcap_reader import PacketMetadata, iter_packets, _validate_path

logger = logging.getLogger(__name__)


class ReplaySpeed(Enum):
    REALTIME = "realtime"
    ACCELERATED = "accelerated"
    UNLIMITED = "unlimited"


@dataclass
class ReplayConfig:
    """Configuration for PCAP replay."""

    speed: ReplaySpeed = ReplaySpeed.UNLIMITED
    speed_multiplier: float = 1.0
    max_packets: int | None = None

    def __post_init__(self) -> None:
        if self.speed == ReplaySpeed.ACCELERATED and self.speed_multiplier <= 0:
            raise ValueError("speed_multiplier must be positive")
        if self.max_packets is not None and self.max_packets <= 0:
            raise ValueError("max_packets must be positive")


@dataclass
class ReplayStats:
    """Statistics from a completed replay session."""

    packets_replayed: int
    total_bytes: int
    first_timestamp: float | None
    last_timestamp: float | None
    wall_clock_duration: float
    pcap_duration: float


class PcapReplay:
    """Replays PCAP packets as an internal stream.

    Packets are delivered to consumers via iteration or callbacks.
    No packets are ever transmitted on a network interface.
    """

    def __init__(self, path: str | Path, config: ReplayConfig | None = None) -> None:
        self._path = _validate_path(path)
        self._config = config or ReplayConfig()
        self._stopped = False

    def stop(self) -> None:
        """Signal the replay to stop early."""
        self._stopped = True

    def _compute_delay(self, prev_ts: float | None, curr_ts: float) -> float:
        if prev_ts is None:
            return 0.0
        gap = curr_ts - prev_ts
        if gap <= 0:
            return 0.0

        if self._config.speed == ReplaySpeed.REALTIME:
            return gap
        elif self._config.speed == ReplaySpeed.ACCELERATED:
            return gap / self._config.speed_multiplier
        return 0.0

    def replay(self) -> Generator[PacketMetadata, None, ReplayStats]:
        """Replay packets from the PCAP, yielding each one.

        Yields:
            PacketMetadata for each replayed packet.

        Returns:
            ReplayStats summarizing the replay session.
        """
        self._stopped = False
        packets_replayed = 0
        total_bytes = 0
        first_ts: float | None = None
        last_ts: float | None = None
        prev_ts: float | None = None
        wall_start = time.monotonic()

        for meta in iter_packets(self._path):
            if self._stopped:
                logger.info("Replay stopped early at packet %d", packets_replayed)
                break

            if self._config.max_packets is not None and packets_replayed >= self._config.max_packets:
                break

            delay = self._compute_delay(prev_ts, meta.timestamp)
            if delay > 0:
                time.sleep(delay)

            if first_ts is None:
                first_ts = meta.timestamp
            last_ts = meta.timestamp
            prev_ts = meta.timestamp

            packets_replayed += 1
            total_bytes += meta.length

            yield meta

        wall_duration = time.monotonic() - wall_start
        pcap_duration = (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0

        return ReplayStats(
            packets_replayed=packets_replayed,
            total_bytes=total_bytes,
            first_timestamp=first_ts,
            last_timestamp=last_ts,
            wall_clock_duration=wall_duration,
            pcap_duration=pcap_duration,
        )

    def replay_with_callback(
        self, callback: Callable[[PacketMetadata], None]
    ) -> ReplayStats:
        """Replay packets, invoking a callback for each one.

        Args:
            callback: Function called with each PacketMetadata.

        Returns:
            ReplayStats summarizing the replay session.
        """
        gen = self.replay()
        try:
            while True:
                meta = next(gen)
                callback(meta)
        except StopIteration as e:
            return e.value
