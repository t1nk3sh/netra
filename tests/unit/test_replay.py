"""Unit tests for capture/replay.py"""

import time
from pathlib import Path

import pytest

from capture.pcap_reader import PacketMetadata
from capture.replay import (
    PcapReplay,
    ReplayConfig,
    ReplaySpeed,
    ReplayStats,
)

SAMPLE_PCAP = Path("data/samples/test_traffic.pcap")
EXPECTED_PACKET_COUNT = 10


@pytest.fixture(scope="module")
def pcap_path() -> Path:
    if not SAMPLE_PCAP.exists():
        from scripts.generate_test_pcap import generate

        generate()
    return SAMPLE_PCAP


class TestReplayConfig:
    def test_default_config(self):
        cfg = ReplayConfig()
        assert cfg.speed == ReplaySpeed.UNLIMITED
        assert cfg.speed_multiplier == 1.0
        assert cfg.max_packets is None

    def test_invalid_multiplier(self):
        with pytest.raises(ValueError, match="speed_multiplier"):
            ReplayConfig(speed=ReplaySpeed.ACCELERATED, speed_multiplier=0)

    def test_invalid_max_packets(self):
        with pytest.raises(ValueError, match="max_packets"):
            ReplayConfig(max_packets=-1)


class TestReplayUnlimited:
    def test_yields_all_packets(self, pcap_path: Path):
        replay = PcapReplay(pcap_path)
        packets = list(replay.replay())
        assert len(packets) == EXPECTED_PACKET_COUNT

    def test_yields_metadata_objects(self, pcap_path: Path):
        replay = PcapReplay(pcap_path)
        for m in replay.replay():
            assert isinstance(m, PacketMetadata)
            break

    def test_timestamps_ordered(self, pcap_path: Path):
        replay = PcapReplay(pcap_path)
        packets = list(replay.replay())
        timestamps = [p.timestamp for p in packets]
        assert timestamps == sorted(timestamps)

    def test_unlimited_is_fast(self, pcap_path: Path):
        replay = PcapReplay(pcap_path, ReplayConfig(speed=ReplaySpeed.UNLIMITED))
        start = time.monotonic()
        list(replay.replay())
        elapsed = time.monotonic() - start
        assert elapsed < 1.0


class TestReplayMaxPackets:
    def test_limits_packet_count(self, pcap_path: Path):
        config = ReplayConfig(max_packets=3)
        replay = PcapReplay(pcap_path, config)
        packets = list(replay.replay())
        assert len(packets) == 3

    def test_single_packet(self, pcap_path: Path):
        config = ReplayConfig(max_packets=1)
        replay = PcapReplay(pcap_path, config)
        packets = list(replay.replay())
        assert len(packets) == 1


class TestReplayAccelerated:
    def test_accelerated_faster_than_realtime(self, pcap_path: Path):
        config = ReplayConfig(speed=ReplaySpeed.ACCELERATED, speed_multiplier=100.0)
        replay = PcapReplay(pcap_path, config)
        start = time.monotonic()
        list(replay.replay())
        elapsed = time.monotonic() - start
        assert elapsed < 1.0


class TestReplayCallback:
    def test_callback_receives_all_packets(self, pcap_path: Path):
        received: list[PacketMetadata] = []
        replay = PcapReplay(pcap_path)
        stats = replay.replay_with_callback(lambda m: received.append(m))
        assert len(received) == EXPECTED_PACKET_COUNT
        assert isinstance(stats, ReplayStats)

    def test_callback_stats(self, pcap_path: Path):
        replay = PcapReplay(pcap_path)
        stats = replay.replay_with_callback(lambda m: None)
        assert stats.packets_replayed == EXPECTED_PACKET_COUNT
        assert stats.total_bytes > 0
        assert stats.first_timestamp is not None
        assert stats.last_timestamp is not None
        assert stats.pcap_duration > 0
        assert stats.wall_clock_duration >= 0


class TestReplayStop:
    def test_stop_halts_replay(self, pcap_path: Path):
        replay = PcapReplay(pcap_path)
        received: list[PacketMetadata] = []
        for m in replay.replay():
            received.append(m)
            if len(received) == 4:
                replay.stop()
        assert len(received) == 4

    def test_stop_via_callback(self, pcap_path: Path):
        replay = PcapReplay(pcap_path)
        count = 0

        def cb(m: PacketMetadata) -> None:
            nonlocal count
            count += 1
            if count >= 5:
                replay.stop()

        replay.replay_with_callback(cb)
        assert count == 5


class TestReplayErrors:
    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            PcapReplay("/nonexistent.pcap")
