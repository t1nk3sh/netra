"""Unit tests for capture/pcap_reader.py"""

from pathlib import Path

import pytest

from capture.pcap_reader import (
    PacketMetadata,
    PcapStatistics,
    get_pcap_statistics,
    iter_packets,
    read_pcap,
)

SAMPLE_PCAP = Path("data/samples/test_traffic.pcap")
EXPECTED_PACKET_COUNT = 10
EXPECTED_FIRST_TS = 1700000000.0
EXPECTED_LAST_TS = 1700000002.0


@pytest.fixture(scope="module")
def pcap_path() -> Path:
    if not SAMPLE_PCAP.exists():
        from scripts.generate_test_pcap import generate

        generate()
    return SAMPLE_PCAP


class TestReadPcap:
    def test_returns_list_of_metadata(self, pcap_path: Path):
        result = read_pcap(pcap_path)
        assert isinstance(result, list)
        assert all(isinstance(m, PacketMetadata) for m in result)

    def test_packet_count(self, pcap_path: Path):
        result = read_pcap(pcap_path)
        assert len(result) == EXPECTED_PACKET_COUNT

    def test_sequential_indices(self, pcap_path: Path):
        result = read_pcap(pcap_path)
        indices = [m.index for m in result]
        assert indices == list(range(EXPECTED_PACKET_COUNT))

    def test_timestamps_are_ordered(self, pcap_path: Path):
        result = read_pcap(pcap_path)
        timestamps = [m.timestamp for m in result]
        assert timestamps == sorted(timestamps)

    def test_ip_addresses_present(self, pcap_path: Path):
        result = read_pcap(pcap_path)
        for m in result:
            assert m.src is not None
            assert m.dst is not None

    def test_tcp_syn_packets(self, pcap_path: Path):
        result = read_pcap(pcap_path)
        syn_packets = [m for m in result if m.tcp_flags == "S"]
        assert len(syn_packets) == 5
        for m in syn_packets:
            assert m.dst == "192.168.1.1"
            assert m.dport == 80

    def test_udp_dns_packets(self, pcap_path: Path):
        result = read_pcap(pcap_path)
        udp_packets = [m for m in result if m.protocol == 17]
        assert len(udp_packets) == 3
        for m in udp_packets:
            assert m.dport == 53

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            read_pcap("/nonexistent/file.pcap")

    def test_not_a_file(self, tmp_path: Path):
        with pytest.raises(ValueError, match="not a file"):
            read_pcap(tmp_path)


class TestIterPackets:
    def test_yields_all_packets(self, pcap_path: Path):
        packets = list(iter_packets(pcap_path))
        assert len(packets) == EXPECTED_PACKET_COUNT

    def test_yields_metadata_objects(self, pcap_path: Path):
        for m in iter_packets(pcap_path):
            assert isinstance(m, PacketMetadata)
            break

    def test_matches_read_pcap(self, pcap_path: Path):
        from_read = read_pcap(pcap_path)
        from_iter = list(iter_packets(pcap_path))
        assert len(from_read) == len(from_iter)
        for r, i in zip(from_read, from_iter):
            assert r.timestamp == i.timestamp
            assert r.src == i.src
            assert r.dst == i.dst
            assert r.length == i.length


class TestGetPcapStatistics:
    def test_returns_statistics(self, pcap_path: Path):
        stats = get_pcap_statistics(pcap_path)
        assert isinstance(stats, PcapStatistics)

    def test_packet_count(self, pcap_path: Path):
        stats = get_pcap_statistics(pcap_path)
        assert stats.packet_count == EXPECTED_PACKET_COUNT

    def test_timestamps(self, pcap_path: Path):
        stats = get_pcap_statistics(pcap_path)
        assert stats.first_timestamp == pytest.approx(EXPECTED_FIRST_TS, abs=0.01)
        assert stats.last_timestamp == pytest.approx(EXPECTED_LAST_TS, abs=0.01)

    def test_duration(self, pcap_path: Path):
        stats = get_pcap_statistics(pcap_path)
        expected_duration = EXPECTED_LAST_TS - EXPECTED_FIRST_TS
        assert stats.duration == pytest.approx(expected_duration, abs=0.01)

    def test_total_bytes_positive(self, pcap_path: Path):
        stats = get_pcap_statistics(pcap_path)
        assert stats.total_bytes > 0

    def test_protocols_present(self, pcap_path: Path):
        stats = get_pcap_statistics(pcap_path)
        assert 6 in stats.protocols  # TCP
        assert 17 in stats.protocols  # UDP

    def test_protocol_counts(self, pcap_path: Path):
        stats = get_pcap_statistics(pcap_path)
        assert stats.protocols[6] == 7   # 5 SYN + 1 SA + 1 PA
        assert stats.protocols[17] == 3  # 3 DNS/UDP
