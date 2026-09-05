"""Read-only PCAP reader for passive traffic analysis.

This module provides functions to read and extract metadata from PCAP files
without modifying the original evidence or transmitting any packets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

from scapy.all import PcapReader as ScapyPcapReader
from scapy.all import rdpcap
from scapy.packet import Packet


@dataclass(frozen=True)
class PacketMetadata:
    """Basic metadata extracted from a single packet."""

    index: int
    timestamp: float
    length: int
    src: str | None
    dst: str | None
    protocol: int | None
    sport: int | None
    dport: int | None
    tcp_flags: str | None


@dataclass
class PcapStatistics:
    """Aggregate statistics for a PCAP file."""

    packet_count: int
    first_timestamp: float
    last_timestamp: float
    duration: float
    total_bytes: int
    protocols: dict[int, int] = field(default_factory=dict)


def _validate_path(path: str | Path) -> Path:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"PCAP file not found: {p}")
    if not p.is_file():
        raise ValueError(f"Path is not a file: {p}")
    return p


def _extract_metadata(pkt: Packet, index: int) -> PacketMetadata:
    src: str | None = None
    dst: str | None = None
    protocol: int | None = None
    sport: int | None = None
    dport: int | None = None
    tcp_flags: str | None = None

    if pkt.haslayer("IP"):
        ip = pkt["IP"]
        src = ip.src
        dst = ip.dst
        protocol = ip.proto
    elif pkt.haslayer("IPv6"):
        ipv6 = pkt["IPv6"]
        src = ipv6.src
        dst = ipv6.dst
        protocol = ipv6.nh

    if pkt.haslayer("TCP"):
        tcp = pkt["TCP"]
        sport = tcp.sport
        dport = tcp.dport
        tcp_flags = str(tcp.flags)
    elif pkt.haslayer("UDP"):
        udp = pkt["UDP"]
        sport = udp.sport
        dport = udp.dport

    return PacketMetadata(
        index=index,
        timestamp=float(pkt.time),
        length=len(pkt),
        src=src,
        dst=dst,
        protocol=protocol,
        sport=sport,
        dport=dport,
        tcp_flags=tcp_flags,
    )


def read_pcap(path: str | Path) -> list[PacketMetadata]:
    """Read all packets from a PCAP and return their metadata.

    Args:
        path: Path to the PCAP file.

    Returns:
        List of PacketMetadata for every packet in the file.
    """
    p = _validate_path(path)
    packets = rdpcap(str(p))
    return [_extract_metadata(pkt, i) for i, pkt in enumerate(packets)]


def iter_packets(path: str | Path) -> Generator[PacketMetadata, None, None]:
    """Iterate over packets in a PCAP without loading all into memory.

    Args:
        path: Path to the PCAP file.

    Yields:
        PacketMetadata for each packet.
    """
    p = _validate_path(path)
    with ScapyPcapReader(str(p)) as reader:
        for i, pkt in enumerate(reader):
            yield _extract_metadata(pkt, i)


def get_pcap_statistics(path: str | Path) -> PcapStatistics:
    """Compute aggregate statistics for a PCAP file.

    Args:
        path: Path to the PCAP file.

    Returns:
        PcapStatistics with counts, timestamps, bytes, and protocol distribution.
    """
    p = _validate_path(path)

    packet_count = 0
    total_bytes = 0
    first_ts: float | None = None
    last_ts: float | None = None
    protocols: dict[int, int] = {}

    with ScapyPcapReader(str(p)) as reader:
        for pkt in reader:
            ts = float(pkt.time)
            pkt_len = len(pkt)

            if first_ts is None:
                first_ts = ts
            last_ts = ts

            packet_count += 1
            total_bytes += pkt_len

            meta = _extract_metadata(pkt, packet_count - 1)
            if meta.protocol is not None:
                protocols[meta.protocol] = protocols.get(meta.protocol, 0) + 1

    if packet_count == 0:
        raise ValueError(f"PCAP file contains no packets: {p}")

    assert first_ts is not None
    assert last_ts is not None

    return PcapStatistics(
        packet_count=packet_count,
        first_timestamp=first_ts,
        last_timestamp=last_ts,
        duration=last_ts - first_ts,
        total_bytes=total_bytes,
        protocols=protocols,
    )
