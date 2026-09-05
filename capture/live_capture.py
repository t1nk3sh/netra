"""Live passive packet capture module.

Sniffs packets from a network interface using Scapy in read-only mode
(no injection, no return-path traffic). Writes rotating PCAP files
for downstream Zeek processing.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from scapy.all import sniff, wrpcap

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = Path("data/live_captures")
DEFAULT_ROTATION_SECONDS = 5
DEFAULT_ROTATION_PACKETS = 50


@dataclass
class CaptureConfig:
    """Configuration for live passive capture."""

    interface: str = "any"
    output_dir: str | Path = DEFAULT_OUTPUT_DIR
    rotation_seconds: int = DEFAULT_ROTATION_SECONDS
    rotation_packets: int = DEFAULT_ROTATION_PACKETS
    bpf_filter: str = ""
    promisc: bool = True


class LiveCapture:
    """Passively sniffs packets from a network interface and writes rotating PCAPs.

    Strictly read-only: no packets are ever transmitted or injected.
    Each rotation window produces a new PCAP file that can be fed to Zeek.
    """

    def __init__(
        self,
        config: CaptureConfig | None = None,
        on_pcap_ready: Callable[[Path], None] | None = None,
    ) -> None:
        self._config = config or CaptureConfig()
        self._output_dir = Path(self._config.output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._on_pcap_ready = on_pcap_ready
        self._running = False
        self._packets: list = []
        self._rotation_count = 0
        self.total_packets_sniffed = 0
        self.last_error: str | None = None
        self._lock = threading.Lock()

    def _flush_packets(self) -> Path | None:
        with self._lock:
            if not self._packets:
                return None
            pkts = self._packets[:]
            self._packets.clear()

        self._rotation_count += 1
        ts = int(time.time())
        pcap_path = self._output_dir / f"capture_{ts}_{self._rotation_count}.pcap"

        wrpcap(str(pcap_path), pkts)
        logger.info("Wrote %d packets to %s", len(pkts), pcap_path)
        return pcap_path

    def _rotation_loop(self) -> None:
        while self._running:
            time.sleep(self._config.rotation_seconds)
            pcap_path = self._flush_packets()
            if pcap_path and self._on_pcap_ready:
                try:
                    self._on_pcap_ready(pcap_path)
                except Exception as e:
                    logger.error("PCAP callback error: %s", e)

    def _packet_handler(self, pkt) -> None:
        if not pkt.haslayer("IP") and not pkt.haslayer("IPv6") and not pkt.haslayer("ARP"):
            return

        should_flush = False
        with self._lock:
            self._packets.append(pkt)
            self.total_packets_sniffed += 1
            if len(self._packets) >= self._config.rotation_packets:
                should_flush = True

        if should_flush:
            pcap_path = self._flush_packets()
            if pcap_path and self._on_pcap_ready:
                try:
                    self._on_pcap_ready(pcap_path)
                except Exception as e:
                    logger.error("PCAP callback error on threshold flush: %s", e)

    def start(self) -> None:
        """Start passive capture. Blocks until stop() is called."""
        self._running = True
        iface_str = self._config.interface.strip().lower() if self._config.interface else "any"
        is_any_iface = (iface_str in ["any", "all", ""])

        if is_any_iface:
            sniff_iface = None
            # On Linux cooked SLL sockets (interface 'any'), BPF filter 'ip' causes packet drops due to 16-byte link header
            sniff_filter = None
        else:
            sniff_iface = self._config.interface
            sniff_filter = self._config.bpf_filter if self._config.bpf_filter else None

        logger.info(
            "Starting live capture on interface=%s (sniff_iface=%s, filter=%s, rotation=%ds, max_packets=%d)",
            self._config.interface,
            sniff_iface,
            sniff_filter,
            self._config.rotation_seconds,
            self._config.rotation_packets,
        )

        rotation_thread = threading.Thread(target=self._rotation_loop, daemon=True)
        rotation_thread.start()

        try:
            sniff(
                iface=sniff_iface,
                filter=sniff_filter,
                promisc=self._config.promisc,
                store=False,
                prn=self._packet_handler,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            err_msg = "Permission denied for raw packet capture. Run: sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python)"
            logger.error(err_msg)
            self.last_error = err_msg
            self._running = False
        except Exception as e:
            logger.error("Capture error: %s", e)
            self.last_error = str(e)
            self._running = False
        finally:
            final_pcap = self._flush_packets()
            if final_pcap and self._on_pcap_ready:
                try:
                    self._on_pcap_ready(final_pcap)
                except Exception as e:
                    logger.error("Final PCAP callback error in cleanup: %s", e)

    def stop(self) -> None:
        """Signal capture to stop."""
        logger.info("Stopping live capture...")
        self._running = False
