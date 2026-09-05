"""Zeek integration for processing PCAPs into structured logs.

Executes Zeek against a PCAP file to produce structured log output
(conn.log, dns.log, ssl.log, etc.). Supports both native Zeek and
Docker-based Zeek execution.

The source PCAP is never modified.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

EXPECTED_LOGS = ["conn.log", "dns.log", "ssl.log"]
DOCKER_IMAGE = "zeek/zeek:latest"


class ZeekBackend(Enum):
    NATIVE = "native"
    DOCKER = "docker"


@dataclass
class ZeekConfig:
    """Configuration for Zeek execution."""

    output_dir: str | Path = "data/zeek"
    backend: ZeekBackend | None = None
    docker_image: str = DOCKER_IMAGE
    extra_scripts: list[str] = field(default_factory=list)


@dataclass
class ZeekResult:
    """Result of a Zeek processing run."""

    success: bool
    output_dir: Path
    logs_produced: list[str]
    returncode: int
    stdout: str
    stderr: str
    pcap_path: str


def detect_backend() -> ZeekBackend | None:
    """Detect which Zeek backend is available."""
    if shutil.which("zeek"):
        return ZeekBackend.NATIVE
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
            return ZeekBackend.DOCKER
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _build_native_command(pcap: Path, output_dir: Path, config: ZeekConfig) -> list[str]:
    cmd = [
        "zeek",
        "-r", str(pcap.resolve()),
        f"LogAscii::use_json=T",
    ]
    cmd.extend(config.extra_scripts)
    return cmd


def _build_docker_command(pcap: Path, output_dir: Path, config: ZeekConfig) -> list[str]:
    pcap_abs = pcap.resolve()
    output_abs = output_dir.resolve()

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{pcap_abs}:/input.pcap:ro",
        "-v", f"{output_abs}:/output",
        "-w", "/output",
        config.docker_image,
        "zeek",
        "-r", "/input.pcap",
        "LogAscii::use_json=T",
    ]
    cmd.extend(config.extra_scripts)
    return cmd


class ZeekRunner:
    """Execute Zeek against PCAPs to produce structured logs.

    Supports native and Docker backends. The source PCAP is never modified.
    """

    def __init__(self, config: ZeekConfig | None = None) -> None:
        self._config = config or ZeekConfig()
        self._backend = self._config.backend or detect_backend()

    @property
    def backend(self) -> ZeekBackend | None:
        return self._backend

    def is_available(self) -> bool:
        """Check if a Zeek backend is available."""
        return self._backend is not None

    def process_pcap(self, pcap_path: str | Path) -> ZeekResult:
        """Run Zeek against a PCAP file.

        Args:
            pcap_path: Path to the PCAP file to process.

        Returns:
            ZeekResult with execution details and produced log paths.

        Raises:
            FileNotFoundError: If the PCAP file does not exist.
            RuntimeError: If no Zeek backend is available.
        """
        pcap = Path(pcap_path)
        if not pcap.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap}")
        if not pcap.is_file():
            raise ValueError(f"Path is not a file: {pcap}")

        if self._backend is None:
            raise RuntimeError(
                "No Zeek backend available. Install Zeek natively or ensure "
                "Docker is running and accessible."
            )

        output_dir = Path(self._config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if self._backend == ZeekBackend.NATIVE:
            cmd = _build_native_command(pcap, output_dir, self._config)
            cwd = output_dir
        else:
            cmd = _build_docker_command(pcap, output_dir, self._config)
            cwd = None

        logger.info("Running Zeek (%s): %s", self._backend.value, " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=cwd,
            )
        except subprocess.TimeoutExpired:
            return ZeekResult(
                success=False,
                output_dir=output_dir,
                logs_produced=[],
                returncode=-1,
                stdout="",
                stderr="Zeek execution timed out after 300 seconds",
                pcap_path=str(pcap),
            )

        logs_produced = self._find_logs(output_dir)

        success = proc.returncode == 0 and len(logs_produced) > 0

        if not success:
            logger.warning(
                "Zeek processing failed (rc=%d): %s",
                proc.returncode,
                proc.stderr[:500],
            )
        else:
            logger.info(
                "Zeek produced %d log files: %s",
                len(logs_produced),
                ", ".join(logs_produced),
            )

        return ZeekResult(
            success=success,
            output_dir=output_dir,
            logs_produced=logs_produced,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            pcap_path=str(pcap),
        )

    def _find_logs(self, output_dir: Path) -> list[str]:
        logs = []
        for f in sorted(output_dir.iterdir()):
            if f.suffix == ".log" and f.is_file():
                logs.append(f.name)
        return logs

    def get_log_path(self, log_name: str) -> Path | None:
        """Get the full path to a specific Zeek log file.

        Args:
            log_name: Log filename, e.g. "conn.log".

        Returns:
            Path to the log file, or None if it doesn't exist.
        """
        p = Path(self._config.output_dir) / log_name
        return p if p.exists() else None

    def list_logs(self) -> list[str]:
        """List all Zeek log files in the output directory."""
        output_dir = Path(self._config.output_dir)
        if not output_dir.exists():
            return []
        return self._find_logs(output_dir)

    def validate_expected_logs(self, expected: list[str] | None = None) -> dict[str, bool]:
        """Check which expected log files are present.

        Args:
            expected: List of expected log filenames.
                     Defaults to conn.log, dns.log, ssl.log.

        Returns:
            Dict mapping log name to presence boolean.
        """
        if expected is None:
            expected = EXPECTED_LOGS
        return {name: self.get_log_path(name) is not None for name in expected}
