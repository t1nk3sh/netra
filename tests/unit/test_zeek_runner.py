"""Unit tests for zeek/runner.py

Tests are split into:
- Pure unit tests (always run): config, path validation, command building, log listing
- Integration tests (require Zeek): marked with @pytest.mark.zeek, skipped if unavailable
"""

from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

import pytest

from zeek.runner import (
    ZeekBackend,
    ZeekConfig,
    ZeekResult,
    ZeekRunner,
    detect_backend,
    _build_native_command,
    _build_docker_command,
    EXPECTED_LOGS,
)

SAMPLE_PCAP = Path("data/samples/test_traffic.pcap")
ZEEK_PCAP = Path("data/samples/zeek_test_traffic.pcap")


@pytest.fixture(scope="module")
def pcap_path() -> Path:
    if not SAMPLE_PCAP.exists():
        from scripts.generate_test_pcap import generate
        generate()
    return SAMPLE_PCAP


@pytest.fixture(scope="module")
def zeek_pcap_path() -> Path:
    if not ZEEK_PCAP.exists():
        from scripts.generate_test_pcap import generate_zeek_pcap
        generate_zeek_pcap()
    return ZEEK_PCAP


class TestZeekConfig:
    def test_default_config(self):
        cfg = ZeekConfig()
        assert cfg.output_dir == "data/zeek"
        assert cfg.backend is None
        assert cfg.docker_image == "zeek/zeek:latest"
        assert cfg.extra_scripts == []

    def test_custom_config(self):
        cfg = ZeekConfig(
            output_dir="/tmp/opencode/zeek_out",
            backend=ZeekBackend.DOCKER,
            docker_image="zeek/zeek:6.0",
            extra_scripts=["local.zeek"],
        )
        assert cfg.backend == ZeekBackend.DOCKER
        assert cfg.docker_image == "zeek/zeek:6.0"


class TestDetectBackend:
    def test_native_preferred(self):
        with patch("zeek.runner.shutil.which", return_value="/usr/bin/zeek"):
            assert detect_backend() == ZeekBackend.NATIVE

    def test_docker_fallback(self):
        with patch("zeek.runner.shutil.which", return_value=None):
            mock_result = MagicMock()
            mock_result.returncode = 0
            with patch("zeek.runner.subprocess.run", return_value=mock_result):
                assert detect_backend() == ZeekBackend.DOCKER

    def test_none_when_nothing_available(self):
        with patch("zeek.runner.shutil.which", return_value=None):
            with patch("zeek.runner.subprocess.run", side_effect=FileNotFoundError):
                assert detect_backend() is None


class TestCommandBuilding:
    def test_native_command(self, pcap_path: Path):
        cfg = ZeekConfig()
        output = Path("/tmp/opencode/zeek_test")
        cmd = _build_native_command(pcap_path, output, cfg)
        assert "zeek" == cmd[0]
        assert "-r" in cmd
        assert "LogAscii::use_json=T" in cmd

    def test_native_command_extra_scripts(self, pcap_path: Path):
        cfg = ZeekConfig(extra_scripts=["local.zeek"])
        output = Path("/tmp/opencode/zeek_test")
        cmd = _build_native_command(pcap_path, output, cfg)
        assert "local.zeek" in cmd

    def test_docker_command(self, pcap_path: Path):
        cfg = ZeekConfig()
        output = Path("/tmp/opencode/zeek_test")
        cmd = _build_docker_command(pcap_path, output, cfg)
        assert "docker" == cmd[0]
        assert "run" in cmd
        assert "--rm" in cmd
        assert "/input.pcap:ro" in cmd[cmd.index("-v") + 1]
        assert "zeek" in cmd
        assert "-r" in cmd
        assert "/input.pcap" in cmd


class TestZeekRunnerUnit:
    def test_is_available_with_mock_native(self):
        cfg = ZeekConfig(backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)
        assert runner.is_available()
        assert runner.backend == ZeekBackend.NATIVE

    def test_is_available_false_when_none(self):
        with patch("zeek.runner.detect_backend", return_value=None):
            cfg = ZeekConfig()
            runner = ZeekRunner(cfg)
            assert not runner.is_available()

    def test_file_not_found(self):
        cfg = ZeekConfig(backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)
        with pytest.raises(FileNotFoundError):
            runner.process_pcap("/nonexistent.pcap")

    def test_not_a_file(self, tmp_path: Path):
        cfg = ZeekConfig(backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)
        with pytest.raises(ValueError, match="not a file"):
            runner.process_pcap(tmp_path)

    def test_no_backend_raises(self, pcap_path: Path):
        with patch("zeek.runner.detect_backend", return_value=None):
            cfg = ZeekConfig()
            runner = ZeekRunner(cfg)
            with pytest.raises(RuntimeError, match="No Zeek backend"):
                runner.process_pcap(pcap_path)

    def test_list_logs_empty_dir(self, tmp_path: Path):
        cfg = ZeekConfig(output_dir=str(tmp_path), backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)
        assert runner.list_logs() == []

    def test_list_logs_finds_log_files(self, tmp_path: Path):
        (tmp_path / "conn.log").write_text("test")
        (tmp_path / "dns.log").write_text("test")
        (tmp_path / "not_a_log.txt").write_text("test")
        cfg = ZeekConfig(output_dir=str(tmp_path), backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)
        logs = runner.list_logs()
        assert "conn.log" in logs
        assert "dns.log" in logs
        assert "not_a_log.txt" not in logs

    def test_get_log_path_exists(self, tmp_path: Path):
        (tmp_path / "conn.log").write_text("test")
        cfg = ZeekConfig(output_dir=str(tmp_path), backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)
        p = runner.get_log_path("conn.log")
        assert p is not None
        assert p.name == "conn.log"

    def test_get_log_path_missing(self, tmp_path: Path):
        cfg = ZeekConfig(output_dir=str(tmp_path), backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)
        assert runner.get_log_path("conn.log") is None

    def test_validate_expected_logs(self, tmp_path: Path):
        (tmp_path / "conn.log").write_text("test")
        (tmp_path / "dns.log").write_text("test")
        cfg = ZeekConfig(output_dir=str(tmp_path), backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)
        result = runner.validate_expected_logs()
        assert result["conn.log"] is True
        assert result["dns.log"] is True
        assert result["ssl.log"] is False

    def test_mock_successful_process(self, pcap_path: Path, tmp_path: Path):
        (tmp_path / "conn.log").write_text("{}")
        (tmp_path / "dns.log").write_text("{}")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""

        cfg = ZeekConfig(output_dir=str(tmp_path), backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)

        with patch("zeek.runner.subprocess.run", return_value=mock_proc):
            result = runner.process_pcap(pcap_path)

        assert isinstance(result, ZeekResult)
        assert result.success is True
        assert "conn.log" in result.logs_produced

    def test_mock_failed_process(self, pcap_path: Path, tmp_path: Path):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "error"

        cfg = ZeekConfig(output_dir=str(tmp_path), backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)

        with patch("zeek.runner.subprocess.run", return_value=mock_proc):
            result = runner.process_pcap(pcap_path)

        assert result.success is False

    def test_timeout_handling(self, pcap_path: Path, tmp_path: Path):
        cfg = ZeekConfig(output_dir=str(tmp_path), backend=ZeekBackend.NATIVE)
        runner = ZeekRunner(cfg)

        with patch(
            "zeek.runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="zeek", timeout=300),
        ):
            result = runner.process_pcap(pcap_path)

        assert result.success is False
        assert result.returncode == -1
        assert "timed out" in result.stderr


zeek_available = detect_backend() is not None


@pytest.mark.skipif(not zeek_available, reason="Zeek not available")
class TestZeekIntegration:
    def test_process_pcap_produces_conn_log(self, zeek_pcap_path: Path, tmp_path: Path):
        cfg = ZeekConfig(output_dir=str(tmp_path))
        runner = ZeekRunner(cfg)
        result = runner.process_pcap(zeek_pcap_path)
        assert result.success
        assert "conn.log" in result.logs_produced

    def test_process_pcap_produces_dns_log(self, zeek_pcap_path: Path, tmp_path: Path):
        cfg = ZeekConfig(output_dir=str(tmp_path))
        runner = ZeekRunner(cfg)
        result = runner.process_pcap(zeek_pcap_path)
        assert result.success
        assert "dns.log" in result.logs_produced
