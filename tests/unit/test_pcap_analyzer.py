"""Unit tests for the PCAP Analyzer module."""

from pathlib import Path
import pytest

from capture.pcap_analyzer import analyze_pcap_file, _extract_scapy_flows


@pytest.fixture
def sample_pcap_path():
    p = Path("data/samples/test_traffic.pcap")
    if not p.exists():
        from scripts.generate_test_pcap import generate
        generate(str(p))
    return p


def test_analyze_pcap_file_success(sample_pcap_path):
    result = analyze_pcap_file(sample_pcap_path)
    
    assert isinstance(result, dict)
    assert result["filename"] == sample_pcap_path.name
    assert result["packet_count"] > 0
    assert result["total_bytes"] > 0
    assert "summary" in result
    assert "total_flows" in result["summary"]
    assert "threats" in result
    assert isinstance(result["threats"], list)
    assert "flows" in result
    assert isinstance(result["flows"], list)
    assert "protocol_distribution" in result


def test_analyze_pcap_file_not_found():
    with pytest.raises(FileNotFoundError):
        analyze_pcap_file("data/samples/non_existent_file.pcap")


def test_analyze_pcap_file_invalid_target(tmp_path):
    d = tmp_path / "somedir"
    d.mkdir()
    with pytest.raises(ValueError):
        analyze_pcap_file(d)


def test_extract_scapy_flows_direct(sample_pcap_path):
    flows = _extract_scapy_flows(sample_pcap_path)
    assert isinstance(flows, list)
    assert len(flows) > 0
    first_flow = flows[0]
    assert "src_ip" in first_flow
    assert "dst_ip" in first_flow
    assert "proto" in first_flow
    assert "duration" in first_flow
    assert "total_bytes" in first_flow
