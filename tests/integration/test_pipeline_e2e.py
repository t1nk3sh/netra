"""End-to-end integration test validating the threat monitoring pipeline."""

from pathlib import Path
import pytest
import pandas as pd

from zeek.log_parser import parse_conn_log
from streaming.pipeline import StreamingPipeline
from inference.predictor import DEFAULT_MODEL_PATH
from alerts.alert_schema import Alert

CONN_LOG = Path("data/samples/zeek_logs/conn.log")


@pytest.fixture(scope="module")
def default_model() -> Path:
    if not DEFAULT_MODEL_PATH.exists():
        from scripts.train_default_model import train_default
        train_default()
    return DEFAULT_MODEL_PATH


class TestE2EPipeline:
    def test_pipeline_e2e_execution(self, default_model: Path):
        assert CONN_LOG.exists()

        # Parse logs
        df = parse_conn_log(CONN_LOG)
        assert not df.empty

        # Ingest into streaming pipeline
        alert_result = []

        def callback(alert: Alert) -> None:
            alert_result.append(alert)

        pipeline = StreamingPipeline(
            window_size_sec=10.0,
            model_path=default_model,
            alert_callback=callback,
        )

        # Feed each log record chronologically
        records = df.sort_values(by="ts").to_dict(orient="records")
        for rec in records:
            pipeline.process_record(rec)

        # Flush
        pipeline.flush()

        # Assertions
        assert len(alert_result) > 0
        
        # Verify alert formatting
        for alert in alert_result:
            assert isinstance(alert, Alert)
            assert alert.id is not None
            assert alert.source == "10.0.0.1"
            assert alert.threat_class.startswith("ml_") or alert.threat_class in ("port_scan", "host_scan", "ddos_syn_flood", "ddos_udp_flood", "ddos_reflection")
            assert 0.0 <= alert.confidence <= 1.0
            assert alert.severity in ("low", "medium", "high", "critical")
            assert isinstance(alert.evidence, dict)

        # Performance evaluation
        stats = pipeline.get_performance_stats()
        assert stats["processed_flows"] == len(records)
        assert stats["avg_latency_per_flow_ms"] >= 0.0
