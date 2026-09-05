"""Unit tests for streaming window manager and pipeline."""

import pytest
from alerts.alert_schema import Alert
from streaming.window_manager import WindowManager
from streaming.pipeline import StreamingPipeline
from inference.predictor import DEFAULT_MODEL_PATH


class TestWindowManager:
    def test_window_manager_tumbling(self):
        # Window size = 2 seconds
        wm = WindowManager(window_size_sec=2.0)
        
        # 1. First record sets window start
        assert list(wm.add_record({"ts": 10.0, "data": "a"})) == []
        assert wm.current_window_start == 10.0
        assert len(wm.buffer) == 1

        # 2. Record within window (ts < start + size) does not trigger split
        assert list(wm.add_record({"ts": 11.5, "data": "b"})) == []
        assert len(wm.buffer) == 2

        # 3. Record at boundary or beyond splits
        closed_windows = list(wm.add_record({"ts": 12.0, "data": "c"}))
        assert len(closed_windows) == 1
        assert len(closed_windows[0]) == 2
        assert closed_windows[0][0]["data"] == "a"
        assert closed_windows[0][1]["data"] == "b"

        # New window is established
        assert wm.current_window_start == 12.0
        assert len(wm.buffer) == 1
        assert wm.buffer[0]["data"] == "c"

    def test_window_manager_flush(self):
        wm = WindowManager(window_size_sec=2.0)
        list(wm.add_record({"ts": 10.0, "data": "a"}))
        list(wm.add_record({"ts": 11.0, "data": "b"}))
        
        remaining = wm.flush()
        assert len(remaining) == 2
        assert wm.buffer == []
        assert wm.current_window_start is None

    def test_invalid_win_size_raises(self):
        with pytest.raises(ValueError):
            WindowManager(window_size_sec=0.0)


class TestStreamingPipeline:
    def test_pipeline_without_ml_runs(self):
        # Uses missing model path so it skips ML prediction gracefully
        pipeline = StreamingPipeline(window_size_sec=5.0, model_path="/nonexistent.joblib")
        assert pipeline.predictor is None

        # Process traffic
        records = [
            {"ts": 1000.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 1234, "dst_port": 80, "proto": "tcp", "conn_state": "SF"},
            {"ts": 1001.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 1235, "dst_port": 80, "proto": "tcp", "conn_state": "SF"},
            # Crossing boundary (5s window) -> 1000.0 + 5.0 = 1005.0
            {"ts": 1006.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 1236, "dst_port": 80, "proto": "tcp", "conn_state": "SF"},
        ]

        alerts = pipeline.process_record(records[0])
        assert alerts == []

        alerts2 = pipeline.process_record(records[1])
        assert alerts2 == []

        # Third record crosses boundary, triggers window processing
        alerts3 = pipeline.process_record(records[2])
        assert isinstance(alerts3, list)

        stats = pipeline.get_performance_stats()
        assert stats["processed_windows"] == 1
        assert stats["processed_flows"] == 2
        assert stats["total_latency_sec"] >= 0.0

    def test_pipeline_with_alert_callback_and_ml(self):
        # Ensure default model exists
        if not DEFAULT_MODEL_PATH.exists():
            from scripts.train_default_model import train_default
            train_default()

        received_alerts = []

        def callback(alert: Alert) -> None:
            received_alerts.append(alert)

        pipeline = StreamingPipeline(
            window_size_sec=3.0,
            model_path=DEFAULT_MODEL_PATH,
            alert_callback=callback,
        )
        assert pipeline.predictor is not None

        # Send a port scan pattern into the generator to see if we trigger scan alerts & callback
        # 15 scans in 1 second
        base_ts = 2000.0
        for i in range(15):
            rec = {
                "ts": base_ts + i * 0.05,
                "src_ip": "10.0.0.9",
                "dst_ip": "192.168.1.1",
                "src_port": 5000 + i,
                "dst_port": 80 + i,
                "proto": "tcp",
                "conn_state": "S0",
                "history": "S",
                "orig_pkts": 1,
                "resp_pkts": 0,
                "orig_bytes": 40,
                "resp_bytes": 0,
            }
            pipeline.process_record(rec)

        # Cross window (3s) -> time = 2000.0 + 3.0 = 2003.0
        cross = {
            "ts": 2005.0,
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 80,
            "dst_port": 80,
            "proto": "tcp",
            "conn_state": "SF",
        }
        
        alerts = pipeline.process_record(cross)
        
        # Alerts should have been generated and emitted to callback
        assert len(alerts) > 0
        assert len(received_alerts) > 0
        # Check alerts
        scan_alerts = [a for a in received_alerts if a.threat_class == "port_scan"]
        assert len(scan_alerts) == 1
        assert scan_alerts[0].source == "10.0.0.9"

        # Test flush
        remaining_alerts = pipeline.flush()
        # Remaining buffer holds the "cross" record
        assert len(pipeline.window_manager.buffer) == 0
        assert pipeline.window_manager.current_window_start is None
