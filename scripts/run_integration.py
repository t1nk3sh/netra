"""End-to-End integration prototype execution runner.

Coordinates:
PCAP -> Zeek logs -> Parsed flows -> Streaming pipeline -> ML / Rule detection -> Alerts
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from capture.pcap_reader import get_pcap_statistics
from zeek.runner import ZeekRunner, ZeekConfig
from zeek.log_parser import parse_conn_log
from streaming.pipeline import StreamingPipeline
from models.training import ModelTrainer
from inference.predictor import DEFAULT_MODEL_PATH

# Setup simple console logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ZEEK_PCAP_PATH = Path("data/samples/zeek_test_traffic.pcap")
FALLBACK_LOGS = Path("data/samples/zeek_logs/conn.log")


def main():
    logger.info("Initializing prototype vertical integration run.")

    # 1. Verify default ML model exists
    if not DEFAULT_MODEL_PATH.exists():
        logger.info("Default ML model artifact not found. Training it first...")
        from scripts.train_default_model import train_default
        train_default()

    # 2. Capture Stats from PCAP
    try:
        if ZEEK_PCAP_PATH.exists():
            stats = get_pcap_statistics(ZEEK_PCAP_PATH)
            logger.info(
                "Observed original raw PCAP: %d packets (%d bytes, duration: %.2fs)",
                stats.packet_count,
                stats.total_bytes,
                stats.duration,
            )
        else:
            logger.warning("Richer PCAP source not found at %s. Regenerating...", ZEEK_PCAP_PATH)
            from scripts.generate_test_pcap import generate_zeek_pcap
            generate_zeek_pcap()
            stats = get_pcap_statistics(ZEEK_PCAP_PATH)
    except Exception as e:
        logger.error("Failed to parse PCAP metadata: %s", e)

    # 3. Process PCAP via Zeek (with automatic fallback to mock logs)
    parsed_df = None
    runner = ZeekRunner()
    if runner.is_available():
        logger.info("Zeek backend detected (%s). Executing against PCAP...", runner.backend.value)
        out_dir = Path("data/temp_zeek")
        runner_cfg = ZeekConfig(output_dir=out_dir)
        zeek_run = ZeekRunner(runner_cfg)
        res = zeek_run.process_pcap(ZEEK_PCAP_PATH)
        
        if res.success and (out_dir / "conn.log").exists():
            logger.info("Zeek execution succeeded. Parsing logs...")
            parsed_df = parse_conn_log(out_dir / "conn.log")
        else:
            logger.warning("Zeek execution yielded no conn.log output: %s", res.stderr)
    else:
        logger.warning("Zeek not available natively or via Docker. Falling back to pre-packaged sample conn.log")

    if parsed_df is None:
        if FALLBACK_LOGS.exists():
            logger.info("Parsing pre-packaged logs from %s", FALLBACK_LOGS)
            parsed_df = parse_conn_log(FALLBACK_LOGS)
        else:
            logger.error("Fallback logs not found at %s. Cannot proceed.", FALLBACK_LOGS)
            sys.exit(1)

    # 4. Stream connection records through the pipeline
    logger.info("Feeding %d connection records into StreamingPipeline...", len(parsed_df))
    
    # Track triggered alerts
    alert_list = []
    
    pipeline = StreamingPipeline(
        window_size_sec=2.0,
        model_path=DEFAULT_MODEL_PATH,
        alert_callback=lambda a: alert_list.append(a),
    )

    # Convert DataFrame rows back to dict records sorted by ts
    records = parsed_df.sort_values(by="ts").to_dict(orient="records")

    for rec in records:
        pipeline.process_record(rec)

    # Flush remaining window
    flushed = pipeline.flush()
    alert_list.extend(flushed)

    # 5. Summarize findings
    logger.info("Processing complete.")
    perf = pipeline.get_performance_stats()
    logger.info(
        "Performance summary:\n"
        "  Processed windows: %d\n"
        "  Processed flows: %d\n"
        "  Flows/sec: %.2f\n"
        "  Avg latency/flow: %.4f ms",
        perf["processed_windows"],
        perf["processed_flows"],
        perf["flows_per_second"],
        perf["avg_latency_per_flow_ms"],
    )

    logger.info("Alerts detected: %d", len(alert_list))
    for alert in alert_list:
        logger.info(
            "  - [%s] (Severity: %s, Conf: %.2f%%) Source: %s -> Targets: %s",
            alert.threat_class,
            alert.severity,
            alert.confidence * 100,
            alert.source,
            alert.destination or "Multiple",
        )
        logger.info("    Evidence: %s", alert.evidence)

    assert len(alert_list) > 0, "No alerts triggered! Incomplete pipeline run."
    logger.info("Integration test prototype check PASSED.")


if __name__ == "__main__":
    main()
