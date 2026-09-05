"""Unit tests for alerts/alert_manager.py"""

import pytest
from datetime import datetime, timezone, timedelta
from alerts.alert_schema import Alert
from alerts.alert_manager import AlertManager


@pytest.fixture
def manager() -> AlertManager:
    return AlertManager(dedup_window_sec=10.0)


class TestAlertManager:
    def test_ingest_alert_returns_true(self, manager: AlertManager):
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            threat_class="port_scan",
            confidence=0.75,
            severity="medium",
            source="10.0.0.1",
            evidence={"ports": [80, 443]}
        )
        assert manager.process_alert(alert) is True
        assert len(manager.alert_history) == 1

    def test_deduplicates_recent_alert_and_returns_false(self, manager: AlertManager):
        base_time = datetime.now(timezone.utc)
        
        alert1 = Alert(
            timestamp=base_time,
            threat_class="port_scan",
            confidence=0.75,
            severity="medium",
            source="10.0.0.1",
            evidence={"ports": [80]}
        )
        
        # Simulating duplicate alert arrival 4 seconds later (within 10s Window)
        alert2 = Alert(
            timestamp=base_time + timedelta(seconds=4),
            threat_class="port_scan",
            confidence=0.85,
            severity="medium",
            source="10.0.0.1",
            evidence={"ports": [443], "more_info": "yes"}
        )

        assert manager.process_alert(alert1) is True
        assert manager.process_alert(alert2) is False  # Suppressed

        # Should only have 1 alert in history
        assert len(manager.alert_history) == 1
        
        # Check that evidence was merged and confidence updated in active alert
        active = manager.active_alerts[("10.0.0.1", "port_scan")]
        assert active.confidence == 0.85
        assert active.evidence["ports"] == [443]
        assert active.evidence["more_info"] == "yes"

    def test_allows_duplicate_beyond_window(self, manager: AlertManager):
        base_time = datetime.now(timezone.utc)
        
        alert1 = Alert(
            timestamp=base_time,
            threat_class="port_scan",
            confidence=0.75,
            severity="medium",
            source="10.0.0.1",
        )
        
        # 12 seconds later (exceeds 10s Window)
        alert2 = Alert(
            timestamp=base_time + timedelta(seconds=12),
            threat_class="port_scan",
            confidence=0.80,
            severity="medium",
            source="10.0.0.1",
        )

        assert manager.process_alert(alert1) is True
        assert manager.process_alert(alert2) is True  # Dispatched

        assert len(manager.alert_history) == 2

    def test_correlation_rules_elevate_severity(self, manager: AlertManager):
        base_time = datetime.now(timezone.utc)
        
        # First threat vector: port scan
        alert1 = Alert(
            timestamp=base_time,
            threat_class="port_scan",
            confidence=0.70,
            severity="medium",
            source="10.0.0.9",
        )
        
        # Second threat vector: DDoS SYN flood from same host
        alert2 = Alert(
            timestamp=base_time + timedelta(seconds=1),
            threat_class="ddos_syn_flood",
            confidence=0.80,
            severity="high",
            source="10.0.0.9",
        )

        assert manager.process_alert(alert1) is True
        assert alert1.severity == "medium"

        assert manager.process_alert(alert2) is True
        # Since source 10.0.0.9 did both port_scan and ddos_syn_flood, the second alert is elevated to critical
        assert alert2.severity == "critical"
        assert "correlated_threats" in alert2.evidence
        assert "port_scan" in alert2.evidence["correlated_threats"]
        assert alert2.confidence > 0.80

    def test_get_alerts_filtering(self, manager: AlertManager):
        base_time = datetime.now(timezone.utc)
        manager.process_alert(Alert(
            timestamp=base_time, threat_class="port_scan", confidence=0.60, severity="low", source="10.0.0.1"
        ))
        manager.process_alert(Alert(
            timestamp=base_time, threat_class="ddos_syn_flood", confidence=0.90, severity="high", source="10.0.0.2"
        ))

        # Query all
        assert len(manager.get_alerts()) == 2
        # Filter by class
        assert len(manager.get_alerts(threat_class="port_scan")) == 1
        # Filter by severity
        assert len(manager.get_alerts(severity="high")) == 1

    def test_alert_callback_execution(self):
        cb_called = False
        received_alert = None

        def test_cb(a: Alert) -> None:
            nonlocal cb_called, received_alert
            cb_called = True
            received_alert = a

        mgr = AlertManager(dispatch_callback=test_cb)
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            threat_class="port_scan",
            confidence=0.60,
            severity="low",
            source="10.0.0.1",
        )
        mgr.process_alert(alert)

        assert cb_called is True
        assert received_alert == alert
