"""Unit tests for FastAPI backend."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from alerts.alert_schema import Alert
from backend.main import app, alert_manager

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_alert_manager():
    # Make sure alert history is empty before each test
    alert_manager.clear()
    yield
    alert_manager.clear()


class TestBackendREST:
    def test_health_endpoint(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_get_alerts_empty(self):
        response = client.get("/alerts")
        assert response.status_code == 200
        assert response.json() == []

    def test_get_alerts_with_data(self):
        # Insert a mock alert
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            threat_class="port_scan",
            confidence=0.90,
            severity="high",
            source="10.0.0.5",
        )
        alert_manager.process_alert(alert)

        response = client.get("/alerts")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["source"] == "10.0.0.5"
        assert data[0]["threat_class"] == "port_scan"

    def test_get_alert_by_id_exists(self):
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            threat_class="ddos_syn_flood",
            confidence=0.85,
            severity="high",
            source="10.0.0.6",
        )
        alert_manager.process_alert(alert)
        alert_id = alert.id

        response = client.get(f"/alerts/{alert_id}")
        assert response.status_code == 200
        assert response.json()["id"] == alert_id
        assert response.json()["source"] == "10.0.0.6"

    def test_get_alert_by_id_missing(self):
        response = client.get("/alerts/missing_id")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]

    def test_statistics_endpoint_calculations(self):
        # Insert different mock alerts
        alert_manager.process_alert(Alert(
            timestamp=datetime.now(timezone.utc),
            threat_class="port_scan",
            confidence=0.6,
            severity="low",
            source="10.0.0.1",
        ))
        alert_manager.process_alert(Alert(
            timestamp=datetime.now(timezone.utc),
            threat_class="port_scan",
            confidence=0.7,
            severity="medium",
            source="10.0.0.2",
        ))
        alert_manager.process_alert(Alert(
            timestamp=datetime.now(timezone.utc),
            threat_class="ddos_syn_flood",
            confidence=0.9,
            severity="critical",
            source="10.0.0.3",
        ))

        response = client.get("/statistics")
        assert response.status_code == 200
        stats = response.json()
        assert stats["total_alerts"] == 3
        assert stats["severity_counts"]["low"] == 1
        assert stats["severity_counts"]["medium"] == 1
        assert stats["severity_counts"]["critical"] == 1
        assert stats["severity_counts"]["high"] == 0
        assert stats["threat_class_counts"]["port_scan"] == 2
        assert stats["threat_class_counts"]["ddos_syn_flood"] == 1

    def test_threat_endpoint_aggregations(self):
        base_time = datetime.now(timezone.utc)
        # 10.0.0.1 causes two threats of different severity
        alert_manager.process_alert(Alert(
            timestamp=base_time,
            threat_class="port_scan",
            confidence=0.5,
            severity="low",
            source="10.0.0.1",
        ))
        alert_manager.process_alert(Alert(
            timestamp=base_time,
            threat_class="ml_rf_threat",
            confidence=0.85,
            severity="high",
            source="10.0.0.1",
        ))
        # 10.0.0.2 causes one threat
        alert_manager.process_alert(Alert(
            timestamp=base_time,
            threat_class="ddos_syn_flood",
            confidence=0.95,
            severity="critical",
            source="10.0.0.2",
        ))

        response = client.get("/threats")
        assert response.status_code == 200
        threats = response.json()
        assert len(threats) == 2
        
        # Check source IP 10.0.0.1 (should be index 0 since it has 2 alerts vs 10.0.0.2's 1 alert)
        assert threats[0]["source"] == "10.0.0.1"
        assert threats[0]["alert_count"] == 2
        assert threats[0]["max_confidence"] == 0.95
        assert threats[0]["highest_severity"] == "critical"
        assert set(threats[0]["threat_classes"]) == {"port_scan", "ml_rf_threat"}

        # Check source IP 10.0.0.2
        assert threats[1]["source"] == "10.0.0.2"
        assert threats[1]["alert_count"] == 1
        assert threats[1]["max_confidence"] == 0.95
        assert threats[1]["highest_severity"] == "critical"

    def test_list_available_pcaps(self):
        response = client.get("/samples/pcaps")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_analyze_pcap_by_path(self):
        sample_path = "data/samples/test_traffic.pcap"
        response = client.post(f"/analyze_pcap?file_path={sample_path}")
        assert response.status_code == 200
        data = response.json()
        assert "packet_count" in data
        assert "summary" in data
        assert "threats" in data
        assert "flows" in data

    def test_analyze_pcap_missing_path(self):
        response = client.post("/analyze_pcap?file_path=non_existent.pcap")
        assert response.status_code == 404


class MockWebSocket:
    def __init__(self):
        self.accepted = False
        self.sent_messages = []

    async def accept(self):
        self.accepted = True

    async def send_json(self, message):
        self.sent_messages.append(message)


class TestBackendWebsocket:
    @pytest.mark.anyio
    async def test_websocket_connection_and_broadcast(self):
        from backend.main import ws_manager

        mock_ws = MockWebSocket()
        
        # Test connect
        await ws_manager.connect(mock_ws)
        assert mock_ws.accepted is True
        assert mock_ws in ws_manager.active_connections

        # Test broadcast
        message = {"event": "alert", "data": {"source": "1.2.3.4", "severity": "high"}}
        await ws_manager.broadcast(message)
        assert len(mock_ws.sent_messages) == 1
        assert mock_ws.sent_messages[0] == message

        # Test disconnect
        ws_manager.disconnect(mock_ws)
        assert mock_ws not in ws_manager.active_connections
