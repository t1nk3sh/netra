"""API Client for connecting the Streamlit dashboard to the FastAPI backend."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger(__name__)


class APIClient:
    """Client for query operations on the central FastAPI threat detection backend."""

    def __init__(self, base_url: str = "http://localhost:8000") -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(timeout=3.0)

    def get_health(self) -> bool:
        """Verify connection and health of backend API."""
        try:
            res = self.client.get(f"{self.base_url}/health")
            return res.status_code == 200 and res.json().get("status") == "ok"
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.debug("Backend health probe failed: %s", e)
            return False

    def get_alerts(
        self, threat_class: Optional[str] = None, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch alert history from backend with optional filtering.

        Args:
            threat_class: Category to filter by.
            severity: Severity class to filter by.
        """
        params = {}
        if threat_class:
            params["threat_class"] = threat_class
        if severity:
            params["severity"] = severity

        try:
            res = self.client.get(f"{self.base_url}/alerts", params=params)
            res.raise_for_status()
            return res.json()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error("Failed to fetch alerts from backend: %s", e)
            return []

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Fetch details of a single alert by ID."""
        try:
            res = self.client.get(f"{self.base_url}/alerts/{alert_id}")
            if res.status_code == 404:
                return None
            res.raise_for_status()
            return res.json()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error("Failed to fetch alert detail for %s: %s", alert_id, e)
            return None

    def get_statistics(self) -> Dict[str, Any]:
        """Fetch summary of alert historical distributions and total numbers."""
        default_stats = {
            "total_alerts": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "threat_class_counts": {},
        }
        try:
            res = self.client.get(f"{self.base_url}/statistics")
            res.raise_for_status()
            return res.json()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error("Failed to fetch statistics from backend: %s", e)
            return default_stats

    def get_threats(self) -> List[Dict[str, Any]]:
        """Fetch active threats grouped/aggregated by source IP."""
        try:
            res = self.client.get(f"{self.base_url}/threats")
            res.raise_for_status()
            return res.json()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error("Failed to fetch threat IP details: %s", e)
            return []

    def get_flows(self) -> List[Dict[str, Any]]:
        """Fetch actively analyzed flows from backend."""
        try:
            res = self.client.get(f"{self.base_url}/flows")
            res.raise_for_status()
            return res.json()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error("Failed to fetch flows from backend: %s", e)
            return []

    def post_flows(self, flows: List[Dict[str, Any]]) -> bool:
        """Post private raw packet/flow metadata to API."""
        try:
            res = self.client.post(f"{self.base_url}/flows", json=flows)
            return res.status_code == 200
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error("Failed to post flows to backend: %s", e)
            return False

    def get_pipeline_stats(self) -> Dict[str, Any]:
        """Fetch real-time pipeline performance and active sensor stats."""
        try:
            res = self.client.get(f"{self.base_url}/pipeline_stats")
            res.raise_for_status()
            return res.json()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.debug("Failed to fetch pipeline stats from backend: %s", e)
            return {}

    def post_pipeline_stats(self, stats: Dict[str, Any]) -> bool:
        """Push real-time pipeline stats from sensor to backend."""
        try:
            res = self.client.post(f"{self.base_url}/pipeline_stats", json=stats)
            return res.status_code == 200
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.debug("Failed to post pipeline stats to backend: %s", e)
            return False
