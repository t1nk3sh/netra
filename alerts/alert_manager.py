"""Alert manager for threat alert ingestion, deduplication, and correlation.

Manages alert lifecycles, suppresses duplicate alarms within configurable
time windows, and correlates alerts for the same source IP.
"""

from __future__ import annotations

import logging
from datetime import timezone
from typing import Any, Callable, Dict, List, Optional

from alerts.alert_schema import Alert

logger = logging.getLogger(__name__)


class AlertManager:
    """Manages deduplication, scoring, correlation, and dispatch of security alerts."""

    def __init__(
        self,
        dedup_window_sec: float = 60.0,
        dispatch_callback: Callable[[Alert], None] | None = None,
    ) -> None:
        self.dedup_window_sec = dedup_window_sec
        self.dispatch_callback = dispatch_callback
        
        # In-memory store of recent alerts for deduplication mapping:
        # (source, threat_class) -> latest Alert
        self.active_alerts: Dict[tuple[str, str], Alert] = {}
        
        # History of all dispatched alerts
        self.alert_history: List[Alert] = []
        
        # Track alerts per source IP to correlate severity elevations
        self.source_history: Dict[str, List[Alert]] = {}

    def process_alert(self, alert: Alert) -> bool:
        """Process a newly generated alert.

        Performs deduplication and correlation. If the alert is not
        suppressed, it will be added to the history and dispatched.

        Args:
            alert: The Alert object.

        Returns:
            bool: True if the alert was dispatched/saved, False if suppressed.
        """
        # Ensure timestamp has timezone
        ts = alert.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        key = (alert.source, alert.threat_class)
        existing = self.active_alerts.get(key)
        
        if existing:
            existing_ts = existing.timestamp
            if existing_ts.tzinfo is None:
                existing_ts = existing_ts.replace(tzinfo=timezone.utc)

            delta = (ts - existing_ts).total_seconds()
            if delta < self.dedup_window_sec:
                logger.info(
                    "Deduplicated alert: source=%s, class=%s (gap=%.2fs)",
                    alert.source,
                    alert.threat_class,
                    delta,
                )
                
                # Merge evidence in the existing active alert buffer
                existing.evidence.update(alert.evidence)
                # Keep the higher confidence
                existing.confidence = max(existing.confidence, alert.confidence)
                return False

        # Apply correlation before dispatch
        self._correlate_and_update(alert)

        # Update deduplication cache
        self.active_alerts[key] = alert
        self.alert_history.append(alert)

        # Dispatch alert
        if self.dispatch_callback:
            try:
                self.dispatch_callback(alert)
            except Exception as e:
                logger.error("Failed to execute alert dispatch callback: %s", e)

        return True

    def _correlate_and_update(self, alert: Alert) -> None:
        """Analyze past alerts for this source to correlate and escalate severity."""
        src = alert.source
        
        if src not in self.source_history:
            self.source_history[src] = []
        self.source_history[src].append(alert)
        
        # Clean older alerts from source history (older than window)
        now_ts = alert.timestamp
        if now_ts.tzinfo is None:
            now_ts = now_ts.replace(tzinfo=timezone.utc)

        cutoff = now_ts.timestamp() - self.dedup_window_sec * 5.0
        self.source_history[src] = [
            a for a in self.source_history[src]
            if (a.timestamp.replace(tzinfo=timezone.utc) if a.timestamp.tzinfo is None else a.timestamp).timestamp() >= cutoff
        ]

        # Determine unique threat classes seen from this source IP recently
        recent_threat_classes = {a.threat_class for a in self.source_history[src]}
        
        # Correlation Rule: Multi-vector threat behavior
        # E.g., if we see BOTH scanning (host/port) and volumetric flood (ddos) or ML threat from a source,
        # elevate the severity of the current alert to critical.
        if len(recent_threat_classes) >= 2:
            alert.severity = "critical"
            alert.evidence["correlated_threats"] = list(recent_threat_classes)
            alert.confidence = min(alert.confidence + 0.1, 1.0)
            logger.info(
                "Elevated alert severity to critical due to multi-vector correlation for source %s",
                src,
            )

    def get_alerts(self, threat_class: Optional[str] = None, severity: Optional[str] = None) -> List[Alert]:
        """Fetch filtered alert history.

        Args:
            threat_class: Optional filter by threat category.
            severity: Optional filter by severity.

        Returns:
            List of Alert objects matches filters.
        """
        filtered = self.alert_history
        if threat_class:
            filtered = [a for a in filtered if a.threat_class == threat_class]
        if severity:
            filtered = [a for a in filtered if a.severity == severity]
        return filtered

    def clear(self) -> None:
        """Clear all lists and deduplication tables."""
        self.active_alerts.clear()
        self.alert_history.clear()
        self.source_history.clear()
