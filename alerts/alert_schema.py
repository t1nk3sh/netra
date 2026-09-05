"""Pydantic schemas for standardized threat alerting."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field


class Alert(BaseModel):
    """Standardized schema for security alerts."""

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the alert",
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Time the alert was generated (UTC)",
    )
    flow_id: Optional[str] = Field(
        None,
        description="Unique identifier for the triggering flow, if applicable",
    )
    threat_class: str = Field(
        ...,
        description="The category of threat detected (e.g., port_scan, ddos)",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Detection confidence score from 0.0 to 1.0",
    )
    severity: str = Field(
        ...,
        description="Severity level of the threat (low, medium, high, critical)",
    )
    source: str = Field(
        ...,
        description="Source IP address or identifier responsible for the behavior",
    )
    destination: Optional[str] = Field(
        None,
        description="Target IP address, subnet, domain, or identifier if single",
    )
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value pairs of statistical indicator values proving the threat",
    )
