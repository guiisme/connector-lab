from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class WebhookEventType(StrEnum):
    ALERT_DETECTED = "alert.detected"


class WebhookAlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WebhookAlertStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class WebhookAlertPayload(BaseModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: WebhookAlertSeverity
    status: WebhookAlertStatus
    detected_at: datetime


class WebhookAlertEvent(BaseModel):
    event_id: str = Field(min_length=1)
    event_type: WebhookEventType
    alert: WebhookAlertPayload


class WebhookAcceptedResponse(BaseModel):
    event_id: str
    status: str
    alert_id: str | None = None
    incident_id: str | None = None
    created: bool | None = None
