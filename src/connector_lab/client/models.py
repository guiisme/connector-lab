from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class AlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class Alert(BaseModel):
    id: str
    title: str
    severity: AlertSeverity
    status: AlertStatus
    detected_at: datetime


class AlertPage(BaseModel):
    items: list[Alert]
    page: int
    page_size: int
    total: int
    has_next: bool


class AlertCollection(BaseModel):
    items: list[Alert]
    total: int
