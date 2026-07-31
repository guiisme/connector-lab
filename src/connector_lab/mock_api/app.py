from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, FastAPI

from connector_lab.mock_api.auth import require_api_key
from connector_lab.mock_api.models import (
    Alert,
    AlertCollection,
    AlertSeverity,
    AlertStatus,
)

app = FastAPI(
    title="Mock Cyber API",
    description="Simulated cybersecurity product API for connector studies.",
)

SAMPLE_ALERTS = [
    Alert(
        id="alert-001",
        title="Suspicious PowerShell execution",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        detected_at=datetime(2026, 7, 31, 18, 0, tzinfo=UTC),
    ),
    Alert(
        id="alert-002",
        title="Multiple failed authentication attempts",
        severity=AlertSeverity.MEDIUM,
        status=AlertStatus.OPEN,
        detected_at=datetime(2026, 7, 31, 18, 15, tzinfo=UTC),
    ),
]


@app.get("/health")
def get_health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/alerts", response_model=AlertCollection)
def get_alerts(
    _: Annotated[None, Depends(require_api_key)],
) -> AlertCollection:
    return AlertCollection(
        items=SAMPLE_ALERTS,
        total=len(SAMPLE_ALERTS),
    )
