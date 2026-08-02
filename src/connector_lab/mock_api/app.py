from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, Query

from connector_lab.mock_api.auth import require_api_key
from connector_lab.mock_api.models import (
    Alert,
    AlertCollection,
    AlertSeverity,
    AlertStatus,
)
from connector_lab.mock_api.oauth import (
    create_bearer_token_dependency,
)
from connector_lab.oauth_config import (
    ALERTS_READ_SCOPE,
    TOKEN_EXPIRES_IN,
)

NowProvider = Callable[[], datetime]

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


def utc_now() -> datetime:
    return datetime.now(UTC)


def paginate_alerts(
    *,
    page: int,
    page_size: int,
) -> AlertCollection:
    total = len(SAMPLE_ALERTS)
    start = (page - 1) * page_size
    end = start + page_size
    items = SAMPLE_ALERTS[start:end]

    return AlertCollection(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        has_next=end < total,
    )


def create_app(
    *,
    now_provider: NowProvider = utc_now,
    token_scopes: frozenset[str] = frozenset(
        {ALERTS_READ_SCOPE},
    ),
) -> FastAPI:
    issued_at = now_provider()
    expires_at = issued_at + timedelta(
        seconds=TOKEN_EXPIRES_IN,
    )
    require_bearer_token = create_bearer_token_dependency(
        expires_at=expires_at,
        now_provider=now_provider,
        token_scopes=token_scopes,
        required_scope=ALERTS_READ_SCOPE,
    )

    api = FastAPI(
        title="Mock Cyber API",
        description=("Simulated cybersecurity product API for connector studies."),
    )

    @api.get("/health")
    def get_health() -> dict[str, str]:
        return {"status": "ok"}

    @api.get("/alerts", response_model=AlertCollection)
    def get_alerts(
        _: Annotated[None, Depends(require_api_key)],
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[
            int,
            Query(ge=1, le=100),
        ] = 50,
    ) -> AlertCollection:
        return paginate_alerts(
            page=page,
            page_size=page_size,
        )

    @api.get(
        "/oauth/alerts",
        response_model=AlertCollection,
    )
    def get_oauth_alerts(
        _: Annotated[None, Depends(require_bearer_token)],
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[
            int,
            Query(ge=1, le=100),
        ] = 50,
    ) -> AlertCollection:
        return paginate_alerts(
            page=page,
            page_size=page_size,
        )

    return api


app = create_app()
