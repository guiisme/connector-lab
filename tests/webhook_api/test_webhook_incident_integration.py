import hashlib
import hmac
import json
from datetime import UTC, datetime

import pytest
from httpx import (
    ASGITransport,
    AsyncClient,
    MockTransport,
    Request,
    Response,
)

from connector_lab.client.itsm_connector import ITSMConnector
from connector_lab.client.models import (
    Alert,
    AlertSeverity,
    AlertStatus,
)
from connector_lab.webhook_api.app import create_app
from connector_lab.workflows.alert_to_incident import (
    AlertIncidentResult,
    AlertToIncidentWorkflow,
)

WEBHOOK_SECRET = "connector-lab-webhook-secret"


def sign_payload(
    payload: bytes,
    timestamp: str,
) -> str:
    signed_content = timestamp.encode() + b"." + payload
    digest = hmac.new(
        WEBHOOK_SECRET.encode(),
        signed_content,
        hashlib.sha256,
    ).hexdigest()

    return f"sha256={digest}"


class FakeAlertProcessor:
    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    async def process(
        self,
        alert: Alert,
    ) -> AlertIncidentResult:
        self.alerts.append(alert)

        return AlertIncidentResult(
            alert_id=alert.id,
            incident_id="INC-0001",
            created=True,
        )


@pytest.mark.asyncio
async def test_valid_webhook_invokes_alert_processor() -> None:
    fixed_now = datetime(
        2026,
        8,
        2,
        0,
        0,
        tzinfo=UTC,
    )
    timestamp = str(int(fixed_now.timestamp()))
    payload = json.dumps(
        {
            "event_id": "event-001",
            "event_type": "alert.detected",
            "alert": {
                "id": "alert-001",
                "title": "Suspicious PowerShell execution",
                "severity": "high",
                "status": "open",
                "detected_at": "2026-08-01T23:59:00Z",
            },
        },
        separators=(",", ":"),
    ).encode()
    processor = FakeAlertProcessor()
    test_app = create_app(
        now_provider=lambda: fixed_now,
        alert_processor=processor,
    )
    transport = ASGITransport(app=test_app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/webhooks/alerts",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Timestamp": timestamp,
                "X-Webhook-Signature": sign_payload(
                    payload,
                    timestamp,
                ),
            },
        )

    assert len(processor.alerts) == 1

    alert = processor.alerts[0]
    assert isinstance(alert, Alert)
    assert alert.id == "alert-001"
    assert alert.title == "Suspicious PowerShell execution"
    assert alert.severity is AlertSeverity.HIGH
    assert alert.status is AlertStatus.OPEN
    assert alert.detected_at == datetime(
        2026,
        8,
        1,
        23,
        59,
        tzinfo=UTC,
    )

    assert response.status_code == 202
    assert response.json() == {
        "event_id": "event-001",
        "status": "accepted",
        "alert_id": "alert-001",
        "incident_id": "INC-0001",
        "created": True,
    }


@pytest.mark.asyncio
async def test_duplicate_delivery_does_not_invoke_processor_again() -> None:
    fixed_now = datetime(
        2026,
        8,
        2,
        0,
        0,
        tzinfo=UTC,
    )
    timestamp = str(int(fixed_now.timestamp()))
    payload = json.dumps(
        {
            "event_id": "event-duplicate",
            "event_type": "alert.detected",
            "alert": {
                "id": "alert-duplicate",
                "title": "Repeated webhook delivery",
                "severity": "medium",
                "status": "open",
                "detected_at": "2026-08-01T23:59:00Z",
            },
        },
        separators=(",", ":"),
    ).encode()
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Signature": sign_payload(
            payload,
            timestamp,
        ),
    }
    processor = FakeAlertProcessor()
    test_app = create_app(
        now_provider=lambda: fixed_now,
        alert_processor=processor,
    )
    transport = ASGITransport(app=test_app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        first_response = await client.post(
            "/webhooks/alerts",
            content=payload,
            headers=headers,
        )
        second_response = await client.post(
            "/webhooks/alerts",
            content=payload,
            headers=headers,
        )

    assert first_response.status_code == 202
    assert second_response.status_code == 202
    assert len(processor.alerts) == 1

    assert second_response.json() == {
        "event_id": "event-duplicate",
        "status": "duplicate",
    }


@pytest.mark.asyncio
async def test_authentication_failure_does_not_invoke_processor() -> None:
    fixed_now = datetime(
        2026,
        8,
        2,
        0,
        0,
        tzinfo=UTC,
    )
    timestamp = str(int(fixed_now.timestamp()))
    processor = FakeAlertProcessor()
    test_app = create_app(
        now_provider=lambda: fixed_now,
        alert_processor=processor,
    )
    transport = ASGITransport(app=test_app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/webhooks/alerts",
            content=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Timestamp": timestamp,
                "X-Webhook-Signature": "sha256=invalid",
            },
        )

    assert response.status_code == 401
    assert processor.alerts == []


@pytest.mark.asyncio
async def test_webhook_creates_one_idempotent_itsm_incident() -> None:
    fixed_now = datetime(
        2026,
        8,
        2,
        0,
        0,
        tzinfo=UTC,
    )
    timestamp = str(int(fixed_now.timestamp()))
    itsm_requests: list[Request] = []

    def handle_itsm_request(request: Request) -> Response:
        itsm_requests.append(request)

        return Response(
            status_code=201,
            json={
                "incident_id": "INC-0001",
                "external_reference": "alert-001",
                "status": "new",
            },
        )

    def event_payload(event_id: str) -> bytes:
        return json.dumps(
            {
                "event_id": event_id,
                "event_type": "alert.detected",
                "alert": {
                    "id": "alert-001",
                    "title": "Suspicious PowerShell execution",
                    "severity": "high",
                    "status": "open",
                    "detected_at": "2026-08-01T23:59:00Z",
                },
            },
            separators=(",", ":"),
        ).encode()

    itsm_transport = MockTransport(handle_itsm_request)

    async with AsyncClient(
        transport=itsm_transport,
    ) as itsm_http_client:
        itsm_connector = ITSMConnector(
            base_url="https://mock-itsm.local",
            api_key="connector-lab-itsm-secret",
            http_client=itsm_http_client,
        )
        workflow = AlertToIncidentWorkflow(
            incident_creator=itsm_connector,
        )
        test_app = create_app(
            now_provider=lambda: fixed_now,
            alert_processor=workflow,
        )
        webhook_transport = ASGITransport(app=test_app)

        async with AsyncClient(
            transport=webhook_transport,
            base_url="http://test",
        ) as webhook_client:
            first_payload = event_payload("event-001")
            first_headers = {
                "Content-Type": "application/json",
                "X-Webhook-Timestamp": timestamp,
                "X-Webhook-Signature": sign_payload(
                    first_payload,
                    timestamp,
                ),
            }
            first_response = await webhook_client.post(
                "/webhooks/alerts",
                content=first_payload,
                headers=first_headers,
            )
            duplicate_response = await webhook_client.post(
                "/webhooks/alerts",
                content=first_payload,
                headers=first_headers,
            )

            second_payload = event_payload("event-002")
            second_response = await webhook_client.post(
                "/webhooks/alerts",
                content=second_payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Webhook-Timestamp": timestamp,
                    "X-Webhook-Signature": sign_payload(
                        second_payload,
                        timestamp,
                    ),
                },
            )

    assert len(itsm_requests) == 1

    assert first_response.json() == {
        "event_id": "event-001",
        "status": "accepted",
        "alert_id": "alert-001",
        "incident_id": "INC-0001",
        "created": True,
    }
    assert duplicate_response.json() == {
        "event_id": "event-001",
        "status": "duplicate",
    }
    assert second_response.json() == {
        "event_id": "event-002",
        "status": "accepted",
        "alert_id": "alert-001",
        "incident_id": "INC-0001",
        "created": False,
    }
