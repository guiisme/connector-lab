import hashlib
import hmac
import json
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.webhook_api.app import app

WEBHOOK_SECRET = "connector-lab-webhook-secret"


def current_timestamp() -> str:
    return str(int(datetime.now(UTC).timestamp()))


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


@pytest.mark.asyncio
async def test_signed_alert_event_is_accepted() -> None:
    timestamp = current_timestamp()
    payload = json.dumps(
        {
            "event_id": "event-001",
            "event_type": "alert.detected",
            "alert": {
                "id": "alert-001",
                "title": "Suspicious PowerShell execution",
                "severity": "high",
                "status": "open",
                "detected_at": "2026-07-31T18:00:00Z",
            },
        },
        separators=(",", ":"),
    ).encode()

    transport = ASGITransport(app=app)

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

    assert response.status_code == 202
    assert response.json() == {
        "event_id": "event-001",
        "status": "accepted",
    }


@pytest.mark.parametrize(
    "signature",
    [
        None,
        "sha256=invalid",
    ],
)
@pytest.mark.asyncio
async def test_unsigned_or_invalid_webhook_is_rejected(
    signature: str | None,
) -> None:
    timestamp = current_timestamp()
    payload = b"{}"
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": timestamp,
    }

    if signature is not None:
        headers["X-Webhook-Signature"] = signature

    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/webhooks/alerts",
            content=payload,
            headers=headers,
        )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Invalid webhook signature",
    }


@pytest.mark.asyncio
async def test_signed_invalid_payload_is_rejected() -> None:
    timestamp = current_timestamp()
    payload = b"{}"
    transport = ASGITransport(
        app=app,
        raise_app_exceptions=False,
    )

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

    assert response.status_code == 422
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_current_timestamped_event_is_accepted() -> None:
    timestamp = current_timestamp()
    payload = json.dumps(
        {
            "event_id": "event-timestamped",
            "event_type": "alert.detected",
            "alert": {
                "id": "alert-timestamped",
                "title": "Timestamped alert",
                "severity": "medium",
                "status": "open",
                "detected_at": "2026-08-01T12:00:00Z",
            },
        },
        separators=(",", ":"),
    ).encode()

    transport = ASGITransport(app=app)

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

    assert response.status_code == 202
    assert response.json() == {
        "event_id": "event-timestamped",
        "status": "accepted",
    }
