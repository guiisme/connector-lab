import hashlib
import hmac
import json

import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.webhook_api.app import app

WEBHOOK_SECRET = "connector-lab-webhook-secret"


def sign_payload(payload: bytes) -> str:
    digest = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return f"sha256={digest}"


@pytest.mark.asyncio
async def test_signed_alert_event_is_accepted() -> None:
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
                "X-Webhook-Signature": sign_payload(payload),
            },
        )

    assert response.status_code == 202
    assert response.json() == {
        "event_id": "event-001",
        "status": "accepted",
    }
