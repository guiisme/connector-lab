import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.webhook_api.app import app, create_app

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


@pytest.mark.parametrize(
    "timestamp_offset",
    [
        timedelta(seconds=-301),
        timedelta(seconds=301),
    ],
)
@pytest.mark.asyncio
async def test_timestamp_outside_tolerance_is_rejected(
    timestamp_offset: timedelta,
) -> None:
    fixed_now = datetime(
        2026,
        8,
        1,
        12,
        0,
        tzinfo=UTC,
    )
    delivery_time = fixed_now + timestamp_offset
    timestamp = str(int(delivery_time.timestamp()))
    payload = json.dumps(
        {
            "event_id": "event-replayed",
            "event_type": "alert.detected",
            "alert": {
                "id": "alert-replayed",
                "title": "Replayed alert",
                "severity": "high",
                "status": "open",
                "detected_at": "2026-08-01T11:59:00Z",
            },
        },
        separators=(",", ":"),
    ).encode()

    test_app = create_app(
        now_provider=lambda: fixed_now,
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

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Invalid webhook timestamp",
    }


@pytest.mark.asyncio
async def test_repeated_event_id_returns_duplicate_status() -> None:
    fixed_now = datetime(
        2026,
        8,
        1,
        12,
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
                "detected_at": "2026-08-01T11:59:00Z",
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

    test_app = create_app(
        now_provider=lambda: fixed_now,
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
    assert first_response.json() == {
        "event_id": "event-duplicate",
        "status": "accepted",
    }

    assert second_response.status_code == 202
    assert second_response.json() == {
        "event_id": "event-duplicate",
        "status": "duplicate",
    }


@pytest.mark.asyncio
async def test_app_instances_have_independent_event_stores() -> None:
    fixed_now = datetime(
        2026,
        8,
        1,
        12,
        0,
        tzinfo=UTC,
    )
    timestamp = str(int(fixed_now.timestamp()))
    payload = json.dumps(
        {
            "event_id": "event-isolated",
            "event_type": "alert.detected",
            "alert": {
                "id": "alert-isolated",
                "title": "Isolated application event",
                "severity": "low",
                "status": "open",
                "detected_at": "2026-08-01T11:59:00Z",
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
    statuses: list[str] = []

    for test_app in (
        create_app(now_provider=lambda: fixed_now),
        create_app(now_provider=lambda: fixed_now),
    ):
        transport = ASGITransport(app=test_app)

        async with AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as client:
            response = await client.post(
                "/webhooks/alerts",
                content=payload,
                headers=headers,
            )

        statuses.append(response.json()["status"])

    assert statuses == ["accepted", "accepted"]


@pytest.mark.parametrize(
    ("timestamp", "expected_detail"),
    [
        (None, "Invalid webhook signature"),
        ("not-a-timestamp", "Invalid webhook timestamp"),
    ],
)
@pytest.mark.asyncio
async def test_missing_or_malformed_timestamp_is_rejected(
    timestamp: str | None,
    expected_detail: str,
) -> None:
    payload = b"{}"
    timestamp_for_signature = timestamp or ""
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": sign_payload(
            payload,
            timestamp_for_signature,
        ),
    }

    if timestamp is not None:
        headers["X-Webhook-Timestamp"] = timestamp

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
        "detail": expected_detail,
    }
