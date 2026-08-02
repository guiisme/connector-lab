from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.mock_api.app import app, create_app


@pytest.mark.asyncio
async def test_oauth_alerts_accepts_valid_bearer_token() -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/oauth/alerts",
            headers={
                "Authorization": ("Bearer connector-lab-access-token"),
            },
        )

    assert response.status_code == 200

    payload = response.json()

    assert payload["page"] == 1
    assert payload["page_size"] == 50
    assert payload["total"] == 2
    assert payload["has_next"] is False
    assert [item["id"] for item in payload["items"]] == [
        "alert-001",
        "alert-002",
    ]


@pytest.mark.parametrize(
    "headers",
    [
        None,
        {"Authorization": "Basic invalid-credentials"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer unknown-access-token"},
    ],
)
@pytest.mark.asyncio
async def test_oauth_alerts_rejects_invalid_authentication(
    headers: dict[str, str] | None,
) -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/oauth/alerts",
            headers=headers,
        )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.json() == {
        "detail": "Invalid access token",
    }


@pytest.mark.asyncio
async def test_oauth_alerts_rejects_expired_token() -> None:
    issued_at = datetime(
        2026,
        8,
        2,
        12,
        0,
        tzinfo=UTC,
    )
    request_time = issued_at + timedelta(seconds=301)
    clock_values = iter(
        [
            issued_at,
            request_time,
        ],
    )

    test_app = create_app(
        now_provider=lambda: next(clock_values),
    )
    transport = ASGITransport(app=test_app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/oauth/alerts",
            headers={
                "Authorization": ("Bearer connector-lab-access-token"),
            },
        )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == ('Bearer error="invalid_token"')
    assert response.json() == {
        "detail": "Access token expired",
    }
