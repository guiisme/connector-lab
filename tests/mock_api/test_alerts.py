from collections.abc import Mapping

import pytest
from httpx import ASGITransport, AsyncClient, Response

from connector_lab.mock_api.app import app


async def request_alerts(
    headers: Mapping[str, str] | None = None,
    params: dict[str, int] | None = None,
) -> Response:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        return await client.get(
            "/alerts",
            headers=headers,
            params=params,
        )


@pytest.mark.asyncio
async def test_alerts_returns_sample_data_with_valid_api_key() -> None:
    response = await request_alerts(
        headers={"X-API-Key": "connector-lab-secret"},
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["total"] == 2
    assert len(payload["items"]) == 2
    assert payload["items"][0] == {
        "id": "alert-001",
        "title": "Suspicious PowerShell execution",
        "severity": "high",
        "status": "open",
        "detected_at": "2026-07-31T18:00:00Z",
    }


@pytest.mark.parametrize(
    "headers",
    [
        None,
        {"X-API-Key": "invalid-key"},
    ],
)
@pytest.mark.asyncio
async def test_alerts_rejects_missing_or_invalid_api_key(
    headers: Mapping[str, str] | None,
) -> None:
    response = await request_alerts(headers=headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid API key"}


@pytest.mark.asyncio
async def test_alerts_returns_deterministic_pages() -> None:
    headers = {"X-API-Key": "connector-lab-secret"}

    first_page = await request_alerts(
        headers=headers,
        params={"page": 1, "page_size": 1},
    )
    second_page = await request_alerts(
        headers=headers,
        params={"page": 2, "page_size": 1},
    )

    assert first_page.status_code == 200
    assert first_page.json()["page"] == 1
    assert first_page.json()["page_size"] == 1
    assert first_page.json()["total"] == 2
    assert first_page.json()["has_next"] is True
    assert [item["id"] for item in first_page.json()["items"]] == [
        "alert-001",
    ]

    assert second_page.status_code == 200
    assert second_page.json()["page"] == 2
    assert second_page.json()["page_size"] == 1
    assert second_page.json()["total"] == 2
    assert second_page.json()["has_next"] is False
    assert [item["id"] for item in second_page.json()["items"]] == [
        "alert-002",
    ]


@pytest.mark.parametrize(
    "params",
    [
        {"page": 0},
        {"page_size": 0},
        {"page_size": 101},
    ],
)
@pytest.mark.asyncio
async def test_alerts_rejects_invalid_pagination(
    params: dict[str, int],
) -> None:
    response = await request_alerts(
        headers={"X-API-Key": "connector-lab-secret"},
        params=params,
    )

    assert response.status_code == 422
