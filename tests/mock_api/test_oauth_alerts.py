import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.mock_api.app import app


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
