import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.mock_api.app import app


@pytest.mark.asyncio
async def test_health_returns_service_status() -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
