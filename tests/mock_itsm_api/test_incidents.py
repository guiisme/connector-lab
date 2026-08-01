import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.mock_itsm_api.app import create_app


@pytest.mark.asyncio
async def test_create_incident_returns_typed_incident() -> None:
    app = create_app()
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/incidents",
            headers={
                "X-API-Key": "connector-lab-itsm-secret",
            },
            json={
                "external_reference": "alert-001",
                "title": "Suspicious PowerShell execution",
                "description": ("Created from cybersecurity alert alert-001"),
                "priority": "high",
            },
        )

    assert response.status_code == 201
    assert response.json() == {
        "incident_id": "INC-0001",
        "external_reference": "alert-001",
        "status": "new",
    }
