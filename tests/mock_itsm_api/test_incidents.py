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


@pytest.mark.asyncio
async def test_create_incident_generates_sequential_identifiers() -> None:
    app = create_app()
    transport = ASGITransport(app=app)
    request_payload = {
        "external_reference": "alert-001",
        "title": "Suspicious activity",
        "description": "Created from a cybersecurity alert",
        "priority": "high",
    }

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        first_response = await client.post(
            "/incidents",
            headers={"X-API-Key": "connector-lab-itsm-secret"},
            json=request_payload,
        )
        second_response = await client.post(
            "/incidents",
            headers={"X-API-Key": "connector-lab-itsm-secret"},
            json={
                **request_payload,
                "external_reference": "alert-002",
            },
        )

    assert first_response.json()["incident_id"] == "INC-0001"
    assert second_response.json()["incident_id"] == "INC-0002"


@pytest.mark.parametrize(
    "headers",
    [
        None,
        {"X-API-Key": "invalid-key"},
    ],
)
@pytest.mark.asyncio
async def test_create_incident_rejects_invalid_authentication(
    headers: dict[str, str] | None,
) -> None:
    app = create_app()
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/incidents",
            headers=headers,
            json={
                "external_reference": "alert-001",
                "title": "Suspicious activity",
                "description": "Created from a cybersecurity alert",
                "priority": "high",
            },
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid API key"}


@pytest.mark.asyncio
async def test_create_incident_rejects_invalid_payload() -> None:
    app = create_app()
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/incidents",
            headers={"X-API-Key": "connector-lab-itsm-secret"},
            json={
                "external_reference": "alert-001",
                "title": "",
                "description": "Created from a cybersecurity alert",
                "priority": "urgent",
            },
        )

    assert response.status_code == 422
