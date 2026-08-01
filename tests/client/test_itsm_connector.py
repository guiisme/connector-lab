import json

import pytest
from httpx import AsyncClient, MockTransport, Request, Response

from connector_lab.client.itsm_connector import ITSMConnector
from connector_lab.client.itsm_models import (
    IncidentCreateRequest,
    IncidentCreateResponse,
    IncidentPriority,
    IncidentStatus,
)


def handle_incident_creation(request: Request) -> Response:
    assert request.method == "POST"
    assert request.url == "https://mock-itsm.local/incidents"
    assert request.headers["X-API-Key"] == "connector-lab-itsm-secret"
    assert json.loads(request.content) == {
        "external_reference": "alert-001",
        "title": "Suspicious PowerShell execution",
        "description": "Created from cybersecurity alert alert-001",
        "priority": "high",
    }

    return Response(
        status_code=201,
        json={
            "incident_id": "INC-0001",
            "external_reference": "alert-001",
            "status": "new",
        },
    )


@pytest.mark.asyncio
async def test_create_incident_returns_typed_response() -> None:
    transport = MockTransport(handle_incident_creation)

    async with AsyncClient(transport=transport) as http_client:
        connector = ITSMConnector(
            base_url="https://mock-itsm.local/",
            api_key="connector-lab-itsm-secret",
            http_client=http_client,
        )
        request = IncidentCreateRequest(
            external_reference="alert-001",
            title="Suspicious PowerShell execution",
            description="Created from cybersecurity alert alert-001",
            priority=IncidentPriority.HIGH,
        )

        result = await connector.create_incident(request)

    assert isinstance(result, IncidentCreateResponse)
    assert result.incident_id == "INC-0001"
    assert result.external_reference == "alert-001"
    assert result.status is IncidentStatus.NEW
