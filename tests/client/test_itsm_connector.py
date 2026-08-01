import json

import pytest
from httpx import (
    AsyncClient,
    ConnectError,
    MockTransport,
    ReadTimeout,
    Request,
    Response,
)

from connector_lab.client.errors import (
    ConnectorAuthenticationError,
    ConnectorConnectionError,
    ConnectorTimeoutError,
)
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


def incident_request() -> IncidentCreateRequest:
    return IncidentCreateRequest(
        external_reference="alert-001",
        title="Suspicious PowerShell execution",
        description="Created from cybersecurity alert alert-001",
        priority=IncidentPriority.HIGH,
    )


@pytest.mark.asyncio
async def test_create_incident_maps_authentication_failure() -> None:
    def handle_unauthorized(request: Request) -> Response:
        return Response(
            status_code=401,
            json={"detail": "Invalid API key"},
        )

    transport = MockTransport(handle_unauthorized)

    async with AsyncClient(transport=transport) as http_client:
        connector = ITSMConnector(
            base_url="https://mock-itsm.local",
            api_key="invalid-key",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorAuthenticationError,
            match="Connector authentication failed",
        ):
            await connector.create_incident(incident_request())


@pytest.mark.asyncio
async def test_create_incident_maps_timeout_failure() -> None:
    def handle_timeout(request: Request) -> Response:
        raise ReadTimeout(
            "External API timed out",
            request=request,
        )

    transport = MockTransport(handle_timeout)

    async with AsyncClient(transport=transport) as http_client:
        connector = ITSMConnector(
            base_url="https://mock-itsm.local",
            api_key="connector-lab-itsm-secret",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorTimeoutError,
            match="Connector request timed out",
        ):
            await connector.create_incident(incident_request())


@pytest.mark.asyncio
async def test_create_incident_maps_connection_failure() -> None:
    def handle_connection_error(request: Request) -> Response:
        raise ConnectError(
            "External API is unavailable",
            request=request,
        )

    transport = MockTransport(handle_connection_error)

    async with AsyncClient(transport=transport) as http_client:
        connector = ITSMConnector(
            base_url="https://mock-itsm.local",
            api_key="connector-lab-itsm-secret",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorConnectionError,
            match="Connector could not reach the external API",
        ):
            await connector.create_incident(incident_request())
