import pytest
from httpx import AsyncClient, MockTransport, Request, Response

from connector_lab.client.alerts_connector import AlertsConnector
from connector_lab.client.errors import ConnectorAuthenticationError
from connector_lab.client.models import Alert, AlertSeverity


def handle_successful_request(request: Request) -> Response:
    assert request.method == "GET"
    assert request.url == ("https://mock-cyber.local/alerts?page=1&page_size=100")
    assert request.headers["X-API-Key"] == "connector-lab-secret"

    return Response(
        status_code=200,
        json={
            "items": [
                {
                    "id": "alert-001",
                    "title": "Suspicious PowerShell execution",
                    "severity": "high",
                    "status": "open",
                    "detected_at": "2026-07-31T18:00:00Z",
                }
            ],
            "page": 1,
            "page_size": 100,
            "total": 1,
            "has_next": False,
        },
    )


@pytest.mark.asyncio
async def test_list_alerts_returns_typed_alerts() -> None:
    transport = MockTransport(handle_successful_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = AlertsConnector(
            base_url="https://mock-cyber.local/",
            api_key="connector-lab-secret",
            http_client=http_client,
        )

        result = await connector.list_alerts()

    assert result.total == 1
    assert len(result.items) == 1
    assert isinstance(result.items[0], Alert)
    assert result.items[0].severity is AlertSeverity.HIGH


def handle_unauthorized_request(request: Request) -> Response:
    assert request.headers["X-API-Key"] == "invalid-key"

    return Response(
        status_code=401,
        json={"detail": "Invalid API key"},
    )


@pytest.mark.asyncio
async def test_list_alerts_raises_connector_authentication_error() -> None:
    transport = MockTransport(handle_unauthorized_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = AlertsConnector(
            base_url="https://mock-cyber.local",
            api_key="invalid-key",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorAuthenticationError,
            match="Connector authentication failed",
        ):
            await connector.list_alerts()


@pytest.mark.asyncio
async def test_list_alerts_retrieves_all_pages() -> None:
    requested_pages: list[int] = []

    def handle_paginated_request(request: Request) -> Response:
        page = int(request.url.params.get("page", "1"))
        page_size = int(request.url.params.get("page_size", "100"))

        requested_pages.append(page)

        return Response(
            status_code=200,
            json={
                "items": [
                    {
                        "id": f"alert-{page:03}",
                        "title": f"Alert from page {page}",
                        "severity": "medium",
                        "status": "open",
                        "detected_at": "2026-07-31T18:00:00Z",
                    }
                ],
                "page": page,
                "page_size": page_size,
                "total": 3,
                "has_next": page < 3,
            },
        )

    transport = MockTransport(handle_paginated_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = AlertsConnector(
            base_url="https://mock-cyber.local",
            api_key="connector-lab-secret",
            http_client=http_client,
        )

        result = await connector.list_alerts()

    assert requested_pages == [1, 2, 3]
    assert [alert.id for alert in result.items] == [
        "alert-001",
        "alert-002",
        "alert-003",
    ]
    assert result.total == 3
