import pytest
from httpx import (
    AsyncClient,
    ConnectError,
    MockTransport,
    ReadTimeout,
    Request,
    Response,
)

from connector_lab.client.alerts_connector import AlertsConnector
from connector_lab.client.errors import (
    ConnectorAuthenticationError,
    ConnectorConnectionError,
    ConnectorPaginationError,
    ConnectorTimeoutError,
)
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
    requested_page_sizes: list[int] = []

    def handle_paginated_request(request: Request) -> Response:
        page = int(request.url.params.get("page", "1"))
        page_size = int(request.url.params.get("page_size", "100"))
        requested_page_sizes.append(page_size)

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
            page_size=1,
        )

        result = await connector.list_alerts()

    assert requested_pages == [1, 2, 3]
    assert [alert.id for alert in result.items] == [
        "alert-001",
        "alert-002",
        "alert-003",
    ]
    assert result.total == 3
    assert requested_page_sizes == [1, 1, 1]


@pytest.mark.asyncio
async def test_list_alerts_supports_empty_response() -> None:
    def handle_empty_response(request: Request) -> Response:
        return Response(
            status_code=200,
            json={
                "items": [],
                "page": 1,
                "page_size": 100,
                "total": 0,
                "has_next": False,
            },
        )

    transport = MockTransport(handle_empty_response)

    async with AsyncClient(transport=transport) as http_client:
        connector = AlertsConnector(
            base_url="https://mock-cyber.local",
            api_key="connector-lab-secret",
            http_client=http_client,
        )

        result = await connector.list_alerts()

    assert result.items == []
    assert result.total == 0


@pytest.mark.asyncio
async def test_list_alerts_rejects_empty_page_with_next_page() -> None:
    def handle_inconsistent_empty_page(request: Request) -> Response:
        page = int(request.url.params["page"])

        return Response(
            status_code=200,
            json={
                "items": [],
                "page": page,
                "page_size": 100,
                "total": 1,
                "has_next": page == 1,
            },
        )

    transport = MockTransport(handle_inconsistent_empty_page)

    async with AsyncClient(transport=transport) as http_client:
        connector = AlertsConnector(
            base_url="https://mock-cyber.local",
            api_key="connector-lab-secret",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorPaginationError,
            match="Empty page cannot have a next page",
        ):
            await connector.list_alerts()


@pytest.mark.asyncio
async def test_list_alerts_rejects_unexpected_page_number() -> None:
    def handle_unexpected_page(request: Request) -> Response:
        requested_page = int(request.url.params["page"])

        return Response(
            status_code=200,
            json={
                "items": [
                    {
                        "id": f"alert-{requested_page:03}",
                        "title": "Pagination validation alert",
                        "severity": "medium",
                        "status": "open",
                        "detected_at": "2026-07-31T18:00:00Z",
                    }
                ],
                "page": 1,
                "page_size": 100,
                "total": 2,
                "has_next": requested_page == 1,
            },
        )

    transport = MockTransport(handle_unexpected_page)

    async with AsyncClient(transport=transport) as http_client:
        connector = AlertsConnector(
            base_url="https://mock-cyber.local",
            api_key="connector-lab-secret",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorPaginationError,
            match="Unexpected page number",
        ):
            await connector.list_alerts()


@pytest.mark.parametrize("page_size", [0, 101])
@pytest.mark.asyncio
async def test_connector_rejects_invalid_page_size(
    page_size: int,
) -> None:
    async with AsyncClient() as http_client:
        with pytest.raises(
            ValueError,
            match="page_size must be between 1 and 100",
        ):
            AlertsConnector(
                base_url="https://mock-cyber.local",
                api_key="connector-lab-secret",
                http_client=http_client,
                page_size=page_size,
            )


@pytest.mark.asyncio
async def test_list_alerts_rejects_duplicate_alerts() -> None:
    def handle_duplicate_alert(request: Request) -> Response:
        page = int(request.url.params["page"])

        return Response(
            status_code=200,
            json={
                "items": [
                    {
                        "id": "alert-001",
                        "title": "Repeated alert",
                        "severity": "medium",
                        "status": "open",
                        "detected_at": "2026-07-31T18:00:00Z",
                    }
                ],
                "page": page,
                "page_size": 100,
                "total": 2,
                "has_next": page == 1,
            },
        )

    transport = MockTransport(handle_duplicate_alert)

    async with AsyncClient(transport=transport) as http_client:
        connector = AlertsConnector(
            base_url="https://mock-cyber.local",
            api_key="connector-lab-secret",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorPaginationError,
            match="Duplicate alert received",
        ):
            await connector.list_alerts()


@pytest.mark.asyncio
async def test_list_alerts_rejects_next_page_after_total_is_reached() -> None:
    def handle_invalid_next_page(request: Request) -> Response:
        page = int(request.url.params["page"])

        return Response(
            status_code=200,
            json={
                "items": [
                    {
                        "id": f"alert-{page:03}",
                        "title": "Pagination limit alert",
                        "severity": "medium",
                        "status": "open",
                        "detected_at": "2026-07-31T18:00:00Z",
                    }
                ],
                "page": page,
                "page_size": 100,
                "total": 1,
                "has_next": page == 1,
            },
        )

    transport = MockTransport(handle_invalid_next_page)

    async with AsyncClient(transport=transport) as http_client:
        connector = AlertsConnector(
            base_url="https://mock-cyber.local",
            api_key="connector-lab-secret",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorPaginationError,
            match="Next page exceeds reported total",
        ):
            await connector.list_alerts()


@pytest.mark.asyncio
async def test_list_alerts_maps_timeout_error() -> None:
    def handle_timeout(request: Request) -> Response:
        raise ReadTimeout(
            "External API timed out",
            request=request,
        )

    transport = MockTransport(handle_timeout)

    async with AsyncClient(transport=transport) as http_client:
        connector = AlertsConnector(
            base_url="https://mock-cyber.local",
            api_key="connector-lab-secret",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorTimeoutError,
            match="Connector request timed out",
        ):
            await connector.list_alerts()


@pytest.mark.asyncio
async def test_list_alerts_maps_connection_error() -> None:
    def handle_connection_error(request: Request) -> Response:
        raise ConnectError(
            "External API is unavailable",
            request=request,
        )

    transport = MockTransport(handle_connection_error)

    async with AsyncClient(transport=transport) as http_client:
        connector = AlertsConnector(
            base_url="https://mock-cyber.local",
            api_key="connector-lab-secret",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorConnectionError,
            match="Connector could not reach the external API",
        ):
            await connector.list_alerts()
