import pytest
from httpx import (
    AsyncClient,
    MockTransport,
    Request,
    Response,
)

from connector_lab.client.oauth_alerts_connector import (
    OAuthAlertsConnector,
)
from connector_lab.client.oauth_token_provider import (
    OAuthTokenProvider,
)


@pytest.mark.asyncio
async def test_oauth_connector_obtains_token_and_retrieves_alerts() -> None:
    requested_paths: list[str] = []

    def handle_request(request: Request) -> Response:
        requested_paths.append(request.url.path)

        if request.url.path == "/oauth/token":
            return Response(
                status_code=200,
                json={
                    "access_token": "connector-access-token",
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "scope": "alerts:read",
                },
            )

        if request.url.path == "/oauth/alerts":
            assert request.headers["Authorization"] == ("Bearer connector-access-token")
            assert request.url.params["page"] == "1"
            assert request.url.params["page_size"] == "100"

            return Response(
                status_code=200,
                json={
                    "items": [
                        {
                            "id": "alert-001",
                            "title": ("Suspicious PowerShell execution"),
                            "severity": "high",
                            "status": "open",
                            "detected_at": ("2026-07-31T18:00:00Z"),
                        },
                    ],
                    "page": 1,
                    "page_size": 100,
                    "total": 1,
                    "has_next": False,
                },
            )

        raise AssertionError(
            f"Unexpected request path: {request.url.path}",
        )

    transport = MockTransport(handle_request)

    async with AsyncClient(transport=transport) as http_client:
        token_provider = OAuthTokenProvider(
            token_url="https://mock-oauth.local/oauth/token",
            client_id="connector-lab-client",
            client_secret="connector-lab-client-secret",
            scope="alerts:read",
            http_client=http_client,
        )
        connector = OAuthAlertsConnector(
            base_url="https://mock-cyber.local",
            token_provider=token_provider,
            http_client=http_client,
        )

        result = await connector.list_alerts()

    assert requested_paths == [
        "/oauth/token",
        "/oauth/alerts",
    ]
    assert result.total == 1
    assert result.items[0].id == "alert-001"
    assert result.items[0].title == ("Suspicious PowerShell execution")


@pytest.mark.asyncio
async def test_oauth_connector_reuses_cached_token_between_calls() -> None:
    token_requests = 0
    alerts_requests = 0

    def handle_request(request: Request) -> Response:
        nonlocal token_requests
        nonlocal alerts_requests

        if request.url.path == "/oauth/token":
            token_requests += 1

            return Response(
                status_code=200,
                json={
                    "access_token": "cached-connector-token",
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "scope": "alerts:read",
                },
            )

        if request.url.path == "/oauth/alerts":
            alerts_requests += 1

            assert request.headers["Authorization"] == ("Bearer cached-connector-token")

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

        raise AssertionError(
            f"Unexpected request path: {request.url.path}",
        )

    transport = MockTransport(handle_request)

    async with AsyncClient(transport=transport) as http_client:
        token_provider = OAuthTokenProvider(
            token_url="https://mock-oauth.local/oauth/token",
            client_id="connector-lab-client",
            client_secret="connector-lab-client-secret",
            scope="alerts:read",
            http_client=http_client,
        )
        connector = OAuthAlertsConnector(
            base_url="https://mock-cyber.local",
            token_provider=token_provider,
            http_client=http_client,
        )

        first_result = await connector.list_alerts()
        second_result = await connector.list_alerts()

    assert token_requests == 1
    assert alerts_requests == 2
    assert first_result.total == 0
    assert second_result.total == 0
