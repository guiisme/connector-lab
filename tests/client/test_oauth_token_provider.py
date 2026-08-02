from base64 import b64encode
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

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
    ConnectorAuthorizationError,
    ConnectorConnectionError,
    ConnectorTimeoutError,
)
from connector_lab.client.oauth_models import OAuthToken
from connector_lab.client.oauth_token_provider import (
    OAuthTokenProvider,
)


@pytest.mark.asyncio
async def test_token_provider_requests_typed_access_token() -> None:
    def handle_token_request(request: Request) -> Response:
        expected_credentials = b64encode(
            b"connector-lab-client:connector-lab-client-secret",
        ).decode()

        assert request.method == "POST"
        assert str(request.url) == ("https://mock-oauth.local/oauth/token")
        assert request.headers["Authorization"] == (f"Basic {expected_credentials}")
        assert request.headers["Content-Type"].startswith(
            "application/x-www-form-urlencoded",
        )
        assert parse_qs(request.content.decode()) == {
            "grant_type": ["client_credentials"],
            "scope": ["alerts:read"],
        }

        return Response(
            status_code=200,
            json={
                "access_token": "connector-lab-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "alerts:read",
            },
        )

    transport = MockTransport(handle_token_request)

    async with AsyncClient(transport=transport) as http_client:
        provider = OAuthTokenProvider(
            token_url="https://mock-oauth.local/oauth/token",
            client_id="connector-lab-client",
            client_secret="connector-lab-client-secret",
            scope="alerts:read",
            http_client=http_client,
        )

        token = await provider.get_token()

    assert isinstance(token, OAuthToken)
    assert token.access_token == "connector-lab-access-token"
    assert token.token_type == "Bearer"
    assert token.expires_in == 300
    assert token.scope == "alerts:read"


@pytest.mark.asyncio
async def test_token_provider_reuses_cached_valid_token() -> None:
    token_requests = 0
    fixed_now = datetime(
        2026,
        8,
        2,
        12,
        0,
        tzinfo=UTC,
    )

    def handle_token_request(request: Request) -> Response:
        nonlocal token_requests
        token_requests += 1

        return Response(
            status_code=200,
            json={
                "access_token": "cached-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "alerts:read",
            },
        )

    transport = MockTransport(handle_token_request)

    async with AsyncClient(transport=transport) as http_client:
        provider = OAuthTokenProvider(
            token_url="https://mock-oauth.local/oauth/token",
            client_id="connector-lab-client",
            client_secret="connector-lab-client-secret",
            scope="alerts:read",
            http_client=http_client,
            now_provider=lambda: fixed_now,
        )

        first_token = await provider.get_token()
        second_token = await provider.get_token()

    assert token_requests == 1
    assert first_token is second_token
    assert first_token.access_token == "cached-access-token"


@pytest.mark.asyncio
async def test_token_provider_renews_expired_token() -> None:
    token_requests = 0
    current_time = datetime(
        2026,
        8,
        2,
        12,
        0,
        tzinfo=UTC,
    )

    def handle_token_request(request: Request) -> Response:
        nonlocal token_requests
        token_requests += 1

        return Response(
            status_code=200,
            json={
                "access_token": (f"access-token-{token_requests}"),
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "alerts:read",
            },
        )

    transport = MockTransport(handle_token_request)

    async with AsyncClient(transport=transport) as http_client:
        provider = OAuthTokenProvider(
            token_url="https://mock-oauth.local/oauth/token",
            client_id="connector-lab-client",
            client_secret="connector-lab-client-secret",
            scope="alerts:read",
            http_client=http_client,
            now_provider=lambda: current_time,
        )

        first_token = await provider.get_token()

        current_time += timedelta(seconds=300)

        second_token = await provider.get_token()

    assert token_requests == 2
    assert first_token.access_token == "access-token-1"
    assert second_token.access_token == "access-token-2"
    assert first_token is not second_token


@pytest.mark.asyncio
async def test_token_provider_renews_with_expiration_margin() -> None:
    token_requests = 0
    current_time = datetime(
        2026,
        8,
        2,
        12,
        0,
        tzinfo=UTC,
    )

    def handle_token_request(request: Request) -> Response:
        nonlocal token_requests
        token_requests += 1

        return Response(
            status_code=200,
            json={
                "access_token": (f"margin-token-{token_requests}"),
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "alerts:read",
            },
        )

    transport = MockTransport(handle_token_request)

    async with AsyncClient(transport=transport) as http_client:
        provider = OAuthTokenProvider(
            token_url="https://mock-oauth.local/oauth/token",
            client_id="connector-lab-client",
            client_secret="connector-lab-client-secret",
            scope="alerts:read",
            http_client=http_client,
            now_provider=lambda: current_time,
            expiration_margin_seconds=30,
        )

        first_token = await provider.get_token()

        current_time += timedelta(seconds=269)
        cached_token = await provider.get_token()

        current_time += timedelta(seconds=1)
        renewed_token = await provider.get_token()

    assert token_requests == 2
    assert cached_token is first_token
    assert renewed_token.access_token == "margin-token-2"
    assert renewed_token is not first_token


@pytest.mark.parametrize(
    (
        "status_code",
        "oauth_error",
        "expected_error",
        "expected_message",
    ),
    [
        (
            401,
            "invalid_client",
            ConnectorAuthenticationError,
            "OAuth client authentication failed",
        ),
        (
            400,
            "invalid_scope",
            ConnectorAuthorizationError,
            "OAuth scope authorization failed",
        ),
    ],
)
@pytest.mark.asyncio
async def test_token_provider_maps_oauth_errors(
    status_code: int,
    oauth_error: str,
    expected_error: type[Exception],
    expected_message: str,
) -> None:
    def handle_token_error(request: Request) -> Response:
        return Response(
            status_code=status_code,
            json={
                "error": oauth_error,
            },
        )

    transport = MockTransport(handle_token_error)

    async with AsyncClient(transport=transport) as http_client:
        provider = OAuthTokenProvider(
            token_url="https://mock-oauth.local/oauth/token",
            client_id="connector-lab-client",
            client_secret="connector-lab-client-secret",
            scope="alerts:read",
            http_client=http_client,
        )

        with pytest.raises(
            expected_error,
            match=expected_message,
        ):
            await provider.get_token()


@pytest.mark.asyncio
async def test_token_provider_maps_timeout_failure() -> None:
    def handle_timeout(request: Request) -> Response:
        raise ReadTimeout(
            "OAuth server timed out",
            request=request,
        )

    transport = MockTransport(handle_timeout)

    async with AsyncClient(transport=transport) as http_client:
        provider = OAuthTokenProvider(
            token_url="https://mock-oauth.local/oauth/token",
            client_id="connector-lab-client",
            client_secret="connector-lab-client-secret",
            scope="alerts:read",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorTimeoutError,
            match="OAuth token request timed out",
        ):
            await provider.get_token()


@pytest.mark.asyncio
async def test_token_provider_maps_connection_failure() -> None:
    def handle_connection_failure(request: Request) -> Response:
        raise ConnectError(
            "OAuth server is unavailable",
            request=request,
        )

    transport = MockTransport(handle_connection_failure)

    async with AsyncClient(transport=transport) as http_client:
        provider = OAuthTokenProvider(
            token_url="https://mock-oauth.local/oauth/token",
            client_id="connector-lab-client",
            client_secret="connector-lab-client-secret",
            scope="alerts:read",
            http_client=http_client,
        )

        with pytest.raises(
            ConnectorConnectionError,
            match="OAuth token endpoint is unavailable",
        ):
            await provider.get_token()


@pytest.mark.asyncio
async def test_token_provider_rejects_negative_expiration_margin() -> None:
    async with AsyncClient() as http_client:
        with pytest.raises(
            ValueError,
            match=("expiration_margin_seconds must be zero or greater"),
        ):
            OAuthTokenProvider(
                token_url="https://mock-oauth.local/oauth/token",
                client_id="connector-lab-client",
                client_secret="connector-lab-client-secret",
                scope="alerts:read",
                http_client=http_client,
                expiration_margin_seconds=-1,
            )
