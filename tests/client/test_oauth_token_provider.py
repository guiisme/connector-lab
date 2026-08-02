from base64 import b64encode
from urllib.parse import parse_qs

import pytest
from httpx import (
    AsyncClient,
    MockTransport,
    Request,
    Response,
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
