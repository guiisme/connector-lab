import pytest
from httpx import (
    ASGITransport,
    AsyncClient,
    BasicAuth,
)

from connector_lab.mock_oauth_api.app import app


@pytest.mark.asyncio
async def test_client_credentials_returns_access_token() -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "scope": "alerts:read",
            },
            auth=BasicAuth(
                username="connector-lab-client",
                password="connector-lab-client-secret",
            ),
        )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "connector-lab-access-token",
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "alerts:read",
    }
