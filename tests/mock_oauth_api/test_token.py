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


@pytest.mark.asyncio
async def test_missing_client_credentials_returns_invalid_client() -> None:
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
        )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Basic"
    assert response.json() == {
        "error": "invalid_client",
    }


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("invalid-client", "connector-lab-client-secret"),
        ("connector-lab-client", "invalid-secret"),
    ],
)
@pytest.mark.asyncio
async def test_invalid_client_credentials_are_rejected(
    username: str,
    password: str,
) -> None:
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
                username=username,
                password=password,
            ),
        )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Basic"
    assert response.json() == {
        "error": "invalid_client",
    }


@pytest.mark.asyncio
async def test_unsupported_grant_type_is_rejected() -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "scope": "alerts:read",
            },
            auth=BasicAuth(
                username="connector-lab-client",
                password="connector-lab-client-secret",
            ),
        )

    assert response.status_code == 400
    assert response.json() == {
        "error": "unsupported_grant_type",
    }


@pytest.mark.asyncio
async def test_unsupported_scope_is_rejected() -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "scope": "alerts:write",
            },
            auth=BasicAuth(
                username="connector-lab-client",
                password="connector-lab-client-secret",
            ),
        )

    assert response.status_code == 400
    assert response.json() == {
        "error": "invalid_scope",
    }
