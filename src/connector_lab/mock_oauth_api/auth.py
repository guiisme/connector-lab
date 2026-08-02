import secrets

from fastapi import status
from fastapi.security import HTTPBasicCredentials

from connector_lab.mock_oauth_api.errors import OAuthError

CLIENT_ID = "connector-lab-client"
CLIENT_SECRET = "connector-lab-client-secret"


def authenticate_client(
    credentials: HTTPBasicCredentials | None,
) -> None:
    if credentials is None:
        raise OAuthError(
            error="invalid_client",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Basic"},
        )

    valid_client_id = secrets.compare_digest(
        credentials.username,
        CLIENT_ID,
    )
    valid_client_secret = secrets.compare_digest(
        credentials.password,
        CLIENT_SECRET,
    )

    if not valid_client_id or not valid_client_secret:
        raise OAuthError(
            error="invalid_client",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Basic"},
        )
