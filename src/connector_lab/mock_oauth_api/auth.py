import secrets

from fastapi import HTTPException, status
from fastapi.security import HTTPBasicCredentials

CLIENT_ID = "connector-lab-client"
CLIENT_SECRET = "connector-lab-client-secret"


def authenticate_client(
    credentials: HTTPBasicCredentials | None,
) -> None:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_client",
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_client",
            headers={"WWW-Authenticate": "Basic"},
        )
