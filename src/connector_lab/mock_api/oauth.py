import secrets
from collections.abc import Callable
from datetime import datetime
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from connector_lab.oauth_config import ACCESS_TOKEN

NowProvider = Callable[[], datetime]
BearerTokenDependency = Callable[
    [HTTPAuthorizationCredentials | None],
    None,
]

bearer_auth = HTTPBearer(auto_error=False)


def create_bearer_token_dependency(
    *,
    expires_at: datetime,
    now_provider: NowProvider,
    token_scopes: frozenset[str],
    required_scope: str,
) -> BearerTokenDependency:
    def require_bearer_token(
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(bearer_auth),
        ],
    ) -> None:
        if credentials is None or not secrets.compare_digest(
            credentials.credentials,
            ACCESS_TOKEN,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid access token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if now_provider() >= expires_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access token expired",
                headers={
                    "WWW-Authenticate": ('Bearer error="invalid_token"'),
                },
            )

        if required_scope not in token_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient access token scope",
                headers={
                    "WWW-Authenticate": (
                        f'Bearer error="insufficient_scope", scope="{required_scope}"'
                    ),
                },
            )

    return require_bearer_token
