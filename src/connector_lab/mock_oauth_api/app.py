from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    Form,
    Request,
    status,
)
from fastapi.responses import JSONResponse
from fastapi.security import (
    HTTPBasic,
    HTTPBasicCredentials,
)

from connector_lab.mock_oauth_api.auth import (
    authenticate_client,
)
from connector_lab.mock_oauth_api.errors import OAuthError
from connector_lab.mock_oauth_api.models import TokenResponse

ACCESS_TOKEN = "connector-lab-access-token"
TOKEN_EXPIRES_IN = 300
ALLOWED_SCOPES = {"alerts:read"}

basic_auth = HTTPBasic(auto_error=False)

app = FastAPI(
    title="Mock OAuth 2.0 API",
    description="Educational OAuth 2.0 Authorization Server.",
)


@app.exception_handler(OAuthError)
async def handle_oauth_error(
    _request: Request,
    error: OAuthError,
) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={"error": error.error},
        headers=error.headers,
    )


@app.post(
    "/oauth/token",
    response_model=TokenResponse,
)
async def issue_access_token(
    credentials: Annotated[
        HTTPBasicCredentials | None,
        Depends(basic_auth),
    ],
    grant_type: Annotated[str, Form()],
    scope: Annotated[str, Form()] = "",
) -> TokenResponse:
    authenticate_client(credentials)

    if grant_type != "client_credentials":
        raise OAuthError(
            error="unsupported_grant_type",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    requested_scopes = set(scope.split())

    if not requested_scopes.issubset(ALLOWED_SCOPES):
        raise OAuthError(
            error="invalid_scope",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return TokenResponse(
        access_token=ACCESS_TOKEN,
        expires_in=TOKEN_EXPIRES_IN,
        scope=scope,
    )
