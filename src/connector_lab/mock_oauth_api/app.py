from typing import Annotated

from fastapi import Depends, FastAPI, Form
from fastapi.security import (
    HTTPBasic,
    HTTPBasicCredentials,
)

from connector_lab.mock_oauth_api.auth import (
    authenticate_client,
)
from connector_lab.mock_oauth_api.models import TokenResponse

ACCESS_TOKEN = "connector-lab-access-token"
TOKEN_EXPIRES_IN = 300

basic_auth = HTTPBasic(auto_error=False)

app = FastAPI(
    title="Mock OAuth 2.0 API",
    description="Educational OAuth 2.0 Authorization Server.",
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

    return TokenResponse(
        access_token=ACCESS_TOKEN,
        expires_in=TOKEN_EXPIRES_IN,
        scope=scope,
    )
