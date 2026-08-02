from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from httpx import (
    AsyncClient,
    BasicAuth,
    HTTPStatusError,
)

from connector_lab.client.errors import (
    ConnectorAuthenticationError,
    ConnectorAuthorizationError,
)
from connector_lab.client.oauth_models import (
    OAuthErrorResponse,
    OAuthToken,
)

NowProvider = Callable[[], datetime]
DEFAULT_EXPIRATION_MARGIN_SECONDS = 30


def utc_now() -> datetime:
    return datetime.now(UTC)


class OAuthTokenProvider:
    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str,
        http_client: AsyncClient,
        now_provider: NowProvider = utc_now,
        expiration_margin_seconds: int = (DEFAULT_EXPIRATION_MARGIN_SECONDS),
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._http_client = http_client
        self._now_provider = now_provider
        if expiration_margin_seconds < 0:
            raise ValueError(
                "expiration_margin_seconds must be zero or greater",
            )

        self._expiration_margin_seconds = expiration_margin_seconds
        self._cached_token: OAuthToken | None = None
        self._expires_at: datetime | None = None

    async def get_token(self) -> OAuthToken:
        current_time = self._now_provider()

        if (
            self._cached_token is not None
            and self._expires_at is not None
            and current_time < self._expires_at
        ):
            return self._cached_token

        response = await self._http_client.post(
            self._token_url,
            data={
                "grant_type": "client_credentials",
                "scope": self._scope,
            },
            auth=BasicAuth(
                username=self._client_id,
                password=self._client_secret,
            ),
        )

        try:
            response.raise_for_status()
        except HTTPStatusError as error:
            oauth_error = OAuthErrorResponse.model_validate(
                error.response.json(),
            )

            if oauth_error.error == "invalid_client":
                raise ConnectorAuthenticationError(
                    "OAuth client authentication failed",
                ) from error

            if oauth_error.error == "invalid_scope":
                raise ConnectorAuthorizationError(
                    "OAuth scope authorization failed",
                ) from error

            raise

        token = OAuthToken.model_validate(
            response.json(),
        )
        self._cached_token = token
        self._expires_at = current_time + timedelta(
            seconds=(token.expires_in - self._expiration_margin_seconds),
        )

        return token
