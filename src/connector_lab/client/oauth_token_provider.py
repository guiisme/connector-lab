from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient, BasicAuth

from connector_lab.client.oauth_models import OAuthToken

NowProvider = Callable[[], datetime]


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
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._http_client = http_client
        self._now_provider = now_provider
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
        response.raise_for_status()

        token = OAuthToken.model_validate(
            response.json(),
        )
        self._cached_token = token
        self._expires_at = current_time + timedelta(
            seconds=token.expires_in,
        )

        return token
