from httpx import AsyncClient, BasicAuth

from connector_lab.client.oauth_models import OAuthToken


class OAuthTokenProvider:
    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str,
        http_client: AsyncClient,
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._http_client = http_client

    async def get_token(self) -> OAuthToken:
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

        return OAuthToken.model_validate(
            response.json(),
        )
