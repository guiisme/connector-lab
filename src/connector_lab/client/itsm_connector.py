from httpx import (
    AsyncClient,
    ConnectError,
    HTTPStatusError,
    TimeoutException,
)

from connector_lab.client.errors import (
    ConnectorAuthenticationError,
    ConnectorConnectionError,
    ConnectorTimeoutError,
)
from connector_lab.client.itsm_models import (
    IncidentCreateRequest,
    IncidentCreateResponse,
)


class ITSMConnector:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        http_client: AsyncClient,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._http_client = http_client

    async def create_incident(
        self,
        request: IncidentCreateRequest,
    ) -> IncidentCreateResponse:
        try:
            response = await self._http_client.post(
                f"{self._base_url}/incidents",
                headers={"X-API-Key": self._api_key},
                json=request.model_dump(mode="json"),
            )
        except TimeoutException as error:
            raise ConnectorTimeoutError(
                "Connector request timed out",
            ) from error
        except ConnectError as error:
            raise ConnectorConnectionError(
                "Connector could not reach the external API",
            ) from error

        try:
            response.raise_for_status()
        except HTTPStatusError as error:
            if error.response.status_code == 401:
                raise ConnectorAuthenticationError(
                    "Connector authentication failed",
                ) from error

            raise

        return IncidentCreateResponse.model_validate(
            response.json(),
        )
