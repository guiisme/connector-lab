from httpx import AsyncClient

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
        response = await self._http_client.post(
            f"{self._base_url}/incidents",
            headers={"X-API-Key": self._api_key},
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()

        return IncidentCreateResponse.model_validate(
            response.json(),
        )
