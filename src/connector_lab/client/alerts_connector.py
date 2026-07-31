from httpx import AsyncClient

from connector_lab.client.models import AlertCollection


class AlertsConnector:
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

    async def list_alerts(self) -> AlertCollection:
        response = await self._http_client.get(
            f"{self._base_url}/alerts",
            headers={"X-API-Key": self._api_key},
        )
        response.raise_for_status()

        return AlertCollection.model_validate(response.json())
