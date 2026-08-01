from httpx import AsyncClient, HTTPStatusError

from connector_lab.client.errors import ConnectorAuthenticationError
from connector_lab.client.models import (
    Alert,
    AlertCollection,
    AlertPage,
)

DEFAULT_PAGE_SIZE = 100


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
        alerts: list[Alert] = []
        page_number = 1

        while True:
            response = await self._http_client.get(
                f"{self._base_url}/alerts",
                headers={"X-API-Key": self._api_key},
                params={
                    "page": page_number,
                    "page_size": DEFAULT_PAGE_SIZE,
                },
            )

            try:
                response.raise_for_status()
            except HTTPStatusError as error:
                if error.response.status_code == 401:
                    raise ConnectorAuthenticationError(
                        "Connector authentication failed",
                    ) from error

                raise

            alert_page = AlertPage.model_validate(response.json())
            alerts.extend(alert_page.items)

            if not alert_page.has_next:
                break

            page_number += 1

        return AlertCollection(
            items=alerts,
            total=len(alerts),
        )
