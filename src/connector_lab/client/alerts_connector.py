from httpx import AsyncClient, HTTPStatusError

from connector_lab.client.errors import (
    ConnectorAuthenticationError,
    ConnectorPaginationError,
)
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
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._http_client = http_client
        if not 1 <= page_size <= 100:
            raise ValueError("page_size must be between 1 and 100")
        self._page_size = page_size

    async def list_alerts(self) -> AlertCollection:
        alerts: list[Alert] = []
        page_number = 1
        seen_alert_ids: set[str] = set()
        reported_total: int | None = None

        while True:
            response = await self._http_client.get(
                f"{self._base_url}/alerts",
                headers={"X-API-Key": self._api_key},
                params={
                    "page": page_number,
                    "page_size": self._page_size,
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
            if alert_page.page != page_number:
                raise ConnectorPaginationError(
                    "Unexpected page number",
                )

            if reported_total is None:
                reported_total = alert_page.total
            elif alert_page.total != reported_total:
                raise ConnectorPaginationError(
                    "Reported total changed between pages",
                )

            if alert_page.has_next and not alert_page.items:
                raise ConnectorPaginationError(
                    "Empty page cannot have a next page",
                )

            for alert in alert_page.items:
                if alert.id in seen_alert_ids:
                    raise ConnectorPaginationError(
                        "Duplicate alert received",
                    )

                seen_alert_ids.add(alert.id)
                alerts.append(alert)

            if alert_page.has_next and len(alerts) >= reported_total:
                raise ConnectorPaginationError(
                    "Next page exceeds reported total",
                )

            if not alert_page.has_next:
                break

            page_number += 1

        return AlertCollection(
            items=alerts,
            total=len(alerts),
        )
