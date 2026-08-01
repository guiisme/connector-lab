from asyncio import sleep
from collections.abc import Awaitable, Callable

from httpx import (
    AsyncClient,
    ConnectError,
    HTTPStatusError,
    Response,
    TimeoutException,
)

from connector_lab.client.errors import (
    ConnectorAuthenticationError,
    ConnectorConnectionError,
    ConnectorPaginationError,
    ConnectorRateLimitError,
    ConnectorTimeoutError,
)
from connector_lab.client.models import (
    Alert,
    AlertCollection,
    AlertPage,
)

DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_RETRIES = 2
DEFAULT_BACKOFF_SECONDS = 1.0

SleepFunc = Callable[[float], Awaitable[None]]


class AlertsConnector:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        http_client: AsyncClient,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
        sleep_func: SleepFunc = sleep,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._http_client = http_client
        if not 1 <= page_size <= 100:
            raise ValueError("page_size must be between 1 and 100")
        self._page_size = page_size
        self._max_retries = max_retries
        self._backoff_seconds = backoff_seconds
        self._sleep_func = sleep_func

    async def list_alerts(self) -> AlertCollection:
        alerts: list[Alert] = []
        page_number = 1
        seen_alert_ids: set[str] = set()
        reported_total: int | None = None

        while True:
            response = await self._get_page_response(page_number)

            try:
                response.raise_for_status()
            except HTTPStatusError as error:
                if error.response.status_code == 401:
                    raise ConnectorAuthenticationError(
                        "Connector authentication failed",
                    ) from error

                if error.response.status_code == 429:
                    raise ConnectorRateLimitError(
                        "Connector rate limit retries exhausted",
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

    async def _get_page_response(
        self,
        page_number: int,
    ) -> Response:
        retry_number = 0

        while True:
            try:
                response = await self._http_client.get(
                    f"{self._base_url}/alerts",
                    headers={"X-API-Key": self._api_key},
                    params={
                        "page": page_number,
                        "page_size": self._page_size,
                    },
                )
            except TimeoutException as error:
                raise ConnectorTimeoutError(
                    "Connector request timed out",
                ) from error
            except ConnectError as error:
                raise ConnectorConnectionError(
                    "Connector could not reach the external API",
                ) from error

            if response.status_code != 429:
                return response

            if retry_number >= self._max_retries:
                return response

            delay = self._backoff_seconds * (2**retry_number)
            await self._sleep_func(delay)
            retry_number += 1
