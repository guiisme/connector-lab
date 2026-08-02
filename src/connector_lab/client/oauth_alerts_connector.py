from typing import Protocol

from httpx import (
    AsyncClient,
    ConnectError,
    HTTPStatusError,
    Response,
    TimeoutException,
)

from connector_lab.client.errors import (
    ConnectorAuthenticationError,
    ConnectorAuthorizationError,
    ConnectorConnectionError,
    ConnectorPaginationError,
    ConnectorTimeoutError,
)
from connector_lab.client.models import (
    Alert,
    AlertCollection,
    AlertPage,
)
from connector_lab.client.oauth_models import OAuthToken

DEFAULT_PAGE_SIZE = 100


class TokenProvider(Protocol):
    async def get_token(self) -> OAuthToken: ...


class OAuthAlertsConnector:
    def __init__(
        self,
        *,
        base_url: str,
        token_provider: TokenProvider,
        http_client: AsyncClient,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> None:
        if not 1 <= page_size <= 100:
            raise ValueError(
                "page_size must be between 1 and 100",
            )

        self._base_url = base_url.rstrip("/")
        self._token_provider = token_provider
        self._http_client = http_client
        self._page_size = page_size

    async def list_alerts(self) -> AlertCollection:
        alerts: list[Alert] = []
        page_number = 1
        seen_alert_ids: set[str] = set()
        reported_total: int | None = None

        while True:
            response = await self._get_page_response(
                page_number,
            )

            try:
                response.raise_for_status()
            except HTTPStatusError as error:
                if error.response.status_code == 401:
                    raise ConnectorAuthenticationError(
                        "OAuth access token was rejected",
                    ) from error

                if error.response.status_code == 403:
                    raise ConnectorAuthorizationError(
                        "OAuth access token lacks required scope",
                    ) from error

                raise

            alert_page = AlertPage.model_validate(
                response.json(),
            )

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
        token = await self._token_provider.get_token()

        try:
            return await self._http_client.get(
                f"{self._base_url}/oauth/alerts",
                headers={
                    "Authorization": (f"{token.token_type} {token.access_token}"),
                },
                params={
                    "page": page_number,
                    "page_size": self._page_size,
                },
            )
        except TimeoutException as error:
            raise ConnectorTimeoutError(
                "OAuth alerts request timed out",
            ) from error
        except ConnectError as error:
            raise ConnectorConnectionError(
                "OAuth alerts endpoint is unavailable",
            ) from error
