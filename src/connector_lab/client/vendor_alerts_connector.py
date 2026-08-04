from json import JSONDecodeError

from httpx import (
    AsyncClient,
    ConnectError,
    HTTPStatusError,
    Response,
    TimeoutException,
)
from pydantic import ValidationError

from connector_lab.client.errors import (
    ConnectorAuthenticationError,
    ConnectorConnectionError,
    ConnectorMalformedResponseError,
    ConnectorPaginationError,
    ConnectorTimeoutError,
)
from connector_lab.client.vendor_alerts_models import (
    VendorDetection,
    VendorDetectionPage,
)

DEFAULT_VENDOR_PAGE_SIZE = 50


class VendorAlertsConnector:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        http_client: AsyncClient,
        page_size: int = DEFAULT_VENDOR_PAGE_SIZE,
    ) -> None:
        if page_size < 1 or page_size > 100:
            raise ValueError(
                "page_size must be between 1 and 100",
            )

        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._http_client = http_client
        self._page_size = page_size

    async def list_detection_page(
        self,
        *,
        cursor: str | None = None,
    ) -> VendorDetectionPage:
        params: dict[str, str | int] = {
            "limit": self._page_size,
        }

        if cursor is not None:
            params["cursor"] = cursor

        response = await self._send_request(
            params=params,
        )

        try:
            response_payload = response.json()
            return VendorDetectionPage.model_validate(
                response_payload,
            )
        except (
            JSONDecodeError,
            ValidationError,
        ) as error:
            raise ConnectorMalformedResponseError(
                "Vendor alerts response is malformed",
            ) from error

    async def list_all_detections(
        self,
    ) -> tuple[VendorDetection, ...]:
        detections: list[VendorDetection] = []
        seen_cursors: set[str] = set()
        cursor: str | None = None

        while True:
            page = await self.list_detection_page(
                cursor=cursor,
            )
            detections.extend(page.records)

            next_cursor = page.next_cursor

            if next_cursor is None:
                return tuple(detections)

            if next_cursor in seen_cursors:
                raise ConnectorPaginationError(
                    "Vendor alerts pagination repeated a cursor",
                )

            seen_cursors.add(next_cursor)
            cursor = next_cursor

    async def _send_request(
        self,
        *,
        params: dict[str, str | int],
    ) -> Response:
        try:
            response = await self._http_client.get(
                f"{self._base_url}/detections",
                headers={
                    "X-Vendor-API-Key": self._api_key,
                },
                params=params,
            )
        except TimeoutException as error:
            raise ConnectorTimeoutError(
                "Vendor alerts request timed out",
            ) from error
        except ConnectError as error:
            raise ConnectorConnectionError(
                "Vendor alerts endpoint is unavailable",
            ) from error

        try:
            response.raise_for_status()
        except HTTPStatusError as error:
            if error.response.status_code == 401:
                raise ConnectorAuthenticationError(
                    "Vendor alerts authentication failed",
                ) from error

            raise

        return response
