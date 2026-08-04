from httpx import AsyncClient

from connector_lab.client.vendor_alerts_models import (
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

        response = await self._http_client.get(
            f"{self._base_url}/detections",
            headers={
                "X-Vendor-API-Key": self._api_key,
            },
            params=params,
        )
        response.raise_for_status()

        return VendorDetectionPage.model_validate(
            response.json(),
        )
