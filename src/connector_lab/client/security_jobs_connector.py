from httpx import AsyncClient

from connector_lab.client.scan_models import (
    ScanJobCreateRequest,
    ScanJobCreateResponse,
    ScanJobStatusResponse,
)


class SecurityJobsConnector:
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

    async def create_job(
        self,
        request: ScanJobCreateRequest,
    ) -> ScanJobCreateResponse:
        response = await self._http_client.post(
            f"{self._base_url}/scan-jobs",
            headers={
                "X-API-Key": self._api_key,
            },
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()

        return ScanJobCreateResponse.model_validate(
            response.json(),
        )

    async def get_job(
        self,
        job_id: str,
    ) -> ScanJobStatusResponse:
        response = await self._http_client.get(
            f"{self._base_url}/scan-jobs/{job_id}",
            headers={
                "X-API-Key": self._api_key,
            },
        )
        response.raise_for_status()

        return ScanJobStatusResponse.model_validate(
            response.json(),
        )
