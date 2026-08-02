from asyncio import sleep
from collections.abc import Awaitable, Callable

from httpx import AsyncClient

from connector_lab.client.scan_models import (
    ScanJobCreateRequest,
    ScanJobCreateResponse,
    ScanJobStatus,
    ScanJobStatusResponse,
)

DEFAULT_POLL_INTERVAL_SECONDS = 1.0

SleepFunc = Callable[
    [float],
    Awaitable[None],
]


class SecurityJobsConnector:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        http_client: AsyncClient,
        poll_interval_seconds: float = (DEFAULT_POLL_INTERVAL_SECONDS),
        sleep_func: SleepFunc = sleep,
    ) -> None:
        if poll_interval_seconds < 0:
            raise ValueError(
                "poll_interval_seconds must be zero or greater",
            )

        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._http_client = http_client
        self._poll_interval_seconds = poll_interval_seconds
        self._sleep_func = sleep_func

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

    async def wait_for_job(
        self,
        job_id: str,
    ) -> ScanJobStatusResponse:
        terminal_statuses = {
            ScanJobStatus.COMPLETED,
            ScanJobStatus.FAILED,
            ScanJobStatus.CANCELLED,
        }

        while True:
            job = await self.get_job(job_id)

            if job.status in terminal_statuses:
                return job

            await self._sleep_func(
                self._poll_interval_seconds,
            )
