from asyncio import sleep
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from httpx import AsyncClient

from connector_lab.client.errors import (
    ConnectorJobTimeoutError,
)
from connector_lab.client.scan_models import (
    ScanJobCreateRequest,
    ScanJobCreateResponse,
    ScanJobStatus,
    ScanJobStatusResponse,
)

DEFAULT_POLL_INTERVAL_SECONDS = 1.0
DEFAULT_POLL_TIMEOUT_SECONDS = 60.0

SleepFunc = Callable[
    [float],
    Awaitable[None],
]
NowProvider = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


class SecurityJobsConnector:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        http_client: AsyncClient,
        poll_interval_seconds: float = (DEFAULT_POLL_INTERVAL_SECONDS),
        poll_timeout_seconds: float = (DEFAULT_POLL_TIMEOUT_SECONDS),
        sleep_func: SleepFunc = sleep,
        now_provider: NowProvider = utc_now,
    ) -> None:
        if poll_interval_seconds < 0:
            raise ValueError(
                "poll_interval_seconds must be zero or greater",
            )

        if poll_timeout_seconds < 0:
            raise ValueError(
                "poll_timeout_seconds must be zero or greater",
            )

        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._http_client = http_client
        self._poll_interval_seconds = poll_interval_seconds
        self._poll_timeout_seconds = poll_timeout_seconds
        self._sleep_func = sleep_func
        self._now_provider = now_provider

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
        started_at = self._now_provider()

        while True:
            elapsed_seconds = (self._now_provider() - started_at).total_seconds()

            if elapsed_seconds >= self._poll_timeout_seconds:
                raise ConnectorJobTimeoutError(
                    "Security job polling timed out",
                )

            job = await self.get_job(job_id)

            if job.status in terminal_statuses:
                return job

            await self._sleep_func(
                self._poll_interval_seconds,
            )
