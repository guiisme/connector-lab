from asyncio import sleep
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

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
    ConnectorJobCancelledError,
    ConnectorJobFailedError,
    ConnectorJobTimeoutError,
    ConnectorTimeoutError,
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
        response = await self._send_request(
            method="POST",
            url=f"{self._base_url}/scan-jobs",
            json_payload=request.model_dump(mode="json"),
        )

        return ScanJobCreateResponse.model_validate(
            response.json(),
        )

    async def get_job(
        self,
        job_id: str,
    ) -> ScanJobStatusResponse:
        response = await self._send_request(
            method="GET",
            url=f"{self._base_url}/scan-jobs/{job_id}",
        )

        return ScanJobStatusResponse.model_validate(
            response.json(),
        )

    async def wait_for_job(
        self,
        job_id: str,
    ) -> ScanJobStatusResponse:
        started_at = self._now_provider()

        while True:
            elapsed_seconds = (self._now_provider() - started_at).total_seconds()

            if elapsed_seconds >= self._poll_timeout_seconds:
                raise ConnectorJobTimeoutError(
                    "Security job polling timed out",
                )

            job = await self.get_job(job_id)

            if job.status is ScanJobStatus.COMPLETED:
                return job

            if job.status is ScanJobStatus.FAILED:
                failure_detail = job.error or "Unknown security job failure"
                raise ConnectorJobFailedError(
                    f"Security job failed: {failure_detail}",
                )

            if job.status is ScanJobStatus.CANCELLED:
                raise ConnectorJobCancelledError(
                    "Security job was cancelled",
                )

            await self._sleep_func(
                self._poll_interval_seconds,
            )

    async def cancel_job(
        self,
        job_id: str,
    ) -> ScanJobStatusResponse:
        response = await self._send_request(
            method="DELETE",
            url=f"{self._base_url}/scan-jobs/{job_id}",
        )

        return ScanJobStatusResponse.model_validate(
            response.json(),
        )

    async def _send_request(
        self,
        *,
        method: str,
        url: str,
        json_payload: object | None = None,
    ) -> Response:
        headers = {
            "X-API-Key": self._api_key,
        }

        try:
            if json_payload is None:
                response = await self._http_client.request(
                    method,
                    url,
                    headers=headers,
                )
            else:
                response = await self._http_client.request(
                    method,
                    url,
                    headers=headers,
                    json=json_payload,
                )
        except TimeoutException as error:
            raise ConnectorTimeoutError(
                "Security jobs request timed out",
            ) from error
        except ConnectError as error:
            raise ConnectorConnectionError(
                "Security jobs endpoint is unavailable",
            ) from error

        try:
            response.raise_for_status()
        except HTTPStatusError as error:
            if error.response.status_code == 401:
                raise ConnectorAuthenticationError(
                    "Security jobs authentication failed",
                ) from error

            raise

        return response
