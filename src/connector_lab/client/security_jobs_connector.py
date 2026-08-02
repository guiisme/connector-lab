from asyncio import sleep
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import uuid4

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
from connector_lab.observability.events import (
    NullOperationalEventRecorder,
    OperationalEvent,
    OperationalEventOutcome,
    OperationalEventRecorder,
)

DEFAULT_POLL_INTERVAL_SECONDS = 1.0
DEFAULT_POLL_TIMEOUT_SECONDS = 60.0

SleepFunc = Callable[
    [float],
    Awaitable[None],
]
NowProvider = Callable[[], datetime]
CorrelationIdProvider = Callable[[], str]


def new_correlation_id() -> str:
    return str(uuid4())


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
        event_recorder: OperationalEventRecorder | None = None,
        correlation_id_provider: CorrelationIdProvider = (new_correlation_id),
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
        self._event_recorder = (
            event_recorder
            if event_recorder is not None
            else NullOperationalEventRecorder()
        )
        self._correlation_id_provider = correlation_id_provider

    def _record_operational_event(
        self,
        *,
        correlation_id: str,
        operation: str,
        outcome: OperationalEventOutcome,
        error_type: str | None = None,
    ) -> None:
        self._event_recorder.record(
            OperationalEvent(
                correlation_id=correlation_id,
                component="security_jobs_connector",
                operation=operation,
                outcome=outcome,
                error_type=error_type,
            ),
        )

    async def create_job(
        self,
        request: ScanJobCreateRequest,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobCreateResponse:
        resolved_correlation_id = correlation_id or self._correlation_id_provider()
        self._event_recorder.record(
            OperationalEvent(
                correlation_id=resolved_correlation_id,
                component="security_jobs_connector",
                operation="create_job",
                outcome=OperationalEventOutcome.STARTED,
            ),
        )

        try:
            response = await self._send_request(
                method="POST",
                url=f"{self._base_url}/scan-jobs",
                json_payload=request.model_dump(mode="json"),
            )
            created_job = ScanJobCreateResponse.model_validate(
                response.json(),
            )
        except Exception as error:
            self._event_recorder.record(
                OperationalEvent(
                    correlation_id=resolved_correlation_id,
                    component="security_jobs_connector",
                    operation="create_job",
                    outcome=OperationalEventOutcome.FAILED,
                    error_type=type(error).__name__,
                ),
            )
            raise

        self._event_recorder.record(
            OperationalEvent(
                correlation_id=resolved_correlation_id,
                component="security_jobs_connector",
                operation="create_job",
                outcome=OperationalEventOutcome.SUCCEEDED,
            ),
        )

        return created_job

    async def get_job(
        self,
        job_id: str,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobStatusResponse:
        resolved_correlation_id = correlation_id or self._correlation_id_provider()
        self._record_operational_event(
            correlation_id=resolved_correlation_id,
            operation="get_job",
            outcome=OperationalEventOutcome.STARTED,
        )

        try:
            response = await self._send_request(
                method="GET",
                url=f"{self._base_url}/scan-jobs/{job_id}",
            )
            job = ScanJobStatusResponse.model_validate(
                response.json(),
            )
        except Exception as error:
            self._record_operational_event(
                correlation_id=resolved_correlation_id,
                operation="get_job",
                outcome=OperationalEventOutcome.FAILED,
                error_type=type(error).__name__,
            )
            raise

        self._record_operational_event(
            correlation_id=resolved_correlation_id,
            operation="get_job",
            outcome=OperationalEventOutcome.SUCCEEDED,
        )

        return job

    async def wait_for_job(
        self,
        job_id: str,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobStatusResponse:
        resolved_correlation_id = correlation_id or self._correlation_id_provider()
        started_at = self._now_provider()

        while True:
            elapsed_seconds = (self._now_provider() - started_at).total_seconds()

            if elapsed_seconds >= self._poll_timeout_seconds:
                raise ConnectorJobTimeoutError(
                    "Security job polling timed out",
                )

            job = await self.get_job(
                job_id,
                correlation_id=resolved_correlation_id,
            )

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
        *,
        correlation_id: str | None = None,
    ) -> ScanJobStatusResponse:
        resolved_correlation_id = correlation_id or self._correlation_id_provider()
        self._record_operational_event(
            correlation_id=resolved_correlation_id,
            operation="cancel_job",
            outcome=OperationalEventOutcome.STARTED,
        )

        try:
            response = await self._send_request(
                method="DELETE",
                url=f"{self._base_url}/scan-jobs/{job_id}",
            )
            job = ScanJobStatusResponse.model_validate(
                response.json(),
            )
        except Exception as error:
            self._record_operational_event(
                correlation_id=resolved_correlation_id,
                operation="cancel_job",
                outcome=OperationalEventOutcome.FAILED,
                error_type=type(error).__name__,
            )
            raise

        self._record_operational_event(
            correlation_id=resolved_correlation_id,
            operation="cancel_job",
            outcome=OperationalEventOutcome.SUCCEEDED,
        )

        return job

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

    async def create_and_wait(
        self,
        request: ScanJobCreateRequest,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobStatusResponse:
        resolved_correlation_id = correlation_id or self._correlation_id_provider()
        created_job = await self.create_job(
            request,
            correlation_id=resolved_correlation_id,
        )

        return await self.wait_for_job(
            created_job.job_id,
            correlation_id=resolved_correlation_id,
        )
