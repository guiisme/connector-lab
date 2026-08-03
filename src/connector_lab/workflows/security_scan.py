from collections.abc import Callable
from time import monotonic
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, Field

from connector_lab.client.errors import (
    ConnectorJobCancelledError,
    ConnectorJobFailedError,
    ConnectorJobTimeoutError,
)
from connector_lab.client.scan_models import (
    ScanJobCreateRequest,
    ScanJobCreateResponse,
    ScanJobResult,
    ScanJobStatus,
    ScanJobStatusResponse,
    ScanType,
)
from connector_lab.observability.events import (
    NullOperationalEventRecorder,
    OperationalEvent,
    OperationalEventOutcome,
    OperationalEventRecorder,
)
from connector_lab.observability.metrics import (
    ConnectorFailureCategory,
    ConnectorMetricObservation,
    ConnectorMetricOutcome,
    ConnectorMetricsRecorder,
    NullConnectorMetricsRecorder,
)

CorrelationIdProvider = Callable[[], str]
MonotonicProvider = Callable[[], float]


def new_correlation_id() -> str:
    return str(uuid4())


class SecurityJobs(Protocol):
    async def create_job(
        self,
        request: ScanJobCreateRequest,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobCreateResponse: ...

    async def wait_for_job(
        self,
        job_id: str,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobStatusResponse: ...


class SecurityScanCommand(BaseModel):
    operation_id: str = Field(min_length=1)
    target: str = Field(min_length=1)
    scan_type: ScanType
    simulate_failure: bool = False


class SecurityScanWorkflowResult(BaseModel):
    operation_id: str
    job_id: str
    status: ScanJobStatus
    result: ScanJobResult | None = None
    error: str | None = None
    created: bool


class SecurityScanWorkflow:
    def __init__(
        self,
        *,
        security_jobs: SecurityJobs,
        event_recorder: OperationalEventRecorder | None = None,
        correlation_id_provider: CorrelationIdProvider = (new_correlation_id),
        metrics_recorder: ConnectorMetricsRecorder | None = None,
        monotonic_provider: MonotonicProvider = monotonic,
    ) -> None:
        self._security_jobs = security_jobs
        self._event_recorder = (
            event_recorder
            if event_recorder is not None
            else NullOperationalEventRecorder()
        )
        self._correlation_id_provider = correlation_id_provider
        self._metrics_recorder = (
            metrics_recorder
            if metrics_recorder is not None
            else NullConnectorMetricsRecorder()
        )
        self._monotonic_provider = monotonic_provider
        self._correlation_ids: dict[str, str] = {}
        self._correlations: dict[str, str] = {}
        self._results: dict[
            str,
            SecurityScanWorkflowResult,
        ] = {}

    def _record_event(
        self,
        *,
        correlation_id: str,
        outcome: OperationalEventOutcome,
        operation: str = "process_scan",
        error_type: str | None = None,
    ) -> None:
        self._event_recorder.record(
            OperationalEvent(
                correlation_id=correlation_id,
                component="security_scan_workflow",
                operation=operation,
                outcome=outcome,
                error_type=error_type,
            ),
        )

    def _record_metric(
        self,
        *,
        correlation_id: str,
        started_at: float,
        outcome: ConnectorMetricOutcome,
        failure_category: (ConnectorFailureCategory | None) = None,
    ) -> None:
        self._metrics_recorder.record(
            ConnectorMetricObservation(
                correlation_id=correlation_id,
                component="security_scan_workflow",
                operation="process_scan",
                outcome=outcome,
                duration_seconds=(self._monotonic_provider() - started_at),
                failure_category=failure_category,
            ),
        )

    async def process(
        self,
        command: SecurityScanCommand,
    ) -> SecurityScanWorkflowResult:
        correlation_id = self._correlation_ids.get(
            command.operation_id,
        )

        if correlation_id is None:
            correlation_id = self._correlation_id_provider()
            self._correlation_ids[command.operation_id] = correlation_id

        workflow_started_at = self._monotonic_provider()

        self._record_event(
            correlation_id=correlation_id,
            outcome=OperationalEventOutcome.STARTED,
        )

        existing_result = self._results.get(
            command.operation_id,
        )

        if existing_result is not None:
            self._record_event(
                correlation_id=correlation_id,
                operation="reuse_scan_result",
                outcome=OperationalEventOutcome.SUCCEEDED,
            )
            self._record_event(
                correlation_id=correlation_id,
                outcome=OperationalEventOutcome.SUCCEEDED,
            )
            self._record_metric(
                correlation_id=correlation_id,
                started_at=workflow_started_at,
                outcome=ConnectorMetricOutcome.SUCCEEDED,
            )

            return existing_result.model_copy(
                update={"created": False},
            )

        job_id = self._correlations.get(
            command.operation_id,
        )
        created = False

        if job_id is None:
            request = ScanJobCreateRequest(
                external_reference=command.operation_id,
                target=command.target,
                scan_type=command.scan_type,
                simulate_failure=command.simulate_failure,
            )
            created_job = await self._security_jobs.create_job(
                request,
                correlation_id=correlation_id,
            )
            job_id = created_job.job_id
            self._correlations[command.operation_id] = job_id
            created = True

        event_outcome: OperationalEventOutcome
        error_type: str | None
        metric_outcome: ConnectorMetricOutcome
        failure_category: ConnectorFailureCategory | None

        try:
            completed_job = await self._security_jobs.wait_for_job(
                job_id,
                correlation_id=correlation_id,
            )
        except ConnectorJobFailedError as error:
            workflow_result = SecurityScanWorkflowResult(
                operation_id=command.operation_id,
                job_id=job_id,
                status=ScanJobStatus.FAILED,
                error=str(error),
                created=created,
            )
            event_outcome = OperationalEventOutcome.FAILED
            error_type = type(error).__name__
            metric_outcome = ConnectorMetricOutcome.FAILED
            failure_category = ConnectorFailureCategory.JOB_FAILED
        except ConnectorJobCancelledError as error:
            workflow_result = SecurityScanWorkflowResult(
                operation_id=command.operation_id,
                job_id=job_id,
                status=ScanJobStatus.CANCELLED,
                error=str(error),
                created=created,
            )
            event_outcome = OperationalEventOutcome.FAILED
            error_type = type(error).__name__
            metric_outcome = ConnectorMetricOutcome.FAILED
            failure_category = ConnectorFailureCategory.JOB_CANCELLED
        except ConnectorJobTimeoutError as error:
            self._record_event(
                correlation_id=correlation_id,
                outcome=OperationalEventOutcome.FAILED,
                error_type=type(error).__name__,
            )
            self._record_metric(
                correlation_id=correlation_id,
                started_at=workflow_started_at,
                outcome=ConnectorMetricOutcome.FAILED,
                failure_category=(ConnectorFailureCategory.JOB_TIMEOUT),
            )
            raise
        else:
            workflow_result = SecurityScanWorkflowResult(
                operation_id=command.operation_id,
                job_id=job_id,
                status=completed_job.status,
                result=completed_job.result,
                error=completed_job.error,
                created=created,
            )
            event_outcome = OperationalEventOutcome.SUCCEEDED
            error_type = None
            metric_outcome = ConnectorMetricOutcome.SUCCEEDED
            failure_category = None

        self._results[command.operation_id] = workflow_result

        self._record_event(
            correlation_id=correlation_id,
            outcome=event_outcome,
            error_type=error_type,
        )
        self._record_metric(
            correlation_id=correlation_id,
            started_at=workflow_started_at,
            outcome=metric_outcome,
            failure_category=failure_category,
        )

        return workflow_result
