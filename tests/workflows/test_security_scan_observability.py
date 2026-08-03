import pytest

from connector_lab.client.scan_models import (
    ScanJobCreateRequest,
    ScanJobCreateResponse,
    ScanJobResult,
    ScanJobStatus,
    ScanJobStatusResponse,
    ScanType,
)
from connector_lab.observability.events import (
    OperationalEvent,
    OperationalEventOutcome,
)
from connector_lab.workflows.security_scan import (
    SecurityScanCommand,
    SecurityScanWorkflow,
)


class RecordingEventRecorder:
    def __init__(self) -> None:
        self.events: list[OperationalEvent] = []

    def record(self, event: OperationalEvent) -> None:
        self.events.append(event)


class CorrelatedSecurityJobs:
    def __init__(self) -> None:
        self.create_correlation_ids: list[str] = []
        self.wait_correlation_ids: list[str] = []

    async def create_job(
        self,
        request: ScanJobCreateRequest,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobCreateResponse:
        assert correlation_id is not None
        self.create_correlation_ids.append(correlation_id)

        return ScanJobCreateResponse(
            job_id="SCAN-0001",
            external_reference=request.external_reference,
            status=ScanJobStatus.PENDING,
        )

    async def wait_for_job(
        self,
        job_id: str,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobStatusResponse:
        assert correlation_id is not None
        self.wait_correlation_ids.append(correlation_id)

        return ScanJobStatusResponse(
            job_id=job_id,
            external_reference="operation-observed",
            status=ScanJobStatus.COMPLETED,
            result=ScanJobResult(
                total_findings=3,
                critical_findings=1,
                high_findings=2,
            ),
        )


@pytest.mark.asyncio
async def test_workflow_propagates_one_correlation_id_to_connector() -> None:
    security_jobs = CorrelatedSecurityJobs()
    recorder = RecordingEventRecorder()
    workflow = SecurityScanWorkflow(
        security_jobs=security_jobs,
        event_recorder=recorder,
        correlation_id_provider=lambda: "scan-correlation-001",
    )

    result = await workflow.process(
        SecurityScanCommand(
            operation_id="operation-observed",
            target="server.example.com",
            scan_type=ScanType.VULNERABILITY,
        ),
    )

    assert result.status is ScanJobStatus.COMPLETED
    assert security_jobs.create_correlation_ids == [
        "scan-correlation-001",
    ]
    assert security_jobs.wait_correlation_ids == [
        "scan-correlation-001",
    ]
    assert recorder.events == [
        OperationalEvent(
            correlation_id="scan-correlation-001",
            component="security_scan_workflow",
            operation="process_scan",
            outcome=OperationalEventOutcome.STARTED,
        ),
        OperationalEvent(
            correlation_id="scan-correlation-001",
            component="security_scan_workflow",
            operation="process_scan",
            outcome=OperationalEventOutcome.SUCCEEDED,
        ),
    ]


@pytest.mark.asyncio
async def test_reprocessed_scan_preserves_correlation_and_records_reuse() -> None:
    generated_correlation_ids: list[str] = []

    def provide_correlation_id() -> str:
        correlation_id = "scan-correlation-reused"
        generated_correlation_ids.append(correlation_id)
        return correlation_id

    security_jobs = CorrelatedSecurityJobs()
    recorder = RecordingEventRecorder()
    workflow = SecurityScanWorkflow(
        security_jobs=security_jobs,
        event_recorder=recorder,
        correlation_id_provider=provide_correlation_id,
    )
    command = SecurityScanCommand(
        operation_id="operation-reused",
        target="server.example.com",
        scan_type=ScanType.VULNERABILITY,
    )

    first_result = await workflow.process(command)
    second_result = await workflow.process(command)

    assert generated_correlation_ids == [
        "scan-correlation-reused",
    ]
    assert security_jobs.create_correlation_ids == [
        "scan-correlation-reused",
    ]
    assert security_jobs.wait_correlation_ids == [
        "scan-correlation-reused",
    ]

    assert first_result.created is True
    assert second_result.created is False
    assert second_result.job_id == first_result.job_id
    assert second_result.status is ScanJobStatus.COMPLETED

    assert recorder.events == [
        OperationalEvent(
            correlation_id="scan-correlation-reused",
            component="security_scan_workflow",
            operation="process_scan",
            outcome=OperationalEventOutcome.STARTED,
        ),
        OperationalEvent(
            correlation_id="scan-correlation-reused",
            component="security_scan_workflow",
            operation="process_scan",
            outcome=OperationalEventOutcome.SUCCEEDED,
        ),
        OperationalEvent(
            correlation_id="scan-correlation-reused",
            component="security_scan_workflow",
            operation="process_scan",
            outcome=OperationalEventOutcome.STARTED,
        ),
        OperationalEvent(
            correlation_id="scan-correlation-reused",
            component="security_scan_workflow",
            operation="reuse_scan_result",
            outcome=OperationalEventOutcome.SUCCEEDED,
        ),
        OperationalEvent(
            correlation_id="scan-correlation-reused",
            component="security_scan_workflow",
            operation="process_scan",
            outcome=OperationalEventOutcome.SUCCEEDED,
        ),
    ]
