import pytest

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
from connector_lab.workflows.security_scan import (
    SecurityScanCommand,
    SecurityScanWorkflow,
)


class FakeSecurityJobs:
    def __init__(self) -> None:
        self.create_requests: list[ScanJobCreateRequest] = []
        self.waited_job_ids: list[str] = []

    async def create_job(
        self,
        request: ScanJobCreateRequest,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobCreateResponse:
        self.create_requests.append(request)

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
        self.waited_job_ids.append(job_id)

        return ScanJobStatusResponse(
            job_id=job_id,
            external_reference="operation-001",
            status=ScanJobStatus.COMPLETED,
            result=ScanJobResult(
                total_findings=3,
                critical_findings=1,
                high_findings=2,
            ),
        )


class TimeoutThenCompleteSecurityJobs(FakeSecurityJobs):
    def __init__(self) -> None:
        super().__init__()
        self.wait_attempts = 0

    async def wait_for_job(
        self,
        job_id: str,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobStatusResponse:
        self.waited_job_ids.append(job_id)
        self.wait_attempts += 1

        if self.wait_attempts == 1:
            raise ConnectorJobTimeoutError(
                "Security job polling timed out",
            )

        return ScanJobStatusResponse(
            job_id=job_id,
            external_reference="operation-timeout",
            status=ScanJobStatus.COMPLETED,
            result=ScanJobResult(
                total_findings=3,
                critical_findings=1,
                high_findings=2,
            ),
        )


class UnsuccessfulSecurityJobs(FakeSecurityJobs):
    def __init__(
        self,
        *,
        wait_error: Exception,
    ) -> None:
        super().__init__()
        self._wait_error = wait_error

    async def wait_for_job(
        self,
        job_id: str,
        *,
        correlation_id: str | None = None,
    ) -> ScanJobStatusResponse:
        self.waited_job_ids.append(job_id)
        raise self._wait_error


@pytest.mark.asyncio
async def test_new_operation_creates_and_awaits_scan_job() -> None:
    security_jobs = FakeSecurityJobs()
    workflow = SecurityScanWorkflow(
        security_jobs=security_jobs,
    )
    command = SecurityScanCommand(
        operation_id="operation-001",
        target="server.example.com",
        scan_type=ScanType.VULNERABILITY,
    )

    result = await workflow.process(command)

    assert len(security_jobs.create_requests) == 1

    request = security_jobs.create_requests[0]
    assert request.external_reference == "operation-001"
    assert request.target == "server.example.com"
    assert request.scan_type is ScanType.VULNERABILITY
    assert request.simulate_failure is False

    assert security_jobs.waited_job_ids == ["SCAN-0001"]

    assert result.operation_id == "operation-001"
    assert result.job_id == "SCAN-0001"
    assert result.status is ScanJobStatus.COMPLETED
    assert result.result is not None
    assert result.result.total_findings == 3
    assert result.created is True


@pytest.mark.asyncio
async def test_reprocessed_operation_returns_existing_result() -> None:
    security_jobs = FakeSecurityJobs()
    workflow = SecurityScanWorkflow(
        security_jobs=security_jobs,
    )
    command = SecurityScanCommand(
        operation_id="operation-001",
        target="server.example.com",
        scan_type=ScanType.VULNERABILITY,
    )

    first_result = await workflow.process(command)
    second_result = await workflow.process(command)

    assert len(security_jobs.create_requests) == 1
    assert security_jobs.waited_job_ids == ["SCAN-0001"]

    assert first_result.operation_id == second_result.operation_id
    assert first_result.job_id == second_result.job_id
    assert first_result.status is ScanJobStatus.COMPLETED
    assert second_result.status is ScanJobStatus.COMPLETED
    assert first_result.result == second_result.result
    assert first_result.created is True
    assert second_result.created is False


@pytest.mark.asyncio
async def test_timed_out_operation_resumes_existing_job() -> None:
    security_jobs = TimeoutThenCompleteSecurityJobs()
    workflow = SecurityScanWorkflow(
        security_jobs=security_jobs,
    )
    command = SecurityScanCommand(
        operation_id="operation-timeout",
        target="slow-server.example.com",
        scan_type=ScanType.VULNERABILITY,
    )

    with pytest.raises(
        ConnectorJobTimeoutError,
        match="Security job polling timed out",
    ):
        await workflow.process(command)

    result = await workflow.process(command)

    assert len(security_jobs.create_requests) == 1
    assert security_jobs.waited_job_ids == [
        "SCAN-0001",
        "SCAN-0001",
    ]
    assert result.operation_id == "operation-timeout"
    assert result.job_id == "SCAN-0001"
    assert result.status is ScanJobStatus.COMPLETED
    assert result.result is not None
    assert result.result.total_findings == 3
    assert result.created is False


@pytest.mark.parametrize(
    (
        "wait_error",
        "expected_status",
        "expected_error",
    ),
    [
        (
            ConnectorJobFailedError(
                "Security job failed: Simulated scan failure",
            ),
            ScanJobStatus.FAILED,
            "Security job failed: Simulated scan failure",
        ),
        (
            ConnectorJobCancelledError(
                "Security job was cancelled",
            ),
            ScanJobStatus.CANCELLED,
            "Security job was cancelled",
        ),
    ],
)
@pytest.mark.asyncio
async def test_unsuccessful_operation_returns_cached_typed_result(
    wait_error: Exception,
    expected_status: ScanJobStatus,
    expected_error: str,
) -> None:
    security_jobs = UnsuccessfulSecurityJobs(
        wait_error=wait_error,
    )
    workflow = SecurityScanWorkflow(
        security_jobs=security_jobs,
    )
    command = SecurityScanCommand(
        operation_id="operation-unsuccessful",
        target="server.example.com",
        scan_type=ScanType.VULNERABILITY,
    )

    first_result = await workflow.process(command)
    second_result = await workflow.process(command)

    assert len(security_jobs.create_requests) == 1
    assert security_jobs.waited_job_ids == ["SCAN-0001"]

    assert first_result.operation_id == "operation-unsuccessful"
    assert first_result.job_id == "SCAN-0001"
    assert first_result.status is expected_status
    assert first_result.result is None
    assert first_result.error == expected_error
    assert first_result.created is True

    assert second_result == first_result.model_copy(
        update={"created": False},
    )


@pytest.mark.asyncio
async def test_scan_command_maps_failure_simulation_to_job_request() -> None:
    security_jobs = FakeSecurityJobs()
    workflow = SecurityScanWorkflow(
        security_jobs=security_jobs,
    )
    command = SecurityScanCommand(
        operation_id="operation-simulated-failure",
        target="legacy-server.example.com",
        scan_type=ScanType.VULNERABILITY,
        simulate_failure=True,
    )

    await workflow.process(command)

    assert len(security_jobs.create_requests) == 1

    request = security_jobs.create_requests[0]
    assert request.external_reference == ("operation-simulated-failure")
    assert request.target == "legacy-server.example.com"
    assert request.scan_type is ScanType.VULNERABILITY
    assert request.simulate_failure is True
