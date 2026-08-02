import pytest

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
