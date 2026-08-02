from typing import Protocol

from pydantic import BaseModel, Field

from connector_lab.client.scan_models import (
    ScanJobCreateRequest,
    ScanJobCreateResponse,
    ScanJobResult,
    ScanJobStatus,
    ScanJobStatusResponse,
    ScanType,
)


class SecurityJobs(Protocol):
    async def create_job(
        self,
        request: ScanJobCreateRequest,
    ) -> ScanJobCreateResponse: ...

    async def wait_for_job(
        self,
        job_id: str,
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
    ) -> None:
        self._security_jobs = security_jobs
        self._correlations: dict[str, str] = {}
        self._results: dict[
            str,
            SecurityScanWorkflowResult,
        ] = {}

    async def process(
        self,
        command: SecurityScanCommand,
    ) -> SecurityScanWorkflowResult:
        existing_result = self._results.get(
            command.operation_id,
        )

        if existing_result is not None:
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
            )
            job_id = created_job.job_id
            self._correlations[command.operation_id] = job_id
            created = True

        completed_job = await self._security_jobs.wait_for_job(
            job_id,
        )
        workflow_result = SecurityScanWorkflowResult(
            operation_id=command.operation_id,
            job_id=job_id,
            status=completed_job.status,
            result=completed_job.result,
            error=completed_job.error,
            created=created,
        )
        self._results[command.operation_id] = workflow_result

        return workflow_result
