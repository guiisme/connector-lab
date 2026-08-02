from dataclasses import dataclass
from itertools import count
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    status,
)

from connector_lab.mock_scan_api.auth import require_api_key
from connector_lab.mock_scan_api.models import (
    ScanJobCreateRequest,
    ScanJobResponse,
    ScanJobResult,
    ScanJobStatus,
    ScanJobStatusResponse,
)


@dataclass
class StoredScanJob:
    request: ScanJobCreateRequest
    status: ScanJobStatus
    status_requests: int = 0


def create_app() -> FastAPI:
    api = FastAPI(
        title="Mock Security Scan API",
        description=("Educational API for asynchronous security jobs."),
    )
    job_sequence = count(1)
    jobs: dict[str, StoredScanJob] = {}

    @api.post(
        "/scan-jobs",
        response_model=ScanJobResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def create_scan_job(
        request: ScanJobCreateRequest,
        _: Annotated[None, Depends(require_api_key)],
    ) -> ScanJobResponse:
        job_id = f"SCAN-{next(job_sequence):04}"
        jobs[job_id] = StoredScanJob(
            request=request,
            status=ScanJobStatus.PENDING,
        )

        return ScanJobResponse(
            job_id=job_id,
            external_reference=request.external_reference,
            status=ScanJobStatus.PENDING,
        )

    @api.get(
        "/scan-jobs/{job_id}",
        response_model=ScanJobStatusResponse,
        response_model_exclude_none=True,
    )
    def get_scan_job(
        job_id: str,
        _: Annotated[None, Depends(require_api_key)],
    ) -> ScanJobStatusResponse:
        job = jobs.get(job_id)

        if job is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan job not found",
            )

        if job.status is ScanJobStatus.PENDING:
            job.status = ScanJobStatus.RUNNING
            job.status_requests += 1
        elif job.status is ScanJobStatus.RUNNING:
            job.status = ScanJobStatus.COMPLETED
            job.status_requests += 1

        result: ScanJobResult | None = None

        if job.status is ScanJobStatus.COMPLETED:
            result = ScanJobResult(
                total_findings=3,
                critical_findings=1,
                high_findings=2,
            )

        return ScanJobStatusResponse(
            job_id=job_id,
            external_reference=(job.request.external_reference),
            status=job.status,
            result=result,
        )

    return api


app = create_app()
