from dataclasses import dataclass
from itertools import count
from typing import Annotated

from fastapi import Depends, FastAPI, status

from connector_lab.mock_scan_api.auth import require_api_key
from connector_lab.mock_scan_api.models import (
    ScanJobCreateRequest,
    ScanJobResponse,
    ScanJobStatus,
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

    return api


app = create_app()
