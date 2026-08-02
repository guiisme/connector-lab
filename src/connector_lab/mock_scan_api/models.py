from enum import StrEnum

from pydantic import BaseModel, Field


class ScanType(StrEnum):
    VULNERABILITY = "vulnerability"


class ScanJobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanJobCreateRequest(BaseModel):
    external_reference: str = Field(min_length=1)
    target: str = Field(min_length=1)
    scan_type: ScanType
    simulate_failure: bool = False


class ScanJobResponse(BaseModel):
    job_id: str
    external_reference: str
    status: ScanJobStatus


class ScanJobResult(BaseModel):
    total_findings: int
    critical_findings: int
    high_findings: int


class ScanJobStatusResponse(ScanJobResponse):
    result: ScanJobResult | None = None
    error: str | None = None
