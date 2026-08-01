from enum import StrEnum

from pydantic import BaseModel, Field


class IncidentPriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StrEnum):
    NEW = "new"


class IncidentCreateRequest(BaseModel):
    external_reference: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    priority: IncidentPriority


class IncidentCreateResponse(BaseModel):
    incident_id: str
    external_reference: str
    status: IncidentStatus
