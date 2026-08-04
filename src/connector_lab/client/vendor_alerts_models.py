from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class VendorObservableKind(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    HOST = "host"
    USER = "user"


class VendorEntityCategory(StrEnum):
    WORKLOAD = "workload"
    IDENTITY = "identity"
    CLOUD_OBJECT = "cloud_object"


class VendorObservable(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    kind: VendorObservableKind
    indicator: str = Field(min_length=1)


class VendorAffectedEntity(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    category: VendorEntityCategory
    key: str = Field(min_length=1)
    label: str = Field(min_length=1)


class VendorDetection(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    detection_key: str = Field(min_length=1)
    event_name: str = Field(min_length=1)
    details: str = Field(min_length=1)
    risk_score: int = Field(ge=0, le=100)
    event_time: datetime
    tenant_ref: str = Field(min_length=1)
    observables: tuple[VendorObservable, ...]
    affected_entity: VendorAffectedEntity


class VendorDetectionPage(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    records: tuple[VendorDetection, ...]
    next_cursor: str | None
