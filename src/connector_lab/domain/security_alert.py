from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
    field_validator,
)

NonBlankText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
    ),
]


class CanonicalAlertSeverity(StrEnum):
    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityAlertEvidenceType(StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    FILE_HASH = "file_hash"
    USER_ACCOUNT = "user_account"
    PROCESS = "process"
    OTHER = "other"


class SecurityAlertResourceType(StrEnum):
    HOST = "host"
    USER_ACCOUNT = "user_account"
    CLOUD_RESOURCE = "cloud_resource"
    APPLICATION = "application"
    NETWORK = "network"
    OTHER = "other"


class SecurityAlertSource(BaseModel):
    model_config = ConfigDict(frozen=True)

    vendor: NonBlankText
    product: NonBlankText
    source_id: NonBlankText


class SecurityAlertEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_type: SecurityAlertEvidenceType
    value: NonBlankText


class SecurityAlertResourceReference(BaseModel):
    model_config = ConfigDict(frozen=True)

    resource_type: SecurityAlertResourceType
    resource_id: NonBlankText
    display_name: NonBlankText | None = None


class CanonicalSecurityAlert(BaseModel):
    model_config = ConfigDict(frozen=True)

    alert_id: NonBlankText
    external_reference: NonBlankText
    title: NonBlankText
    description: NonBlankText
    severity: CanonicalAlertSeverity
    detected_at: datetime
    source: SecurityAlertSource
    evidence: tuple[SecurityAlertEvidence, ...] = ()
    resources: tuple[
        SecurityAlertResourceReference,
        ...,
    ] = ()

    @field_validator("detected_at")
    @classmethod
    def validate_detected_at_timezone(
        cls,
        detected_at: datetime,
    ) -> datetime:
        if detected_at.tzinfo is None or detected_at.utcoffset() is None:
            raise ValueError(
                "detected_at must be timezone-aware",
            )

        return detected_at
