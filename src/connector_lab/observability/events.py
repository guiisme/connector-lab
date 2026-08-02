from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, Field


class OperationalEventOutcome(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class OperationalEvent(BaseModel):
    correlation_id: str = Field(min_length=1)
    component: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    outcome: OperationalEventOutcome
    error_type: str | None = None


class OperationalEventRecorder(Protocol):
    def record(
        self,
        event: OperationalEvent,
    ) -> None: ...


class NullOperationalEventRecorder:
    def record(
        self,
        event: OperationalEvent,
    ) -> None:
        pass
