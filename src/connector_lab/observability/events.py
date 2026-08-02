import json
import logging
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


class LoggingOperationalEventRecorder:
    def __init__(
        self,
        *,
        logger: logging.Logger,
    ) -> None:
        self._logger = logger

    def record(
        self,
        event: OperationalEvent,
    ) -> None:
        payload = json.dumps(
            event.model_dump(mode="json"),
            sort_keys=True,
        )

        if event.outcome is OperationalEventOutcome.FAILED:
            self._logger.error(payload)
            return

        self._logger.info(payload)
