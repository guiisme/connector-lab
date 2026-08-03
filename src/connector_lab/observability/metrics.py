from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class ConnectorMetricOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ConnectorFailureCategory(StrEnum):
    AUTHENTICATION = "authentication"
    CONNECTION = "connection"
    REQUEST_TIMEOUT = "request_timeout"
    JOB_TIMEOUT = "job_timeout"
    OTHER = "other"


class ConnectorMetricObservation(BaseModel):
    component: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    outcome: ConnectorMetricOutcome
    duration_seconds: float = Field(ge=0)
    failure_category: ConnectorFailureCategory | None = None


class ConnectorTelemetrySnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    total_requests: int
    successful_requests: int
    failed_requests: int
    authentication_failures: int
    connection_failures: int
    request_timeouts: int
    job_timeouts: int
    durations_seconds: tuple[float, ...]


class ConnectorMetricsRecorder(Protocol):
    def record(
        self,
        observation: ConnectorMetricObservation,
    ) -> None: ...


class NullConnectorMetricsRecorder:
    def record(
        self,
        observation: ConnectorMetricObservation,
    ) -> None:
        pass


class InMemoryConnectorMetricsRecorder:
    def __init__(self) -> None:
        self._total_requests = 0
        self._successful_requests = 0
        self._failed_requests = 0
        self._authentication_failures = 0
        self._connection_failures = 0
        self._request_timeouts = 0
        self._job_timeouts = 0
        self._durations_seconds: list[float] = []

    def record(
        self,
        observation: ConnectorMetricObservation,
    ) -> None:
        self._total_requests += 1
        self._durations_seconds.append(
            observation.duration_seconds,
        )

        if observation.outcome is ConnectorMetricOutcome.SUCCEEDED:
            self._successful_requests += 1
            return

        self._failed_requests += 1

        if observation.failure_category is ConnectorFailureCategory.AUTHENTICATION:
            self._authentication_failures += 1
        elif observation.failure_category is ConnectorFailureCategory.CONNECTION:
            self._connection_failures += 1
        elif observation.failure_category is ConnectorFailureCategory.REQUEST_TIMEOUT:
            self._request_timeouts += 1
        elif observation.failure_category is ConnectorFailureCategory.JOB_TIMEOUT:
            self._job_timeouts += 1

    def snapshot(self) -> ConnectorTelemetrySnapshot:
        return ConnectorTelemetrySnapshot(
            total_requests=self._total_requests,
            successful_requests=self._successful_requests,
            failed_requests=self._failed_requests,
            authentication_failures=(self._authentication_failures),
            connection_failures=self._connection_failures,
            request_timeouts=self._request_timeouts,
            job_timeouts=self._job_timeouts,
            durations_seconds=tuple(
                self._durations_seconds,
            ),
        )
