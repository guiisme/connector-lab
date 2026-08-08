from collections.abc import Callable
from time import monotonic
from typing import Protocol
from uuid import uuid4

from connector_lab.domain.security_alert import (
    CanonicalSecurityAlert,
)
from connector_lab.normalization.errors import (
    AlertNormalizationConflictError,
)
from connector_lab.observability.events import (
    NullOperationalEventRecorder,
    OperationalEvent,
    OperationalEventOutcome,
    OperationalEventRecorder,
)
from connector_lab.observability.metrics import (
    ConnectorFailureCategory,
    ConnectorMetricObservation,
    ConnectorMetricOutcome,
    ConnectorMetricsRecorder,
    NullConnectorMetricsRecorder,
)

CorrelationIdProvider = Callable[[], str]
MonotonicProvider = Callable[[], float]


def new_correlation_id() -> str:
    return str(uuid4())


class NormalizedAlertSource(Protocol):
    @property
    def vendor(self) -> str: ...

    async def list_normalized_alerts(
        self,
    ) -> tuple[CanonicalSecurityAlert, ...]: ...


class MultiVendorAlertNormalizationWorkflow:
    def __init__(
        self,
        *,
        sources: tuple[NormalizedAlertSource, ...],
        event_recorder: OperationalEventRecorder | None = None,
        metrics_recorder: ConnectorMetricsRecorder | None = None,
        correlation_id_provider: CorrelationIdProvider = (new_correlation_id),
        monotonic_provider: MonotonicProvider = monotonic,
    ) -> None:
        self._sources = sources
        self._event_recorder = (
            event_recorder
            if event_recorder is not None
            else NullOperationalEventRecorder()
        )
        self._metrics_recorder = (
            metrics_recorder
            if metrics_recorder is not None
            else NullConnectorMetricsRecorder()
        )
        self._correlation_id_provider = correlation_id_provider
        self._monotonic_provider = monotonic_provider

    def _component(self, vendor: str) -> str:
        return f"multi_vendor_alert_normalization:{vendor}"

    def _record_event(
        self,
        *,
        vendor: str,
        correlation_id: str,
        outcome: OperationalEventOutcome,
        error_type: str | None = None,
    ) -> None:
        self._event_recorder.record(
            OperationalEvent(
                correlation_id=correlation_id,
                component=self._component(vendor),
                operation="list_normalized_alerts",
                outcome=outcome,
                error_type=error_type,
            ),
        )

    def _record_metric(
        self,
        *,
        vendor: str,
        correlation_id: str,
        started_at: float,
        outcome: ConnectorMetricOutcome,
        failure_category: (ConnectorFailureCategory | None) = None,
    ) -> None:
        self._metrics_recorder.record(
            ConnectorMetricObservation(
                correlation_id=correlation_id,
                component=self._component(vendor),
                operation="list_normalized_alerts",
                outcome=outcome,
                duration_seconds=(self._monotonic_provider() - started_at),
                failure_category=failure_category,
            ),
        )

    async def run(
        self,
    ) -> tuple[CanonicalSecurityAlert, ...]:
        correlation_id = self._correlation_id_provider()
        alerts_by_id: dict[
            str,
            CanonicalSecurityAlert,
        ] = {}

        for source in self._sources:
            started_at = self._monotonic_provider()
            self._record_event(
                vendor=source.vendor,
                correlation_id=correlation_id,
                outcome=OperationalEventOutcome.STARTED,
            )

            try:
                alerts = await source.list_normalized_alerts()

                for alert in alerts:
                    existing_alert = alerts_by_id.get(
                        alert.alert_id,
                    )

                    if existing_alert is None:
                        alerts_by_id[alert.alert_id] = alert
                        continue

                    if existing_alert != alert:
                        raise AlertNormalizationConflictError(
                            vendor=source.vendor,
                            message=("Conflicting canonical alert identity"),
                        )
            except Exception as error:
                self._record_event(
                    vendor=source.vendor,
                    correlation_id=correlation_id,
                    outcome=OperationalEventOutcome.FAILED,
                    error_type=type(error).__name__,
                )
                self._record_metric(
                    vendor=source.vendor,
                    correlation_id=correlation_id,
                    started_at=started_at,
                    outcome=ConnectorMetricOutcome.FAILED,
                    failure_category=(ConnectorFailureCategory.OTHER),
                )
                raise

            self._record_event(
                vendor=source.vendor,
                correlation_id=correlation_id,
                outcome=OperationalEventOutcome.SUCCEEDED,
            )
            self._record_metric(
                vendor=source.vendor,
                correlation_id=correlation_id,
                started_at=started_at,
                outcome=ConnectorMetricOutcome.SUCCEEDED,
            )

        return tuple(alerts_by_id.values())
