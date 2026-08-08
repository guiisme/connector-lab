from datetime import UTC, datetime

import pytest

from connector_lab.domain.security_alert import (
    CanonicalAlertSeverity,
    CanonicalSecurityAlert,
    SecurityAlertSource,
)
from connector_lab.normalization.errors import (
    AlertNormalizationError,
)
from connector_lab.observability.events import (
    OperationalEvent,
    OperationalEventOutcome,
)
from connector_lab.observability.metrics import (
    ConnectorFailureCategory,
    ConnectorMetricObservation,
    ConnectorMetricOutcome,
)
from connector_lab.workflows.multi_vendor_alert_normalization import (
    MultiVendorAlertNormalizationWorkflow,
)


class RecordingEvents:
    def __init__(self) -> None:
        self.items: list[OperationalEvent] = []

    def record(self, event: OperationalEvent) -> None:
        self.items.append(event)


class RecordingMetrics:
    def __init__(self) -> None:
        self.items: list[ConnectorMetricObservation] = []

    def record(
        self,
        observation: ConnectorMetricObservation,
    ) -> None:
        self.items.append(observation)


class SuccessfulSource:
    @property
    def vendor(self) -> str:
        return "mock-vendor"

    async def list_normalized_alerts(
        self,
    ) -> tuple[CanonicalSecurityAlert, ...]:
        return (
            CanonicalSecurityAlert(
                alert_id="mock-vendor:tenant-001:DET-1001",
                external_reference="DET-1001",
                title="Normalized detection",
                description="Canonical description.",
                severity=CanonicalAlertSeverity.HIGH,
                detected_at=datetime(
                    2026,
                    8,
                    8,
                    12,
                    0,
                    tzinfo=UTC,
                ),
                source=SecurityAlertSource(
                    vendor="mock-vendor",
                    product="Mock Vendor Detection API",
                    source_id="tenant-001",
                ),
            ),
        )


class FailingSource:
    @property
    def vendor(self) -> str:
        return "mock-vendor"

    async def list_normalized_alerts(
        self,
    ) -> tuple[CanonicalSecurityAlert, ...]:
        raise AlertNormalizationError(
            vendor=self.vendor,
            message="api-secret raw-sensitive-payload",
        )


@pytest.mark.asyncio
async def test_workflow_records_vendor_aware_telemetry() -> None:
    events = RecordingEvents()
    metrics = RecordingMetrics()
    clock = iter([10.0, 10.25])
    workflow = MultiVendorAlertNormalizationWorkflow(
        sources=(SuccessfulSource(),),
        event_recorder=events,
        metrics_recorder=metrics,
        correlation_id_provider=lambda: "correlation-001",
        monotonic_provider=clock.__next__,
    )

    result = await workflow.run()

    assert len(result) == 1
    assert [event.outcome for event in events.items] == [
        OperationalEventOutcome.STARTED,
        OperationalEventOutcome.SUCCEEDED,
    ]
    assert all(
        event.component == "multi_vendor_alert_normalization:mock-vendor"
        for event in events.items
    )
    assert all(event.correlation_id == "correlation-001" for event in events.items)
    assert metrics.items[0].outcome is (ConnectorMetricOutcome.SUCCEEDED)
    assert metrics.items[0].duration_seconds == 0.25


@pytest.mark.asyncio
async def test_workflow_records_safe_failure_telemetry() -> None:
    events = RecordingEvents()
    metrics = RecordingMetrics()
    clock = iter([20.0, 20.5])
    workflow = MultiVendorAlertNormalizationWorkflow(
        sources=(FailingSource(),),
        event_recorder=events,
        metrics_recorder=metrics,
        correlation_id_provider=lambda: "correlation-002",
        monotonic_provider=clock.__next__,
    )

    with pytest.raises(AlertNormalizationError):
        await workflow.run()

    assert events.items[-1].outcome is (OperationalEventOutcome.FAILED)
    assert events.items[-1].error_type == ("AlertNormalizationError")
    assert metrics.items[-1].outcome is (ConnectorMetricOutcome.FAILED)
    assert metrics.items[-1].failure_category is (ConnectorFailureCategory.OTHER)

    telemetry = repr(events.items) + repr(metrics.items)
    assert "api-secret" not in telemetry
    assert "raw-sensitive-payload" not in telemetry
