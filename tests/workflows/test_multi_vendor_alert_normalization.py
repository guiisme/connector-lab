from datetime import UTC, datetime

import pytest

from connector_lab.domain.security_alert import (
    CanonicalAlertSeverity,
    CanonicalSecurityAlert,
    SecurityAlertSource,
)
from connector_lab.normalization.errors import (
    AlertNormalizationConflictError,
)
from connector_lab.workflows.multi_vendor_alert_normalization import (
    MultiVendorAlertNormalizationWorkflow,
)


class FakeNormalizedAlertSource:
    def __init__(
        self,
        *,
        vendor: str,
        alerts: tuple[CanonicalSecurityAlert, ...],
    ) -> None:
        self._vendor = vendor
        self._alerts = alerts

    @property
    def vendor(self) -> str:
        return self._vendor

    async def list_normalized_alerts(
        self,
    ) -> tuple[CanonicalSecurityAlert, ...]:
        return self._alerts


def create_alert(
    *,
    alert_id: str,
    vendor: str,
    title: str = "Normalized alert",
) -> CanonicalSecurityAlert:
    return CanonicalSecurityAlert(
        alert_id=alert_id,
        external_reference=f"external-{alert_id}",
        title=title,
        description="Canonical alert description.",
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
            vendor=vendor,
            product=f"{vendor} product",
            source_id="tenant-001",
        ),
    )


@pytest.mark.asyncio
async def test_workflow_aggregates_canonical_alert_sources() -> None:
    first_alert = create_alert(
        alert_id="connector-lab:tenant-001:alert-001",
        vendor="connector-lab",
    )
    second_alert = create_alert(
        alert_id="mock-vendor:tenant-001:DET-1001",
        vendor="mock-vendor",
    )
    workflow = MultiVendorAlertNormalizationWorkflow(
        sources=(
            FakeNormalizedAlertSource(
                vendor="connector-lab",
                alerts=(first_alert,),
            ),
            FakeNormalizedAlertSource(
                vendor="mock-vendor",
                alerts=(second_alert,),
            ),
        ),
    )

    result = await workflow.run()

    assert result == (
        first_alert,
        second_alert,
    )


@pytest.mark.asyncio
async def test_workflow_deduplicates_identical_alerts() -> None:
    alert = create_alert(
        alert_id="mock-vendor:tenant-001:DET-1001",
        vendor="mock-vendor",
    )
    workflow = MultiVendorAlertNormalizationWorkflow(
        sources=(
            FakeNormalizedAlertSource(
                vendor="mock-vendor",
                alerts=(
                    alert,
                    alert,
                ),
            ),
        ),
    )

    result = await workflow.run()

    assert result == (alert,)


@pytest.mark.asyncio
async def test_workflow_rejects_conflicting_canonical_identity() -> None:
    first_alert = create_alert(
        alert_id="mock-vendor:tenant-001:DET-1001",
        vendor="mock-vendor",
        title="First representation",
    )
    conflicting_alert = create_alert(
        alert_id="mock-vendor:tenant-001:DET-1001",
        vendor="mock-vendor",
        title="Conflicting representation",
    )
    workflow = MultiVendorAlertNormalizationWorkflow(
        sources=(
            FakeNormalizedAlertSource(
                vendor="mock-vendor",
                alerts=(
                    first_alert,
                    conflicting_alert,
                ),
            ),
        ),
    )

    with pytest.raises(
        AlertNormalizationConflictError,
        match="Conflicting canonical alert identity",
    ) as raised:
        await workflow.run()

    assert raised.value.vendor == "mock-vendor"
