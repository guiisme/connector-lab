from datetime import UTC, datetime

import pytest

from connector_lab.client.models import (
    Alert,
    AlertCollection,
    AlertSeverity,
    AlertStatus,
)
from connector_lab.client.vendor_alerts_models import (
    VendorAffectedEntity,
    VendorDetection,
    VendorEntityCategory,
)
from connector_lab.normalization.mock_cyber_adapter import (
    MockCyberAlertNormalizationAdapter,
)
from connector_lab.normalization.sources import (
    MockCyberNormalizedAlertSource,
    VendorDetectionNormalizedAlertSource,
)
from connector_lab.normalization.vendor_detection_adapter import (
    VendorDetectionNormalizationAdapter,
)


class FakeMockCyberConnector:
    async def list_alerts(self) -> AlertCollection:
        return AlertCollection(
            items=[
                Alert(
                    id="alert-001",
                    title="Original vendor alert",
                    severity=AlertSeverity.HIGH,
                    status=AlertStatus.OPEN,
                    detected_at=datetime(
                        2026,
                        8,
                        8,
                        10,
                        0,
                        tzinfo=UTC,
                    ),
                ),
            ],
            total=1,
        )


class FakeVendorDetectionConnector:
    async def list_all_detections(
        self,
    ) -> tuple[VendorDetection, ...]:
        return (
            VendorDetection(
                detection_key="DET-1001",
                event_name="Second vendor detection",
                details="Detection details.",
                risk_score=85,
                event_time=datetime(
                    2026,
                    8,
                    8,
                    10,
                    5,
                    tzinfo=UTC,
                ),
                tenant_ref="vendor-tenant-001",
                observables=(),
                affected_entity=VendorAffectedEntity(
                    category=VendorEntityCategory.WORKLOAD,
                    key="asset-001",
                    label="application-server-01",
                ),
            ),
        )


@pytest.mark.asyncio
async def test_mock_cyber_source_returns_canonical_alerts() -> None:
    source = MockCyberNormalizedAlertSource(
        connector=FakeMockCyberConnector(),
        adapter=MockCyberAlertNormalizationAdapter(
            source_id="tenant-001",
        ),
    )

    alerts = await source.list_normalized_alerts()

    assert source.vendor == "connector-lab"
    assert len(alerts) == 1
    assert alerts[0].alert_id == ("connector-lab:tenant-001:alert-001")
    assert alerts[0].source.vendor == "connector-lab"


@pytest.mark.asyncio
async def test_vendor_detection_source_returns_canonical_alerts() -> None:
    source = VendorDetectionNormalizedAlertSource(
        connector=FakeVendorDetectionConnector(),
        adapter=VendorDetectionNormalizationAdapter(),
    )

    alerts = await source.list_normalized_alerts()

    assert source.vendor == "mock-vendor"
    assert len(alerts) == 1
    assert alerts[0].alert_id == ("mock-vendor:vendor-tenant-001:DET-1001")
    assert alerts[0].source.vendor == "mock-vendor"
