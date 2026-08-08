import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.client.alerts_connector import (
    AlertsConnector,
)
from connector_lab.client.vendor_alerts_connector import (
    VendorAlertsConnector,
)
from connector_lab.domain.security_alert import (
    CanonicalAlertSeverity,
    CanonicalSecurityAlert,
)
from connector_lab.mock_api.app import app as mock_cyber_app
from connector_lab.mock_vendor_api.app import (
    app as mock_vendor_app,
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
from connector_lab.workflows.multi_vendor_alert_normalization import (
    MultiVendorAlertNormalizationWorkflow,
)


@pytest.mark.asyncio
async def test_both_vendor_apis_produce_one_canonical_collection() -> None:
    mock_cyber_transport = ASGITransport(
        app=mock_cyber_app,
    )
    mock_vendor_transport = ASGITransport(
        app=mock_vendor_app,
    )

    async with (
        AsyncClient(
            transport=mock_cyber_transport,
            base_url="http://mock-cyber",
        ) as mock_cyber_client,
        AsyncClient(
            transport=mock_vendor_transport,
            base_url="http://mock-vendor",
        ) as mock_vendor_client,
    ):
        workflow = MultiVendorAlertNormalizationWorkflow(
            sources=(
                MockCyberNormalizedAlertSource(
                    connector=AlertsConnector(
                        base_url="http://mock-cyber",
                        api_key="connector-lab-secret",
                        http_client=mock_cyber_client,
                        page_size=1,
                    ),
                    adapter=(
                        MockCyberAlertNormalizationAdapter(
                            source_id="mock-tenant-001",
                        )
                    ),
                ),
                VendorDetectionNormalizedAlertSource(
                    connector=VendorAlertsConnector(
                        base_url="http://mock-vendor",
                        api_key=("connector-lab-vendor-secret"),
                        http_client=mock_vendor_client,
                        page_size=1,
                    ),
                    adapter=(VendorDetectionNormalizationAdapter()),
                ),
            ),
        )

        alerts = await workflow.run()

    assert len(alerts) == 4
    assert all(isinstance(alert, CanonicalSecurityAlert) for alert in alerts)
    assert tuple(alert.alert_id for alert in alerts) == (
        "connector-lab:mock-tenant-001:alert-001",
        "connector-lab:mock-tenant-001:alert-002",
        "mock-vendor:vendor-tenant-001:DET-1001",
        "mock-vendor:vendor-tenant-001:DET-1002",
    )
    assert tuple(alert.severity for alert in alerts) == (
        CanonicalAlertSeverity.HIGH,
        CanonicalAlertSeverity.MEDIUM,
        CanonicalAlertSeverity.CRITICAL,
        CanonicalAlertSeverity.MEDIUM,
    )
    assert {alert.source.vendor for alert in alerts} == {
        "connector-lab",
        "mock-vendor",
    }

    first_vendor_detection = alerts[2]
    assert first_vendor_detection.external_reference == ("DET-1001")
    assert len(first_vendor_detection.evidence) == 1
    assert len(first_vendor_detection.resources) == 1
