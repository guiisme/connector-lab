from datetime import UTC, datetime

import pytest

from connector_lab.client.models import (
    Alert,
    AlertSeverity,
    AlertStatus,
)
from connector_lab.domain.security_alert import (
    CanonicalAlertSeverity,
)
from connector_lab.normalization.errors import (
    AlertNormalizationError,
)
from connector_lab.normalization.mock_cyber_adapter import (
    MockCyberAlertNormalizationAdapter,
)


def create_alert(
    *,
    severity: AlertSeverity = AlertSeverity.HIGH,
    detected_at: datetime | None = None,
) -> Alert:
    return Alert(
        id="alert-001",
        title="Suspicious PowerShell execution",
        severity=severity,
        status=AlertStatus.OPEN,
        detected_at=detected_at
        or datetime(
            2026,
            7,
            31,
            18,
            0,
            tzinfo=UTC,
        ),
    )


def test_mock_cyber_adapter_preserves_identity_and_source() -> None:
    adapter = MockCyberAlertNormalizationAdapter(
        source_id="tenant-001",
    )

    normalized = adapter.normalize(
        create_alert(),
    )

    assert normalized.alert_id == ("connector-lab:tenant-001:alert-001")
    assert normalized.external_reference == "alert-001"
    assert normalized.title == ("Suspicious PowerShell execution")
    assert normalized.description == ("Vendor alert status: open.")
    assert normalized.detected_at == datetime(
        2026,
        7,
        31,
        18,
        0,
        tzinfo=UTC,
    )
    assert normalized.source.vendor == "connector-lab"
    assert normalized.source.product == "Mock Cyber API"
    assert normalized.source.source_id == "tenant-001"
    assert normalized.evidence == ()
    assert normalized.resources == ()


@pytest.mark.parametrize(
    (
        "vendor_severity",
        "canonical_severity",
    ),
    [
        (
            AlertSeverity.LOW,
            CanonicalAlertSeverity.LOW,
        ),
        (
            AlertSeverity.MEDIUM,
            CanonicalAlertSeverity.MEDIUM,
        ),
        (
            AlertSeverity.HIGH,
            CanonicalAlertSeverity.HIGH,
        ),
        (
            AlertSeverity.CRITICAL,
            CanonicalAlertSeverity.CRITICAL,
        ),
    ],
)
def test_mock_cyber_adapter_maps_severity(
    vendor_severity: AlertSeverity,
    canonical_severity: CanonicalAlertSeverity,
) -> None:
    adapter = MockCyberAlertNormalizationAdapter(
        source_id="tenant-001",
    )

    normalized = adapter.normalize(
        create_alert(
            severity=vendor_severity,
        ),
    )

    assert normalized.severity is canonical_severity


def test_mock_cyber_adapter_identifies_normalization_failure() -> None:
    adapter = MockCyberAlertNormalizationAdapter(
        source_id="tenant-001",
    )
    alert = create_alert(
        detected_at=datetime(
            2026,
            7,
            31,
            18,
            0,
        ),
    )

    with pytest.raises(
        AlertNormalizationError,
        match="Mock Cyber API alert normalization failed",
    ) as raised:
        adapter.normalize(alert)

    assert raised.value.vendor == "connector-lab"
