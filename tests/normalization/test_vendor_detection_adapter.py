from datetime import UTC, datetime

import pytest

from connector_lab.client.vendor_alerts_models import (
    VendorAffectedEntity,
    VendorDetection,
    VendorEntityCategory,
    VendorObservable,
    VendorObservableKind,
)
from connector_lab.domain.security_alert import (
    CanonicalAlertSeverity,
    SecurityAlertEvidenceType,
    SecurityAlertResourceType,
)
from connector_lab.normalization.errors import (
    AlertNormalizationError,
)
from connector_lab.normalization.vendor_detection_adapter import (
    VendorDetectionNormalizationAdapter,
)


def create_detection(
    *,
    risk_score: int = 85,
    event_time: datetime | None = None,
    observables: tuple[VendorObservable, ...] = (),
    entity_category: VendorEntityCategory = (VendorEntityCategory.WORKLOAD),
) -> VendorDetection:
    return VendorDetection(
        detection_key="DET-1001",
        event_name="Suspicious sign-in pattern",
        details=("Multiple unusual authentication attempts detected."),
        risk_score=risk_score,
        event_time=event_time
        or datetime(
            2026,
            8,
            3,
            10,
            0,
            tzinfo=UTC,
        ),
        tenant_ref="vendor-tenant-001",
        observables=observables,
        affected_entity=VendorAffectedEntity(
            category=entity_category,
            key="asset-001",
            label="application-server-01",
        ),
    )


def test_vendor_detection_adapter_preserves_contract() -> None:
    adapter = VendorDetectionNormalizationAdapter()

    normalized = adapter.normalize(
        create_detection(),
    )

    assert normalized.alert_id == ("mock-vendor:vendor-tenant-001:DET-1001")
    assert normalized.external_reference == "DET-1001"
    assert normalized.title == "Suspicious sign-in pattern"
    assert normalized.description == (
        "Multiple unusual authentication attempts detected."
    )
    assert normalized.severity is (CanonicalAlertSeverity.CRITICAL)
    assert normalized.detected_at == datetime(
        2026,
        8,
        3,
        10,
        0,
        tzinfo=UTC,
    )
    assert normalized.source.vendor == "mock-vendor"
    assert normalized.source.product == ("Mock Vendor Detection API")
    assert normalized.source.source_id == ("vendor-tenant-001")


@pytest.mark.parametrize(
    (
        "risk_score",
        "expected_severity",
    ),
    [
        (0, CanonicalAlertSeverity.INFORMATIONAL),
        (1, CanonicalAlertSeverity.LOW),
        (39, CanonicalAlertSeverity.LOW),
        (40, CanonicalAlertSeverity.MEDIUM),
        (59, CanonicalAlertSeverity.MEDIUM),
        (60, CanonicalAlertSeverity.HIGH),
        (79, CanonicalAlertSeverity.HIGH),
        (80, CanonicalAlertSeverity.CRITICAL),
        (100, CanonicalAlertSeverity.CRITICAL),
    ],
)
def test_vendor_detection_adapter_maps_risk_score(
    risk_score: int,
    expected_severity: CanonicalAlertSeverity,
) -> None:
    adapter = VendorDetectionNormalizationAdapter()

    normalized = adapter.normalize(
        create_detection(
            risk_score=risk_score,
        ),
    )

    assert normalized.severity is expected_severity


@pytest.mark.parametrize(
    (
        "observable_kind",
        "expected_type",
    ),
    [
        (
            VendorObservableKind.IP,
            SecurityAlertEvidenceType.IP_ADDRESS,
        ),
        (
            VendorObservableKind.DOMAIN,
            SecurityAlertEvidenceType.DOMAIN,
        ),
        (
            VendorObservableKind.HOST,
            SecurityAlertEvidenceType.HOSTNAME,
        ),
        (
            VendorObservableKind.USER,
            SecurityAlertEvidenceType.USER_ACCOUNT,
        ),
    ],
)
def test_vendor_detection_adapter_maps_observables(
    observable_kind: VendorObservableKind,
    expected_type: SecurityAlertEvidenceType,
) -> None:
    adapter = VendorDetectionNormalizationAdapter()

    normalized = adapter.normalize(
        create_detection(
            observables=(
                VendorObservable(
                    kind=observable_kind,
                    indicator="observable-value",
                ),
            ),
        ),
    )

    assert len(normalized.evidence) == 1
    assert normalized.evidence[0].evidence_type is (expected_type)
    assert normalized.evidence[0].value == ("observable-value")


@pytest.mark.parametrize(
    (
        "entity_category",
        "expected_type",
    ),
    [
        (
            VendorEntityCategory.WORKLOAD,
            SecurityAlertResourceType.HOST,
        ),
        (
            VendorEntityCategory.IDENTITY,
            SecurityAlertResourceType.USER_ACCOUNT,
        ),
        (
            VendorEntityCategory.CLOUD_OBJECT,
            SecurityAlertResourceType.CLOUD_RESOURCE,
        ),
    ],
)
def test_vendor_detection_adapter_maps_affected_entity(
    entity_category: VendorEntityCategory,
    expected_type: SecurityAlertResourceType,
) -> None:
    adapter = VendorDetectionNormalizationAdapter()

    normalized = adapter.normalize(
        create_detection(
            entity_category=entity_category,
        ),
    )

    assert len(normalized.resources) == 1
    assert normalized.resources[0].resource_type is (expected_type)
    assert normalized.resources[0].resource_id == "asset-001"
    assert normalized.resources[0].display_name == ("application-server-01")


def test_vendor_detection_adapter_identifies_failure() -> None:
    adapter = VendorDetectionNormalizationAdapter()
    detection = create_detection(
        event_time=datetime(
            2026,
            8,
            3,
            10,
            0,
        ),
    )

    with pytest.raises(
        AlertNormalizationError,
        match="Vendor detection normalization failed",
    ) as raised:
        adapter.normalize(detection)

    assert raised.value.vendor == "mock-vendor"
