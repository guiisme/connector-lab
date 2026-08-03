from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from connector_lab.domain.security_alert import (
    CanonicalAlertSeverity,
    CanonicalSecurityAlert,
    SecurityAlertEvidence,
    SecurityAlertEvidenceType,
    SecurityAlertResourceReference,
    SecurityAlertResourceType,
    SecurityAlertSource,
)


def test_canonical_alert_preserves_identity_and_source_metadata() -> None:
    detected_at = datetime(
        2026,
        8,
        3,
        12,
        30,
        tzinfo=UTC,
    )
    source = SecurityAlertSource(
        vendor="Example Security",
        product="Example Detection Platform",
        source_id="tenant-001",
    )

    alert = CanonicalSecurityAlert(
        alert_id="canonical-alert-001",
        external_reference="vendor-alert-987",
        title="Suspicious administrative activity",
        description=("Administrative behavior exceeded the expected baseline."),
        severity=CanonicalAlertSeverity.HIGH,
        detected_at=detected_at,
        source=source,
    )

    assert alert.alert_id == "canonical-alert-001"
    assert alert.external_reference == "vendor-alert-987"
    assert alert.title == "Suspicious administrative activity"
    assert alert.severity is CanonicalAlertSeverity.HIGH
    assert alert.detected_at == detected_at
    assert alert.source.vendor == "Example Security"
    assert alert.source.product == ("Example Detection Platform")
    assert alert.source.source_id == "tenant-001"
    assert alert.evidence == ()

    with pytest.raises(
        ValidationError,
        match="Instance is frozen",
    ):
        alert.title = "Changed title"


@pytest.mark.parametrize(
    "field_name",
    [
        "alert_id",
        "external_reference",
        "title",
        "description",
    ],
)
def test_canonical_alert_rejects_blank_required_text(
    field_name: str,
) -> None:
    alert_data: dict[str, object] = {
        "alert_id": "canonical-alert-001",
        "external_reference": "vendor-alert-987",
        "title": "Suspicious administrative activity",
        "description": "Administrative behavior detected.",
        "severity": CanonicalAlertSeverity.HIGH,
        "detected_at": datetime(
            2026,
            8,
            3,
            12,
            30,
            tzinfo=UTC,
        ),
        "source": SecurityAlertSource(
            vendor="Example Security",
            product="Example Detection Platform",
            source_id="tenant-001",
        ),
    }
    alert_data[field_name] = "   "

    with pytest.raises(ValidationError):
        CanonicalSecurityAlert.model_validate(
            alert_data,
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "vendor",
        "product",
        "source_id",
    ],
)
def test_security_alert_source_rejects_blank_text(
    field_name: str,
) -> None:
    source_data = {
        "vendor": "Example Security",
        "product": "Example Detection Platform",
        "source_id": "tenant-001",
    }
    source_data[field_name] = "   "

    with pytest.raises(ValidationError):
        SecurityAlertSource.model_validate(
            source_data,
        )


def test_canonical_alert_rejects_timestamp_without_timezone() -> None:
    with pytest.raises(
        ValidationError,
        match="detected_at must be timezone-aware",
    ):
        CanonicalSecurityAlert(
            alert_id="canonical-alert-001",
            external_reference="vendor-alert-987",
            title="Suspicious administrative activity",
            description="Administrative behavior detected.",
            severity=CanonicalAlertSeverity.HIGH,
            detected_at=datetime(
                2026,
                8,
                3,
                12,
                30,
            ),
            source=SecurityAlertSource(
                vendor="Example Security",
                product="Example Detection Platform",
                source_id="tenant-001",
            ),
        )


def test_canonical_alert_preserves_typed_evidence_and_resources() -> None:
    evidence = SecurityAlertEvidence(
        evidence_type=(SecurityAlertEvidenceType.IP_ADDRESS),
        value="192.0.2.10",
    )
    resource = SecurityAlertResourceReference(
        resource_type=SecurityAlertResourceType.HOST,
        resource_id="host-001",
        display_name="application-server-01",
    )

    alert = CanonicalSecurityAlert(
        alert_id="canonical-alert-002",
        external_reference="vendor-alert-988",
        title="Unexpected remote connection",
        description=("A protected host communicated with an unexpected address."),
        severity=CanonicalAlertSeverity.MEDIUM,
        detected_at=datetime(
            2026,
            8,
            3,
            13,
            0,
            tzinfo=UTC,
        ),
        source=SecurityAlertSource(
            vendor="Example Security",
            product="Example Detection Platform",
            source_id="tenant-001",
        ),
        evidence=(evidence,),
        resources=(resource,),
    )

    assert alert.evidence == (evidence,)
    assert alert.evidence[0].evidence_type is (SecurityAlertEvidenceType.IP_ADDRESS)
    assert alert.resources == (resource,)
    assert alert.resources[0].resource_type is (SecurityAlertResourceType.HOST)
    assert alert.resources[0].resource_id == "host-001"
    assert alert.resources[0].display_name == ("application-server-01")


def test_canonical_alert_rejects_duplicate_evidence() -> None:
    evidence = SecurityAlertEvidence(
        evidence_type=SecurityAlertEvidenceType.DOMAIN,
        value="example.test",
    )

    with pytest.raises(
        ValidationError,
        match="evidence entries must be unique",
    ):
        CanonicalSecurityAlert(
            alert_id="canonical-alert-003",
            external_reference="vendor-alert-989",
            title="Repeated domain evidence",
            description="The same evidence was supplied twice.",
            severity=CanonicalAlertSeverity.LOW,
            detected_at=datetime(
                2026,
                8,
                3,
                14,
                0,
                tzinfo=UTC,
            ),
            source=SecurityAlertSource(
                vendor="Example Security",
                product="Example Detection Platform",
                source_id="tenant-001",
            ),
            evidence=(
                evidence,
                evidence,
            ),
        )


def test_canonical_alert_rejects_duplicate_resource_reference() -> None:
    resource = SecurityAlertResourceReference(
        resource_type=SecurityAlertResourceType.CLOUD_RESOURCE,
        resource_id="cloud-resource-001",
        display_name="production-workload",
    )

    with pytest.raises(
        ValidationError,
        match="resource references must be unique",
    ):
        CanonicalSecurityAlert(
            alert_id="canonical-alert-004",
            external_reference="vendor-alert-990",
            title="Repeated affected resource",
            description=("The same affected resource was supplied twice."),
            severity=CanonicalAlertSeverity.HIGH,
            detected_at=datetime(
                2026,
                8,
                3,
                14,
                30,
                tzinfo=UTC,
            ),
            source=SecurityAlertSource(
                vendor="Example Security",
                product="Example Detection Platform",
                source_id="tenant-001",
            ),
            resources=(
                resource,
                resource,
            ),
        )
