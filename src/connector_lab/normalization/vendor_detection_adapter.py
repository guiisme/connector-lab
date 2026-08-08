from pydantic import ValidationError

from connector_lab.client.vendor_alerts_models import (
    VendorDetection,
    VendorEntityCategory,
    VendorObservableKind,
)
from connector_lab.domain.security_alert import (
    CanonicalAlertSeverity,
    CanonicalSecurityAlert,
    SecurityAlertEvidence,
    SecurityAlertEvidenceType,
    SecurityAlertResourceReference,
    SecurityAlertResourceType,
    SecurityAlertSource,
)
from connector_lab.normalization.errors import (
    AlertNormalizationError,
)

VENDOR = "mock-vendor"
PRODUCT = "Mock Vendor Detection API"

EVIDENCE_TYPE_MAPPING = {
    VendorObservableKind.IP: (SecurityAlertEvidenceType.IP_ADDRESS),
    VendorObservableKind.DOMAIN: (SecurityAlertEvidenceType.DOMAIN),
    VendorObservableKind.HOST: (SecurityAlertEvidenceType.HOSTNAME),
    VendorObservableKind.USER: (SecurityAlertEvidenceType.USER_ACCOUNT),
}

RESOURCE_TYPE_MAPPING = {
    VendorEntityCategory.WORKLOAD: (SecurityAlertResourceType.HOST),
    VendorEntityCategory.IDENTITY: (SecurityAlertResourceType.USER_ACCOUNT),
    VendorEntityCategory.CLOUD_OBJECT: (SecurityAlertResourceType.CLOUD_RESOURCE),
}


def map_risk_score(
    risk_score: int,
) -> CanonicalAlertSeverity:
    if risk_score == 0:
        return CanonicalAlertSeverity.INFORMATIONAL

    if risk_score < 40:
        return CanonicalAlertSeverity.LOW

    if risk_score < 60:
        return CanonicalAlertSeverity.MEDIUM

    if risk_score < 80:
        return CanonicalAlertSeverity.HIGH

    return CanonicalAlertSeverity.CRITICAL


class VendorDetectionNormalizationAdapter:
    @property
    def vendor(self) -> str:
        return VENDOR

    def normalize(
        self,
        alert: VendorDetection,
    ) -> CanonicalSecurityAlert:
        try:
            evidence = tuple(
                SecurityAlertEvidence(
                    evidence_type=(EVIDENCE_TYPE_MAPPING[observable.kind]),
                    value=observable.indicator,
                )
                for observable in alert.observables
            )
            affected_entity = alert.affected_entity
            resources = (
                SecurityAlertResourceReference(
                    resource_type=(RESOURCE_TYPE_MAPPING[affected_entity.category]),
                    resource_id=affected_entity.key,
                    display_name=affected_entity.label,
                ),
            )

            return CanonicalSecurityAlert(
                alert_id=(f"{self.vendor}:{alert.tenant_ref}:{alert.detection_key}"),
                external_reference=alert.detection_key,
                title=alert.event_name,
                description=alert.details,
                severity=map_risk_score(
                    alert.risk_score,
                ),
                detected_at=alert.event_time,
                source=SecurityAlertSource(
                    vendor=self.vendor,
                    product=PRODUCT,
                    source_id=alert.tenant_ref,
                ),
                evidence=evidence,
                resources=resources,
            )
        except ValidationError as error:
            raise AlertNormalizationError(
                vendor=self.vendor,
                message=("Vendor detection normalization failed"),
            ) from error
