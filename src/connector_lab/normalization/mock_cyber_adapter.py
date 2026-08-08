from pydantic import ValidationError

from connector_lab.client.models import (
    Alert,
    AlertSeverity,
)
from connector_lab.domain.security_alert import (
    CanonicalAlertSeverity,
    CanonicalSecurityAlert,
    SecurityAlertSource,
)
from connector_lab.normalization.errors import (
    AlertNormalizationError,
)

VENDOR = "connector-lab"
PRODUCT = "Mock Cyber API"

SEVERITY_MAPPING = {
    AlertSeverity.LOW: CanonicalAlertSeverity.LOW,
    AlertSeverity.MEDIUM: CanonicalAlertSeverity.MEDIUM,
    AlertSeverity.HIGH: CanonicalAlertSeverity.HIGH,
    AlertSeverity.CRITICAL: CanonicalAlertSeverity.CRITICAL,
}


class MockCyberAlertNormalizationAdapter:
    def __init__(
        self,
        *,
        source_id: str,
    ) -> None:
        self._source_id = source_id

    @property
    def vendor(self) -> str:
        return VENDOR

    def normalize(
        self,
        alert: Alert,
    ) -> CanonicalSecurityAlert:
        try:
            return CanonicalSecurityAlert(
                alert_id=(f"{self.vendor}:{self._source_id}:{alert.id}"),
                external_reference=alert.id,
                title=alert.title,
                description=(f"Vendor alert status: {alert.status.value}."),
                severity=SEVERITY_MAPPING[alert.severity],
                detected_at=alert.detected_at,
                source=SecurityAlertSource(
                    vendor=self.vendor,
                    product=PRODUCT,
                    source_id=self._source_id,
                ),
            )
        except ValidationError as error:
            raise AlertNormalizationError(
                vendor=self.vendor,
                message=("Mock Cyber API alert normalization failed"),
            ) from error
