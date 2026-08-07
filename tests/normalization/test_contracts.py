from datetime import UTC, datetime

from connector_lab.domain.security_alert import (
    CanonicalAlertSeverity,
    CanonicalSecurityAlert,
    SecurityAlertSource,
)
from connector_lab.normalization.contracts import (
    AlertNormalizationAdapter,
)
from connector_lab.normalization.errors import (
    AlertNormalizationError,
)


class ExampleVendorAlert:
    pass


class ExampleNormalizationAdapter:
    @property
    def vendor(self) -> str:
        return "example-vendor"

    def normalize(
        self,
        alert: ExampleVendorAlert,
    ) -> CanonicalSecurityAlert:
        return CanonicalSecurityAlert(
            alert_id="example-vendor:tenant-001:alert-001",
            external_reference="alert-001",
            title="Example alert",
            description="Example normalized alert.",
            severity=CanonicalAlertSeverity.HIGH,
            detected_at=datetime(
                2026,
                8,
                7,
                12,
                0,
                tzinfo=UTC,
            ),
            source=SecurityAlertSource(
                vendor=self.vendor,
                product="Example Security Platform",
                source_id="tenant-001",
            ),
        )


def test_normalization_adapter_is_structurally_compatible() -> None:
    adapter = ExampleNormalizationAdapter()

    assert isinstance(
        adapter,
        AlertNormalizationAdapter,
    )

    normalized_alert = adapter.normalize(
        ExampleVendorAlert(),
    )

    assert normalized_alert.source.vendor == "example-vendor"
    assert normalized_alert.external_reference == "alert-001"


def test_normalization_error_identifies_originating_vendor() -> None:
    error = AlertNormalizationError(
        vendor="example-vendor",
        message="Alert normalization failed",
    )

    assert str(error) == "Alert normalization failed"
    assert error.vendor == "example-vendor"
