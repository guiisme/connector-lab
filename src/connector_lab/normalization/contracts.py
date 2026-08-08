from typing import (
    Protocol,
    TypeVar,
    runtime_checkable,
)

from connector_lab.domain.security_alert import (
    CanonicalSecurityAlert,
)

VendorAlertT = TypeVar(
    "VendorAlertT",
    contravariant=True,
)


@runtime_checkable
class AlertNormalizationAdapter(
    Protocol[VendorAlertT],
):
    @property
    def vendor(self) -> str: ...

    def normalize(
        self,
        alert: VendorAlertT,
    ) -> CanonicalSecurityAlert: ...
