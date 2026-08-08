from typing import Protocol

from connector_lab.domain.security_alert import (
    CanonicalSecurityAlert,
)
from connector_lab.normalization.errors import (
    AlertNormalizationConflictError,
)


class NormalizedAlertSource(Protocol):
    @property
    def vendor(self) -> str: ...

    async def list_normalized_alerts(
        self,
    ) -> tuple[CanonicalSecurityAlert, ...]: ...


class MultiVendorAlertNormalizationWorkflow:
    def __init__(
        self,
        *,
        sources: tuple[NormalizedAlertSource, ...],
    ) -> None:
        self._sources = sources

    async def run(
        self,
    ) -> tuple[CanonicalSecurityAlert, ...]:
        alerts_by_id: dict[
            str,
            CanonicalSecurityAlert,
        ] = {}

        for source in self._sources:
            alerts = await source.list_normalized_alerts()

            for alert in alerts:
                existing_alert = alerts_by_id.get(
                    alert.alert_id,
                )

                if existing_alert is None:
                    alerts_by_id[alert.alert_id] = alert
                    continue

                if existing_alert != alert:
                    raise AlertNormalizationConflictError(
                        vendor=source.vendor,
                        message=("Conflicting canonical alert identity"),
                    )

        return tuple(alerts_by_id.values())
