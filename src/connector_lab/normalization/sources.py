from typing import Protocol

from connector_lab.client.models import (
    Alert,
    AlertCollection,
)
from connector_lab.client.vendor_alerts_models import (
    VendorDetection,
)
from connector_lab.domain.security_alert import (
    CanonicalSecurityAlert,
)
from connector_lab.normalization.contracts import (
    AlertNormalizationAdapter,
)


class MockCyberConnectorProtocol(Protocol):
    async def list_alerts(
        self,
    ) -> AlertCollection: ...


class VendorDetectionConnectorProtocol(Protocol):
    async def list_all_detections(
        self,
    ) -> tuple[VendorDetection, ...]: ...


class MockCyberNormalizedAlertSource:
    def __init__(
        self,
        *,
        connector: MockCyberConnectorProtocol,
        adapter: AlertNormalizationAdapter[Alert],
    ) -> None:
        self._connector = connector
        self._adapter = adapter

    @property
    def vendor(self) -> str:
        return self._adapter.vendor

    async def list_normalized_alerts(
        self,
    ) -> tuple[CanonicalSecurityAlert, ...]:
        collection = await self._connector.list_alerts()

        return tuple(self._adapter.normalize(alert) for alert in collection.items)


class VendorDetectionNormalizedAlertSource:
    def __init__(
        self,
        *,
        connector: VendorDetectionConnectorProtocol,
        adapter: AlertNormalizationAdapter[VendorDetection],
    ) -> None:
        self._connector = connector
        self._adapter = adapter

    @property
    def vendor(self) -> str:
        return self._adapter.vendor

    async def list_normalized_alerts(
        self,
    ) -> tuple[CanonicalSecurityAlert, ...]:
        detections = await self._connector.list_all_detections()

        return tuple(self._adapter.normalize(detection) for detection in detections)
