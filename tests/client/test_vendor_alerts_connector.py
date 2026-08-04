from datetime import UTC, datetime

import pytest
from httpx import (
    AsyncClient,
    MockTransport,
    Request,
    Response,
)

from connector_lab.client.vendor_alerts_connector import (
    VendorAlertsConnector,
)
from connector_lab.client.vendor_alerts_models import (
    VendorEntityCategory,
    VendorObservableKind,
)


@pytest.mark.asyncio
async def test_list_detection_page_sends_typed_vendor_request() -> None:
    def handle_request(request: Request) -> Response:
        assert request.method == "GET"
        assert str(request.url) == ("https://vendor.example/detections?limit=1")
        assert request.headers["X-Vendor-API-Key"] == ("connector-lab-vendor-secret")

        return Response(
            status_code=200,
            json={
                "records": [
                    {
                        "detection_key": "DET-1001",
                        "event_name": ("Suspicious sign-in pattern"),
                        "details": (
                            "Multiple unusual authentication attempts detected."
                        ),
                        "risk_score": 85,
                        "event_time": ("2026-08-03T10:00:00Z"),
                        "tenant_ref": "vendor-tenant-001",
                        "observables": [
                            {
                                "kind": "ip",
                                "indicator": "192.0.2.10",
                            },
                        ],
                        "affected_entity": {
                            "category": "workload",
                            "key": "asset-001",
                            "label": "application-server-01",
                        },
                    },
                ],
                "next_cursor": "cursor-2",
            },
        )

    transport = MockTransport(handle_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = VendorAlertsConnector(
            base_url="https://vendor.example/",
            api_key="connector-lab-vendor-secret",
            http_client=http_client,
            page_size=1,
        )

        page = await connector.list_detection_page()

    assert len(page.records) == 1

    detection = page.records[0]
    assert detection.detection_key == "DET-1001"
    assert detection.risk_score == 85
    assert detection.event_time == datetime(
        2026,
        8,
        3,
        10,
        0,
        tzinfo=UTC,
    )
    assert detection.observables[0].kind is (VendorObservableKind.IP)
    assert detection.affected_entity.category is (VendorEntityCategory.WORKLOAD)
    assert page.next_cursor == "cursor-2"
