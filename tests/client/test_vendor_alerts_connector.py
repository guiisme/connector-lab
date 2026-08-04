from datetime import UTC, datetime

import pytest
from httpx import (
    AsyncClient,
    ConnectError,
    MockTransport,
    ReadTimeout,
    Request,
    Response,
)

from connector_lab.client.errors import (
    ConnectorAuthenticationError,
    ConnectorConnectionError,
    ConnectorTimeoutError,
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


@pytest.mark.asyncio
async def test_list_all_detections_traverses_cursor_pages() -> None:
    requested_urls: list[str] = []

    def handle_request(request: Request) -> Response:
        requested_urls.append(str(request.url))

        if request.url.params.get("cursor") is None:
            return Response(
                status_code=200,
                json={
                    "records": [
                        {
                            "detection_key": "DET-1001",
                            "event_name": "Suspicious sign-in pattern",
                            "details": (
                                "Multiple unusual authentication attempts detected."
                            ),
                            "risk_score": 85,
                            "event_time": "2026-08-03T10:00:00Z",
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

        assert request.url.params["cursor"] == "cursor-2"

        return Response(
            status_code=200,
            json={
                "records": [
                    {
                        "detection_key": "DET-1002",
                        "event_name": "Unexpected domain communication",
                        "details": (
                            "A protected workload contacted an unusual domain."
                        ),
                        "risk_score": 45,
                        "event_time": "2026-08-03T10:05:00Z",
                        "tenant_ref": "vendor-tenant-001",
                        "observables": [
                            {
                                "kind": "domain",
                                "indicator": "example.test",
                            },
                        ],
                        "affected_entity": {
                            "category": "cloud_object",
                            "key": "cloud-object-002",
                            "label": "analytics-workload",
                        },
                    },
                ],
                "next_cursor": None,
            },
        )

    transport = MockTransport(handle_request)

    async with AsyncClient(transport=transport) as http_client:
        connector = VendorAlertsConnector(
            base_url="https://vendor.example",
            api_key="connector-lab-vendor-secret",
            http_client=http_client,
            page_size=1,
        )

        detections = await connector.list_all_detections()

    assert requested_urls == [
        "https://vendor.example/detections?limit=1",
        "https://vendor.example/detections?limit=1&cursor=cursor-2",
    ]
    assert [detection.detection_key for detection in detections] == [
        "DET-1001",
        "DET-1002",
    ]
    assert detections[1].observables[0].kind is (VendorObservableKind.DOMAIN)
    assert detections[1].affected_entity.category is (VendorEntityCategory.CLOUD_OBJECT)


@pytest.mark.parametrize(
    (
        "failure_kind",
        "expected_error",
        "expected_message",
    ),
    [
        (
            "authentication",
            ConnectorAuthenticationError,
            "Vendor alerts authentication failed",
        ),
        (
            "connection",
            ConnectorConnectionError,
            "Vendor alerts endpoint is unavailable",
        ),
        (
            "timeout",
            ConnectorTimeoutError,
            "Vendor alerts request timed out",
        ),
    ],
)
@pytest.mark.asyncio
async def test_list_detection_page_maps_request_failure(
    failure_kind: str,
    expected_error: type[Exception],
    expected_message: str,
) -> None:
    def handle_failure(request: Request) -> Response:
        if failure_kind == "authentication":
            return Response(
                status_code=401,
                json={
                    "detail": "Invalid vendor API key",
                },
            )

        if failure_kind == "connection":
            raise ConnectError(
                "Vendor endpoint unavailable",
                request=request,
            )

        raise ReadTimeout(
            "Vendor request timed out",
            request=request,
        )

    transport = MockTransport(handle_failure)

    async with AsyncClient(transport=transport) as http_client:
        connector = VendorAlertsConnector(
            base_url="https://vendor.example",
            api_key="invalid-vendor-key",
            http_client=http_client,
        )

        with pytest.raises(
            expected_error,
            match=expected_message,
        ):
            await connector.list_detection_page()
