import pytest
from httpx import ASGITransport, AsyncClient

from connector_lab.mock_vendor_api.app import app


@pytest.mark.asyncio
async def test_list_detections_returns_vendor_specific_first_page() -> None:
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/detections",
            headers={
                "X-Vendor-API-Key": ("connector-lab-vendor-secret"),
            },
            params={
                "limit": 1,
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "records": [
            {
                "detection_key": "DET-1001",
                "event_name": "Suspicious sign-in pattern",
                "details": ("Multiple unusual authentication attempts detected."),
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
    }
